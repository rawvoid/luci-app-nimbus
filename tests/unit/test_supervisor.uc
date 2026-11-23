#!/usr/bin/ucode
'use strict';

import * as fs from 'fs';
import * as uloop from 'uloop';
import * as common from 'common';

let passed = 0;

function check(cond, msg) {
	if (!cond) {
		warn(sprintf('FAIL: %s\n', msg));
		exit(1);
	}
	passed++;
}

let repo_root = getenv('NIMBUS_REPO_ROOT') || '/work';
let nimbus_lib = repo_root + '/nimbus/files/usr/share/nimbus';
let sup_script = nimbus_lib + '/supervisor.uc';
let tmp_root = getenv('TMPDIR') || '/tmp';
let work_dir = sprintf('%s/sup_test_%d', tmp_root, time());
check(common.ensure_dir(work_dir, 0755), 'create work_dir');

let conf_dir = work_dir + '/etc_config';
let save_dir = work_dir + '/tmp_uci';
let run_dir = work_dir + '/run';
check(common.ensure_dir(conf_dir, 0755), 'create conf_dir');
check(common.ensure_dir(save_dir, 0755), 'create save_dir');
check(common.ensure_dir(run_dir, 0755), 'create run_dir');

function write_uci_nimbus(fail_open, dns_mode) {
	let text = sprintf(
		"config main 'global'\n" +
		"\toption enabled '1'\n" +
		"\toption topology 'main'\n" +
		"\toption proxy_mode 'tproxy_redirect'\n" +
		"\toption fail_open '%s'\n" +
		"\toption ipv4_enable '1'\n" +
		"\toption ipv6_enable '1'\n" +
		"\toption gomemlimit 'auto'\n\n" +
		"config proxy 'proxy'\n" +
		"\toption redirect_port '7891'\n" +
		"\toption tproxy_port '7892'\n" +
		"\toption outbound_mark '0xff'\n" +
		"\toption proxy_mark '0x1'\n" +
		"\toption route_table '100'\n\n" +
		"config dns 'dns'\n" +
		"\toption mode '%s'\n" +
		"\toption singbox_dns_port '5353'\n\n" +
		"config whitelist 'whitelist'\n" +
		"\toption enabled '1'\n" +
		"\toption auto_update '1'\n" +
		"\toption update_cron '30 4 * * *'\n\n" +
		"config list_source 'cn_ipv4'\n" +
		"\toption name 'China IPv4'\n" +
		"\toption type 'url'\n" +
		"\toption enabled '1'\n" +
		"\toption family 'ipv4'\n" +
		"\toption url 'https://example.com/cn_v4.txt'\n\n" +
		"config list_source 'custom_direct'\n" +
		"\toption name 'Custom Direct'\n" +
		"\toption type 'local'\n" +
		"\toption enabled '1'\n" +
		"\toption family 'auto'\n" +
		"\toption filename 'custom_direct.txt'\n\n" +
		"config profile 'main_sub'\n" +
		"\toption name 'Main Sub'\n" +
		"\toption type 'subscription'\n" +
		"\toption filename 'main_sub.json'\n" +
		"\toption url 'https://example.com/sub.json'\n" +
		"\toption auto_update '1'\n" +
		"\toption update_interval_hours '24'\n",
		fail_open,
		dns_mode
	);
	return common.atomic_write(conf_dir + '/nimbus', text, 0644);
}

let pid_file = run_dir + '/sing-box.pid';
let state_file = run_dir + '/state.json';
let lock_file = run_dir + '/nimbus.lock';
let rules_file = run_dir + '/rules.nft';
let cfg_file = run_dir + '/config.json';
let log_file = run_dir + '/nimbus.log';
let local_lists_dir = work_dir + '/lists/local';
let cache_lists_dir = work_dir + '/lists/cache';
let crontab_file = work_dir + '/crontab_root';
check(common.ensure_dir(local_lists_dir, 0755), 'create local_lists_dir');
check(common.ensure_dir(cache_lists_dir, 0755), 'create cache_lists_dir');
check(common.atomic_write(local_lists_dir + '/custom_direct.txt', '1.1.8.0/24\n2400:3200::/32\n', 0644), 'seed custom_direct.txt');
check(common.atomic_write(cache_lists_dir + '/cn_ipv4.txt', '1.0.1.0/24\n1.0.2.0/23\n', 0644), 'seed cn_ipv4.txt');

check(common.atomic_write(cfg_file, '{"outbounds":[{"type":"direct","tag":"direct"}]}\n', 0600), 'write dummy config.json');

// 1. Test SIGTERM graceful shutdown (no Fail Handler triggered) + 512KB->256KB log truncation timer
let mock_ok_bin = work_dir + '/mock-sing-box-ok.sh';
let env_dump_file = work_dir + '/child_env.txt';
check(common.atomic_write(mock_ok_bin, sprintf(
	'#!/bin/sh\n' +
	'printf "GOMEMLIMIT=%%s\\nGOGC=%%s\\nARGS=%%s\\n" "$GOMEMLIMIT" "$GOGC" "$*" > "%s"\n' +
	'trap "exit 0" TERM INT\n' +
	'while :; do sleep 1; done\n',
	env_dump_file
), 0755), 'write mock_ok_bin');

check(write_uci_nimbus('0', 'singbox'), 'write uci fail_open=0');
check(common.write_state({ state: 'running', last_error: null, warnings: [] }, state_file), 'seed running state');

// Seed log file > 512KB (560KB) to test supervisor log hysteresis timer
let chunk_line = '2026-11-22 00:00:00 [info] supervisor log rotation test line 0123456789abcdef\n';
let big_buf = '';
while (length(big_buf) < 560000)
	big_buf = big_buf + chunk_line;
check(common.atomic_write(log_file, big_buf, 0644), 'seed >512KB log file');

uloop.init();
let sup_exit_code = null;
let sup_env = {
	PATH: getenv('PATH') || '/usr/sbin:/usr/bin:/sbin:/bin',
	NIMBUS_UCI_CONFDIR: conf_dir,
	NIMBUS_UCI_SAVEDIR: save_dir,
	NIMBUS_BIN_PATH: mock_ok_bin,
	NIMBUS_CONFIG_FILE: cfg_file,
	NIMBUS_WORK_DIR: run_dir,
	NIMBUS_PID_FILE: pid_file,
	NIMBUS_STATE_FILE: state_file,
	NIMBUS_LOCK_FILE: lock_file,
	NIMBUS_RULES_FILE: rules_file,
	NIMBUS_LOG_FILE: log_file,
	NIMBUS_LOCAL_LISTS_DIR: local_lists_dir,
	NIMBUS_CACHE_LISTS_DIR: cache_lists_dir,
	NIMBUS_CRONTAB_FILE: crontab_file,
	NIMBUS_LOG_TIMER_MS: '40',
	NIMBUS_KILL_GRACE_MS: '1000',
	NIMBUS_SKIP_ROUTES: '1'
};

let sup_proc = uloop.process(
	'/usr/bin/ucode',
	[ '-S', '-L', nimbus_lib, sup_script ],
	sup_env,
	(code) => {
		sup_exit_code = code;
		uloop.end();
	}
);

let observed_child_pid = null;
let poll_timer = null;
let polls = 0;

function check_pid_and_stop() {
	polls++;
	let raw_pid = fs.readfile(pid_file);
	let st_log = fs.stat(log_file);
	if (type(raw_pid) == 'string' && match(trim(raw_pid), /^[0-9]+$/) &&
		st_log && st_log.size <= common.LOG_KEEP_BYTES) {
		observed_child_pid = trim(raw_pid);
		system([ '/bin/kill', '-TERM', '' + sup_proc.pid() ]);
		return;
	}
	if (polls > 50) {
		system([ '/bin/kill', '-KILL', '' + sup_proc.pid() ]);
		uloop.end();
		return;
	}
	poll_timer = uloop.timer(40, check_pid_and_stop);
}
poll_timer = uloop.timer(40, check_pid_and_stop);
uloop.run();

check(observed_child_pid != null, 'supervisor wrote real child PID to sing-box.pid');
check(sup_exit_code == 0, 'supervisor exited cleanly with code 0 on SIGTERM');
check(fs.stat(pid_file) == null, 'supervisor cleaned up sing-box.pid on SIGTERM');
let st_after_sigterm = common.read_state(state_file);
check(st_after_sigterm.state == 'running' && st_after_sigterm.last_error == null,
	'SIGTERM shutdown did NOT trigger Fail Handler');
let st_log_after = fs.stat(log_file);
check(st_log_after != null && st_log_after.size <= common.LOG_KEEP_BYTES && st_log_after.size > 200000,
	'supervisor timer truncated >512KB log file in-place to <=256KB');
let env_dump = fs.readfile(env_dump_file) || '';
check(index(env_dump, 'GOGC=50') >= 0 && match(env_dump, /GOMEMLIMIT=[0-9]+MiB/) != null &&
	index(env_dump, 'ARGS=run -c ' + cfg_file + ' -D ' + run_dir) >= 0,
	'supervisor passed GOMEMLIMIT, GOGC=50, and run -c ... -D ... arguments');

// 2. Test crash retry exhaustion (3 retries within 60s -> 4 total runs) with fail_open='0' -> lockdown
let crash_count_file = work_dir + '/crash_count.txt';
let mock_crash_bin = work_dir + '/mock-sing-box-crash.sh';
check(common.atomic_write(crash_count_file, '0\n', 0644), 'init crash_count_file');
check(common.atomic_write(mock_crash_bin, sprintf(
	'#!/bin/sh\n' +
	'c=$(cat "%s" 2>/dev/null || echo 0)\n' +
	'c=$((c + 1))\n' +
	'printf "%%s\\n" "$c" > "%s"\n' +
	'exit 42\n',
	crash_count_file, crash_count_file
), 0755), 'write mock_crash_bin');

let crash_env_0 = {
	...sup_env,
	NIMBUS_BIN_PATH: mock_crash_bin,
	NIMBUS_MAX_RETRIES: '3',
	NIMBUS_RETRY_WINDOW_SEC: '60',
	NIMBUS_RETRY_BACKOFF_MS: '20',
	NIMBUS_NFT_CHECK_ONLY: '1'
};

let rc_crash_0 = null;
let p_crash_0 = uloop.process(
	'/usr/bin/ucode',
	[ '-S', '-L', nimbus_lib, sup_script ],
	crash_env_0,
	(code) => {
		rc_crash_0 = code;
		uloop.end();
	}
);
check(p_crash_0 != null, 'spawn supervisor for fail_open=0 crash test');
uloop.run();

check(rc_crash_0 == 0, 'supervisor exited after exhausting retries without respawning forever');
check(trim(fs.readfile(crash_count_file) || '') == '4',
	'supervisor ran initial spawn + 3 retries = 4 total attempts within 60s window');
check(fs.stat(pid_file) == null, 'sing-box.pid cleaned up after crash exhaustion');
let st_lockdown = common.read_state(state_file);
check(st_lockdown.state == 'lockdown' &&
	type(st_lockdown.last_error) == 'string' && index(st_lockdown.last_error, '3 retries exhausted') >= 0,
	'fail_open=0 switches state.json to lockdown with last_error');
check(type(st_lockdown.warnings) == 'array' && length(st_lockdown.warnings) >= 1 &&
	index(st_lockdown.warnings[0], 'dns.mode="singbox"') >= 0,
	'fail_open=0 in dns.mode=singbox records DNS lockdown recovery warning');
let lockdown_nft = fs.readfile(rules_file) || '';
check(index(lockdown_nft, 'chain forward_lockdown {') >= 0 &&
	index(lockdown_nft, 'counter name "lockdown_dropped"') >= 0 &&
	index(lockdown_nft, '1.0.1.0/24') >= 0 &&
	index(lockdown_nft, '2400:3200::/32') >= 0,
	'fail_open=0 generated and validated lockdown rules.nft with active whitelist bypass sets');
check(st_lockdown.whitelist?.v4_count == 3 && st_lockdown.whitelist?.v6_count == 1,
	'fail_open=0 records active whitelist counts in lockdown state.json');

// 3. Test crash retry exhaustion with fail_open='1' -> state: "error" & delete table
check(write_uci_nimbus('1', 'none'), 'write uci fail_open=1');
check(common.atomic_write(crash_count_file, '0\n', 0644), 'reset crash_count_file');
check(common.write_state({ state: 'running', last_error: null, warnings: [] }, state_file), 're-seed running state');

let rc_crash_1 = null;
let p_crash_1 = uloop.process(
	'/usr/bin/ucode',
	[ '-S', '-L', nimbus_lib, sup_script ],
	crash_env_0,
	(code) => {
		rc_crash_1 = code;
		uloop.end();
	}
);
check(p_crash_1 != null, 'spawn supervisor for fail_open=1 crash test');
uloop.run();

let st_err = common.read_state(state_file);
check(st_err.state == 'error' &&
	type(st_err.last_error) == 'string' && index(st_err.last_error, '3 retries exhausted') >= 0,
	'fail_open=1 switches state.json to error with last_error');

// 4. Test --prepare-start, smart --prepare-reload (SHA256 comparison), --hotplug, and --stop
let singbox_bin = getenv('SINGBOX_BIN') || '/usr/local/bin/sing-box';
let fixture_profile = repo_root + '/tests/fixtures/v114_modern.json';
check(write_uci_nimbus('0', 'none'), 'reset uci for prepare-start/reload tests');

let prep_env = {
	...sup_env,
	NIMBUS_BIN_PATH: singbox_bin,
	NIMBUS_PROFILE_PATH: fixture_profile,
	NIMBUS_CHECK_DIR: work_dir + '/check-dir',
	NIMBUS_NFT_CHECK_ONLY: '1'
};

function run_sup_cmd(arg, extra_env) {
	let code_out = null;
	uloop.process(
		'/usr/bin/ucode',
		[ '-S', '-L', nimbus_lib, sup_script, arg ],
		{ ...prep_env, ...(extra_env || {}) },
		(c) => {
			code_out = c;
			uloop.end();
		}
	);
	uloop.run();
	return code_out;
}

// Seed list_meta and sub_meta before --prepare-start to verify preservation across start/reload/stop
check(common.write_state({
	state: 'stopped',
	list_meta: { cn_ipv4: { status: 'updated', v4_count: 2 } },
	sub_meta: { main_sub: { status: 'updated', size_bytes: 512 } },
	warnings: [],
	last_error: null
}, state_file), 'seed state.json with list_meta and sub_meta');

check(run_sup_cmd('--prepare-start') == 0, '--prepare-start succeeds with real sing-box check and nft -c -f');
let st_running = common.read_state(state_file);
check(st_running.state == 'running' && type(st_running.config_hash) == 'string' &&
	length(st_running.config_hash) == 64,
	'--prepare-start writes state=running and 64-char SHA256 config_hash');
check(st_running.whitelist?.enabled === true &&
	st_running.whitelist?.v4_count == 3 &&
	st_running.whitelist?.v6_count == 1,
	'--prepare-start populates active whitelist counts in state.json');
check(st_running.list_meta?.cn_ipv4?.v4_count == 2 &&
	st_running.sub_meta?.main_sub?.size_bytes == 512,
	'--prepare-start preserves existing list_meta and sub_meta in state.json');
let running_nft = fs.readfile(rules_file) || '';
check(index(running_nft, '1.0.1.0/24') >= 0 &&
	index(running_nft, '1.1.8.0/24') >= 0 &&
	index(running_nft, '2400:3200::/32') >= 0,
	'--prepare-start passes active whitelist bypass_v4/bypass_v6 into nft.apply_rules');
let cron_after_prep = fs.readfile(crontab_file) || '';
check(index(cron_after_prep, '# nimbus-whitelist') >= 0 &&
	index(cron_after_prep, '# nimbus-profile') >= 0,
	'--prepare-start syncs whitelist and profile cron jobs');

// Seed live PID (current test process PID is alive in /proc)
let self_pid = fs.readlink('/proc/self') || '1';
check(common.atomic_write(pid_file, self_pid + '\n', 0644), 'seed alive PID for smart reload check');
check(run_sup_cmd('--prepare-reload') == 10,
	'--prepare-reload returns exit code 10 (skip sing-box restart) when config.json SHA256 is unchanged');

// Change profile to v111_legacy.json so config.json SHA256 changes -> must return 0 (full reload)
check(run_sup_cmd('--prepare-reload', {
	NIMBUS_PROFILE_PATH: repo_root + '/tests/fixtures/v111_legacy.json'
}) == 0, '--prepare-reload returns exit code 0 (restart required) when config.json SHA256 changes');

// Hotplug refresh in running state
check(run_sup_cmd('--hotplug') == 0, '--hotplug refreshes dynamic interface sets when running');

// Clean stop
check(run_sup_cmd('--stop') == 0, '--stop tears down dataplane cleanly');
let st_stopped = common.read_state(state_file);
check(st_stopped.state == 'stopped' && st_stopped.last_error == null && fs.stat(pid_file) == null &&
	st_stopped.list_meta?.cn_ipv4?.v4_count == 2 &&
	st_stopped.sub_meta?.main_sub?.size_bytes == 512 &&
	st_stopped.whitelist?.v4_count == 3,
	'--stop transitions state.json to stopped, cleans sing-box.pid, and preserves list_meta/sub_meta/whitelist');

// 5. Regression test: core binary upgrade triggers restart (exit 0) even with identical config.json SHA256
let core_stamp_file = run_dir + '/core.stamp';
let test_core_bin = work_dir + '/sing-box-wrapper';
let make_wrapper = (tag) => sprintf('#!/bin/sh\n# %s\nexec "%s" "$@"\n', tag, singbox_bin);
check(common.atomic_write(test_core_bin, make_wrapper('v1'), 0755), 'write wrapper binary v1');

check(run_sup_cmd('--prepare-start', {
	NIMBUS_BIN_PATH: test_core_bin,
	NIMBUS_CORE_STAMP_FILE: core_stamp_file
}) == 0, '--prepare-start succeeds with wrapper binary v1');

let st_core_v1 = common.read_state(state_file);
let sha_v1 = common.sha256_file(test_core_bin);
let stamp_st = fs.stat(core_stamp_file);
let stamp_v1 = trim(fs.readfile(core_stamp_file) || '');
check(st_core_v1.core?.bin_path == test_core_bin &&
	st_core_v1.core?.bin_sha256 == sha_v1 &&
	stamp_st != null && (stamp_st.mode & 0777) == 0600 &&
	length(stamp_v1) > 0,
	'--prepare-start stores core.bin_sha256 in state.json and writes core.stamp with mode 0600');

check(common.atomic_write(pid_file, self_pid + '\n', 0644), 'seed alive PID for core unchanged check');
check(run_sup_cmd('--prepare-reload', {
	NIMBUS_BIN_PATH: test_core_bin,
	NIMBUS_CORE_STAMP_FILE: core_stamp_file
}) == 10, '--prepare-reload returns 10 when both config.json and core binary are unchanged');

// Replace binary in-place (different SHA256, identical config.json) -> MUST exit 0 (NOT 10)
check(common.atomic_write(test_core_bin, make_wrapper('v2-upgraded'), 0755), 'replace wrapper binary with v2');
let sha_v2 = common.sha256_file(test_core_bin);
check(sha_v2 != sha_v1, 'wrapper v2 has different SHA256');
check(run_sup_cmd('--prepare-reload', {
	NIMBUS_BIN_PATH: test_core_bin,
	NIMBUS_CORE_STAMP_FILE: core_stamp_file
}) == 0, '--prepare-reload returns exit 0 (restart required) when sing-box binary changes even with identical config.json');

let st_core_v2 = common.read_state(state_file);
let stamp_v2 = trim(fs.readfile(core_stamp_file) || '');
check(st_core_v2.core?.bin_sha256 == sha_v2 && stamp_v2 != stamp_v1,
	'--prepare-reload updates state.core.bin_sha256 and core.stamp after binary replacement');

// Legacy state.json missing bin_sha256 must be handled cleanly without crashing
let legacy_st = {
	...st_core_v2,
	core: {
		bin_path: test_core_bin,
		version: st_core_v2.core?.version
	}
};
check(common.write_state(legacy_st, state_file), 'seed legacy state missing core.bin_sha256');
check(run_sup_cmd('--prepare-reload', {
	NIMBUS_BIN_PATH: test_core_bin,
	NIMBUS_CORE_STAMP_FILE: core_stamp_file
}) == 10, '--prepare-reload handles missing core.bin_sha256 cleanly and skips restart when path/version match');
check(common.read_state(state_file)?.core?.bin_sha256 == sha_v2,
	'--prepare-reload backfills core.bin_sha256 on legacy state');

// 6. Verify init.d/nimbus procd config.json tracking, NIMBUS_CORE_STAMP env, + NIMBUS_PREPARED guard and Makefile 0755 hotplug install
let init_script = fs.readfile(repo_root + '/nimbus/files/etc/init.d/nimbus') || '';
check(index(init_script, 'procd_set_param file /var/run/nimbus/config.json') >= 0,
	'init.d/nimbus registers /var/run/nimbus/config.json with procd_set_param file');
check(index(init_script, 'core_stamp=$(cat /var/run/nimbus/core.stamp 2>/dev/null || true)') >= 0 &&
	index(init_script, 'NIMBUS_CORE_STAMP="$core_stamp"') >= 0,
	'init.d/nimbus reads /var/run/nimbus/core.stamp and exports NIMBUS_CORE_STAMP in procd_set_param env');
check(index(init_script, 'if [ "${NIMBUS_PREPARED:-0}" != "1" ]; then') >= 0 &&
	index(init_script, 'NIMBUS_PREPARED=1') >= 0,
	'init.d/nimbus guards --prepare-start with NIMBUS_PREPARED when triggered from reload_service');
let makefile_text = fs.readfile(repo_root + '/nimbus/Makefile') || '';
check(index(makefile_text, '$(INSTALL_BIN) ./files/etc/hotplug.d/iface/90-nimbus $(1)/etc/hotplug.d/iface/90-nimbus') >= 0,
	'nimbus/Makefile installs 90-nimbus with $(INSTALL_BIN) (0755)');

// 7. P0 regression test: Fail Handler falls back to static emergency lockdown if primary lockdown fails, and marks error if nft is completely broken
check(write_uci_nimbus('0', 'none'), 'reset uci fail_open=0 for emergency lockdown fallback test');
let mock_nft_flaky = work_dir + '/mock-nft-flaky.sh';
let nft_call_file = work_dir + '/nft_calls.txt';
check(common.atomic_write(nft_call_file, '0\n', 0644), 'init nft_call_file');
check(common.atomic_write(mock_nft_flaky, sprintf(
	'#!/bin/sh\n' +
	'n=$(cat "%s" 2>/dev/null || echo 0)\n' +
	'n=$((n + 1))\n' +
	'printf "%%s\\n" "$n" > "%s"\n' +
	'if [ "$n" -eq 1 ]; then\n' +
	'\techo "simulated primary lockdown failure" >&2\n' +
	'\texit 1\n' +
	'fi\n' +
	'exec /usr/sbin/nft "$@"\n',
	nft_call_file, nft_call_file
), 0755), 'write mock_nft_flaky');

check(run_sup_cmd('--fail-handler', { NFT_BIN: mock_nft_flaky }) == 0, '--fail-handler runs with flaky nft');
let st_emg = common.read_state(state_file);
check(st_emg.state == 'lockdown' &&
	trim(fs.readfile(nft_call_file) || '') == '2' &&
	length(filter(st_emg.warnings || [], (w) => index(w, 'emergency static fail-closed') >= 0)) == 1,
	'Fail Handler falls back to static emergency lockdown and validates with real nft when primary lockdown fails');

let mock_nft_dead = work_dir + '/mock-nft-dead.sh';
check(common.atomic_write(mock_nft_dead, '#!/bin/sh\necho "nft totally broken" >&2\nexit 1\n', 0755), 'write mock_nft_dead');
check(run_sup_cmd('--fail-handler', { NFT_BIN: mock_nft_dead }) == 0, '--fail-handler runs with dead nft');
let st_dead = common.read_state(state_file);
check(st_dead.state == 'error' && index(st_dead.last_error || '', 'CRITICAL') >= 0,
	'Fail Handler refuses to claim state=lockdown when both primary and emergency lockdown fail');

printf('test_supervisor.uc: %d assertions passed\n', passed);
