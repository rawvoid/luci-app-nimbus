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
		"\toption singbox_dns_port '5353'\n",
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
	index(lockdown_nft, 'counter name "lockdown_dropped"') >= 0,
	'fail_open=0 generated and validated lockdown rules.nft');

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

check(run_sup_cmd('--prepare-start') == 0, '--prepare-start succeeds with real sing-box check and nft -c -f');
let st_running = common.read_state(state_file);
check(st_running.state == 'running' && type(st_running.config_hash) == 'string' &&
	length(st_running.config_hash) == 64,
	'--prepare-start writes state=running and 64-char SHA256 config_hash');

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
check(st_stopped.state == 'stopped' && st_stopped.last_error == null && fs.stat(pid_file) == null,
	'--stop transitions state.json to stopped and cleans sing-box.pid');

printf('test_supervisor.uc: %d assertions passed\n', passed);
