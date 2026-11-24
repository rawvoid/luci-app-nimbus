#!/usr/bin/ucode
'use strict';

import * as fs from 'fs';
import * as common from 'common';
import * as pu from 'profile_updater';

let passed = 0;

function check(cond, msg) {
	if (!cond) {
		warn(sprintf('FAIL: %s\n', msg));
		exit(1);
	}
	passed++;
}

let repo_root = getenv('NIMBUS_REPO_ROOT') || '/work';
let singbox_bin = getenv('SINGBOX_BIN') || '/usr/local/bin/sing-box';
let modern_fixture = fs.readfile(repo_root + '/tests/fixtures/v114_modern.json');
let legacy_fixture = fs.readfile(repo_root + '/tests/fixtures/v111_legacy.json');
check(type(modern_fixture) == 'string' && type(legacy_fixture) == 'string', 'load profile fixtures');

let tmp_root = getenv('TMPDIR') || '/tmp';
let work_dir = sprintf('%s/prof_test_%d', tmp_root, time());
let conf_dir = work_dir + '/etc_config';
let profiles_dir = work_dir + '/profiles';
let state_file = work_dir + '/state.json';
let check_dir = work_dir + '/check-dir';
check(common.ensure_dir(conf_dir, 0755), 'create conf_dir');
check(common.ensure_dir(profiles_dir, 0755), 'create profiles_dir');

let uci_text =
	"config main 'global'\n" +
	"\toption enabled '1'\n" +
	"\toption active_profile 'main_sub'\n" +
	"\toption topology 'main'\n" +
	"\toption proxy_mode 'tproxy_redirect'\n" +
	"\toption fail_open '0'\n" +
	"\toption ipv4_enable '1'\n" +
	"\toption ipv6_enable '1'\n\n" +
	"config proxy 'proxy'\n" +
	"\toption redirect_port '7891'\n" +
	"\toption tproxy_port '7892'\n" +
	"\toption outbound_mark '0xff'\n" +
	"\toption proxy_mark '0x1'\n" +
	"\toption route_table '100'\n\n" +
	"config profile 'main_sub'\n" +
	"\toption name 'Main Subscription'\n" +
	"\toption type 'subscription'\n" +
	"\toption filename 'main_sub.json'\n" +
	"\toption as_config '1'\n" +
	"\toption url 'https://example.com/sub.json'\n" +
	"\toption user_agent 'sing-box/nimbus-test'\n" +
	"\toption via_proxy '0'\n" +
	"\toption auto_update '1'\n" +
	"\toption update_interval_hours '24'\n\n" +
	"config profile 'nodes_sub'\n" +
	"\toption name 'Nodes Only Sub'\n" +
	"\toption type 'subscription'\n" +
	"\toption filename 'nodes_sub.json'\n" +
	"\toption as_config '0'\n" +
	"\toption url 'https://example.com/nodes.json'\n" +
	"\toption via_proxy '0'\n" +
	"\toption auto_update '0'\n\n" +
	"config profile 'local_p'\n" +
	"\toption name 'Local Profile'\n" +
	"\toption type 'local'\n" +
	"\toption filename 'local_p.json'\n" +
	"\toption as_config '1'\n";

check(common.atomic_write(conf_dir + '/nimbus', uci_text, 0644), 'seed nimbus uci');
let uci_hash_before = common.sha256_file(conf_dir + '/nimbus');
check(common.write_state({ state: 'running', warnings: [], last_error: null }, state_file), 'seed running state');

let reload_count = 0;
let last_curl_argv = null;

let base_opts = {
	uci_confdir: conf_dir,
	profiles_dir: profiles_dir,
	state_file: state_file,
	bin_path: singbox_bin,
	check_dir: check_dir,
	on_reload: () => {
		reload_count++;
		return true;
	}
};

// 1. Initial subscription fetch + real sing-box check in /tmp + atomic publish + service reload
let res1 = pu.update_profiles('main_sub', {
	...base_opts,
	runner: (argv) => {
		last_curl_argv = argv;
		let out_idx = index(argv, '-o');
		common.atomic_write(argv[out_idx + 1], modern_fixture, 0600);
		return 0;
	}
});

check(res1.ok === true && res1.reloaded === true && reload_count == 1,
	'initial subscription update passes real sing-box check, writes file, and reloads running service');
check(type(last_curl_argv) == 'array' &&
	index(last_curl_argv, '-A') >= 0 &&
	index(last_curl_argv, 'sing-box/nimbus-test') >= 0 &&
	index(last_curl_argv, 'https://example.com/sub.json') >= 0,
	'curl invoked with array arguments including custom User-Agent');
check(length(res1.results) == 1 && res1.results[0].id == 'main_sub' &&
	res1.results[0].status == 'updated' && res1.results[0].changed === true,
	'result reports main_sub status=updated and changed=true');

let target_file = profiles_dir + '/main_sub.json';
let st_prof1 = fs.stat(target_file);
check(st_prof1 != null && fs.readfile(target_file) == modern_fixture,
	'main_sub.json atomically written to profiles_dir');

// 2. Second fetch with identical content (same SHA256) -> no disk write, no service reload
let res2 = pu.update_profiles('main_sub', {
	...base_opts,
	runner: (argv) => {
		let out_idx = index(argv, '-o');
		common.atomic_write(argv[out_idx + 1], modern_fixture, 0600);
		return 0;
	}
});
let st_prof2 = fs.stat(target_file);
check(res2.ok === true && res2.reloaded === false && reload_count == 1 &&
	res2.results[0].status == 'unchanged' && res2.results[0].changed === false &&
	st_prof2.inode == st_prof1.inode,
	'identical SHA256 skips file write (inode preserved) and skips service reload');

// Verify sub_meta is stored in state.json and UCI file was never modified
let st_state = common.read_state(state_file);
check(type(st_state.sub_meta?.main_sub) == 'object' &&
	st_state.sub_meta.main_sub.sha256 == common.sha256_str(modern_fixture),
	'sub_meta stored in state.json');
check(common.sha256_file(conf_dir + '/nimbus') == uci_hash_before,
	'UCI config file on disk never modified with runtime subscription metadata');

// 3. Invalid JSON or failing sing-box check MUST NOT overwrite existing profile
let bad_singbox_cfg = '{"outbounds":[{"type":"nonexistent_protocol_xyz","tag":"bad"}]}\n';
let res_bad_check = pu.update_profiles('main_sub', {
	...base_opts,
	runner: (argv) => {
		let out_idx = index(argv, '-o');
		common.atomic_write(argv[out_idx + 1], bad_singbox_cfg, 0600);
		return 0;
	}
});
check(res_bad_check.ok === false && res_bad_check.reloaded === false &&
	res_bad_check.results[0].status == 'failed',
	'subscription failing sing-box check is rejected');
check(fs.readfile(target_file) == modern_fixture && fs.stat(target_file).inode == st_prof1.inode,
	'existing valid profile is byte-for-byte untouched when sing-box check fails');

let res_bad_json = pu.update_profiles('main_sub', {
	...base_opts,
	runner: (argv) => {
		let out_idx = index(argv, '-o');
		common.atomic_write(argv[out_idx + 1], '{broken json', 0600);
		return 0;
	}
});
check(res_bad_json.ok === false && fs.readfile(target_file) == modern_fixture,
	'existing valid profile untouched when downloaded subscription is invalid JSON');

// 4. Scheduled hourly dispatcher (due_only) and cron sync
let now_ts = time();
let res_not_due = pu.run_scheduled_updates({
	...base_opts,
	now: now_ts + 3600,
	runner: () => 0
});
check(res_not_due.ok === true && length(res_not_due.results) == 0,
	'run_scheduled_updates skips subscription when interval (24h) has not elapsed');

let res_due = pu.run_scheduled_updates({
	...base_opts,
	now: now_ts + (25 * 3600),
	runner: (argv) => {
		let out_idx = index(argv, '-o');
		common.atomic_write(argv[out_idx + 1], legacy_fixture, 0600);
		return 0;
	}
});
check(res_due.ok === true && length(res_due.results) == 1 &&
	res_due.results[0].status == 'updated' && res_due.reloaded === true,
	'run_scheduled_updates updates subscription once interval has elapsed');

let crontab_file = work_dir + '/crontab_root';
let cron_add = pu.sync_cron(null, {
	uci_confdir: conf_dir,
	crontab_path: crontab_file
});
check(cron_add.ok === true && cron_add.changed === true &&
	index(fs.readfile(crontab_file) || '', '# nimbus-profile') >= 0,
	'sync_cron registers hourly # nimbus-profile cron job');

let cron_sub_tag = pu.sync_cron(null, {
	uci_confdir: conf_dir,
	crontab_path: crontab_file,
	cron_tag: 'nimbus-sub-sync'
});
check(cron_sub_tag.ok === true && index(fs.readfile(crontab_file) || '', '# nimbus-sub-sync') >= 0,
	'sync_cron supports # nimbus-sub-sync tag');

let cron_del = pu.sync_cron(null, {
	uci_confdir: conf_dir,
	crontab_path: crontab_file,
	enabled: false
});
check(cron_del.ok === true && index(fs.readfile(crontab_file) || '', '# nimbus-profile') < 0,
	'sync_cron removes cron job when no auto_update subscription is enabled');

// 5. Regression test: concurrent state transition during download, lock release before reload, and E_LOCKED
let lock_file = work_dir + '/nimbus.lock';

// 5a. Concurrent transition running -> stopped during download preserves stopped and skips reload
check(common.write_state({
	state: 'running',
	warnings: [ 'before' ],
	core: { version: '1.14.4' },
	last_error: null
}, state_file), 'seed running state for concurrent stop test');

let reload_during_stopped = 0;
let res_conc_stop = pu.update_profiles('main_sub', {
	...base_opts,
	lock_file: lock_file,
	on_reload: () => {
		reload_during_stopped++;
		return true;
	},
	runner: (argv) => {
		common.write_state({
			state: 'stopped',
			warnings: [ 'stopped-during-sub-dl' ],
			core: { version: '1.14.4' },
			last_error: null
		}, state_file);
		let out_idx = index(argv, '-o');
		common.atomic_write(argv[out_idx + 1], modern_fixture, 0600);
		return 0;
	}
});
let st_after_conc = common.read_state(state_file);
check(res_conc_stop.ok === true && res_conc_stop.reloaded === false && reload_during_stopped == 0,
	'update_profiles skips service reload when state transitioned to stopped during download');
check(st_after_conc.state == 'stopped' &&
	st_after_conc.warnings[0] == 'stopped-during-sub-dl' &&
	st_after_conc.sub_meta?.main_sub?.status == 'updated',
	'update_profiles preserves concurrent state=stopped while committing fresh sub_meta');

// 5b. Lock is released BEFORE on_reload executes (prevents deadlock with supervisor --prepare-reload)
check(common.write_state({ state: 'running', warnings: [], last_error: null }, state_file),
	'seed running state for lock-release-before-reload test');
let lock_free_in_reload = false;
let res_lock_rel = pu.update_profiles('main_sub', {
	...base_opts,
	lock_file: lock_file,
	on_reload: () => {
		let lfh = common.acquire_lock(0, lock_file);
		if (lfh) {
			lock_free_in_reload = true;
			common.release_lock(lfh);
		}
		return true;
	},
	runner: (argv) => {
		let out_idx = index(argv, '-o');
		common.atomic_write(argv[out_idx + 1], legacy_fixture, 0600);
		return 0;
	}
});
check(res_lock_rel.ok === true && res_lock_rel.reloaded === true && lock_free_in_reload === true,
	'update_profiles releases nimbus.lock before calling trigger_service_reload');

// 5c. Lock contention returns E_LOCKED cleanly
let held_fh = common.acquire_lock(0, lock_file);
check(held_fh != null, 'acquire nimbus.lock for profile contention test');
let res_locked = pu.update_profiles('main_sub', {
	...base_opts,
	lock_file: lock_file,
	lock_timeout_ms: 40,
	runner: (argv) => {
		let out_idx = index(argv, '-o');
		common.atomic_write(argv[out_idx + 1], modern_fixture, 0600);
		return 0;
	}
});
check(res_locked.ok === false && res_locked.code == common.ERR_LOCKED && res_locked.reloaded === false,
	'update_profiles returns E_LOCKED when nimbus.lock is held');
common.release_lock(held_fh);

// 6. Verify as_config=0 bare-array subscription update & list_profiles metadata
let nodes_arr_raw = '[{"type":"shadowsocks","tag":"N1","server":"198.51.100.1","server_port":8388,"method":"aes-128-gcm","password":"pw"}]\n';
let reload_before_nodes = reload_count;
let res_nodes_sub = pu.update_profiles('nodes_sub', {
	...base_opts,
	runner: (argv) => {
		let out_idx = index(argv, '-o');
		common.atomic_write(argv[out_idx + 1], nodes_arr_raw, 0600);
		return 0;
	}
});
check(res_nodes_sub.ok === true && res_nodes_sub.reloaded === false && reload_count == reload_before_nodes &&
	fs.readfile(profiles_dir + '/nodes_sub.json') == nodes_arr_raw,
	'as_config=0 subscription accepts bare outbound array and skips reloading unrelated active profile');

let plist = pu.list_profiles(null, {
	uci_confdir: conf_dir,
	profiles_dir: profiles_dir,
	composers_dir: work_dir + '/composers'
});
let by_id = {};
for (let p in (plist?.profiles || []))
	by_id[p.id] = p;
check(plist.ok === true &&
	by_id.main_sub?.as_config === true && by_id.main_sub?.active === true &&
	by_id.nodes_sub?.as_config === false && by_id.nodes_sub?.active === false &&
	type(by_id.nodes_sub?.used_by_composers) == 'array' &&
	by_id.local_p?.as_config === true,
	'list_profiles exposes as_config, active, and used_by_composers metadata');

printf('test_profile_updater.uc: %d assertions passed\n', passed);
