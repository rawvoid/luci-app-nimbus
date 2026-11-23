#!/usr/bin/ucode
'use strict';

import * as fs from 'fs';
import * as uloop from 'uloop';
import * as common from 'common';
import * as cb from 'config_builder';

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
let rpcd_script = repo_root + '/nimbus/files/usr/share/rpcd/ucode/luci.nimbus.uc';
let acl_path = repo_root + '/luci-app-nimbus/root/usr/share/rpcd/acl.d/luci-app-nimbus.json';
let menu_path = repo_root + '/luci-app-nimbus/root/usr/share/luci/menu.d/luci-app-nimbus.json';

let tmp_root = getenv('TMPDIR') || '/tmp';
let work_dir = sprintf('%s/rpc_test_%d', tmp_root, time());
let conf_dir = work_dir + '/etc_config';
let save_dir = work_dir + '/tmp_uci';
let run_dir = work_dir + '/run';
let profiles_dir = work_dir + '/profiles';
let local_lists_dir = work_dir + '/lists_local';
let cache_lists_dir = work_dir + '/lists_cache';
let check_dir = work_dir + '/check_dir';
let core_work_dir = work_dir + '/core_dl';
let crontab_file = work_dir + '/crontab_root';
let upload_dir = work_dir + '/uploads';

for (let d in [ work_dir, conf_dir, save_dir, run_dir, profiles_dir, local_lists_dir, cache_lists_dir, core_work_dir, upload_dir ])
	check(common.ensure_dir(d, 0755), sprintf('create dir %s', d));

let state_file = run_dir + '/state.json';
let config_file = run_dir + '/config.json';
let pid_file = run_dir + '/sing-box.pid';
let lock_file = run_dir + '/nimbus.lock';
let log_file = run_dir + '/nimbus.log';
let core_task_file = run_dir + '/core_task.json';
let bypass_nft_path = run_dir + '/bypass_sets.nft';
let upload_profile_path = upload_dir + '/upload.json';
let upload_list_path = upload_dir + '/upload.txt';
let upload_bin_path = upload_dir + '/upload.bin';
let init_script = work_dir + '/mock-init.sh';
let mock_curl = work_dir + '/mock-curl.sh';

let uci_seed =
	"config main 'global'\n" +
	"\toption enabled '1'\n" +
	"\toption config_mode 'profile'\n" +
	"\toption active_profile ''\n" +
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
	"config dns 'dns'\n" +
	"\toption mode 'none'\n" +
	"\toption singbox_dns_port '5353'\n\n" +
	"config core 'core'\n" +
	"\toption bin_path '" + singbox_bin + "'\n" +
	"\toption repo 'SagerNet/sing-box'\n" +
	"\toption channel 'stable'\n\n" +
	"config whitelist 'whitelist'\n" +
	"\toption enabled '1'\n" +
	"\toption auto_update '1'\n" +
	"\toption update_cron '30 4 * * *'\n";

check(common.atomic_write(conf_dir + '/nimbus', uci_seed, 0644), 'seed nimbus UCI');

let rpc_cfg = {
	uci_confdir: conf_dir,
	uci_savedir: save_dir,
	state_file: state_file,
	config_file: config_file,
	pid_file: pid_file,
	lock_file: lock_file,
	log_file: log_file,
	profiles_dir: profiles_dir,
	local_lists_dir: local_lists_dir,
	cache_lists_dir: cache_lists_dir,
	core_task_file: core_task_file,
	upload_profile_path: upload_profile_path,
	upload_list_path: upload_list_path,
	upload_bin_path: upload_bin_path,
	crontab_file: crontab_file,
	check_dir: check_dir,
	core_work_dir: core_work_dir,
	init_script: init_script,
	curl_bin: mock_curl,
	openwrt_arch: 'aarch64_cortex-a53',
	tmp_free_bytes: 200 * 1024 * 1024,
	target_free_bytes: 200 * 1024 * 1024,
	same_fs: false,
	nft_dry_run: true,
	skip_nft: true,
	skip_cron_reload: true,
	skip_reload: true,
	disable_ubus: true,
	bin_path: singbox_bin
};

global.__nimbus_rpc_cfg = rpc_cfg;

uloop.init();

let loaded_fn = loadfile(rpcd_script);
check(type(loaded_fn) == 'function', 'loadfile compiles luci.nimbus.uc cleanly');
let plugin = loaded_fn();
check(type(plugin) == 'object' && type(plugin['luci.nimbus']) == 'object',
	'luci.nimbus.uc exports { "luci.nimbus": methods }');
let rpc = plugin['luci.nimbus'];

function call_rpc(name, args) {
	check(exists(rpc, name) && type(rpc[name]?.call) == 'function',
		sprintf('RPC method "%s" exists with callable call()', name));

	let replied = false;
	let out = null;
	let req = {
		args: args || {},
		reply: (res) => {
			replied = true;
			out = res;
			uloop.end();
		}
	};
	let sync_res = rpc[name].call(req);
	if (replied)
		return out;
	if (type(sync_res) == 'object' && exists(sync_res, 'ok'))
		return sync_res;

	let timed_out = false;
	let guard = uloop.timer(10000, () => {
		timed_out = true;
		uloop.end();
	});
	uloop.run();
	guard.cancel();
	check(!timed_out && replied, sprintf('async RPC "%s" completed within timeout', name));
	return out;
}

// 1. Verify exact 23 methods and 100% parity with acl.d & menu.d
let expected_read = [
	'status', 'log_read', 'profile_list', 'profile_read',
	'list_status', 'list_read', 'core_info', 'core_check_update', 'core_task_status'
];
let expected_write = [
	'api_secret', 'service_action', 'log_clear', 'profile_save',
	'profile_meta_save', 'profile_activate', 'profile_delete', 'profile_update',
	'whitelist_config_save', 'list_source_save', 'list_save', 'list_delete',
	'list_update', 'core_install'
];

let acl_doc = common.read_json(acl_path);
let menu_doc = common.read_json(menu_path);
check(type(acl_doc?.['luci-app-nimbus']) == 'object', 'acl.d JSON is valid');
check(type(menu_doc?.['admin/services/nimbus']) == 'object', 'menu.d JSON is valid');

let acl_read = acl_doc['luci-app-nimbus']?.read?.ubus?.['luci.nimbus'] || [];
let acl_write = acl_doc['luci-app-nimbus']?.write?.ubus?.['luci.nimbus'] || [];
check(length(acl_read) == 9 && length(acl_write) == 14, 'acl.d splits 9 read + 14 write methods');
check(length(keys(rpc)) == 23, 'luci.nimbus exposes exact 23 methods');

for (let m in expected_read) {
	check(index(acl_read, m) >= 0 && index(acl_write, m) < 0, sprintf('acl.d places "%s" strictly in read', m));
	check(exists(rpc, m), sprintf('rpc exposes read method "%s"', m));
}
for (let m in expected_write) {
	check(index(acl_write, m) >= 0 && index(acl_read, m) < 0, sprintf('acl.d places "%s" strictly in write', m));
	check(exists(rpc, m), sprintf('rpc exposes write method "%s"', m));
}

let write_files = acl_doc['luci-app-nimbus']?.write?.file || {};
check(index(acl_doc['luci-app-nimbus']?.write?.['cgi-io'] || [], 'upload') >= 0, 'acl.d allows cgi-io upload');
check(index(acl_doc['luci-app-nimbus']?.write?.uci || [], 'nimbus') >= 0, 'acl.d write uci restricted to nimbus');
check(exists(write_files, '/tmp/nimbus-upload.json') &&
	exists(write_files, '/tmp/nimbus-upload.txt') &&
	exists(write_files, '/tmp/nimbus-upload.bin'),
	'acl.d authorizes exact 3 fixed /tmp/nimbus-upload.* paths');

let expected_views = [ 'overview', 'settings', 'profiles', 'whitelists', 'core', 'logs' ];
for (let i = 0; i < length(expected_views); i++) {
	let v = expected_views[i];
	let item = menu_doc['admin/services/nimbus/' + v];
	check(item?.action?.type == 'view' && item?.action?.path == ('nimbus/' + v) && item?.order == ((i + 1) * 10),
		sprintf('menu.d defines view nimbus/%s with order %d', v, (i + 1) * 10));
}

// 2. Test status vs api_secret secret isolation & /proc/<pid> aggregation
let dual_api_raw = fs.readfile(repo_root + '/tests/fixtures/dual_api_v115.json');
check(type(dual_api_raw) == 'string' && length(dual_api_raw) > 0, 'load dual_api_v115.json');
let dual_api_json = json(dual_api_raw);
check(common.write_json_atomic(config_file, dual_api_json, 0600), 'write runtime config.json with API secrets');

let sb_secret_val = dual_api_json.services[0].secret;
let clash_secret_val = dual_api_json.experimental.clash_api.secret;
check(length(sb_secret_val) > 0 && length(clash_secret_val) > 0, 'dual_api fixture has non-empty secrets');

let probed_apis = cb.probe_apis(dual_api_json);
check(common.write_state({
	state: 'running',
	enabled: true,
	topology: 'main',
	proxy_mode: 'tproxy_redirect',
	fail_open: false,
	active_profile: 'main_sub',
	core: { bin_path: singbox_bin, version: '1.14.4' },
	effective: {
		outbound_mark: '0xff',
		redirect_port: 7891,
		tproxy_port: 7892,
		dns_mode: 'singbox',
		dns_port: 5353,
		inbound_sources: { redirect: 'auto', tproxy: 'user', tun: null },
		fakeip: { ipv4: [ '198.18.0.0/15' ], ipv6: [ 'fc00::/18' ] }
	},
	whitelist: { enabled: true, v4_count: 100, v6_count: 25 },
	apis: probed_apis,
	warnings: [],
	last_error: null
}, state_file), 'seed state.json');

let self_pid = fs.readlink('/proc/self');
check(common.atomic_write(pid_file, self_pid + '\n', 0644), 'seed sing-box.pid with live pid');
rpc_cfg.mock_counters = {
	tcp_packets: 1234, tcp_bytes: 567890,
	udp_packets: 42, udp_bytes: 8400,
	tun_packets: 0, tun_bytes: 0,
	lockdown_rejected_packets: 0
};

let st_res = call_rpc('status', {});
let st_raw_str = sprintf('%J', st_res);
check(st_res.ok === true && st_res.state == 'running' &&
	st_res.process.running === true && st_res.process.pid == int(self_pid, 10) && st_res.process.rss_kb > 0 &&
	st_res.core.installed === true && st_res.core.version == '1.14.4' &&
	st_res.effective.outbound_mark == '0xff' &&
	st_res.counters.tcp_packets == 1234 && st_res.counters.udp_packets == 42 &&
	st_res.apis.singbox_api.has_secret === true && st_res.apis.clash_api.has_secret === true,
	'status aggregates state.json, live /proc/<pid>, core, counters, and API flags');
check(index(st_raw_str, sb_secret_val) < 0 && index(st_raw_str, clash_secret_val) < 0 &&
	!exists(st_res.apis.singbox_api, 'secret') && !exists(st_res.apis.clash_api, 'secret'),
	'status strictly isolates and never leaks plaintext API secrets');

let sec_res = call_rpc('api_secret', {});
check(sec_res.ok === true &&
	sec_res.singbox_api_secret == sb_secret_val &&
	sec_res.clash_api_secret == clash_secret_val,
	'api_secret reads plaintext secrets from 0600 runtime config.json');

// 3. Test non-blocking E_LOCKED contention across ALL 14 write methods
let held_lock = common.acquire_lock(0, lock_file);
check(held_lock != null, 'acquire nimbus.lock externally');

check(common.atomic_write(upload_bin_path, 'mockbin', 0644), 'stage upload bin for lock check');
let locked_calls = [
	[ 'api_secret', {} ],
	[ 'service_action', { action: 'reload' } ],
	[ 'log_clear', {} ],
	[ 'profile_save', { filename: 'x.json', content: '{}', validate: false } ],
	[ 'profile_meta_save', { name: 'X', type: 'local', filename: 'x.json' } ],
	[ 'profile_activate', { section_id: 'x', reload: false } ],
	[ 'profile_delete', { section_id: 'x' } ],
	[ 'profile_update', {} ],
	[ 'whitelist_config_save', { enabled: true, auto_update: true, update_cron: '30 4 * * *' } ],
	[ 'list_source_save', { name: 'X', type: 'local', filename: 'x.txt' } ],
	[ 'list_save', { filename: 'x.txt', content: '1.0.1.0/24\n' } ],
	[ 'list_delete', { section_id: 'x' } ],
	[ 'list_update', {} ],
	[ 'core_install', { source: 'upload' } ]
];

let t_lock0 = clock(true);
for (let c in locked_calls) {
	let r = call_rpc(c[0], c[1]);
	check(r.ok === false && r.code == common.ERR_LOCKED,
		sprintf('write method "%s" immediately returns E_LOCKED under contention', c[0]));
}
let t_lock1 = clock(true);
let lock_elapsed_ms = ((t_lock1[0] - t_lock0[0]) * 1000) + int((t_lock1[1] - t_lock0[1]) / 1000000);
check(lock_elapsed_ms < 500, sprintf('all 14 E_LOCKED rejections were non-blocking (%dms)', lock_elapsed_ms));
common.release_lock(held_lock);
fs.unlink(upload_bin_path);

// 4. Test path traversal, invalid args, 256KB payload cap, and symlink upload rejection
for (let bad_prof in [ '../etc/shadow', '../bad.json', 'a/b.json', 'a..b.json', 'test.sh', '.json' ]) {
	let r1 = call_rpc('profile_read', { filename: bad_prof });
	let r2 = call_rpc('profile_save', { filename: bad_prof, content: '{}', validate: false });
	let r3 = call_rpc('profile_meta_save', { name: 'Bad', type: 'local', filename: bad_prof });
	check(r1.code == common.ERR_INVALID_ARG && r2.code == common.ERR_INVALID_ARG && r3.code == common.ERR_INVALID_ARG,
		sprintf('malicious profile filename "%s" rejected with E_INVALID_ARG', bad_prof));
}

for (let bad_list in [ '../etc/passwd', '../bad.txt', 'a/b.txt', 'test.sh', '.txt' ]) {
	let r1 = call_rpc('list_read', { filename: bad_list });
	let r2 = call_rpc('list_save', { filename: bad_list, content: '1.0.1.0/24\n' });
	let r3 = call_rpc('list_source_save', { name: 'Bad', type: 'local', filename: bad_list });
	check(r1.code == common.ERR_INVALID_ARG && r2.code == common.ERR_INVALID_ARG && r3.code == common.ERR_INVALID_ARG,
		sprintf('malicious list filename "%s" rejected with E_INVALID_ARG', bad_list));
}

for (let bad_id in [ '../bad', 'bad-id', 'a/b', 'x;rm' ]) {
	let r1 = call_rpc('profile_activate', { section_id: bad_id });
	let r2 = call_rpc('profile_delete', { section_id: bad_id });
	let r3 = call_rpc('list_delete', { section_id: bad_id });
	check(r1.code == common.ERR_INVALID_ARG && r2.code == common.ERR_INVALID_ARG && r3.code == common.ERR_INVALID_ARG,
		sprintf('malicious section_id "%s" rejected with E_INVALID_ARG', bad_id));
}

let huge_buf = '';
let chunk_256 = '1.0.1.0/24                                                                                                                      ';
while (length(huge_buf) <= common.MAX_DIRECT_TEXT_BYTES)
	huge_buf += chunk_256;

let big_prof = call_rpc('profile_save', { filename: 'big.json', content: huge_buf, validate: false });
let big_list = call_rpc('list_save', { filename: 'big.txt', content: huge_buf });
check(big_prof.ok === false && big_prof.code == common.ERR_INVALID_ARG &&
	big_list.ok === false && big_list.code == common.ERR_INVALID_ARG,
	'256KB direct text payload limit enforced with E_INVALID_ARG');

let sym_secret = work_dir + '/secret_target.txt';
check(common.atomic_write(sym_secret, '{"should_not_read":true}\n', 0600), 'write symlink target');
check(fs.symlink(sym_secret, upload_profile_path), 'create symlink at upload_profile_path');
check(fs.symlink(sym_secret, upload_list_path), 'create symlink at upload_list_path');
check(fs.symlink(sym_secret, upload_bin_path), 'create symlink at upload_bin_path');

let sym_p = call_rpc('profile_save', { filename: 'sym.json', from_upload: true, validate: false });
let sym_l = call_rpc('list_save', { filename: 'sym.txt', from_upload: true });
let sym_c = call_rpc('core_install', { source: 'upload' });
check(sym_p.code == common.ERR_INVALID_ARG && sym_l.code == common.ERR_INVALID_ARG && sym_c.code == common.ERR_INVALID_ARG,
	'symlink uploads strictly rejected across profile_save, list_save, and core_install');
fs.unlink(upload_profile_path);
fs.unlink(upload_list_path);
fs.unlink(upload_bin_path);

// 5. Test log_read & inode-preserving log_clear
let log_lines = '';
for (let i = 1; i <= 15; i++)
	log_lines += sprintf('log line %d\n', i);
check(common.atomic_write(log_file, log_lines, 0644), 'seed nimbus.log');
let st_log_before = fs.stat(log_file);

let lr_bad = call_rpc('log_read', { lines: 2500 });
check(lr_bad.ok === false && lr_bad.code == common.ERR_INVALID_ARG, 'log_read rejects lines > 2000');

let lr_ok = call_rpc('log_read', { lines: 5 });
check(lr_ok.ok === true && lr_ok.truncated === true &&
	index(lr_ok.content, 'log line 11\n') == 0 && index(lr_ok.content, 'log line 15\n') >= 0,
	'log_read returns trailing N lines and truncated=true');

let lc_ok = call_rpc('log_clear', {});
let st_log_after = fs.stat(log_file);
check(lc_ok.ok === true && st_log_after != null && st_log_after.size == 0 && st_log_after.inode == st_log_before.inode,
	'log_clear truncates log to 0 bytes while preserving inode');

// 6. Test profile CRUD, real sing-box check validation, activation, conflict & atomic delete
let modern_raw = fs.readfile(repo_root + '/tests/fixtures/v114_modern.json');
let legacy_raw = fs.readfile(repo_root + '/tests/fixtures/v111_legacy.json');

let pm1 = call_rpc('profile_meta_save', {
	section_id: '',
	name: 'Local One',
	type: 'local',
	filename: 'local_one.json'
});
check(pm1.ok === true && pm1.section_id == 'local_one', 'profile_meta_save creates new local profile section');

let pm_dup = call_rpc('profile_meta_save', {
	section_id: '',
	name: 'Duplicate File',
	type: 'local',
	filename: 'local_one.json'
});
check(pm_dup.ok === false && pm_dup.code == common.ERR_CONFLICT, 'profile_meta_save rejects duplicate filename with E_CONFLICT');

let ps_bad_json = call_rpc('profile_save', { filename: 'local_one.json', content: '{bad json' });
check(ps_bad_json.ok === false && ps_bad_json.code == common.ERR_VALIDATE_FAILED && fs.stat(profiles_dir + '/local_one.json') == null,
	'profile_save rejects invalid JSON without writing file');

let ps_bad_sb = call_rpc('profile_save', {
	filename: 'local_one.json',
	content: '{"outbounds":[{"type":"nonexistent_proto_xyz","tag":"bad"}]}',
	validate: true
});
check(ps_bad_sb.ok === false && ps_bad_sb.code == common.ERR_VALIDATE_FAILED && fs.stat(profiles_dir + '/local_one.json') == null,
	'profile_save rejects config failing real sing-box check without writing file');

let pa1 = call_rpc('profile_activate', { section_id: 'local_one', reload: false });
check(pa1.ok === true && pa1.active_profile == 'local_one' && pa1.reloaded === false,
	'profile_activate switches global.active_profile');

let ps_ok = call_rpc('profile_save', { filename: 'local_one.json', content: modern_raw, validate: true });
check(ps_ok.ok === true && ps_ok.checked === true && ps_ok.reload_required === true &&
	fs.readfile(profiles_dir + '/local_one.json') == modern_raw,
	'profile_save passes real sing-box check, writes file, and flags reload_required=true for active running profile');

let pr_ok = call_rpc('profile_read', { filename: 'local_one.json' });
check(pr_ok.ok === true && pr_ok.content == modern_raw, 'profile_read returns raw profile content');

let del_conflict = call_rpc('profile_delete', { section_id: 'local_one' });
check(del_conflict.ok === false && del_conflict.code == common.ERR_CONFLICT,
	'profile_delete rejects deleting active profile with E_CONFLICT');

let pm_sub = call_rpc('profile_meta_save', {
	section_id: '',
	name: 'Main Sub',
	type: 'subscription',
	filename: 'main_sub.json',
	url: 'https://example.com/sub.json',
	user_agent: 'sing-box/nimbus-rpc',
	via_proxy: false,
	auto_update: true,
	update_interval_hours: 12
});
check(pm_sub.ok === true && pm_sub.section_id == 'main_sub', 'profile_meta_save creates subscription profile');
check(index(fs.readfile(crontab_file) || '', '# nimbus-profile') >= 0,
	'profile_meta_save syncs # nimbus-profile cron job');

let plist = call_rpc('profile_list', {});
check(plist.ok === true && plist.active_profile == 'local_one' && length(plist.profiles) == 2,
	'profile_list enumerates profiles and active_profile');

let pa2 = call_rpc('profile_activate', { section_id: 'main_sub', reload: false });
check(pa2.ok === true && pa2.active_profile == 'main_sub', 'activate second profile');

let del_ok = call_rpc('profile_delete', { section_id: 'local_one' });
check(del_ok.ok === true && fs.stat(profiles_dir + '/local_one.json') == null,
	'profile_delete atomically deletes UCI section and profile file');
let plist2 = call_rpc('profile_list', {});
check(length(plist2.profiles) == 1 && plist2.profiles[0].id == 'main_sub',
	'profile_list confirms deleted profile removed from UCI');

// 7. Test profile_update & list_update async workers via mock curl
let mock_sub_src = work_dir + '/sub_src.json';
let mock_list_src = work_dir + '/list_src.txt';
check(common.atomic_write(mock_sub_src, legacy_raw, 0644), 'write mock sub source');
check(common.atomic_write(mock_list_src, '# mock list\n1.0.1.0/24\n2400:3200::/32\n', 0644), 'write mock list source');

check(common.atomic_write(mock_curl, sprintf(
	'#!/bin/sh\n' +
	'out=""\n' +
	'url=""\n' +
	'while [ "$#" -gt 0 ]; do\n' +
	'\tcase "$1" in\n' +
	'\t\t-o) out="$2"; shift 2 ;;\n' +
	'\t\t-A|-z|--connect-timeout|--max-time|--proxy) shift 2 ;;\n' +
	'\t\t-*) shift ;;\n' +
	'\t\t*) url="$1"; shift ;;\n' +
	'\tesac\n' +
	'done\n' +
	'case "$url" in\n' +
	'\t*sub.json) cp -f "%s" "$out" ;;\n' +
	'\t*list.txt) cp -f "%s" "$out" ;;\n' +
	'\t*) exit 22 ;;\n' +
	'esac\n',
	mock_sub_src, mock_list_src
), 0755), 'write mock_curl script');

let pu_res = call_rpc('profile_update', { section_id: 'main_sub' });
check(pu_res.ok === true && length(pu_res.results) == 1 &&
	pu_res.results[0].status == 'updated' && fs.readfile(profiles_dir + '/main_sub.json') == legacy_raw,
	'profile_update asynchronously fetches, passes real sing-box check, and writes subscription file');

// 8. Test whitelist_config_save, list_source_save, list_save, list_read, list_status, list_update, list_delete
let wl_bad_cron = call_rpc('whitelist_config_save', { enabled: true, auto_update: true, update_cron: 'bad' });
check(wl_bad_cron.ok === false && wl_bad_cron.code == common.ERR_INVALID_ARG,
	'whitelist_config_save rejects invalid cron');

let wl_ok = call_rpc('whitelist_config_save', { enabled: true, auto_update: true, update_cron: '15 3 * * *' });
check(wl_ok.ok === true && wl_ok.hot_reloaded === true &&
	index(fs.readfile(crontab_file) || '', '15 3 * * *') >= 0 &&
	index(fs.readfile(crontab_file) || '', '# nimbus-whitelist') >= 0,
	'whitelist_config_save updates cron and hot reloads nft sets');

let ls_local = call_rpc('list_source_save', {
	section_id: '',
	name: 'Custom Direct',
	type: 'local',
	enabled: true,
	family: 'auto',
	filename: 'custom_direct.txt'
});
check(ls_local.ok === true && ls_local.section_id == 'custom_direct' &&
	fs.stat(local_lists_dir + '/custom_direct.txt') != null,
	'list_source_save creates local UCI section and empty .txt file');

let ls_dup = call_rpc('list_source_save', {
	section_id: '',
	name: 'Dup Local',
	type: 'local',
	filename: 'custom_direct.txt'
});
check(ls_dup.ok === false && ls_dup.code == common.ERR_CONFLICT,
	'list_source_save rejects duplicate local filename with E_CONFLICT');

let ls_url = call_rpc('list_source_save', {
	section_id: '',
	name: 'Remote List',
	type: 'url',
	enabled: true,
	family: 'auto',
	url: 'https://example.com/list.txt',
	via_proxy: false
});
check(ls_url.ok === true && length(ls_url.section_id) > 0, 'list_source_save creates remote url list_source');

let lsave_bad = call_rpc('list_save', {
	filename: 'custom_direct.txt',
	content: '1.1.8.0/24\n1.2.3.999/24\n'
});
check(lsave_bad.ok === false && lsave_bad.code == common.ERR_VALIDATE_FAILED &&
	lsave_bad.invalid_lines[0].line == 2 &&
	fs.readfile(local_lists_dir + '/custom_direct.txt') == '',
	'list_save rejects invalid CIDR with line number and leaves original file untouched');

let lsave_ok = call_rpc('list_save', {
	filename: 'custom_direct.txt',
	content: '# local\n1.1.8.0/24\n2400:3200::1\n'
});
check(lsave_ok.ok === true && lsave_ok.v4_count == 1 && lsave_ok.v6_count == 1 && lsave_ok.hot_reloaded === true,
	'list_save saves valid entries and hot reloads nftables');

let lread_ok = call_rpc('list_read', { filename: 'custom_direct.txt' });
check(lread_ok.ok === true && index(lread_ok.content, '1.1.8.0/24') >= 0, 'list_read returns saved list content');

let lu_res = call_rpc('list_update', { section_id: ls_url.section_id });
check(lu_res.ok === true && lu_res.hot_reloaded === true &&
	lu_res.results[0].status == 'updated' &&
	lu_res.nft_loaded.v4_count == 2 && lu_res.nft_loaded.v6_count == 2,
	'list_update asynchronously fetches remote list and triggers nft hot reload');

let lstat = call_rpc('list_status', {});
check(lstat.ok === true && lstat.nft_loaded.v4_count == 2 && lstat.nft_loaded.v6_count == 2 && length(lstat.sources) == 2,
	'list_status returns global policy, nft_loaded counts, and both sources');

let ldel_ok = call_rpc('list_delete', { section_id: ls_url.section_id });
check(ldel_ok.ok === true && fs.stat(cache_lists_dir + '/' + ls_url.section_id + '.txt') == null,
	'list_delete removes UCI section and cached remote list file');

// 9. Test service_action async dispatch (success & lockdown failure)
let sa_bad = call_rpc('service_action', { action: 'explode' });
check(sa_bad.ok === false && sa_bad.code == common.ERR_INVALID_ARG, 'service_action rejects invalid action');

check(common.atomic_write(init_script, sprintf(
	'#!/bin/sh\n' +
	'case "$1" in\n' +
	'\tstart) printf \'{"state":"running","last_error":null,"warnings":[]}\\n\' > "%s"; exit 0 ;;\n' +
	'\tstop) printf \'{"state":"stopped","last_error":null,"warnings":[]}\\n\' > "%s"; exit 0 ;;\n' +
	'\treload) printf \'{"state":"lockdown","last_error":"bad check","warnings":[]}\\n\' > "%s"; exit 1 ;;\n' +
	'esac\n',
	state_file, state_file, state_file
), 0755), 'write mock init script');

let sa_start = call_rpc('service_action', { action: 'start' });
check(sa_start.ok === true && sa_start.state == 'running', 'service_action start returns state=running');

let sa_fail = call_rpc('service_action', { action: 'reload' });
check(sa_fail.ok === false && sa_fail.code == common.ERR_VALIDATE_FAILED && sa_fail.state == 'lockdown',
	'service_action reload failure returns E_VALIDATE_FAILED and state=lockdown');

let sa_stop = call_rpc('service_action', { action: 'stop' });
check(sa_stop.ok === true && sa_stop.state == 'stopped', 'service_action stop returns state=stopped');

// 10. Test core_info, core_check_update, core_install (detached background + E_LOCKED + polling), core_task_status
let pkg_dir = work_dir + '/core_pkg/sing-box-1.14.4-linux-arm64-musl';
check(common.ensure_dir(pkg_dir, 0755), 'create core_pkg dir');
check(common.atomic_write(pkg_dir + '/sing-box', '#!/bin/sh\necho "sing-box version 1.14.4"\n', 0755),
	'create mock sing-box binary in pkg');
check(system([ '/bin/tar', '-czf', upload_bin_path, '-C', work_dir + '/core_pkg', 'sing-box-1.14.4-linux-arm64-musl' ]) == 0,
	'build uploadable sing-box tar.gz');

let installed_target = work_dir + '/bin_installed/sing-box';
rpc_cfg.bin_path = installed_target;

let cinfo = call_rpc('core_info', {});
check(cinfo.ok === true && cinfo.arch.target == 'arm64' && cinfo.installed.exists === false,
	'core_info runs asynchronously via worker and reports arch + install state');

rpc_cfg.release_json = fs.readfile(repo_root + '/tests/fixtures/github_release.json');
let cchk = call_rpc('core_check_update', {});
check(cchk.ok === true && cchk.latest_version == '1.14.4' && cchk.update_available === true &&
	cchk.asset.name == 'sing-box-1.14.4-linux-arm64-musl.tar.gz',
	'core_check_update asynchronously parses GitHub release for target architecture');

let cinst_bad = call_rpc('core_install', { source: 'custom_url' });
check(cinst_bad.ok === false && cinst_bad.code == common.ERR_INVALID_ARG, 'core_install rejects unsupported source');

let cinst = call_rpc('core_install', { source: 'upload' });
check(cinst.ok === true && cinst.started === true, 'core_install returns { ok: true, started: true } immediately');

let cinst_dup = call_rpc('core_install', { source: 'upload' });
check(cinst_dup.ok === false && cinst_dup.code == common.ERR_LOCKED,
	'concurrent core_install immediately returns E_LOCKED while background task is active');

// Poll core_task_status under uloop until background uloop.process finishes and is reaped
let final_task = null;
let poll_cnt = 0;
function poll_core_task() {
	poll_cnt++;
	let ts = call_rpc('core_task_status', {});
	if (ts.state == 'done' || ts.state == 'failed' || poll_cnt >= 100) {
		final_task = ts;
		uloop.end();
		return;
	}
	uloop.timer(50, poll_core_task);
}
uloop.timer(50, poll_core_task);
uloop.run();

check(final_task != null && final_task.state == 'done' && final_task.progress == 100 &&
	final_task.installed_version == '1.14.4' && fs.stat(installed_target) != null &&
	fs.stat(upload_bin_path) == null,
	'detached core_install completes, updates core_task.json to done (100%), installs binary, and cleans upload file');

let cinfo2 = call_rpc('core_info', {});
check(cinfo2.ok === true && cinfo2.installed.exists === true && cinfo2.installed.version == '1.14.4',
	'core_info reflects newly installed sing-box binary');

// 11. Test valid from_upload on profile_save & list_save, profile_activate(reload=true), stale PID, and async status_probe
check(common.atomic_write(upload_profile_path, modern_raw, 0600), 'stage valid upload profile');
let ps_up = call_rpc('profile_save', { filename: 'uploaded_ok.json', from_upload: true, validate: true });
check(ps_up.ok === true && ps_up.checked === true && fs.stat(upload_profile_path) == null &&
	fs.readfile(profiles_dir + '/uploaded_ok.json') == modern_raw,
	'profile_save(from_upload=true) validates, writes file, and removes upload temp file');

check(common.atomic_write(upload_list_path, '223.5.5.5\n', 0600), 'stage valid upload list');
let ls_up = call_rpc('list_save', { filename: 'custom_direct.txt', from_upload: true });
check(ls_up.ok === true && ls_up.v4_count == 1 && fs.stat(upload_list_path) == null &&
	fs.readfile(local_lists_dir + '/custom_direct.txt') == '223.5.5.5\n',
	'list_save(from_upload=true) validates, writes file, and removes upload temp file');

// Test profile_activate(reload=true) when service is running
check(common.write_state({ state: 'running', warnings: [], last_error: null }, state_file), 'seed running state for activate reload');
check(common.atomic_write(init_script, sprintf(
	'#!/bin/sh\n' +
	'if [ "$1" = "reload" ]; then printf \'{"state":"running","last_error":null,"warnings":[]}\\n\' > "%s"; exit 0; fi\n' +
	'exit 0\n',
	state_file
), 0755), 'update mock init script for reload');
let pa_rel = call_rpc('profile_activate', { section_id: 'main_sub', reload: true });
check(pa_rel.ok === true && pa_rel.reloaded === true, 'profile_activate(reload=true) triggers async reload when running');

// Test stale PID + async status_probe (nft -j counters & core version)
check(common.atomic_write(pid_file, '999999\n', 0644), 'seed dead pid');
let mock_nft_bin = work_dir + '/mock-nft.sh';
check(common.atomic_write(mock_nft_bin,
	'#!/bin/sh\n' +
	'printf \'{"nftables":[{"counter":{"table":"nimbus","name":"tcp_proxied","packets":77,"bytes":8888}},{"counter":{"table":"nimbus","name":"udp_proxied","packets":11,"bytes":222}}]}\n\'\n',
	0755), 'write mock_nft_bin');
check(common.write_state({ state: 'running', core: { bin_path: installed_target, version: null }, warnings: [], last_error: null }, state_file),
	'seed state without core version for async status_probe');
rpc_cfg.mock_counters = null;
rpc_cfg.skip_nft = false;
rpc_cfg.nft_bin = mock_nft_bin;
let st_probe = call_rpc('status', {});
check(st_probe.ok === true && st_probe.process.running === false && st_probe.process.pid == null &&
	st_probe.counters.tcp_packets == 77 && st_probe.counters.udp_packets == 11 &&
	st_probe.core.version == '1.14.4',
	'status detects stale dead PID and asynchronously probes nft counters + core version');

// Test profile_meta_save edit existing + disable auto_update removes cron
let pm_edit = call_rpc('profile_meta_save', {
	section_id: 'main_sub',
	name: 'Main Sub Edited',
	type: 'subscription',
	filename: 'main_sub.json',
	url: 'https://example.com/sub2.json',
	auto_update: false,
	update_interval_hours: 48
});
check(pm_edit.ok === true && pm_edit.section_id == 'main_sub' &&
	index(fs.readfile(crontab_file) || '', '# nimbus-profile') < 0,
	'profile_meta_save edits existing section and removes # nimbus-profile cron when auto_update=false');

// Test profile_save with validate=false skips sing-box check
let ps_nocheck = call_rpc('profile_save', {
	filename: 'nocheck.json',
	content: '{"outbounds":[{"type":"nonexistent_proto_xyz","tag":"bad"}]}',
	validate: false
});
check(ps_nocheck.ok === true && ps_nocheck.checked === false &&
	fs.stat(profiles_dir + '/nocheck.json') != null,
	'profile_save with validate=false saves valid JSON without running sing-box check');

// Test status normalizes internal fail_open=1 state="error" -> "stopped"
check(common.write_state({ state: 'error', last_error: 'crash exhausted', warnings: [] }, state_file),
	'seed state=error');
rpc_cfg.skip_nft = true;
let st_err = call_rpc('status', {});
check(st_err.ok === true && st_err.state == 'stopped' && st_err.last_error == 'crash exhausted',
	'status normalizes state="error" to "stopped" while preserving last_error');

printf('test_rpc_contract.uc: %d assertions passed\n', passed);
