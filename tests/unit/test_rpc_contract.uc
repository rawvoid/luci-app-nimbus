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
let composer_file = work_dir + '/composer.json';
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
	composer_file: composer_file,
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

// 1. Verify exact 29 methods and 100% parity with acl.d & menu.d
let expected_read = [
	'status', 'log_read', 'profile_list', 'profile_read',
	'list_status', 'list_read', 'core_info', 'core_check_update', 'core_task_status',
	'composer_get', 'composer_nodes', 'composer_preview', 'composer_import'
];
let expected_write = [
	'api_secret', 'service_action', 'log_clear', 'profile_save',
	'profile_meta_save', 'profile_activate', 'profile_delete', 'profile_update',
	'whitelist_config_save', 'list_source_save', 'list_save', 'list_delete',
	'list_update', 'core_install', 'composer_save', 'composer_mode_set'
];

let acl_doc = common.read_json(acl_path);
let menu_doc = common.read_json(menu_path);
check(type(acl_doc?.['luci-app-nimbus']) == 'object', 'acl.d JSON is valid');
check(type(menu_doc?.['admin/services/nimbus']) == 'object', 'menu.d JSON is valid');

let acl_read = acl_doc['luci-app-nimbus']?.read?.ubus?.['luci.nimbus'] || [];
let acl_write = acl_doc['luci-app-nimbus']?.write?.ubus?.['luci.nimbus'] || [];
check(length(acl_read) == 13 && length(acl_write) == 16, 'acl.d splits 13 read + 16 write methods');
check(length(keys(rpc)) == 29, 'luci.nimbus exposes exact 29 methods');

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
	st_res.config_mode == 'profile' && st_res.composer === null &&
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

// 3. Test non-blocking E_LOCKED contention across ALL 16 write methods
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
	[ 'core_install', { source: 'upload' } ],
	[ 'composer_save', { composer_json: '{}', validate: false, reload: false } ],
	[ 'composer_mode_set', { mode: 'composer', reload: false } ]
];

let t_lock0 = clock(true);
for (let c in locked_calls) {
	let r = call_rpc(c[0], c[1]);
	check(r.ok === false && r.code == common.ERR_LOCKED,
		sprintf('write method "%s" immediately returns E_LOCKED under contention', c[0]));
}
let t_lock1 = clock(true);
let lock_elapsed_ms = ((t_lock1[0] - t_lock0[0]) * 1000) + int((t_lock1[1] - t_lock0[1]) / 1000000);
check(lock_elapsed_ms < 500, sprintf('all 16 E_LOCKED rejections were non-blocking (%dms)', lock_elapsed_ms));
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

// 12. Test Phase 3A Composer RPCs & dual-mode profile_save / profile_delete / status
rpc_cfg.bin_path = singbox_bin;

// 12.1 composer_get when composer.json does not exist yet
let cg0 = call_rpc('composer_get', {});
check(cg0.ok === true && cg0.config_mode == 'profile' && cg0.exists === false && cg0.mtime === null &&
	type(cg0.composer) == 'object' && type(cg0.composer_json) == 'string' &&
	type(cg0.profiles) == 'array' &&
	cg0.auto_inbounds?.redirect_port == 7891 && cg0.auto_inbounds?.tproxy_port == 7892 &&
	cg0.auto_inbounds?.singbox_dns_port == 5353,
	'composer_get returns empty skeleton, profiles, and auto_inbounds when uninitialized');

// 12.2 composer_import (from profile and json, plus validation errors)
let ci_bad_src = call_rpc('composer_import', { source: 'ftp' });
check(ci_bad_src.ok === false && ci_bad_src.code == common.ERR_INVALID_ARG,
	'composer_import rejects unsupported source');
let ci_bad_id = call_rpc('composer_import', { source: 'profile', profile_id: '../bad' });
check(ci_bad_id.ok === false && ci_bad_id.code == common.ERR_INVALID_ARG,
	'composer_import rejects invalid profile_id');
let ci_miss = call_rpc('composer_import', { source: 'profile', profile_id: 'no_such_prof' });
check(ci_miss.ok === false && ci_miss.code == common.ERR_NOT_FOUND,
	'composer_import returns E_NOT_FOUND for missing profile');
let pm_imp = call_rpc('profile_meta_save', {
	section_id: '',
	name: 'Uploaded OK',
	type: 'local',
	filename: 'uploaded_ok.json'
});
check(pm_imp.ok === true, 'create profile metadata for uploaded_ok.json');
let ci_prof = call_rpc('composer_import', { source: 'profile', profile_id: pm_imp.section_id });
check(ci_prof.ok === true && type(ci_prof.composer) == 'object' && type(ci_prof.composer_json) == 'string' &&
	type(ci_prof.warnings) == 'array',
	'composer_import imports existing profile without touching disk');
let ci_json = call_rpc('composer_import', { source: 'json', content: modern_raw });
check(ci_json.ok === true && length(ci_json.composer.outbounds) >= 1 && fs.stat(composer_file) == null,
	'composer_import imports raw JSON without creating composer.json on disk');
let ci_big = call_rpc('composer_import', { source: 'json', content: huge_buf });
check(ci_big.ok === false && ci_big.code == common.ERR_INVALID_ARG,
	'composer_import enforces 256KB direct transfer limit');

// 12.3 composer_mode_set
let cms_bad = call_rpc('composer_mode_set', { mode: 'invalid' });
check(cms_bad.ok === false && cms_bad.code == common.ERR_INVALID_ARG,
	'composer_mode_set rejects invalid mode');

check(common.write_state({ state: 'running', warnings: [], last_error: null }, state_file),
	'seed running state for composer_mode_set');
let cms_norel = call_rpc('composer_mode_set', { mode: 'composer', reload: false });
check(cms_norel.ok === true && cms_norel.config_mode == 'composer' &&
	cms_norel.reload_required === true && cms_norel.reloaded === false,
	'composer_mode_set updates UCI config_mode and flags reload_required without reloading when reload=false');

let lock_probe_flag = work_dir + '/reload_lock_probe.txt';
check(common.atomic_write(init_script, sprintf(
	'#!/bin/sh\n' +
	'if [ "$1" = "reload" ]; then\n' +
	'\tucode -S -L "%s/nimbus/files/usr/share/nimbus" -e "import * as c from \'common\'; let fh = c.acquire_lock(0, \'%s\'); if (!fh) exit(42); c.release_lock(fh);"\n' +
	'\trc=$?\n' +
	'\tprintf \'%%s\\n\' "$rc" > "%s"\n' +
	'\t[ "$rc" -eq 0 ] || exit "$rc"\n' +
	'\tprintf \'{"state":"running","last_error":null,"warnings":[]}\\n\' > "%s"\n' +
	'\texit 0\n' +
	'fi\n' +
	'exit 0\n',
	repo_root, lock_file, lock_probe_flag, state_file
), 0755), 'write mock init script verifying nimbus.lock is released before reload');

let cms_rel = call_rpc('composer_mode_set', { mode: 'composer', reload: true });
check(cms_rel.ok === true && cms_rel.config_mode == 'composer' &&
	cms_rel.reload_required === true && cms_rel.reloaded === true &&
	trim(fs.readfile(lock_probe_flag) || '') == '0',
	'composer_mode_set(reload=true) releases nimbus.lock before reload and completes reload');

// 12.4 Seed subscription sources in composer mode & test composer_save + RFC 7396 null override
let sub_a_raw = fs.readfile(repo_root + '/tests/fixtures/sub_nodes_a.json');
let sub_b_raw = fs.readfile(repo_root + '/tests/fixtures/sub_nodes_b.json');
let pm_src_a = call_rpc('profile_meta_save', {
	section_id: '', name: 'Source A', type: 'local', filename: 'source_a.json'
});
let pm_src_b = call_rpc('profile_meta_save', {
	section_id: '', name: 'Source B', type: 'local', filename: 'source_b.json'
});
check(pm_src_a.ok === true && pm_src_b.ok === true, 'create profile sections for composer sources');

// profile_save in composer mode: reject empty object & reject invalid structure, accept JSON object and JSON array
let ps_comp_empty = call_rpc('profile_save', { filename: 'source_a.json', content: '{}', validate: true });
check(ps_comp_empty.ok === false && ps_comp_empty.code == common.ERR_VALIDATE_FAILED,
	'profile_save in composer mode rejects empty object with zero outbounds');
let ps_comp_zero = call_rpc('profile_save', { filename: 'source_a.json', content: '{"outbounds":[]}', validate: true });
check(ps_comp_zero.ok === false && ps_comp_zero.code == common.ERR_VALIDATE_FAILED,
	'profile_save in composer mode rejects empty outbounds array');

let ps_comp_a = call_rpc('profile_save', { filename: 'source_a.json', content: sub_a_raw, validate: true });
check(ps_comp_a.ok === true && ps_comp_a.checked === false && ps_comp_a.reload_required === false &&
	fs.readfile(profiles_dir + '/source_a.json') == sub_a_raw,
	'profile_save in composer mode saves unenabled source profile without sing-box check');
let ps_comp_b = call_rpc('profile_save', { filename: 'source_b.json', content: sub_b_raw, validate: true });
check(ps_comp_b.ok === true && ps_comp_b.checked === false &&
	fs.readfile(profiles_dir + '/source_b.json') == sub_b_raw,
	'profile_save in composer mode accepts JSON array of outbounds');

let comp_draft = {
	schema_version: 1,
	sources: {
		[pm_src_a.section_id]: {
			enabled: true,
			tag_prefix: '[A] ',
			include_regex: '',
			exclude_regex: '剩余流量',
			exclude_types: [ 'selector', 'urltest', 'direct', 'block', 'dns' ],
			strip_fields: [ 'domain_resolver', 'routing_mark' ],
			node_override: { tcp_fast_open: false }
		},
		[pm_src_b.section_id]: {
			enabled: false,
			tag_prefix: '[B] ',
			include_regex: '',
			exclude_regex: '',
			exclude_types: [ 'selector', 'urltest', 'direct', 'block', 'dns' ],
			strip_fields: [ 'domain_resolver', 'routing_mark' ],
			node_override: {}
		}
	},
	inbounds: [],
	outbound_groups: [
		{
			id: 'grp_proxy', enabled: true, type: 'selector', tag: 'Proxy',
			outbounds: [ 'direct' ],
			providers: [ { profile_id: '*', include_regex: '', exclude_regex: '' } ],
			fallback_outbound: 'direct', config: {}
		}
	],
	outbounds: [
		{ id: 'out_direct', enabled: true, type: 'direct', tag: 'direct', config: {} }
	],
	dns: {
		final: 'dns-direct',
		strategy: '',
		extra: { disable_cache: true },
		servers: [
			{ id: 'dns_direct', enabled: true, type: 'udp', tag: 'dns-direct', config: { server: '223.5.5.5' } }
		],
		rules: []
	},
	rule_sets: [],
	route: {
		final: 'Proxy',
		default_domain_resolver: 'dns-direct',
		extra: {},
		rules: []
	},
	override: {
		dns: { disable_cache: null },
		experimental: { cache_file: { enabled: true } }
	}
};

let cs_bad_json = call_rpc('composer_save', { composer_json: '{bad', validate: false, reload: false });
check(cs_bad_json.ok === false && cs_bad_json.code == common.ERR_VALIDATE_FAILED,
	'composer_save rejects malformed composer_json');
let cs_big = call_rpc('composer_save', { composer_json: huge_buf, validate: false, reload: false });
check(cs_big.ok === false && cs_big.code == common.ERR_INVALID_ARG,
	'composer_save rejects >256KB composer_json');
let cs_missing = call_rpc('composer_save', { composer_json: '', validate: false, reload: false });
check(cs_missing.ok === false && cs_missing.code == common.ERR_INVALID_ARG,
	'composer_save requires composer or composer_json');

let bad_comp_draft = { ...comp_draft, outbounds: [ { id: 'bad1', enabled: true, type: 'nonexistent_proto_xyz', tag: 'bad', config: {} } ] };
let cs_bad_sb = call_rpc('composer_save', { composer_json: sprintf('%.2J', bad_comp_draft), validate: true, reload: false });
check(cs_bad_sb.ok === false && cs_bad_sb.code == common.ERR_VALIDATE_FAILED && fs.stat(composer_file) == null,
	'composer_save fails real sing-box check and does not write composer.json');

let cs_ok = call_rpc('composer_save', {
	composer_json: sprintf('%.2J', comp_draft),
	validate: true,
	reload: false
});
let st_comp_file = fs.lstat(composer_file);
check(cs_ok.ok === true && cs_ok.checked === true && cs_ok.changed === true &&
	cs_ok.reload_required === true && cs_ok.reloaded === false &&
	st_comp_file != null && (st_comp_file.mode & 0777) == 0600,
	'composer_save validates via real sing-box check, writes 0600 composer.json, and sets reload_required=true');

let cs_unchanged = call_rpc('composer_save', {
	composer_json: sprintf('%.2J', comp_draft),
	validate: false,
	reload: false
});
check(cs_unchanged.ok === true && cs_unchanged.checked === false &&
	cs_unchanged.changed === false && cs_unchanged.reload_required === false,
	'composer_save detects unchanged SHA256 and sets changed=false, reload_required=false');

fs.unlink(lock_probe_flag);
let cs_reload = call_rpc('composer_save', {
	composer_json: sprintf('%.2J', comp_draft),
	validate: true,
	reload: true
});
check(cs_reload.ok === true && cs_reload.reloaded === true && cs_reload.reload_required === true &&
	trim(fs.readfile(lock_probe_flag) || '') == '0',
	'composer_save(reload=true) releases nimbus.lock before init_script reload and replies reloaded=true');

// 12.5 composer_get & status in composer mode
let cg1 = call_rpc('composer_get', {});
check(cg1.ok === true && cg1.config_mode == 'composer' && cg1.exists === true && cg1.mtime != null &&
	cg1.composer.override?.dns?.disable_cache === null,
	'composer_get returns saved composer preserving RFC 7396 null patch keys');

let st_comp = call_rpc('status', {});
check(st_comp.ok === true && st_comp.config_mode == 'composer' &&
	st_comp.composer != null && st_comp.composer.initialized === true &&
	st_comp.composer.enabled_sources == 1 && st_comp.composer.extracted_nodes == 3,
	'status in composer mode includes live composer summary');

// 12.6 composer_nodes
let cn_all = call_rpc('composer_nodes', {});
check(cn_all.ok === true && length(cn_all.nodes) == 3 && cn_all.per_source_counts[pm_src_a.section_id] == 3,
	'composer_nodes extracts nodes from enabled sources');
let cn_filt = call_rpc('composer_nodes', { include_regex: 'HK|JP', exclude_regex: 'JP' });
check(cn_filt.ok === true && length(cn_filt.nodes) == 1 && cn_filt.nodes[0].tag == '[A] HK-01',
	'composer_nodes filters nodes by include_regex and exclude_regex');
let cn_draft = call_rpc('composer_nodes', {
	profile_id: pm_src_b.section_id,
	composer: comp_draft
});
check(cn_draft.ok === true && length(cn_draft.nodes) == 2 && cn_draft.nodes[0].tag == '[B] HK-01',
	'composer_nodes supports req.args.composer draft object for specific profile_id');

// 12.7 composer_preview (saved, draft with RFC 7396 null, and failing sing-box check still returning preview)
let cp_ok = call_rpc('composer_preview', { validate: true });
check(cp_ok.ok === true && cp_ok.checked === true && cp_ok.check_ok === true && cp_ok.check_error === null &&
	!exists(cp_ok.composed?.dns || {}, 'disable_cache') &&
	type(cp_ok.composed_json) == 'string' && type(cp_ok.effective_json) == 'string' &&
	cp_ok.summary?.extracted_nodes == 3,
	'composer_preview transforms, applies RFC 7396 null patch, runs sing-box check, and returns summary');

let cp_bad_sb = call_rpc('composer_preview', {
	composer_json: sprintf('%.2J', bad_comp_draft),
	validate: true
});
check(cp_bad_sb.ok === true && cp_bad_sb.checked === true && cp_bad_sb.check_ok === false &&
	type(cp_bad_sb.check_error) == 'string' && length(cp_bad_sb.check_error) > 0 &&
	type(cp_bad_sb.composed) == 'object' && type(cp_bad_sb.effective) == 'object',
	'composer_preview returns ok=true with check_ok=false and check_error when sing-box check fails');

let cp_nocheck = call_rpc('composer_preview', { validate: false });
check(cp_nocheck.ok === true && cp_nocheck.checked === false && cp_nocheck.check_ok === null &&
	cp_nocheck.check_error === null,
	'composer_preview with validate=false skips sing-box check');

// 12.8 profile_save & profile_delete in composer mode
let ps_enabled_bad = call_rpc('profile_save', {
	filename: 'source_a.json',
	content: '[{"type":"nonexistent_proto_xyz","tag":"bad-node"}]',
	validate: true
});
check(ps_enabled_bad.ok === false && ps_enabled_bad.code == common.ERR_VALIDATE_FAILED &&
	fs.readfile(profiles_dir + '/source_a.json') == sub_a_raw,
	'profile_save in composer mode rejects enabled source failing sing-box check without overwriting');

let ps_enabled_src = call_rpc('profile_save', { filename: 'source_a.json', content: sub_a_raw, validate: true });
check(ps_enabled_src.ok === true && ps_enabled_src.checked === true && ps_enabled_src.reload_required === true,
	'profile_save in composer mode runs sing-box check and flags reload_required=true for enabled source');

let pdel_conflict = call_rpc('profile_delete', { section_id: pm_src_a.section_id });
check(pdel_conflict.ok === false && pdel_conflict.code == common.ERR_CONFLICT,
	'profile_delete in composer mode rejects deleting source enabled in composer.json');

// Set active_profile to unenabled source_b, then delete source_b in composer mode -> clears active_profile
let pa_b = call_rpc('profile_activate', { section_id: pm_src_b.section_id, reload: false });
check(pa_b.ok === true, 'activate source_b before deleting in composer mode');
let pdel_b = call_rpc('profile_delete', { section_id: pm_src_b.section_id });
check(pdel_b.ok === true && fs.stat(profiles_dir + '/source_b.json') == null,
	'profile_delete deletes unenabled source in composer mode');
let plist_after = call_rpc('profile_list', {});
check(plist_after.ok === true && plist_after.active_profile == '',
	'profile_delete in composer mode clears dangling global.active_profile');

// 13. Regression assertions: args schema parity, composer_save(validate=false) warnings, lockdown reload_required, lock cleanup
for (let m in [ 'composer_nodes', 'composer_preview', 'composer_save' ]) {
	check(exists(rpc[m].args, 'composer') && type(rpc[m].args.composer) == 'object' &&
		exists(rpc[m].args, 'composer_json') && type(rpc[m].args.composer_json) == 'string',
		sprintf('%s args schema declares both composer (object) and composer_json (string)', m));
}

let warn_draft = {
	...comp_draft,
	sources: {
		[pm_src_a.section_id]: comp_draft.sources[pm_src_a.section_id],
		missing_src: { enabled: true, tag_prefix: '', include_regex: '', exclude_regex: '' }
	}
};
let cs_warn_nocheck = call_rpc('composer_save', {
	composer_json: sprintf('%.2J', warn_draft),
	validate: false,
	reload: false
});
check(cs_warn_nocheck.ok === true && cs_warn_nocheck.checked === false &&
	type(cs_warn_nocheck.warnings) == 'array' &&
	length(filter(cs_warn_nocheck.warnings, (w) => index(w, 'missing_src') >= 0)) == 1,
	'composer_save({ validate: false }) still returns Stage A warnings');

// Restore clean composer_file and test profile_save reload_required in lockdown (composer + profile modes)
check(common.write_json_atomic(state_file, { state: 'lockdown' }, 0600), 'set state=lockdown for profile_save check');
let ps_lockdown_comp = call_rpc('profile_save', { filename: 'source_a.json', content: sub_a_raw, validate: true });
check(ps_lockdown_comp.ok === true && ps_lockdown_comp.reload_required === true,
	'profile_save in composer mode flags reload_required=true when service state is lockdown');

let mode_prof_back = call_rpc('composer_mode_set', { mode: 'profile', reload: false });
let act_main = call_rpc('profile_activate', { section_id: 'main_sub', reload: false });
let ps_lockdown_prof = call_rpc('profile_save', { filename: 'main_sub.json', content: legacy_raw, validate: true });
check(mode_prof_back.ok === true && act_main.ok === true &&
	ps_lockdown_prof.ok === true && ps_lockdown_prof.reload_required === true,
	'profile_save in profile mode flags reload_required=true when service state is lockdown');

// Verify worker failure releases in_flight_write and nimbus.lock cleanly
let saved_ucode_bin = rpc_cfg.ucode_bin;
rpc_cfg.ucode_bin = '/nonexistent/ucode_bin_xyz';
let cs_worker_fail = call_rpc('composer_save', {
	composer_json: sprintf('%.2J', comp_draft),
	validate: false,
	reload: false
});
rpc_cfg.ucode_bin = saved_ucode_bin;
let probe_lock = common.acquire_lock(0, lock_file);
check(cs_worker_fail.ok === false && probe_lock != null,
	'failed composer_save worker releases in_flight_write and nimbus.lock cleanly');
if (probe_lock)
	common.release_lock(probe_lock);

let lc_after_fail = call_rpc('log_clear', {});
check(lc_after_fail.ok === true, 'subsequent write RPC succeeds without E_LOCKED after worker failure');

printf('test_rpc_contract.uc: %d assertions passed\n', passed);
