#!/usr/bin/ucode
'use strict';

import * as fs from 'fs';
import * as common from 'common';

let passed = 0;

function check(cond, msg) {
	if (!cond) {
		warn(sprintf('FAIL: %s\n', msg));
		exit(1);
	}
	passed++;
}

let tmp_root = getenv('TMPDIR') || '/tmp';
let work_dir = sprintf('%s/common_test_%d', tmp_root, time());
check(common.ensure_dir(work_dir, 0755), 'ensure_dir creates work_dir');

// 1. Constants check
check(common.RUN_DIR == '/var/run/nimbus', 'RUN_DIR constant');
check(common.STATE_FILE == '/var/run/nimbus/state.json', 'STATE_FILE constant');
check(common.CONFIG_FILE == '/var/run/nimbus/config.json', 'CONFIG_FILE constant');
check(common.PID_FILE == '/var/run/nimbus/sing-box.pid', 'PID_FILE constant');
check(common.LOCK_FILE == '/var/run/nimbus/nimbus.lock', 'LOCK_FILE constant');
check(common.LOG_FILE == '/var/log/nimbus.log', 'LOG_FILE constant');
check(common.COMPOSER_FILE == '/etc/nimbus/composer.json', 'COMPOSER_FILE constant');
check(common.PROFILES_DIR == '/etc/nimbus/profiles', 'PROFILES_DIR constant');
check(common.CONFIG_MODE_COMPOSER == 'composer', 'CONFIG_MODE_COMPOSER constant');
check(common.CONFIG_MODE_PROFILE == 'profile', 'CONFIG_MODE_PROFILE constant');
check(common.LOCAL_LISTS_DIR == '/etc/nimbus/lists/local', 'LOCAL_LISTS_DIR constant');
check(common.CACHE_LISTS_DIR == '/etc/nimbus/lists/cache', 'CACHE_LISTS_DIR constant');
check(common.DNS_BACKUP_FILE == '/etc/nimbus/dns_backup.json', 'DNS_BACKUP_FILE constant');
check(common.CRONTABS_ROOT == '/etc/crontabs/root', 'CRONTABS_ROOT constant');
check(common.CT_BYPASS_BIT == 0x10, 'CT_BYPASS_BIT constant');
check(common.CT_PROXY_BIT == 0x20, 'CT_PROXY_BIT constant');
check(common.CT_MARK_MASK == 0x30, 'CT_MARK_MASK constant');
check(common.RULE_PRIO_PROXY == 1000, 'RULE_PRIO_PROXY constant');
check(index(common.RESERVED_V4, '198.18.0.0/15') < 0, 'RESERVED_V4 excludes fakeip range');
check(index(common.RESERVED_V6, 'fc00::/7') >= 0, 'RESERVED_V6 includes fc00::/7');

// 2. ensure_dir recursive + idempotent
let nested = work_dir + '/a/b/c';
check(common.ensure_dir(nested, 0755), 'ensure_dir recursive');
check(common.ensure_dir(nested, 0755), 'ensure_dir idempotent');
check(fs.stat(nested)?.type == 'directory', 'ensure_dir created directory');

// 3. atomic_write (0600 + no leftover tmp files)
let atomic_path = work_dir + '/sub/secret.txt';
check(common.atomic_write(atomic_path, 'hello nimbus\n', 0600), 'atomic_write succeeds');
check(fs.readfile(atomic_path) == 'hello nimbus\n', 'atomic_write content matches');
let st_atomic = fs.stat(atomic_path);
check(st_atomic != null && (st_atomic.mode & 0777) == 0600, 'atomic_write sets 0600 permissions');
let sub_entries = fs.lsdir(work_dir + '/sub');
check(length(sub_entries) == 1 && sub_entries[0] == 'secret.txt', 'atomic_write leaves no temp files');

// 4. read_json / write_json_atomic
let json_path = work_dir + '/data.json';
check(common.write_json_atomic(json_path, { k: 'v', n: 42 }, 0644), 'write_json_atomic succeeds');
let st_json = fs.stat(json_path);
check(st_json != null && (st_json.mode & 0777) == 0644, 'write_json_atomic sets 0644 permissions');
let parsed = common.read_json(json_path);
check(parsed?.k == 'v' && parsed?.n == 42, 'read_json roundtrip');
check(common.read_json(work_dir + '/missing.json') == null, 'read_json missing returns null');
check(common.atomic_write(work_dir + '/bad.json', '{not json', 0600), 'write bad json');
check(common.read_json(work_dir + '/bad.json') == null, 'read_json invalid returns null');

// 5. write_state / read_state secret stripping & 0600
let state_path = work_dir + '/state.json';
let state_in = {
	state: 'running',
	secret: 'top-secret',
	singbox_api_secret: 'top-sb-secret',
	effective: {
		outbound_mark: '0xff',
		clash_api_secret: 'nested-clash-secret'
	},
	extra: [
		{ label: 'keep', secret: 'array-secret' }
	],
	apis: {
		singbox_api: {
			detected: true,
			port: 9091,
			has_secret: true,
			secret: 'super-secret-sb'
		},
		clash_api: {
			detected: true,
			port: 9090,
			has_secret: true,
			secret: 'super-secret-clash'
		}
	},
	warnings: []
};
check(common.write_state(state_in, state_path), 'write_state succeeds');
let st_state = fs.stat(state_path);
check(st_state != null && (st_state.mode & 0777) == 0600, 'state.json has 0600 permissions');
let state_disk_raw = fs.readfile(state_path);
check(index(state_disk_raw, 'top-secret') < 0, 'state.json strips top-level secret on disk');
check(index(state_disk_raw, 'top-sb-secret') < 0, 'state.json strips top-level singbox_api_secret on disk');
check(index(state_disk_raw, 'nested-clash-secret') < 0, 'state.json strips nested clash_api_secret outside apis');
check(index(state_disk_raw, 'array-secret') < 0, 'state.json strips secret inside array elements');
check(index(state_disk_raw, 'super-secret-sb') < 0, 'state.json strips singbox_api secret on disk');
check(index(state_disk_raw, 'super-secret-clash') < 0, 'state.json strips clash_api secret on disk');
let state_out = common.read_state(state_path);
check(!exists(state_out, 'secret') && !exists(state_out, 'singbox_api_secret'), 'read_state has no top-level secrets');
check(!exists(state_out?.effective, 'clash_api_secret'), 'read_state has no secret in effective');
check(state_out?.extra?.[0]?.label == 'keep' && !exists(state_out?.extra?.[0], 'secret'), 'read_state strips secret in array while keeping non-secret fields');
check(state_out?.apis?.singbox_api?.has_secret === true, 'state.json preserves has_secret');
check(!exists(state_out?.apis?.singbox_api, 'secret'), 'read_state has no secret key in singbox_api');
check(!exists(state_out?.apis?.clash_api, 'secret'), 'read_state has no secret key in clash_api');
check(state_in.secret == 'top-secret' && state_in.apis.singbox_api.secret == 'super-secret-sb', 'write_state does not mutate caller object');

// 6. Non-blocking acquire_lock(0) + bounded timeout
let lock_path = work_dir + '/test.lock';
let lh1 = common.acquire_lock(0, lock_path);
check(lh1 != null, 'acquire_lock(0) acquires uncontended lock');
let lh2 = common.acquire_lock(0, lock_path);
check(lh2 == null, 'acquire_lock(0) immediately returns null on contention');
let t0 = clock(true);
let lh3 = common.acquire_lock(80, lock_path);
let t1 = clock(true);
let dt_ms = ((t1[0] - t0[0]) * 1000) + int((t1[1] - t0[1]) / 1000000);
check(lh3 == null && dt_ms >= 60, 'acquire_lock(80) times out after ~80ms on contention');
common.release_lock(lh1);
let lh4 = common.acquire_lock(0, lock_path);
check(lh4 != null, 'acquire_lock(0) succeeds after release_lock');
common.release_lock(lh4);

// 7. uci_get_all with isolated confdir
let uci_conf = work_dir + '/uci_conf';
let uci_save = work_dir + '/uci_save';
common.ensure_dir(uci_conf, 0755);
common.ensure_dir(uci_save, 0755);
let repo_root = getenv('NIMBUS_REPO_ROOT') || '';
let sample_uci = fs.readfile(repo_root + '/nimbus/files/etc/config/nimbus');
check(type(sample_uci) == 'string' && length(sample_uci) > 0, 'repo default uci config readable');
common.atomic_write(uci_conf + '/nimbus', sample_uci, 0644);
let all_uci = common.uci_get_all('nimbus', uci_conf, uci_save);
check(all_uci?.global?.config_mode == 'composer', 'uci_get_all reads default global.config_mode');
check(all_uci?.global?.proxy_mode == 'tproxy_redirect', 'uci_get_all reads global.proxy_mode');
check(all_uci?.global?.fail_open == '0', 'uci_get_all reads global.fail_open');
check(all_uci?.proxy?.outbound_mark == '0xff', 'uci_get_all reads proxy.outbound_mark');
check(all_uci?.proxy?.route_table == '100', 'uci_get_all reads proxy.route_table');
check(all_uci?.proxy?.sniff == '0', 'uci_get_all reads proxy.sniff');
check(all_uci?.custom_direct?.filename == 'custom_direct.txt', 'uci_get_all reads custom_direct');

// 8. hex_u32_parse & format_hex_u32
check(common.hex_u32_parse('0xff') == 255, 'hex_u32_parse 0xff');
check(common.hex_u32_parse('0x1') == 1, 'hex_u32_parse 0x1');
check(common.hex_u32_parse('ff') == 255, 'hex_u32_parse ff');
check(common.hex_u32_parse('0X10') == 16, 'hex_u32_parse 0X10');
check(common.hex_u32_parse('0xffffffff') == 0xffffffff, 'hex_u32_parse max u32');
check(common.hex_u32_parse('0x0') == null, 'hex_u32_parse rejects 0x0');
check(common.hex_u32_parse('0') == null, 'hex_u32_parse rejects 0');
check(common.hex_u32_parse('-1') == null, 'hex_u32_parse rejects -1');
check(common.hex_u32_parse('0x100000000') == null, 'hex_u32_parse rejects overflow');
check(common.hex_u32_parse('0x1g') == null, 'hex_u32_parse rejects trailing invalid char');
check(common.hex_u32_parse('xyz') == null, 'hex_u32_parse rejects non-hex');
check(common.hex_u32_parse('') == null, 'hex_u32_parse rejects empty');
check(common.hex_u32_parse(null) == null, 'hex_u32_parse rejects null');
check(common.format_hex_u32(255) == '0xff', 'format_hex_u32 255');
check(common.format_hex_u32(1) == '0x1', 'format_hex_u32 1');
check(common.format_hex_u32(-1) == null, 'format_hex_u32 rejects negative');

// 9. Filename validation
check(common.is_valid_profile_filename('main_sub.json'), 'valid profile filename');
check(common.is_valid_profile_filename('cfg-1.2.json'), 'valid profile filename with dash/dot');
check(!common.is_valid_profile_filename('../etc/shadow'), 'rejects path traversal in profile');
check(!common.is_valid_profile_filename('../bad.json'), 'rejects ../ in profile');
check(!common.is_valid_profile_filename('a/b.json'), 'rejects slash in profile');
check(!common.is_valid_profile_filename('a..b.json'), 'rejects .. in profile');
check(!common.is_valid_profile_filename('.json'), 'rejects bare .json');
check(!common.is_valid_profile_filename('test.sh'), 'rejects non-json profile');
check(!common.is_valid_profile_filename('bad name.json'), 'rejects space in profile');
check(!common.is_valid_profile_filename(null), 'rejects null profile');

check(common.is_valid_list_filename('custom_direct.txt'), 'valid list filename');
check(common.is_valid_list_filename('list-v4.1.txt'), 'valid list filename with dash/dot');
check(!common.is_valid_list_filename('../bad.txt'), 'rejects ../ in list');
check(!common.is_valid_list_filename('dir/list.txt'), 'rejects slash in list');
check(!common.is_valid_list_filename('list.json'), 'rejects non-txt list');
check(!common.is_valid_list_filename('.txt'), 'rejects bare .txt');

// 9b. Config mode normalization
check(common.normalize_config_mode('profile') == 'profile', 'normalize_config_mode profile');
check(common.normalize_config_mode(' PROFILE ') == 'profile', 'normalize_config_mode uppercase padded profile');
check(common.normalize_config_mode('composer') == 'composer', 'normalize_config_mode composer');
check(common.normalize_config_mode('') == 'composer', 'normalize_config_mode empty defaults to composer');
check(common.normalize_config_mode(null) == 'composer', 'normalize_config_mode null defaults to composer');
check(common.normalize_config_mode('unknown') == 'composer', 'normalize_config_mode unknown defaults to composer');
check(common.normalize_config_mode({ global: { config_mode: 'profile' } }) == 'profile', 'normalize_config_mode uci object profile');
check(common.normalize_config_mode({ global: {} }) == 'composer', 'normalize_config_mode uci object missing defaults to composer');

// 10. sha256_str & sha256_file
check(common.sha256_str('') == 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'sha256 empty string');
check(common.sha256_str('abc') == 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', 'sha256 abc');
let special_file = work_dir + "/my file 'quoted' $(id).txt";
check(common.atomic_write(special_file, 'abc', 0644), 'write special filename');
check(common.sha256_file(special_file) == 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', 'sha256_file handles special chars safely');
let orig_cwd = fs.getcwd();
check(fs.chdir(work_dir), 'chdir to work_dir for leading-dash filename test');
let dash_wrote = common.atomic_write('-dash-file.txt', 'abc', 0644);
let dash_digest = dash_wrote ? common.sha256_file('-dash-file.txt') : null;
if (orig_cwd)
	fs.chdir(orig_cwd);
check(dash_wrote && dash_digest == 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', 'sha256_file handles leading-dash filename safely');
check(common.sha256_file(work_dir + '/nonexistent') == null, 'sha256_file missing returns null');

// 11. cron_sync_tag
let crontab = work_dir + '/crontab';
check(common.cron_sync_tag('nimbus-whitelist', null, crontab).changed === false, 'cron_sync_tag noop on missing file');
check(fs.stat(crontab) == null, 'cron_sync_tag does not create file when removing');

check(common.atomic_write(crontab, '0 3 * * * /sbin/other\n0 * * * * /usr/bin/sub # nimbus-profile\n', 0600), 'seed crontab');
let c1 = common.cron_sync_tag('nimbus-whitelist', '30 4 * * * /usr/bin/wl', crontab);
check(c1.ok === true && c1.changed === true, 'cron_sync_tag adds whitelist line');
let c2 = common.cron_sync_tag('nimbus-whitelist', '30 4 * * * /usr/bin/wl # nimbus-whitelist', crontab);
check(c2.ok === true && c2.changed === false, 'cron_sync_tag is idempotent');
let cron_txt = fs.readfile(crontab);
check(index(cron_txt, '0 3 * * * /sbin/other') >= 0, 'cron_sync_tag preserves unrelated lines');
check(index(cron_txt, '# nimbus-profile') >= 0, 'cron_sync_tag preserves other nimbus tags');
check(index(cron_txt, '30 4 * * * /usr/bin/wl # nimbus-whitelist') >= 0, 'cron_sync_tag wrote tagged line');

let c3 = common.cron_sync_tag('nimbus-whitelist', '15 5 * * * /usr/bin/wl2', crontab);
check(c3.ok === true && c3.changed === true, 'cron_sync_tag updates changed schedule');
let cron_txt2 = fs.readfile(crontab);
check(index(cron_txt2, '15 5 * * * /usr/bin/wl2 # nimbus-whitelist') >= 0, 'cron_sync_tag updated line present');
check(index(cron_txt2, '30 4 * * * /usr/bin/wl') < 0, 'cron_sync_tag removed old line');

let c4 = common.cron_sync_tag('nimbus-whitelist', null, crontab);
check(c4.ok === true && c4.changed === true, 'cron_sync_tag removes tagged line');
let cron_txt3 = fs.readfile(crontab);
check(index(cron_txt3, 'nimbus-whitelist') < 0 && index(cron_txt3, 'nimbus-profile') >= 0, 'cron_sync_tag removal keeps other lines');
check((fs.stat(crontab).mode & 0777) == 0600, 'cron_sync_tag keeps 0600 mode');
let common_src = fs.readfile((getenv('NIMBUS_REPO_ROOT') || '/work') + '/nimbus/files/usr/share/nimbus/common.uc') || '';
check(index(common_src, "system([ '/etc/init.d/cron', 'reload' ], 5000)") >= 0,
	'cron_sync_tag reloads /etc/init.d/cron when CRONTABS_ROOT changes');

// 12. truncate_log_hysteresis (>512KB -> <=256KB newline-aligned, same inode)
let log_path = work_dir + '/nimbus.log';
let fh_log = fs.open(log_path, 'w', 0644);
check(fh_log != null, 'create test log file');
let line_idx = 0;
let written_total = 0;
while (written_total <= common.LOG_HIGH_BYTES + 65536) {
	let row = sprintf('line-%06d 0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ\n', line_idx);
	fh_log.write(row);
	written_total += length(row);
	line_idx++;
}
fh_log.close();

let st_before = fs.stat(log_path);
check(st_before.size > common.LOG_HIGH_BYTES, 'test log exceeds 512KB high watermark');
let trunc_res = common.truncate_log_hysteresis(log_path);
check(trunc_res.ok === true && trunc_res.truncated === true, 'truncate_log_hysteresis truncated large log');
let st_after = fs.stat(log_path);
check(st_after.size <= common.LOG_KEEP_BYTES, 'truncated log is <= 256KB');
check(st_after.size > common.LOG_KEEP_BYTES - 256, 'truncated log preserved ~256KB tail');
check(st_after.inode == st_before.inode, 'truncate_log_hysteresis preserved inode in-place');

let log_content = fs.readfile(log_path);
let first_line_end = index(log_content, '\n');
let first_line = substr(log_content, 0, first_line_end);
check(match(first_line, /^line-[0-9]{6} 0123456789/) != null, 'truncated log starts at clean newline boundary');
let last_expected = sprintf('line-%06d ', line_idx - 1);
check(index(log_content, last_expected) >= 0, 'truncated log kept newest lines at tail');

let trunc_noop = common.truncate_log_hysteresis(log_path);
check(trunc_noop.ok === true && trunc_noop.truncated === false, 'truncate_log_hysteresis skips below high watermark');

let hugeline_path = work_dir + '/hugeline.log';
let huge_line = '';
for (let i = 0; i < 149; i++)
	huge_line += 'x';
huge_line += '\n';
check(common.atomic_write(hugeline_path, huge_line, 0644), 'create huge single-line log');
let huge_res = common.truncate_log_hysteresis(hugeline_path, 100, 50);
check(huge_res.ok === true && huge_res.truncated === true && huge_res.new_size == 50, 'truncate_log_hysteresis preserves trailing huge line instead of truncating to 0');
check(fs.readfile(hugeline_path) == substr(huge_line, 100), 'truncate_log_hysteresis keeps exact 50-byte tail on single huge line');

let sym_target = work_dir + '/symlink_target.txt';
let sym_log = work_dir + '/symlink.log';
check(common.atomic_write(sym_target, huge_line, 0644), 'create symlink target log');
check(fs.symlink(sym_target, sym_log), 'create log symlink');
let sym_res = common.truncate_log_hysteresis(sym_log, 100, 50);
check(sym_res.ok === false && sym_res.truncated === false, 'truncate_log_hysteresis rejects symlink path');
check(length(fs.readfile(sym_target)) == 150, 'truncate_log_hysteresis leaves symlink target untouched');

// 13. log_msg helper
check(common.log_msg('warn', 'test warning message', log_path), 'log_msg appends cleanly');
let after_msg = fs.readfile(log_path);
check(index(after_msg, '[nimbus] [warn] test warning message\n') >= 0, 'log_msg format matches');

printf('test_common.uc: %d assertions passed\n', passed);
