#!/usr/bin/ucode
'use strict';

import * as fs from 'fs';
import * as common from 'common';
import * as lu from 'list_updater';

let passed = 0;

function check(cond, msg) {
	if (!cond) {
		warn(sprintf('FAIL: %s\n', msg));
		exit(1);
	}
	passed++;
}

let repo_root = getenv('NIMBUS_REPO_ROOT') || '/work';
let dirty_fixture = repo_root + '/tests/fixtures/whitelist_dirty.txt';
let tmp_root = getenv('TMPDIR') || '/tmp';
let work_dir = sprintf('%s/list_test_%d', tmp_root, time());
check(common.ensure_dir(work_dir, 0755), 'create work_dir');

// 1. Parse and clean dirty fixture (comments, CRLF, :port, [ipv6]:port, domains, deduplication, and /0 + loopback + reserved + invalid CIDR rejection)
let dirty_raw = fs.readfile(dirty_fixture);
check(type(dirty_raw) == 'string' && length(dirty_raw) > 0, 'read tests/fixtures/whitelist_dirty.txt');

let strict_res = lu.parse_list_content(dirty_raw, 'auto');
check(strict_res.ok === false && strict_res.code == common.ERR_VALIDATE_FAILED,
	'strict parse_list_content rejects dirty fixture containing /0, reserved, and malformed lines');
check(length(strict_res.invalid_lines) == 10 && strict_res.invalid_count == 15,
	'parse_list_content caps invalid_lines at 10 while recording all 15 invalid lines');
check(strict_res.invalid_lines[0].line == 20 && strict_res.invalid_lines[0].text == '0.0.0.0/0',
	'first invalid line accurately identifies 0.0.0.0/0 at line 20');
check(strict_res.invalid_lines[1].line == 21 && strict_res.invalid_lines[1].text == '::/0',
	'second invalid line accurately identifies ::/0 at line 21');

let clean_res = lu.clean_list_content(dirty_raw, 'auto');
check(clean_res.ok === true, 'clean_list_content succeeds on dirty fixture');
check(clean_res.v4_count == 4 &&
	clean_res.v4[0] == '1.0.1.0/24' &&
	clean_res.v4[1] == '1.0.2.0/23' &&
	clean_res.v4[2] == '223.5.5.5' &&
	clean_res.v4[3] == '114.114.114.114',
	'clean_list_content extracts 4 deduplicated public IPv4 entries and strips :53 port');
check(clean_res.v6_count == 3 &&
	clean_res.v6[0] == '2400:3200::/32' &&
	clean_res.v6[1] == '2400:3200::1' &&
	clean_res.v6[2] == '2408:8000::/20',
	'clean_list_content extracts 3 deduplicated public IPv6 entries and strips [ipv6]:443 brackets/port');
check(clean_res.domain_count == 2 &&
	clean_res.domains[0] == 'baidu.com' &&
	clean_res.domains[1] == 'sub.example.com',
	'clean_list_content extracts 2 valid domains and strips :8443 port');

// Verify none of the rejected /0, loopback, private, Fake-IP, or malformed entries leaked into v4/v6/domains
let all_entries = [ ...clean_res.v4, ...clean_res.v6, ...clean_res.domains ];
for (let bad in [
	'0.0.0.0/0', '::/0', '1.2.3.4/0', '127.0.0.1', '::1', '10.0.0.1',
	'172.16.5.0/24', '192.168.1.0/24', '169.254.1.1', '198.18.0.1',
	'fe80::1', 'fc00::1', '1.2.3.999/24', '1.2.3.4/33', '2400:3200::/129'
]) {
	check(index(all_entries, bad) < 0, sprintf('rejected entry "%s" did not leak into cleaned output', bad));
}

// 2. HTML error page detection and CRLF handling
let html_res = lu.parse_list_content('1.0.1.0/24\r\n<!DOCTYPE html>\r\n<html><body>502 Bad Gateway</body></html>\r\n', 'auto');
check(html_res.ok === false && html_res.is_html === true && html_res.invalid_lines[0].line == 2,
	'HTML error page is rejected with accurate line number');
check(lu.clean_list_content('<html><body>error</body></html>', 'auto').ok === false,
	'clean_list_content also rejects HTML error pages');

// 3. Family filtering ('ipv4' vs 'ipv6')
let v4_only_bad = lu.parse_list_content('1.0.1.0/24\n2400:3200::/32\n', 'ipv4');
check(v4_only_bad.ok === false && v4_only_bad.invalid_lines[0].line == 2,
	'ipv4-only list rejects IPv6 entry in strict mode');
let v6_only_ok = lu.parse_list_content('2400:3200::/32\r\n[2400:3200::2]:443\r\n', 'ipv6');
check(v6_only_ok.ok === true && v6_only_ok.v6_count == 2 && v6_only_ok.v4_count == 0,
	'ipv6-only list accepts valid IPv6 CIDR and [ipv6]:port with CRLF');

// 4. Local list saving, validation failure preservation, and remote SHA256 cache update
let local_dir = work_dir + '/lists/local';
let cache_dir = work_dir + '/lists/cache';
let state_file = work_dir + '/state.json';
let bypass_nft = work_dir + '/bypass_sets.nft';
let conf_dir = work_dir + '/etc_config';
check(common.ensure_dir(local_dir, 0755), 'create local_dir');
check(common.ensure_dir(cache_dir, 0755), 'create cache_dir');
check(common.ensure_dir(conf_dir, 0755), 'create conf_dir');

let uci_text =
	"config whitelist 'whitelist'\n" +
	"\toption enabled '1'\n" +
	"\toption auto_update '1'\n" +
	"\toption update_cron '30 4 * * *'\n\n" +
	"config list_source 'cn_ipv4'\n" +
	"\toption name 'China IPv4'\n" +
	"\toption type 'url'\n" +
	"\toption enabled '1'\n" +
	"\toption family 'ipv4'\n" +
	"\toption url 'https://example.com/chnroutes.txt'\n\n" +
	"config list_source 'custom_direct'\n" +
	"\toption name 'Custom Direct'\n" +
	"\toption type 'local'\n" +
	"\toption enabled '1'\n" +
	"\toption family 'auto'\n" +
	"\toption filename 'custom_direct.txt'\n";
check(common.atomic_write(conf_dir + '/nimbus', uci_text, 0644), 'seed nimbus uci config');
let uci_hash_before = common.sha256_file(conf_dir + '/nimbus');

check(common.write_state({ state: 'running', warnings: [], last_error: null }, state_file), 'seed running state');

let list_opts = {
	uci_confdir: conf_dir,
	local_dir: local_dir,
	cache_dir: cache_dir,
	state_file: state_file,
	bypass_nft_path: bypass_nft,
	nft_dry_run: true
};

// Save valid local list
let save_ok = lu.save_local_list(
	'custom_direct.txt',
	'# local direct\n1.1.8.0/24\n2400:3200::/32\n',
	list_opts
);
check(save_ok.ok === true && save_ok.v4_count == 1 && save_ok.v6_count == 1 && save_ok.hot_reloaded === true,
	'save_local_list writes valid file and hot-reloads bypass_sets.nft');

// Attempt to save invalid local list -> must fail and preserve original custom_direct.txt
let save_bad = lu.save_local_list(
	'custom_direct.txt',
	'1.1.8.0/24\n1.2.3.999/24\n',
	list_opts
);
check(save_bad.ok === false && save_bad.code == common.ERR_VALIDATE_FAILED &&
	save_bad.invalid_lines[0].line == 2,
	'save_local_list rejects invalid CIDR at line 2');
check(index(fs.readfile(local_dir + '/custom_direct.txt') || '', '1.2.3.999') < 0,
	'save_local_list preserves original local list file on validation failure');

// 5. Remote list_source download via curl runner, SHA256 comparison, and state.json list_meta
let remote_payload_v1 = '# BGP export\n1.0.1.0/24\n1.0.2.0/23\n1.0.8.0/21\n';
let recorded_curl_argv = null;
let nft_reload_count = 0;

let upd1 = lu.update_lists(null, {
	...list_opts,
	nft_dry_run: false,
	nft_runner: () => {
		nft_reload_count++;
		return { rc: 0, output: '' };
	},
	runner: (argv) => {
		recorded_curl_argv = argv;
		let out_idx = index(argv, '-o');
		if (out_idx >= 0 && out_idx + 1 < length(argv))
			common.atomic_write(argv[out_idx + 1], remote_payload_v1, 0600);
		return 0;
	}
});

check(upd1.ok === true && upd1.hot_reloaded === true && nft_reload_count == 1,
	'initial update_lists downloads remote list and triggers nft set hot reload');
check(type(recorded_curl_argv) == 'array' &&
	index(recorded_curl_argv, '--connect-timeout') >= 0 &&
	index(recorded_curl_argv, '10') >= 0 &&
	index(recorded_curl_argv, '--max-time') >= 0 &&
	index(recorded_curl_argv, '30') >= 0 &&
	index(recorded_curl_argv, '-fsSL') >= 0,
	'update_lists passes array curl arguments (--connect-timeout 10 --max-time 30 -fsSL)');
check(length(upd1.results) == 1 && upd1.results[0].id == 'cn_ipv4' &&
	upd1.results[0].status == 'updated' && upd1.results[0].changed === true &&
	upd1.results[0].v4_count == 3,
	'update_lists reports cn_ipv4 updated with 3 IPv4 entries');
check(upd1.nft_loaded.v4_count == 4 && upd1.nft_loaded.v6_count == 1,
	'merged nft_loaded combines 3 remote IPv4 + 1 local IPv4 and 1 local IPv6');

let cache_file = cache_dir + '/cn_ipv4.txt';
let st_cache1 = fs.stat(cache_file);
check(st_cache1 != null, 'cn_ipv4.txt written to cache_dir');

// Re-run update_lists with identical payload -> SHA256 matches -> must NOT overwrite cache file or re-trigger nft reload
let upd2 = lu.update_lists('cn_ipv4', {
	...list_opts,
	nft_dry_run: false,
	nft_runner: () => {
		nft_reload_count++;
		return { rc: 0, output: '' };
	},
	runner: (argv) => {
		let out_idx = index(argv, '-o');
		common.atomic_write(argv[out_idx + 1], remote_payload_v1, 0600);
		return 0;
	}
});
let st_cache2 = fs.stat(cache_file);
check(upd2.ok === true && upd2.results[0].status == 'unchanged' &&
	upd2.results[0].changed === false && upd2.hot_reloaded === false &&
	nft_reload_count == 1 && st_cache2.inode == st_cache1.inode,
	'identical SHA256 skips cache file write (inode preserved) and skips redundant nft reload');

// Verify runtime metadata is stored in state.json list_meta and NEVER in UCI
let st_after = common.read_state(state_file);
check(type(st_after.list_meta?.cn_ipv4) == 'object' &&
	st_after.list_meta.cn_ipv4.sha256 == common.sha256_str(remote_payload_v1) &&
	st_after.list_meta.cn_ipv4.v4_count == 3 &&
	st_after.whitelist.v4_count == 4 && st_after.whitelist.v6_count == 1,
	'runtime list_meta and whitelist counts stored in state.json');
check(common.sha256_file(conf_dir + '/nimbus') == uci_hash_before,
	'UCI config file on disk was never modified with runtime metadata');

// 6. Remote download of HTML error page fails and preserves existing cache file
let upd_html = lu.update_lists('cn_ipv4', {
	...list_opts,
	runner: (argv) => {
		let out_idx = index(argv, '-o');
		common.atomic_write(argv[out_idx + 1], '<html><body>404 Not Found</body></html>\n', 0600);
		return 0;
	}
});
check(upd_html.ok === false && upd_html.results[0].status == 'failed',
	'remote HTML error response is rejected');
check(fs.readfile(cache_file) == remote_payload_v1,
	'existing cn_ipv4.txt cache preserved when remote returns HTML error page');

// 7. Cron synchronization via common.cron_sync_tag
let crontab_file = work_dir + '/crontab_root';
let cron_on = lu.sync_cron(null, {
	uci_confdir: conf_dir,
	crontab_path: crontab_file
});
check(cron_on.ok === true && cron_on.changed === true, 'sync_cron adds whitelist cron job');
let cron_content = fs.readfile(crontab_file) || '';
check(index(cron_content, '30 4 * * *') >= 0 && index(cron_content, '# nimbus-whitelist') >= 0,
	'crontab contains 30 4 * * * schedule with # nimbus-whitelist tag');

let cron_custom_tag = lu.sync_cron(null, {
	uci_confdir: conf_dir,
	crontab_path: crontab_file,
	cron_tag: 'nimbus-list-sync'
});
check(cron_custom_tag.ok === true && index(fs.readfile(crontab_file) || '', '# nimbus-list-sync') >= 0,
	'sync_cron supports # nimbus-list-sync tag');

let cron_off = lu.sync_cron(null, {
	uci_confdir: conf_dir,
	crontab_path: crontab_file,
	auto_update: '0'
});
check(cron_off.ok === true && cron_off.changed === true &&
	index(fs.readfile(crontab_file) || '', '# nimbus-whitelist') < 0,
	'sync_cron removes cron entry when auto_update=0');

printf('test_list_updater.uc: %d assertions passed\n', passed);
