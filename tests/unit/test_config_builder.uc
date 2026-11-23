#!/usr/bin/ucode
'use strict';

import * as fs from 'fs';
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

function make_uci(overrides) {
	let o = overrides || {};
	return {
		global: {
			topology: o.topology ?? 'main',
			proxy_mode: 'tproxy_redirect',
			fail_open: '0',
			lan_interfaces: o.lan_interfaces ?? [ 'lan' ],
			wan_interfaces: o.wan_interfaces ?? [ 'wan', 'wan6' ],
			ipv4_enable: o.ipv4_enable ?? '1',
			ipv6_enable: o.ipv6_enable ?? '1',
			proxy_local: o.proxy_local ?? '0',
			log_level: o.log_level ?? 'warn',
			active_profile: 'test_prof'
		},
		proxy: {
			redirect_port: o.redirect_port ?? '7891',
			tproxy_port: o.tproxy_port ?? '7892',
			outbound_mark: o.outbound_mark ?? '0xff',
			proxy_mark: o.proxy_mark ?? '0x1',
			route_table: '100',
			block_quic: o.block_quic ?? '0',
			sniff: o.sniff
		},
		dns: {
			mode: o.dns_mode ?? 'none',
			singbox_dns_port: o.singbox_dns_port ?? '5353',
			local_dns_policy: o.local_dns_policy ?? 'auto',
			local_fallback_server: exists(o, 'local_fallback_server') ? o.local_fallback_server : '223.5.5.5'
		},
		core: {
			bin_path: getenv('SINGBOX_BIN') || '/usr/local/bin/sing-box'
		},
		test_prof: {
			'.type': 'profile',
			filename: 'test.json'
		}
	};
}

let singbox_bin = getenv('SINGBOX_BIN') || '/usr/local/bin/sing-box';
let repo_root = getenv('NIMBUS_REPO_ROOT') || '/work';
let fixtures_dir = repo_root + '/tests/fixtures';
let tmp_root = getenv('TMPDIR') || '/tmp';
let work_dir = sprintf('%s/cb_test_%d', tmp_root, time());
check(common.ensure_dir(work_dir, 0755), 'create work_dir');

let check_dir = work_dir + '/nimbus-check-dir';

// Record fixture SHA256 before tests to ensure read-only preservation
let fixture_names = [
	'v111_legacy.json',
	'v114_modern.json',
	'user_custom_inbounds.json',
	'tun_conflict.json',
	'dual_api_v115.json'
];
let fixture_hashes = {};
for (let name in fixture_names) {
	let p = fixtures_dir + '/' + name;
	fixture_hashes[name] = common.sha256_file(p);
	check(fixture_hashes[name] != null, 'fixture exists: ' + name);
}

// 1. probe_core_version
let ver_res = cb.probe_core_version(singbox_bin);
check(ver_res.ok === true && match(ver_res.version, /^[0-9]+\.[0-9]+\.[0-9]+$/) != null,
	'probe_core_version extracts semver');
let missing_ver = cb.probe_core_version('/nonexistent/sing-box');
check(missing_ver.ok === false && missing_ver.code == common.ERR_NOT_FOUND,
	'probe_core_version rejects missing binary');

// 2. Fixture 1: v111_legacy.json (fails raw check, passes after transform)
let legacy_path = fixtures_dir + '/v111_legacy.json';
let raw_legacy_chk = cb.run_singbox_check(singbox_bin, legacy_path, check_dir);
check(raw_legacy_chk.ok === false, 'raw v111_legacy.json fails sing-box 1.14.4 check due to deprecated inbound fields');
check(fs.stat(check_dir) == null, 'run_singbox_check cleans check_dir even on failure');

let out_legacy = work_dir + '/out_legacy/config.json';
let res_legacy = cb.build_config({
	uci: make_uci(),
	profile_path: legacy_path,
	bin_path: singbox_bin,
	output_path: out_legacy,
	check_dir: check_dir
});
check(res_legacy.ok === true, 'v111_legacy builds and passes sing-box check');
check(fs.stat(check_dir) == null, 'build_config cleans check_dir after success');
let st_legacy = fs.stat(out_legacy);
check(st_legacy != null && (st_legacy.mode & 0777) == 0600, 'output config.json has 0600 permissions');
let leg_cfg = res_legacy.config;
check(leg_cfg.log.disabled === false && leg_cfg.log.level == 'warn' &&
	leg_cfg.log.output == '/var/log/nimbus.log' && leg_cfg.log.timestamp === true,
	'log overridden cleanly with /var/log/nimbus.log');
check(leg_cfg.route.default_mark == 255 && res_legacy.context.effective_outbound_mark == 255,
	'default_mark injected as 255 (0xff)');
check(leg_cfg.route.final == 'direct', 'route.final defaults to first outbound tag');
let mixed_in = null;
let redir_in = null;
let tp_in = null;
for (let inb in leg_cfg.inbounds) {
	if (inb.tag == 'mixed-in') mixed_in = inb;
	if (inb.tag == common.TAG_REDIRECT_IN) redir_in = inb;
	if (inb.tag == common.TAG_TPROXY_IN) tp_in = inb;
}
check(mixed_in != null && !exists(mixed_in, 'sniff') && !exists(mixed_in, 'sniff_override_destination') &&
	!exists(mixed_in, 'sniff_timeout') && !exists(mixed_in, 'domain_strategy'),
	'deprecated inbound fields stripped from mixed-in');
check(redir_in != null && redir_in.listen == '::' && redir_in.listen_port == 7891 && !exists(redir_in, 'sniff'),
	'auto-filled redirect inbound without deprecated sniff');
check(tp_in != null && tp_in.listen == '::' && tp_in.listen_port == 7892 && tp_in.network == 'udp' && !exists(tp_in, 'sniff'),
	'auto-filled UDP tproxy inbound without deprecated sniff');
check(res_legacy.context.inbound_sources.redirect == 'auto' && res_legacy.context.inbound_sources.tproxy == 'auto',
	'inbound_sources tracks auto injection');
check(leg_cfg.route.rules[0].action == 'sniff' &&
	index(leg_cfg.route.rules[0].inbound, common.TAG_REDIRECT_IN) >= 0 &&
	index(leg_cfg.route.rules[0].inbound, common.TAG_TPROXY_IN) >= 0 &&
	index(leg_cfg.route.rules[0].inbound, 'mixed-in') >= 0,
	'sniff rule injected for auto inbounds and migrated mixed-in');

// 3. Fixture 2: v114_modern.json with dns.mode='singbox', block_quic='1', fakeip extraction
let out_modern = work_dir + '/out_modern/config.json';
let res_modern = cb.build_config({
	uci: make_uci({ dns_mode: 'singbox', block_quic: '1', log_level: 'info' }),
	profile_path: fixtures_dir + '/v114_modern.json',
	bin_path: singbox_bin,
	output_path: out_modern,
	check_dir: check_dir
});
check(res_modern.ok === true, 'v114_modern with dns.mode=singbox + block_quic=1 passes sing-box check');
check(res_modern.context.effective_dns_port == 5353, 'effective_dns_port is 5353');
check(length(res_modern.context.fakeip.ipv4) == 1 && res_modern.context.fakeip.ipv4[0] == '198.18.0.0/15',
	'extracts fakeip IPv4 range');
check(length(res_modern.context.fakeip.ipv6) == 1 && res_modern.context.fakeip.ipv6[0] == 'fc00::/18',
	'extracts fakeip IPv6 range');
let dns_inb = null;
for (let inb in res_modern.config.inbounds) {
	if (inb.tag == common.TAG_DNS_IN)
		dns_inb = inb;
}
check(dns_inb != null && dns_inb.type == 'direct' && dns_inb.listen == '127.0.0.1' && dns_inb.listen_port == 5353,
	'injected IPv4 loopback direct DNS inbound');
check(res_modern.config.route.rules[0].action == 'hijack-dns' &&
	res_modern.config.route.rules[0].inbound[0] == common.TAG_DNS_IN,
	'prepended hijack-dns rule at index 0');
check(res_modern.config.route.rules[1].action == 'sniff',
	'inserted sniff rule right after hijack-dns');
check(res_modern.config.route.rules[2].protocol == 'quic' && res_modern.config.route.rules[2].action == 'reject',
	'inserted quic reject rule right after sniff');

// 4. Fixture 3: user_custom_inbounds.json (reuse custom redirect/tproxy/dns + keep mixed + block_quic)
let out_custom = work_dir + '/out_custom/config.json';
let res_custom = cb.build_config({
	uci: make_uci({ dns_mode: 'singbox', block_quic: '1' }),
	profile_path: fixtures_dir + '/user_custom_inbounds.json',
	bin_path: singbox_bin,
	output_path: out_custom,
	check_dir: check_dir
});
check(res_custom.ok === true, 'user_custom_inbounds passes sing-box check');
check(res_custom.context.effective_redirect_port == 17891 && res_custom.context.inbound_sources.redirect == 'user',
	'reuses custom redirect port 17891');
check(res_custom.context.effective_tproxy_port == 17892 && res_custom.context.inbound_sources.tproxy == 'user',
	'reuses custom tproxy port 17892');
check(res_custom.context.effective_dns_port == 15353, 'reuses custom direct DNS inbound port 15353');
check(res_custom.context.effective_outbound_mark == 510 && res_custom.config.route.default_mark == 510,
	'preserves custom route.default_mark 510');
check(res_custom.config.route.final == 'proxy', 'preserves explicit route.final');
check(length(res_custom.config.inbounds) == 4, 'does not inject extra inbounds when user inbounds satisfy requirements');
check(res_custom.config.route.rules[0].action == 'hijack-dns', 'existing hijack-dns remains first');
check(res_custom.config.route.rules[1].action == 'sniff' &&
	index(res_custom.config.route.rules[1].inbound, 'user-redir') >= 0 &&
	index(res_custom.config.route.rules[1].inbound, 'user-tproxy') >= 0,
	'injects sniff rule for user redirect/tproxy when block_quic=1');
check(res_custom.config.route.rules[2].protocol == 'quic' && res_custom.config.route.rules[2].action == 'reject',
	'injects quic reject after sniff when block_quic=1');

// 5. Fixture 4: tun_conflict.json (strip tun, keep socks, recursive logical remapping in route.rules & dns.rules)
let out_tun = work_dir + '/out_tun/config.json';
let res_tun = cb.build_config({
	uci: make_uci(),
	profile_path: fixtures_dir + '/tun_conflict.json',
	bin_path: singbox_bin,
	output_path: out_tun,
	check_dir: check_dir
});
check(res_tun.ok === true, 'tun_conflict transformed config passes sing-box check');
let has_tun = false;
let has_socks = false;
for (let inb in res_tun.config.inbounds) {
	if (inb.type == 'tun') has_tun = true;
	if (inb.tag == 'socks-in') has_socks = true;
}
check(!has_tun && has_socks, 'tun inbound stripped while socks-in kept untouched');
let rr = res_tun.config.route.rules;
check(rr[0].action == 'sniff' && length(rr[0].inbound) == 2 &&
	rr[0].inbound[0] == common.TAG_REDIRECT_IN && rr[0].inbound[1] == common.TAG_TPROXY_IN,
	'remapped string inbound tun-in in top-level sniff rule without duplicating sniff');
check(length(rr) == 2, 'no duplicate sniff rule inserted when remapped rule already covers both');
let logical_r = rr[1];
check(logical_r.type == 'logical' &&
	length(logical_r.rules[0].inbound) == 3 &&
	logical_r.rules[0].inbound[0] == common.TAG_REDIRECT_IN &&
	logical_r.rules[0].inbound[1] == common.TAG_TPROXY_IN &&
	logical_r.rules[0].inbound[2] == 'socks-in',
	'remapped tun-in inside nested logical route rule preserving socks-in');
check(logical_r.rules[1].rules[0].inbound[0] == common.TAG_REDIRECT_IN &&
	logical_r.rules[1].rules[0].inbound[1] == common.TAG_TPROXY_IN,
	'remapped tun-in inside doubly-nested logical route rule');
let dr = res_tun.config.dns.rules[0];
check(dr.type == 'logical' &&
	length(dr.rules[0].inbound) == 2 &&
	dr.rules[0].inbound[0] == common.TAG_REDIRECT_IN &&
	dr.rules[0].inbound[1] == common.TAG_TPROXY_IN,
	'remapped tun-in inside nested logical dns.rules');

// 6. Fixture 5: dual_api_v115.json (services api + experimental.clash_api + secret isolation)
let out_api = work_dir + '/out_api/config.json';
let res_api = cb.build_config({
	uci: make_uci(),
	profile_path: fixtures_dir + '/dual_api_v115.json',
	bin_path: singbox_bin,
	output_path: out_api,
	check_dir: check_dir
});
check(res_api.ok === true, 'dual_api_v115 passes sing-box check');
let sb_api = res_api.context.apis.singbox_api;
let cl_api = res_api.context.apis.clash_api;
check(sb_api.detected === true && sb_api.scheme == 'http' && sb_api.listen == '::' &&
	sb_api.port == 9091 && sb_api.has_secret === true && sb_api.dashboard_enabled === true &&
	sb_api.dashboard_path == '/dashboard/' && sb_api.loopback_only === false && sb_api.no_secret === false &&
	!exists(sb_api, 'secret'),
	'singbox_api metadata probed accurately without exposing plaintext secret in context');
check(cl_api.detected === true && cl_api.listen == '0.0.0.0' && cl_api.port == 9090 &&
	cl_api.has_secret === true && cl_api.external_ui === true &&
	cl_api.loopback_only === false && cl_api.no_secret === false && !exists(cl_api, 'secret'),
	'clash_api metadata probed accurately without exposing plaintext secret in context');

let secrets = cb.extract_api_secrets(res_api.config);
check(secrets.singbox_api_secret == 'sb-secret-115' && secrets.clash_api_secret == 'clash-secret-115',
	'extract_api_secrets recovers secrets from runtime config');

let state_path = work_dir + '/state.json';
check(common.write_state({ state: 'running', apis: res_api.context.apis }, state_path), 'write_state succeeds');
let state_disk = fs.readfile(state_path);
check(index(state_disk, 'sb-secret-115') < 0 && index(state_disk, 'clash-secret-115') < 0,
	'state.json contains zero plaintext API secrets');

// 7. Rejection: route.default_mark == proxy_mark (int and hex string)
let dm_int_res = cb.transform_config({
	outbounds: [ { type: 'direct', tag: 'direct' } ],
	route: { default_mark: 1 }
}, make_uci({ proxy_mark: '0x1' }));
check(dm_int_res.ok === false && dm_int_res.code == common.ERR_VALIDATE_FAILED,
	'rejects integer route.default_mark == proxy_mark');

let dm_hex_res = cb.transform_config({
	outbounds: [ { type: 'direct', tag: 'direct' } ],
	route: { default_mark: '0x01' }
}, make_uci({ proxy_mark: '0x1' }));
check(dm_hex_res.ok === false && dm_hex_res.code == common.ERR_VALIDATE_FAILED,
	'rejects hex string route.default_mark == proxy_mark');

let uci_mark_coll = cb.transform_config({
	outbounds: [ { type: 'direct', tag: 'direct' } ]
}, make_uci({ outbound_mark: '0x5', proxy_mark: '0x5' }));
check(uci_mark_coll.ok === false && uci_mark_coll.code == common.ERR_VALIDATE_FAILED,
	'rejects equal UCI outbound_mark and proxy_mark');

// 8. DNS loop protection & local DNS auto-adaptation when dns.mode == 'singbox'
let local_dns_cfg = {
	dns: {
		servers: [
			{ type: 'local', tag: 'dns-local', prefer_go: true, detour: 'direct' },
			{ type: 'udp', tag: 'dns-remote', server: '8.8.8.8' }
		]
	},
	outbounds: [ { type: 'direct', tag: 'direct' } ]
};
let local_dns_err = cb.transform_config(local_dns_cfg, make_uci({
	dns_mode: 'singbox',
	local_dns_policy: 'reject'
}));
check(local_dns_err.ok === false && local_dns_err.code == common.ERR_VALIDATE_FAILED &&
	length(local_dns_err.warnings) > 0 && index(local_dns_err.error, 'local') >= 0,
	'dns.mode=singbox + local_dns_policy=reject rejects type=local DNS server');

let fake_resolv = work_dir + '/resolv.conf.auto';
common.atomic_write(fake_resolv, '# comment\nnameserver 127.0.0.1\nnameserver ::1\nnameserver 10.11.1.1\nnameserver 223.6.6.6\n', 0644);
let fake_dump_main = {
	interface: [
		{ interface: 'lan', up: true, 'ipv4-address': [ { address: '10.11.1.1', mask: 24 } ] },
		{ interface: 'wan', up: true, 'ipv4-address': [ { address: '100.64.1.2', mask: 24 } ], 'dns-server': [ '223.6.6.6' ] }
	]
};
let local_dns_wan = cb.transform_config(local_dns_cfg, make_uci({
	dns_mode: 'singbox',
	local_dns_policy: 'auto'
}), {
	resolv_auto_path: fake_resolv,
	ubus_dump: fake_dump_main,
	skip_ubus: true,
	skip_network_uci: true
});
check(local_dns_wan.ok === true &&
	local_dns_wan.config.dns.servers[0].type == 'udp' &&
	local_dns_wan.config.dns.servers[0].server == '223.6.6.6' &&
	local_dns_wan.config.dns.servers[0].tag == 'dns-local' &&
	local_dns_wan.config.dns.servers[0].detour == 'direct' &&
	!exists(local_dns_wan.config.dns.servers[0], 'prefer_go') &&
	local_dns_wan.context.local_dns_source == 'wan' &&
	local_dns_wan.context.local_dns_server == '223.6.6.6',
	'auto policy skips loopback/own IP and rewrites type=local to detected WAN DNS');

let local_dns_fb = cb.transform_config(local_dns_cfg, make_uci({
	dns_mode: 'singbox',
	local_dns_policy: 'auto',
	local_fallback_server: '119.29.29.29'
}), {
	resolv_auto_path: work_dir + '/nonexistent.auto',
	ubus_dump: { interface: [] },
	skip_ubus: true,
	skip_network_uci: true
});
check(local_dns_fb.ok === true &&
	local_dns_fb.config.dns.servers[0].type == 'udp' &&
	local_dns_fb.config.dns.servers[0].server == '119.29.29.29' &&
	local_dns_fb.context.local_dns_source == 'fallback',
	'auto policy uses configurable local_fallback_server when no WAN DNS is available');

let local_dns_empty_fb = cb.transform_config(local_dns_cfg, make_uci({
	dns_mode: 'singbox',
	local_dns_policy: 'auto',
	local_fallback_server: ''
}), {
	resolv_auto_path: work_dir + '/nonexistent.auto',
	ubus_dump: { interface: [] },
	skip_ubus: true,
	skip_network_uci: true
});
check(local_dns_empty_fb.ok === false && local_dns_empty_fb.code == common.ERR_VALIDATE_FAILED,
	'auto policy fails clearly when WAN DNS is unavailable and local_fallback_server is empty');

let local_dns_force_fb = cb.transform_config(local_dns_cfg, make_uci({
	dns_mode: 'singbox',
	local_dns_policy: 'fallback',
	local_fallback_server: '114.114.114.114'
}), {
	wan_dns_servers: [ '223.6.6.6' ],
	skip_ubus: true,
	skip_network_uci: true
});
check(local_dns_force_fb.ok === true &&
	local_dns_force_fb.config.dns.servers[0].server == '114.114.114.114' &&
	local_dns_force_fb.context.local_dns_source == 'fallback',
	'fallback policy forces configured direct DNS even when WAN DNS exists');

let side_dns_res = cb.transform_config(local_dns_cfg, make_uci({
	topology: 'side',
	dns_mode: 'singbox',
	local_dns_policy: 'auto'
}), {
	wan_dns_servers: [ '10.11.1.1' ],
	ubus_dump: {
		interface: [
			{ interface: 'lan', up: true, 'ipv4-address': [ { address: '10.11.1.2', mask: 24 } ] }
		]
	},
	skip_ubus: true,
	skip_network_uci: true
});
check(side_dns_res.ok === true &&
	side_dns_res.config.dns.servers[0].server == '10.11.1.1' &&
	length(filter(side_dns_res.context.warnings, (w) => index(w, 'side-router mode') >= 0)) > 0,
	'side-router mode emits cross-device loop warning when upstream DNS is inside LAN subnet');

let local_dns_build_chk = cb.build_config({
	uci: make_uci({ dns_mode: 'singbox', local_dns_policy: 'fallback', local_fallback_server: '223.5.5.5' }),
	raw_config: {
		...local_dns_cfg,
		route: { default_domain_resolver: 'dns-remote' }
	},
	bin_path: singbox_bin,
	check_dir: work_dir + '/check_local_dns',
	validate_only: true
});
check(local_dns_build_chk.ok === true, 'rewritten local DNS passes real sing-box check');

let local_dns_none = cb.transform_config(local_dns_cfg, make_uci({ dns_mode: 'none' }));
check(local_dns_none.ok === true && local_dns_none.config.dns.servers[0].type == 'local',
	'dns.mode=none with proxy_local=0 preserves type=local DNS server');

let local_dns_proxy_local = cb.transform_config(local_dns_cfg, make_uci({
	dns_mode: 'none',
	proxy_local: '1',
	local_dns_policy: 'auto'
}), {
	resolv_auto_path: fake_resolv,
	ubus_dump: fake_dump_main,
	skip_ubus: true,
	skip_network_uci: true
});
check(local_dns_proxy_local.ok === true &&
	local_dns_proxy_local.config.dns.servers[0].type == 'udp' &&
	local_dns_proxy_local.config.dns.servers[0].server == '223.6.6.6' &&
	local_dns_proxy_local.context.local_dns_source == 'wan' &&
	local_dns_proxy_local.context.effective_dns_port == null,
	'dns.mode=none + proxy_local=1 rewrites type=local to safe WAN DNS without injecting direct DNS inbound');

let local_dns_proxy_local_reject = cb.transform_config(local_dns_cfg, make_uci({
	dns_mode: 'none',
	proxy_local: '1',
	local_dns_policy: 'reject'
}));
check(local_dns_proxy_local_reject.ok === false && local_dns_proxy_local_reject.code == common.ERR_VALIDATE_FAILED,
	'dns.mode=none + proxy_local=1 + local_dns_policy=reject rejects type=local bootstrap loop');

let no_dns_proxy_local = cb.transform_config({
	outbounds: [ { type: 'direct', tag: 'direct' } ]
}, make_uci({ dns_mode: 'none', proxy_local: '1' }));
check(no_dns_proxy_local.ok === true,
	'dns.mode=none + proxy_local=1 allows pure-IP configs without dns.servers');

let fakeip_zero_prefix = cb.transform_config({
	dns: { servers: [ { type: 'fakeip', tag: 'f', inet4_range: '0.0.0.0/0' } ] },
	outbounds: [ { type: 'direct', tag: 'direct' } ]
}, make_uci());
check(fakeip_zero_prefix.ok === false && fakeip_zero_prefix.code == common.ERR_VALIDATE_FAILED,
	'extract_fakeip rejects /0 Fake-IP range');

let empty_dns_err = cb.transform_config({
	dns: { servers: [] },
	outbounds: [ { type: 'direct', tag: 'direct' } ]
}, make_uci({ dns_mode: 'singbox' }));
check(empty_dns_err.ok === false && empty_dns_err.code == common.ERR_VALIDATE_FAILED,
	'dns.mode=singbox rejects empty dns.servers');

// 9. Loopback listen rewrite, 0.0.0.0 IPv6 warning, ipv6_enable='0', non-UDP tproxy, port collision
let loop_inb_res = cb.transform_config({
	inbounds: [
		{ type: 'redirect', tag: 'r-in', listen: '127.0.0.1', listen_port: 7891 },
		{ type: 'tproxy', tag: 't-in', listen: '0.0.0.0', listen_port: 7892, network: 'udp' }
	],
	outbounds: [ { type: 'direct', tag: 'direct' } ]
}, make_uci({ ipv6_enable: '1' }));
check(loop_inb_res.ok === true, 'loopback/0.0.0.0 transform succeeds');
check(loop_inb_res.config.inbounds[0].listen == '::', 'rewrites loopback redirect listen 127.0.0.1 to ::');
check(loop_inb_res.config.inbounds[1].listen == '0.0.0.0', 'preserves explicit 0.0.0.0 listen');
check(length(loop_inb_res.context.warnings) == 2, 'emits warnings for loopback rewrite and 0.0.0.0 with ipv6_enable=1');

let v4_only_res = cb.transform_config({
	outbounds: [ { type: 'direct', tag: 'direct' } ]
}, make_uci({ ipv6_enable: '0' }));
check(v4_only_res.ok === true && v4_only_res.config.inbounds[0].listen == '0.0.0.0' &&
	v4_only_res.config.inbounds[1].listen == '0.0.0.0',
	'auto-injected inbounds use 0.0.0.0 when ipv6_enable=0');

let tcp_only_tp = cb.transform_config({
	inbounds: [
		{ type: 'tproxy', tag: 'tp-tcp-only', listen: '::', listen_port: 7895, network: 'tcp' }
	],
	outbounds: [ { type: 'direct', tag: 'direct' } ]
}, make_uci());
check(tcp_only_tp.ok === true && tcp_only_tp.context.inbound_sources.tproxy == 'auto' &&
	tcp_only_tp.context.effective_tproxy_port == 7892,
	'ignores TCP-only tproxy inbound and auto-injects UDP tproxy inbound');

let port_coll = cb.transform_config({
	inbounds: [
		{ type: 'mixed', tag: 'mixed-in', listen: '127.0.0.1', listen_port: 7891 }
	],
	outbounds: [ { type: 'direct', tag: 'direct' } ]
}, make_uci({ redirect_port: '7891' }));
check(port_coll.ok === false && port_coll.code == common.ERR_VALIDATE_FAILED,
	'rejects auto-injected redirect_port colliding with existing inbound');

// 10. Dual API variants: dashboard.enabled=false/true/string/bool, TLS, loopback_only, no_secret, clash formats
let api_false = cb.probe_apis({
	services: [ { type: 'api', listen: '127.0.0.1', listen_port: 9091, dashboard: { enabled: false } } ],
	experimental: { clash_api: { external_controller: '[::1]:9090' } }
});
check(api_false.singbox_api.detected === true && api_false.singbox_api.dashboard_enabled === false &&
	api_false.singbox_api.dashboard_path == null && api_false.singbox_api.loopback_only === true &&
	api_false.singbox_api.no_secret === false,
	'services api with dashboard.enabled=false and loopback has dashboard_enabled=false and no_secret=false');
check(api_false.clash_api.detected === true && api_false.clash_api.listen == '::1' &&
	api_false.clash_api.port == 9090 && api_false.clash_api.loopback_only === true &&
	api_false.clash_api.no_secret === false,
	'clash_api parses [::1]:9090 as loopback_only=true');

let api_variants = cb.probe_apis({
	services: [ { type: 'api', listen: '0.0.0.0', listen_port: 9443, tls: { enabled: true }, dashboard: 'dash-dir' } ],
	experimental: { clash_api: { external_controller: ':9095' } }
});
check(api_variants.singbox_api.scheme == 'https' && api_variants.singbox_api.dashboard_enabled === true &&
	api_variants.singbox_api.dashboard_path == '/dashboard/' && api_variants.singbox_api.no_secret === true,
	'services api detects TLS https, string dashboard, and no_secret on non-loopback');
check(api_variants.clash_api.detected === true && api_variants.clash_api.listen == '::' &&
	api_variants.clash_api.port == 9095 && api_variants.clash_api.no_secret === true,
	'clash_api parses :9095 and sets no_secret=true');

let api_bool_dash = cb.probe_apis({
	services: [ { type: 'api', listen_port: 9091, dashboard: true } ]
});
check(api_bool_dash.singbox_api.dashboard_enabled === true && api_bool_dash.singbox_api.listen == '127.0.0.1' &&
	api_bool_dash.singbox_api.loopback_only === true,
	'services api handles dashboard: true and omitted listen defaulting to loopback');

// 11. Empty inbound rule drop during tun remap + cfg.proxy.sniff='1'
let empty_rule_res = cb.transform_config({
	inbounds: [
		{ type: 'tun', tag: 'tun-in' },
		{ type: 'redirect', tag: 'u-redir', listen: '::', listen_port: 7891 },
		{ type: 'tproxy', tag: 'u-tp', listen: '::', listen_port: 7892, network: 'udp' }
	],
	outbounds: [ { type: 'direct', tag: 'direct' } ],
	route: {
		rules: [
			{ inbound: [], outbound: 'direct' },
			{ type: 'logical', mode: 'and', rules: [ { inbound: [] } ], outbound: 'direct' }
		]
	}
}, make_uci({ sniff: '1' }));
check(empty_rule_res.ok === true && length(empty_rule_res.config.route.rules) == 1 &&
	empty_rule_res.config.route.rules[0].action == 'sniff',
	'drops empty-inbound rules during tun remap and injects sniff when proxy.sniff=1');

// 12. validate_only=true leaves no output file and cleans temp files
let val_out = work_dir + '/should_not_exist.json';
let val_res = cb.build_config({
	uci: make_uci(),
	profile_path: fixtures_dir + '/v114_modern.json',
	bin_path: singbox_bin,
	output_path: val_out,
	check_dir: check_dir,
	validate_only: true
});
check(val_res.ok === true && fs.stat(val_out) == null && fs.stat(check_dir) == null,
	'validate_only=true verifies with sing-box check without creating output_path');

// 13. Additional edge cases: immutability, default_mark=0, tproxy loopback, dns port collision, dashboard={}, [::]:9090, atomic non-overwrite
let orig_raw = {
	inbounds: [ { type: 'mixed', tag: 'm', listen: '127.0.0.1', listen_port: 1080, sniff: true } ],
	outbounds: [ { type: 'direct', tag: 'direct' } ],
	route: { default_mark: 0, rules: [] }
};
let imm_res = cb.transform_config(orig_raw, make_uci());
check(imm_res.ok === true && imm_res.config.route.default_mark == 255 &&
	orig_raw.inbounds[0].sniff === true && orig_raw.route.default_mark === 0,
	'transform_config treats default_mark=0 as unset and does not mutate caller object');

let tp_loop_res = cb.transform_config({
	inbounds: [
		{ type: 'redirect', tag: 'r', listen: '::', listen_port: 7891 },
		{ type: 'tproxy', tag: 't', listen: '::1', listen_port: 7892, network: 'udp' }
	],
	outbounds: [ { type: 'direct', tag: 'direct' } ]
}, make_uci());
check(tp_loop_res.ok === true && tp_loop_res.config.inbounds[1].listen == '::' &&
	length(tp_loop_res.context.warnings) == 1,
	'rewrites tproxy loopback listen ::1 to :: with warning');

let dns_coll = cb.transform_config({
	dns: { servers: [ { type: 'udp', tag: 'd', server: '8.8.8.8' } ] },
	inbounds: [ { type: 'mixed', tag: 'm', listen: '127.0.0.1', listen_port: 5353 } ],
	outbounds: [ { type: 'direct', tag: 'direct' } ]
}, make_uci({ dns_mode: 'singbox', singbox_dns_port: '5353' }));
check(dns_coll.ok === false && dns_coll.code == common.ERR_VALIDATE_FAILED,
	'rejects singbox_dns_port colliding with existing inbound');

let api_empty_obj = cb.probe_apis({
	services: [ { type: 'api', listen: '::', listen_port: 9091, dashboard: {} } ],
	experimental: { clash_api: { external_controller: '[::]:9090', secret: 's' } }
});
check(api_empty_obj.singbox_api.dashboard_enabled === false &&
	api_empty_obj.clash_api.listen == '::' && api_empty_obj.clash_api.port == 9090 &&
	api_empty_obj.clash_api.loopback_only === false && api_empty_obj.clash_api.has_secret === true,
	'dashboard object defaults to enabled=false and clash_api parses [::]:9090');

// Atomic non-overwrite when sing-box check fails + active_profile validation errors
let keep_dir = work_dir + '/keep_out';
let keep_path = keep_dir + '/config.json';
check(common.atomic_write(keep_path, '{"sentinel":true}\n', 0600), 'seed existing runtime config');
let bad_sb = cb.build_config({
	uci: make_uci(),
	raw_config: {
		outbounds: [ { type: 'invalid-outbound-type', tag: 'bad' } ]
	},
	bin_path: singbox_bin,
	output_path: keep_path,
	check_dir: check_dir
});
check(bad_sb.ok === false && bad_sb.code == common.ERR_VALIDATE_FAILED &&
	length(bad_sb.error) > 0 && fs.readfile(keep_path) == '{"sentinel":true}\n' &&
	fs.stat(check_dir) == null,
	'failed sing-box check preserves existing config.json and cleans check_dir');
let keep_entries = fs.lsdir(keep_dir);
check(length(keep_entries) == 1 && keep_entries[0] == 'config.json',
	'failed build_config leaves zero temp files in output directory');

let bad_prof_uci = make_uci();
bad_prof_uci.test_prof.filename = '../escape.json';
let bad_prof_res = cb.build_config({
	uci: bad_prof_uci,
	bin_path: singbox_bin,
	skip_check: true,
	core_version: '1.14.4',
	validate_only: true
});
check(bad_prof_res.ok === false && bad_prof_res.code == common.ERR_INVALID_ARG,
	'rejects path traversal in active profile filename');

// 14. Confirm fixtures are untouched byte-for-byte
for (let name in fixture_names) {
	let p = fixtures_dir + '/' + name;
	check(common.sha256_file(p) == fixture_hashes[name], 'fixture untouched: ' + name);
}

printf('test_config_builder.uc: %d assertions passed\n', passed);
