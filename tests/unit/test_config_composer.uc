#!/usr/bin/ucode
'use strict';

import * as fs from 'fs';
import * as uloop from 'uloop';
import * as common from 'common';
import * as cc from 'config_composer';
import * as cb from 'config_builder';
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
let fixtures_dir = repo_root + '/tests/fixtures';
let singbox_bin = getenv('SINGBOX_BIN') || '/usr/local/bin/sing-box';
let tmp_root = getenv('TMPDIR') || '/tmp';
let work_dir = sprintf('%s/cc_test_%d', tmp_root, time());
check(common.ensure_dir(work_dir, 0755), 'create work_dir');

// Record fixture SHA256 before tests to guarantee read-only preservation
let fixture_names = [
	'sub_nodes_a.json',
	'sub_nodes_b.json',
	'v114_modern.json',
	'dual_api_v115.json'
];
let fixture_hashes = {};
for (let name in fixture_names) {
	fixture_hashes[name] = common.sha256_file(fixtures_dir + '/' + name);
	check(fixture_hashes[name] != null, 'fixture exists: ' + name);
}

let check_dir = work_dir + '/check-dir';
let profiles_dir = work_dir + '/profiles';
let composer_file = work_dir + '/composer.json';
check(common.ensure_dir(profiles_dir, 0755), 'create profiles_dir');

function make_composer_uci(mode) {
	return {
		global: {
			enabled: '1',
			config_mode: mode,
			topology: 'main',
			proxy_mode: 'tproxy_redirect',
			fail_open: '0',
			lan_interfaces: [ 'lan' ],
			wan_interfaces: [ 'wan', 'wan6' ],
			ipv4_enable: '1',
			ipv6_enable: '1',
			proxy_local: '0',
			log_level: 'warn',
			active_profile: 'sub_a'
		},
		proxy: {
			redirect_port: '7891',
			tproxy_port: '7892',
			outbound_mark: '0xff',
			proxy_mark: '0x1',
			route_table: '100'
		},
		dns: {
			mode: 'none',
			singbox_dns_port: '5353',
			local_dns_policy: 'auto',
			local_fallback_server: '223.5.5.5'
		},
		core: {
			bin_path: singbox_bin
		},
		sub_a: {
			'.type': 'profile',
			'.name': 'sub_a',
			'.index': 0,
			name: 'Sub A',
			type: 'subscription',
			filename: 'sub_a.json',
			url: 'https://example.com/a.json'
		},
		sub_b: {
			'.type': 'profile',
			'.name': 'sub_b',
			'.index': 1,
			name: 'Sub B',
			type: 'subscription',
			filename: 'sub_b.json',
			url: 'https://example.com/b.json'
		}
	};
}

// 1. deep_clone and RFC 7396 merge_patch
let mp_target = {
	a: { keep: 1, drop: 2, replace: 'old' },
	arr: [ 1, 2 ],
	scalar: { nested: true }
};
let mp_patch = {
	a: { drop: null, missing_drop: null, replace: 'new', added: 3 },
	arr: [ 9 ],
	scalar: 'primitive'
};
let mp_res = cc.merge_patch(mp_target, mp_patch);
check(mp_res.a.keep == 1 && !exists(mp_res.a, 'drop') && !exists(mp_res.a, 'missing_drop') &&
	mp_res.a.replace == 'new' && mp_res.a.added == 3 &&
	length(mp_res.arr) == 1 && mp_res.arr[0] == 9 && mp_res.scalar == 'primitive',
	'merge_patch applies RFC 7396 recursive merge, null deletion, and array replacement');
check(mp_target.a.drop == 2 && length(mp_target.arr) == 2 && type(mp_target.scalar) == 'object',
	'merge_patch does not mutate target');
mp_res.a.added = 999;
check(mp_patch.a.added == 3, 'merge_patch does not alias patch objects');

// 2. create_empty_composer and create_standard_114_preset pass normalize_composer & sing-box 1.14.4 check
let empty_comp = cc.create_empty_composer();
let empty_norm = cc.normalize_composer(empty_comp);
check(empty_norm.ok === true && empty_norm.composer.schema_version == 1,
	'create_empty_composer passes normalize_composer');

let empty_build = cb.build_config({
	uci: make_composer_uci('composer'),
	composer: empty_comp,
	profiles_dir: profiles_dir,
	bin_path: singbox_bin,
	check_dir: check_dir,
	validate_only: true
});
check(empty_build.ok === true && empty_build.context.config_mode == 'composer' &&
	type(empty_build.composed_config) == 'object' &&
	empty_build.context.composer?.initialized === true,
	'create_empty_composer compiles and passes real sing-box 1.14.4 check');

let preset_comp = cc.create_standard_114_preset();
let preset_norm = cc.normalize_composer(preset_comp);
check(preset_norm.ok === true, 'create_standard_114_preset passes normalize_composer');

let preset_build = cb.build_config({
	uci: make_composer_uci('composer'),
	composer: preset_comp,
	profiles_dir: profiles_dir,
	bin_path: singbox_bin,
	check_dir: check_dir,
	validate_only: true
});
check(preset_build.ok === true &&
	preset_build.context.apis?.singbox_api?.detected === true &&
	preset_build.context.apis?.singbox_api?.dashboard_enabled === true &&
	index(preset_build.context.fakeip?.ipv4 || [], '198.18.0.0/15') >= 0 &&
	index(preset_build.context.fakeip?.ipv6 || [], 'fc00::/18') >= 0 &&
	length(preset_build.context.warnings || []) >= 1,
	'create_standard_114_preset compiles, detects API/Fake-IP, warns on empty Auto fallback, and passes real sing-box 1.14.4 check');
check(length(preset_build.composed_config.inbounds) == 1 &&
	preset_build.composed_config.inbounds[0].tag == 'mixed-in' &&
	length(preset_build.config.inbounds) == 3,
	'composed_config captures Stage A before Stage B injects transparent inbounds');

// 3. compile_regex and normalize_composer validation
check(cc.compile_regex(null, 'test') == null && cc.compile_regex('   ', 'test') == null,
	'compile_regex returns null for null/empty/whitespace pattern');
let re_ok = cc.compile_regex('HK|香港', 'test');
check(type(re_ok) == 'regexp' && match('Relay-香港-01', re_ok) != null && match('relay-hk', re_ok) != null,
	'compile_regex compiles case-insensitive POSIX ERE');
let re_bad = cc.compile_regex('[unclosed', 'sources.sub_a.include_regex');
check(type(re_bad) == 'object' && re_bad.ok === false && re_bad.code == common.ERR_VALIDATE_FAILED,
	'compile_regex returns E_VALIDATE_FAILED on invalid POSIX ERE');

let bad_schema = cc.normalize_composer({ schema_version: 2 });
check(bad_schema.ok === false && bad_schema.code == common.ERR_VALIDATE_FAILED, 'rejects unsupported schema_version');

let bad_ov_type = cc.normalize_composer({ override: [] });
check(bad_ov_type.ok === false && bad_ov_type.code == common.ERR_VALIDATE_FAILED, 'rejects non-object override');

let bad_nov = cc.normalize_composer({ sources: { a: { node_override: 'str' } } });
check(bad_nov.ok === false && bad_nov.code == common.ERR_VALIDATE_FAILED, 'rejects non-object node_override');

let bad_prov_re = cc.normalize_composer({
	outbound_groups: [
		{ enabled: true, type: 'selector', tag: 'Proxy', providers: [ { profile_id: '*', exclude_regex: '(broken' } ] }
	]
});
check(bad_prov_re.ok === false && bad_prov_re.code == common.ERR_VALIDATE_FAILED, 'rejects invalid regex in provider');

let bad_inb_missing = cc.normalize_composer({
	inbounds: [ { enabled: true, type: 'mixed', tag: '' } ]
});
check(bad_inb_missing.ok === false && bad_inb_missing.code == common.ERR_VALIDATE_FAILED, 'rejects enabled inbound missing tag');

let disabled_inb = cc.normalize_composer({
	inbounds: [ { enabled: false, type: '', tag: '' } ]
});
check(disabled_inb.ok === true, 'allows disabled item without type/tag');

let cfg_style_norm = cc.normalize_composer({
	dns: {
		servers: [ { enabled: true, config: { type: 'udp', tag: 'd1', server: '1.1.1.1' } } ],
		rules: [ { enabled: true, config: { domain_suffix: [ 'example.com' ], action: 'route', server: 'd1' } } ]
	},
	route: {
		rules: [ { enabled: true, config: { ip_is_private: true, action: 'route', outbound: 'direct' } } ]
	}
});
check(cfg_style_norm.ok === true &&
	cfg_style_norm.composer.dns.servers[0].type == 'udp' &&
	cfg_style_norm.composer.dns.servers[0].tag == 'd1' &&
	cfg_style_norm.composer.dns.rules[0].action == 'route' &&
	cfg_style_norm.composer.dns.rules[0].server == 'd1' &&
	cfg_style_norm.composer.route.rules[0].action == 'route' &&
	cfg_style_norm.composer.route.rules[0].outbound == 'direct',
	'normalize_composer supports rules without tag and config-nested type/tag/action/server/outbound');

// 4. read_composer & save_composer (0600, SHA256 skip write)
check(cc.read_composer(composer_file) == null, 'read_composer returns null when missing');
let sv1 = cc.save_composer(preset_comp, composer_file);
let st_c1 = fs.stat(composer_file);
check(sv1.ok === true && sv1.changed === true && st_c1 != null && (st_c1.mode & 0777) == 0600,
	'save_composer writes composer.json atomically with 0600 permissions');
let sv2 = cc.save_composer(preset_comp, composer_file);
let st_c2 = fs.stat(composer_file);
check(sv2.ok === true && sv2.changed === false && sv2.sha256 == sv1.sha256 && st_c2.inode == st_c1.inode,
	'save_composer skips disk write when SHA256 is unchanged');
let read_back = cc.read_composer(composer_file);
check(type(read_back) == 'object' && length(read_back.outbound_groups) == 2,
	'read_composer returns normalized composer object');

// 5. extract_source_nodes: array/object, exclude_types, regex, strip_fields, node_override, tag_prefix, detour remap, deduplication
let sub_a_doc = {
	outbounds: [
		{ type: 'selector', tag: 'Auto', outbounds: [ 'HK-01' ] },
		{ type: 'direct', tag: 'direct' },
		{ type: 'shadowsocks', tag: 'HK-01', server: '198.51.100.10', server_port: 8388, method: 'aes-128-gcm', password: 'p1', domain_resolver: 'dns-old', routing_mark: 123 },
		{ type: 'vless', tag: 'Relay-US', server: '198.51.100.11', server_port: 443, uuid: '11111111-1111-1111-1111-111111111111', detour: 'HK-01' },
		{ type: 'trojan', tag: 'Expired-01', server: '198.51.100.12', server_port: 443, password: 'p2' }
	]
};
let sub_b_doc = [
	{ type: 'shadowsocks', tag: 'HK-01', server: '198.51.100.20', server_port: 8388, method: 'aes-128-gcm', password: 'p3' },
	{ type: 'anytls', tag: 'JP-01', server: '198.51.100.21', server_port: 443, password: 'p4', tls: { enabled: true, server_name: 'jp.example.com' } }
];

let shared_tags = { Proxy: true, direct: true };
let ext_a = cc.extract_source_nodes(sub_a_doc, {
	tag_prefix: '[A] ',
	include_regex: 'HK|Relay|Expired',
	exclude_regex: 'Expired',
	node_override: { udp_fragment: true, routing_mark: null }
}, shared_tags);
check(ext_a.ok === true && length(ext_a.nodes) == 2 && ext_a.total_raw == 5 && ext_a.filtered_out == 3,
	'extract_source_nodes filters exclude_types and include/exclude regex against original_tag');
check(ext_a.nodes[0].tag == '[A] HK-01' && !exists(ext_a.nodes[0], 'domain_resolver') &&
	!exists(ext_a.nodes[0], 'routing_mark') && ext_a.nodes[0].udp_fragment === true,
	'extract_source_nodes strips DEFAULT_STRIP_FIELDS and applies node_override');
check(ext_a.nodes[1].tag == '[A] Relay-US' && ext_a.nodes[1].detour == '[A] HK-01',
	'extract_source_nodes remaps intra-source chained detour to final tag');

let ext_b = cc.extract_source_nodes(sub_b_doc, { tag_prefix: '[A] ' }, shared_tags);
check(ext_b.ok === true && length(ext_b.nodes) == 2 &&
	ext_b.nodes[0].tag == '[A] HK-01 #2' && ext_b.nodes[1].type == 'anytls' &&
	length(ext_b.warnings) == 1,
	'extract_source_nodes deduplicates colliding tags across sources with warning and keeps unknown protocol types');

let ext_bad = cc.extract_source_nodes({ not_outbounds: [] }, {}, {});
check(ext_bad.ok === false && ext_bad.code == common.ERR_VALIDATE_FAILED,
	'extract_source_nodes rejects invalid source document structure');

// 6. Full Stage A compose + Stage B build_config + real sing-box 1.14.4 check
check(common.write_json_atomic(profiles_dir + '/sub_a.json', sub_a_doc, 0644), 'write sub_a.json');
check(common.write_json_atomic(profiles_dir + '/sub_b.json', sub_b_doc, 0644), 'write sub_b.json');

let custom_comp = cc.create_standard_114_preset();
custom_comp.sources = {
	sub_a: { enabled: true, tag_prefix: '[A] ', include_regex: '', exclude_regex: 'Expired' },
	sub_b: { enabled: true, tag_prefix: '[B] ', include_regex: '', exclude_regex: '' },
	missing_sub: { enabled: true, tag_prefix: '', include_regex: '', exclude_regex: '' }
};
custom_comp.outbound_groups = [
	{
		id: 'grp_proxy',
		enabled: true,
		type: 'selector',
		tag: 'Proxy',
		remark: '',
		outbounds: [ 'Auto', 'HK-Only', 'direct' ],
		providers: [ { profile_id: '*', include_regex: '', exclude_regex: '' } ],
		fallback_outbound: 'direct',
		config: { default: 'NonExistentDefault' }
	},
	{
		id: 'grp_hk',
		enabled: true,
		type: 'urltest',
		tag: 'HK-Only',
		remark: '',
		outbounds: [],
		providers: [ { profile_id: 'sub_a', include_regex: '\\[A\\] HK', exclude_regex: '' } ],
		fallback_outbound: 'direct',
		config: {}
	},
	{
		id: 'grp_auto',
		enabled: true,
		type: 'urltest',
		tag: 'Auto',
		remark: '',
		outbounds: [],
		providers: [ { profile_id: '*', include_regex: '', exclude_regex: '' } ],
		fallback_outbound: 'direct',
		config: { url: 'https://www.gstatic.com/generate_204', interval: '5m', tolerance: 50 }
	}
];
custom_comp.rule_sets = [
	{
		id: 'rs_inline',
		enabled: true,
		type: 'inline',
		tag: 'inline-cn',
		format: 'source',
		remark: '',
		config: { rules: [ { domain_suffix: [ '.cn' ] } ] }
	}
];
custom_comp.dns.rules = [
	{ id: 'dr_cn', enabled: true, remark: '', action: 'route', server: 'dns-cn', config: { rule_set: [ 'inline-cn' ] } },
	{ id: 'dr_fake', enabled: true, remark: '', action: 'route', server: 'dns-fakeip', config: { query_type: [ 'A', 'AAAA' ] } }
];
custom_comp.route.rules = [
	{ id: 'rr_sniff', enabled: true, remark: '', action: 'sniff', outbound: '', config: {} },
	{ id: 'rr_dns', enabled: true, remark: '', action: 'hijack-dns', outbound: '', config: { protocol: 'dns' } },
	{ id: 'rr_priv', enabled: true, remark: '', action: 'route', outbound: 'direct', config: { ip_is_private: true } },
	{ id: 'rr_cn', enabled: true, remark: '', action: 'route', outbound: 'direct', config: { rule_set: [ 'inline-cn' ] } }
];
custom_comp.override = {
	services: [
		{ type: 'api', tag: 'api', listen: '::', listen_port: 9091, dashboard: true }
	],
	experimental: {
		cache_file: { enabled: true, store_fakeip: true },
		clash_api: null
	}
};

check(cc.save_composer(custom_comp, composer_file).ok === true, 'save custom_comp');
let uci_unset_mode = make_composer_uci(null);
delete uci_unset_mode.global.config_mode;

let full_build = cb.build_config({
	uci: uci_unset_mode,
	composer_file: composer_file,
	profiles_dir: profiles_dir,
	bin_path: singbox_bin,
	check_dir: check_dir,
	validate_only: true
});
check(full_build.ok === true && full_build.context.config_mode == 'composer',
	'unset global.config_mode defaults to composer and passes real sing-box 1.14.4 check');
let outb_list = full_build.composed_config.outbounds;
check(outb_list[0].tag == 'Proxy' && !exists(outb_list[0], 'default') &&
	outb_list[1].tag == 'HK-Only' && length(outb_list[1].outbounds) == 1 && outb_list[1].outbounds[0] == '[A] HK-01' &&
	outb_list[2].tag == 'Auto' && length(outb_list[2].outbounds) == 4 &&
	outb_list[3].tag == 'direct' && outb_list[4].tag == '[A] HK-01' && outb_list[6].tag == '[B] HK-01',
	'outbounds ordered [groups, manual, ordered sources], provider filters final tags, and invalid selector.default pruned');
check(!exists(full_build.composed_config.route.rule_set[0], 'format'),
	'inline rule_set omits format field');
check(length(filter(full_build.context.warnings, (w) => index(w, 'NonExistentDefault') >= 0)) == 1 &&
	length(filter(full_build.context.warnings, (w) => index(w, 'missing UCI profile section') >= 0)) == 1,
	'compose emits warnings for pruned selector default and missing UCI profile section');

// Empty group with empty fallback_outbound fails
let empty_fb_comp = cc.deep_clone(custom_comp);
empty_fb_comp.outbound_groups[1].providers = [ { profile_id: 'sub_a', include_regex: '^NO_SUCH_NODE$', exclude_regex: '' } ];
empty_fb_comp.outbound_groups[1].fallback_outbound = '';
let empty_fb_res = cc.compose(uci_unset_mode, { composer: empty_fb_comp, profiles_dir: profiles_dir });
check(empty_fb_res.ok === false && empty_fb_res.code == common.ERR_VALIDATE_FAILED,
	'compose rejects empty group when fallback_outbound is empty');

// Missing composer.json returns ERR_NOT_FOUND
let missing_comp_res = cc.compose(uci_unset_mode, { composer_file: work_dir + '/nonexistent.json' });
check(missing_comp_res.ok === false && missing_comp_res.code == common.ERR_NOT_FOUND,
	'compose returns ERR_NOT_FOUND when composer.json is missing');

// 7. query_nodes & summarize_composer & import_from_singbox
let q_all = cc.query_nodes(uci_unset_mode, { composer_file: composer_file, profiles_dir: profiles_dir });
check(q_all.ok === true && length(q_all.nodes) == 4 && q_all.per_source_counts.sub_a == 2 && q_all.per_source_counts.sub_b == 2,
	'query_nodes returns extracted nodes across all enabled sources');
let q_filt = cc.query_nodes(uci_unset_mode, {
	composer_file: composer_file,
	profiles_dir: profiles_dir,
	profile_id: 'sub_b',
	include_regex: 'JP'
});
check(q_filt.ok === true && length(q_filt.nodes) == 1 && q_filt.nodes[0].tag == '[B] JP-01',
	'query_nodes filters by profile_id and include_regex');
let q_missing = cc.query_nodes(uci_unset_mode, { composer_file: composer_file, profile_id: 'nope' });
check(q_missing.ok === false && q_missing.code == common.ERR_NOT_FOUND, 'query_nodes rejects unknown profile_id');

let sum_uninit = cc.summarize_composer(uci_unset_mode, { composer_file: work_dir + '/nonexistent.json' });
check(sum_uninit.initialized === false && sum_uninit.groups == 0 && sum_uninit.extracted_nodes == 0,
	'summarize_composer returns initialized=false with zero counts when uninitialized');
let sum_init = cc.summarize_composer(uci_unset_mode, { composer_file: composer_file, profiles_dir: profiles_dir });
check(sum_init.initialized === true && sum_init.enabled_sources == 2 && sum_init.extracted_nodes == 4 &&
	sum_init.groups == 3 && sum_init.manual_outbounds == 1 && sum_init.rule_sets == 1,
	'summarize_composer returns accurate summary counts');

let imp_res = cc.import_from_singbox(full_build.config);
check(imp_res.ok === true &&
	length(imp_res.composer.inbounds) == 1 &&
	length(imp_res.composer.outbound_groups) == 3 &&
	length(imp_res.composer.outbounds) == 5 &&
	!exists(imp_res.composer.override, 'log') &&
	length(imp_res.composer.override.services || []) == 1 &&
	length(filter(imp_res.warnings, (w) => index(w, 'nimbus-redirect-in') >= 0)) == 1,
	'import_from_singbox excludes auto-injected inbounds and log, splits groups/outbounds, and preserves override');

// 8. profile_updater composer mode (array & object, unused vs enabled source, bad protocol rejection)
let pu_conf_dir = work_dir + '/pu_conf';
let pu_prof_dir = work_dir + '/pu_profs';
let pu_state = work_dir + '/pu_state.json';
let pu_comp_file = work_dir + '/pu_composer.json';
common.ensure_dir(pu_conf_dir, 0755);
common.ensure_dir(pu_prof_dir, 0755);
common.atomic_write(pu_conf_dir + '/nimbus',
	"config main 'global'\n" +
	"\toption enabled '1'\n" +
	"\toption config_mode 'composer'\n" +
	"\toption active_profile ''\n\n" +
	"config proxy 'proxy'\n" +
	"\toption redirect_port '7891'\n" +
	"\toption tproxy_port '7892'\n" +
	"\toption outbound_mark '0xff'\n" +
	"\toption proxy_mark '0x1'\n\n" +
	"config profile 'sub_used'\n" +
	"\toption name 'Used Sub'\n" +
	"\toption type 'subscription'\n" +
	"\toption filename 'sub_used.json'\n" +
	"\toption url 'https://example.com/used.json'\n\n" +
	"config profile 'sub_unused'\n" +
	"\toption name 'Unused Sub'\n" +
	"\toption type 'subscription'\n" +
	"\toption filename 'sub_unused.json'\n" +
	"\toption url 'https://example.com/unused.json'\n",
	0644);
common.write_state({ state: 'running', warnings: [], last_error: null }, pu_state);

let pu_comp = cc.create_standard_114_preset();
pu_comp.sources = {
	sub_used: { enabled: true, tag_prefix: '[U] ', include_regex: '', exclude_regex: '' },
	sub_unused: { enabled: false, tag_prefix: '', include_regex: '', exclude_regex: '' }
};
pu_comp.rule_sets = [];
pu_comp.dns.rules = [ { id: 'dr_f', enabled: true, remark: '', action: 'route', server: 'dns-fakeip', config: { query_type: [ 'A', 'AAAA' ] } } ];
pu_comp.route.rules = [ { id: 'rr_p', enabled: true, remark: '', action: 'route', outbound: 'direct', config: { ip_is_private: true } } ];
check(cc.save_composer(pu_comp, pu_comp_file).ok === true, 'save pu_composer.json');

let pu_reloads = 0;
let pu_opts = {
	uci_confdir: pu_conf_dir,
	profiles_dir: pu_prof_dir,
	composer_file: pu_comp_file,
	state_file: pu_state,
	bin_path: singbox_bin,
	check_dir: check_dir,
	on_reload: () => {
		pu_reloads++;
		return true;
	}
};

// Valid bare array for enabled source -> passes sing-box check, saves, reloads!
let valid_arr_json = sprintf('%.2J\n', sub_b_doc);
let pu_res_used = pu.update_profiles('sub_used', {
	...pu_opts,
	runner: (argv) => {
		common.atomic_write(argv[index(argv, '-o') + 1], valid_arr_json, 0600);
		return 0;
	}
});
check(pu_res_used.ok === true && pu_res_used.reloaded === true && pu_reloads == 1 &&
	fs.readfile(pu_prof_dir + '/sub_used.json') == valid_arr_json,
	'composer mode profile_updater accepts bare outbound array, passes sing-box check, and reloads running service');

// Broken protocol for enabled source -> rejected without touching existing file!
let pu_res_bad = pu.update_profiles('sub_used', {
	...pu_opts,
	runner: (argv) => {
		common.atomic_write(argv[index(argv, '-o') + 1], '[{"type":"no_such_proto","tag":"bad"}]', 0600);
		return 0;
	}
});
check(pu_res_bad.ok === false && pu_res_bad.reloaded === false &&
	fs.readfile(pu_prof_dir + '/sub_used.json') == valid_arr_json,
	'composer mode profile_updater rejects invalid outbound protocol via sing-box check without overwriting');

// Unused source saves valid array without triggering reload, and rejects empty array
let pu_res_unused_empty = pu.update_profiles('sub_unused', {
	...pu_opts,
	runner: (argv) => {
		common.atomic_write(argv[index(argv, '-o') + 1], '[]', 0600);
		return 0;
	}
});
check(pu_res_unused_empty.ok === false, 'composer mode profile_updater rejects empty array []');

let pu_res_unused_ok = pu.update_profiles('sub_unused', {
	...pu_opts,
	runner: (argv) => {
		common.atomic_write(argv[index(argv, '-o') + 1], valid_arr_json, 0600);
		return 0;
	}
});
check(pu_res_unused_ok.ok === true && pu_res_unused_ok.reloaded === false && pu_reloads == 1,
	'composer mode profile_updater saves unused subscription without reloading running service');

// 9. supervisor.uc --prepare-start & --prepare-reload in composer mode
let sup_run = work_dir + '/sup_run';
let sup_state = sup_run + '/state.json';
let sup_cfg = sup_run + '/config.json';
let sup_rules = sup_run + '/rules.nft';
let sup_pid = sup_run + '/sing-box.pid';
common.ensure_dir(sup_run, 0755);
common.write_json_atomic(pu_prof_dir + '/sub_used.json', sub_b_doc, 0644);
common.atomic_write(sup_pid, (fs.readlink('/proc/self') || '1') + '\n', 0644);

uloop.init();
let sup_script = repo_root + '/nimbus/files/usr/share/nimbus/supervisor.uc';
let nimbus_lib = repo_root + '/nimbus/files/usr/share/nimbus';
let run_sup = (arg) => {
	let code_out = null;
	uloop.process(
		'/usr/bin/ucode',
		[ '-S', '-L', nimbus_lib, sup_script, arg ],
		{
			PATH: getenv('PATH') || '/usr/sbin:/usr/bin:/sbin:/bin',
			NIMBUS_UCI_CONFDIR: pu_conf_dir,
			NIMBUS_UCI_SAVEDIR: work_dir + '/pu_save',
			NIMBUS_BIN_PATH: singbox_bin,
			NIMBUS_COMPOSER_FILE: pu_comp_file,
			NIMBUS_PROFILES_DIR: pu_prof_dir,
			NIMBUS_WORK_DIR: sup_run,
			NIMBUS_CONFIG_FILE: sup_cfg,
			NIMBUS_STATE_FILE: sup_state,
			NIMBUS_PID_FILE: sup_pid,
			NIMBUS_LOCK_FILE: sup_run + '/nimbus.lock',
			NIMBUS_RULES_FILE: sup_rules,
			NIMBUS_LOG_FILE: sup_run + '/nimbus.log',
			NIMBUS_CHECK_DIR: check_dir,
			NIMBUS_NFT_CHECK_ONLY: '1',
			NIMBUS_SKIP_ROUTES: '1'
		},
		(c) => { code_out = c; uloop.end(); }
	);
	uloop.run();
	return code_out;
};

check(run_sup('--prepare-start') == 0, 'supervisor --prepare-start succeeds in composer mode');
let st_sup = common.read_state(sup_state);
check(st_sup.state == 'running' && st_sup.config_mode == 'composer' &&
	st_sup.composer?.initialized === true && st_sup.composer?.enabled_sources == 1 &&
	st_sup.composer?.extracted_nodes == 2,
	'supervisor writes config_mode=composer and composer summary into state.json');
check(run_sup('--prepare-reload') == 10,
	'supervisor --prepare-reload returns 10 when composed runtime config is unchanged');

// 10. Direct fixture subscription extraction (sub_nodes_a.json & sub_nodes_b.json), info-node filtering, detour remap, deduplication, and services override (api + hysteria-realm)
let fix_doc_a = common.read_json(fixtures_dir + '/sub_nodes_a.json');
let fix_doc_b = common.read_json(fixtures_dir + '/sub_nodes_b.json');
check(type(fix_doc_a) == 'object' && type(fix_doc_a.outbounds) == 'array', 'load sub_nodes_a.json object fixture');
check(type(fix_doc_b) == 'array' && length(fix_doc_b) == 2, 'load sub_nodes_b.json bare array fixture');

let fix_tags = { Proxy: true, Auto: true, direct: true };
let fix_ext_a = cc.extract_source_nodes(fix_doc_a, {
	tag_prefix: '[A] ',
	exclude_regex: '剩余流量'
}, fix_tags);
check(fix_ext_a.ok === true && fix_ext_a.total_raw == 8 && fix_ext_a.filtered_out == 5 &&
	length(fix_ext_a.nodes) == 3,
	'sub_nodes_a extracts 3 proxy nodes and filters built-in groups/types plus info node');
check(fix_ext_a.nodes[0].tag == '[A] HK-01' && fix_ext_a.nodes[0].type == 'vless' &&
	!exists(fix_ext_a.nodes[0], 'domain_resolver') && !exists(fix_ext_a.nodes[0], 'routing_mark'),
	'sub_nodes_a strips dangling domain_resolver and routing_mark from HK-01');
check(fix_ext_a.nodes[1].tag == '[A] JP-01' && fix_ext_a.nodes[1].type == 'hysteria2' &&
	fix_ext_a.nodes[2].tag == '[A] US-Relay' && fix_ext_a.nodes[2].type == 'trojan' &&
	fix_ext_a.nodes[2].detour == '[A] HK-01',
	'sub_nodes_a preserves hysteria2 JP-01 and remaps US-Relay detour to [A] HK-01');
check(length(filter(fix_ext_a.nodes, (n) => index(n.tag, '剩余流量') >= 0)) == 0,
	'sub_nodes_a excludes info node matching 剩余流量');

let fix_ext_b = cc.extract_source_nodes(fix_doc_b, { tag_prefix: '[A] ' }, fix_tags);
check(fix_ext_b.ok === true && length(fix_ext_b.nodes) == 2 &&
	fix_ext_b.nodes[0].tag == '[A] HK-01 #2' && fix_ext_b.nodes[0].type == 'shadowsocks' &&
	fix_ext_b.nodes[1].tag == '[A] SG-01' && fix_ext_b.nodes[1].type == 'anytls' &&
	length(fix_ext_b.warnings) == 1,
	'sub_nodes_b deduplicates colliding HK-01 to [A] HK-01 #2 with warning and keeps anytls SG-01');

let fix_uci = make_composer_uci('composer');
delete fix_uci.sub_a;
delete fix_uci.sub_b;
fix_uci.sub_nodes_a = {
	'.type': 'profile',
	'.name': 'sub_nodes_a',
	'.index': 0,
	name: 'Fixture Sub A',
	type: 'subscription',
	filename: 'sub_nodes_a.json',
	url: 'https://example.com/sub_nodes_a.json'
};
fix_uci.sub_nodes_b = {
	'.type': 'profile',
	'.name': 'sub_nodes_b',
	'.index': 1,
	name: 'Fixture Sub B',
	type: 'subscription',
	filename: 'sub_nodes_b.json',
	url: 'https://example.com/sub_nodes_b.json'
};

let fix_comp = cc.create_standard_114_preset();
fix_comp.sources = {
	sub_nodes_a: { enabled: true, tag_prefix: '[A] ', include_regex: '', exclude_regex: '剩余流量' },
	sub_nodes_b: { enabled: true, tag_prefix: '[A] ', include_regex: '', exclude_regex: '' }
};
fix_comp.rule_sets = [];
fix_comp.dns.rules = [
	{ id: 'dr_fix_fake', enabled: true, remark: '', action: 'route', server: 'dns-fakeip', config: { query_type: [ 'A', 'AAAA' ] } }
];
fix_comp.route.rules = [
	{ id: 'rr_fix_sniff', enabled: true, remark: '', action: 'sniff', outbound: '', config: {} },
	{ id: 'rr_fix_dns', enabled: true, remark: '', action: 'hijack-dns', outbound: '', config: { protocol: 'dns' } },
	{ id: 'rr_fix_priv', enabled: true, remark: '', action: 'route', outbound: 'direct', config: { ip_is_private: true } }
];
fix_comp.override = {
	services: [
		{
			type: 'hysteria-realm',
			tag: 'hy-realm',
			listen: '127.0.0.1',
			listen_port: 9443,
			users: [
				{ name: 'node1', token: 'realm-token-01', max_realms: 4 }
			]
		},
		{
			type: 'api',
			tag: 'api',
			listen: '::',
			listen_port: 9091,
			secret: 'fix-api-secret',
			dashboard: { enabled: true }
		}
	],
	experimental: {
		cache_file: { enabled: true, store_fakeip: true }
	}
};

let fix_out_path = work_dir + '/fix_out/config.json';
let fix_build = cb.build_config({
	uci: fix_uci,
	composer: fix_comp,
	profiles_dir: fixtures_dir,
	output_path: fix_out_path,
	bin_path: singbox_bin,
	check_dir: check_dir
});
let st_fix_out = fs.stat(fix_out_path);
check(fix_build.ok === true && st_fix_out != null && (st_fix_out.mode & 0777) == 0600,
	'direct fixture composer build passes real sing-box 1.14.4 check and writes 0600 config.json');
check(fix_build.context.composer?.enabled_sources == 2 &&
	fix_build.context.composer?.extracted_nodes == 5,
	'direct fixture build loads 5 nodes across sub_nodes_a.json and sub_nodes_b.json');

let fix_outb_map = {};
for (let o in fix_build.composed_config.outbounds)
	fix_outb_map[o.tag] = o;
check(exists(fix_outb_map, '[A] HK-01') &&
	exists(fix_outb_map, '[A] JP-01') &&
	exists(fix_outb_map, '[A] US-Relay') &&
	fix_outb_map['[A] US-Relay'].detour == '[A] HK-01' &&
	exists(fix_outb_map, '[A] HK-01 #2') &&
	fix_outb_map['[A] HK-01 #2'].type == 'shadowsocks' &&
	exists(fix_outb_map, '[A] SG-01') &&
	fix_outb_map['[A] SG-01'].type == 'anytls' &&
	length(filter(fix_build.composed_config.outbounds, (o) => index(o.tag, '剩余流量') >= 0)) == 0,
	'direct fixture compose verifies detour remap, cross-source deduplication, and info-node exclusion');
check(length(filter(fix_build.context.warnings, (w) => index(w, '[A] HK-01 #2') >= 0)) == 1,
	'direct fixture compose emits deduplication warning for colliding HK-01');
check(length(fix_build.composed_config.services || []) == 2 &&
	fix_build.config.services[0].type == 'hysteria-realm' &&
	fix_build.config.services[1].type == 'api' &&
	fix_build.context.apis?.singbox_api?.detected === true &&
	fix_build.context.apis?.singbox_api?.port == 9091 &&
	fix_build.context.apis?.singbox_api?.has_secret === true &&
	fix_build.context.apis?.singbox_api?.dashboard_enabled === true,
	'override services preserves hysteria-realm + api and Stage B detects singbox_api');

let fix_q = cc.query_nodes(fix_uci, { composer: fix_comp, profiles_dir: fixtures_dir });
check(fix_q.ok === true && length(fix_q.nodes) == 5 &&
	fix_q.per_source_counts.sub_nodes_a == 3 && fix_q.per_source_counts.sub_nodes_b == 2,
	'query_nodes reads sub_nodes_a.json and sub_nodes_b.json directly from fixtures_dir');

// 11. Empty-group fallback_outbound: 'direct' recovery with valid sing-box 1.14.4 check
let fb_rec_comp = cc.deep_clone(fix_comp);
push(fb_rec_comp.outbound_groups, {
	id: 'grp_zero',
	enabled: true,
	type: 'urltest',
	tag: 'Zero-Match',
	remark: 'Empty fallback test',
	outbounds: [],
	providers: [ { profile_id: '*', include_regex: '^NO_MATCHING_NODE_XYZ$', exclude_regex: '' } ],
	fallback_outbound: 'direct',
	config: {}
});
let fb_rec_build = cb.build_config({
	uci: fix_uci,
	composer: fb_rec_comp,
	profiles_dir: fixtures_dir,
	bin_path: singbox_bin,
	check_dir: check_dir,
	validate_only: true
});
let zero_grp = filter(fb_rec_build.composed_config?.outbounds || [], (o) => o.tag == 'Zero-Match')[0];
check(fb_rec_build.ok === true &&
	zero_grp != null &&
	length(zero_grp.outbounds) == 1 && zero_grp.outbounds[0] == 'direct' &&
	length(filter(fb_rec_build.context.warnings, (w) => index(w, 'Zero-Match') >= 0 && index(w, 'direct') >= 0)) == 1,
	'empty group recovers via fallback_outbound="direct", emits warning, and passes real sing-box 1.14.4 check');

// 12. import_from_singbox round-trip on v114_modern.json and dual_api_v115.json
let v114_raw = fs.readfile(fixtures_dir + '/v114_modern.json');
let dual_raw_obj = common.read_json(fixtures_dir + '/dual_api_v115.json');
check(type(v114_raw) == 'string' && type(dual_raw_obj) == 'object', 'load v114_modern.json and dual_api_v115.json');

let imp_v114 = cc.import_from_singbox(v114_raw);
check(imp_v114.ok === true &&
	length(imp_v114.composer.outbounds) == 1 &&
	length(imp_v114.composer.dns.servers) == 3 &&
	length(imp_v114.composer.dns.rules) == 2 &&
	length(imp_v114.composer.route.rules) == 1 &&
	imp_v114.composer.route.default_domain_resolver == 'dns-direct',
	'import_from_singbox decomposes v114_modern.json accurately');

let comp_v114 = cc.compose(fix_uci, { composer: imp_v114.composer, profiles_dir: fixtures_dir });
check(comp_v114.ok === true, 'compose succeeds on v114_modern imported draft');
let build_v114 = cb.build_config({
	uci: fix_uci,
	composer: imp_v114.composer,
	profiles_dir: fixtures_dir,
	bin_path: singbox_bin,
	check_dir: check_dir,
	validate_only: true
});
check(build_v114.ok === true &&
	build_v114.context.config_mode == 'composer' &&
	index(build_v114.context.fakeip?.ipv4 || [], '198.18.0.0/15') >= 0 &&
	index(build_v114.context.fakeip?.ipv6 || [], 'fc00::/18') >= 0,
	'v114_modern imported draft passes Stage A compose, Stage B build_config, and real sing-box 1.14.4 check');

let imp_dual = cc.import_from_singbox(dual_raw_obj);
check(imp_dual.ok === true &&
	length(imp_dual.composer.outbounds) == 1 &&
	length(imp_dual.composer.dns.servers) == 2 &&
	length(imp_dual.composer.override?.services || []) == 1 &&
	imp_dual.composer.override.services[0].type == 'api' &&
	imp_dual.composer.override?.experimental?.clash_api?.external_controller == '0.0.0.0:9090',
	'import_from_singbox decomposes dual_api_v115.json services and clash_api into override');

let comp_dual = cc.compose(fix_uci, { composer: imp_dual.composer, profiles_dir: fixtures_dir });
check(comp_dual.ok === true, 'compose succeeds on dual_api_v115 imported draft');
let build_dual = cb.build_config({
	uci: fix_uci,
	composer: imp_dual.composer,
	profiles_dir: fixtures_dir,
	bin_path: singbox_bin,
	check_dir: check_dir,
	validate_only: true
});
check(build_dual.ok === true &&
	build_dual.context.config_mode == 'composer' &&
	build_dual.context.apis?.singbox_api?.detected === true &&
	build_dual.context.apis?.singbox_api?.port == 9091 &&
	build_dual.context.apis?.singbox_api?.has_secret === true &&
	build_dual.context.apis?.singbox_api?.dashboard_enabled === true &&
	build_dual.context.apis?.clash_api?.detected === true &&
	build_dual.context.apis?.clash_api?.port == 9090 &&
	build_dual.context.apis?.clash_api?.has_secret === true &&
	build_dual.context.apis?.clash_api?.external_ui === true &&
	index(build_dual.context.fakeip?.ipv4 || [], '198.18.0.0/15') >= 0,
	'dual_api_v115 imported draft preserves dual APIs, passes Stage A compose + Stage B build_config, and passes real sing-box 1.14.4 check');

// 13. Regression: query_nodes tag consistency for single profile_id (enabled & disabled)
let coll_comp = cc.deep_clone(custom_comp);
coll_comp.sources = {
	sub_a: { enabled: true, tag_prefix: '[A] ', include_regex: '', exclude_regex: 'Expired' },
	sub_b: { enabled: true, tag_prefix: '[A] ', include_regex: '', exclude_regex: '' }
};
let coll_compose = cc.compose(uci_unset_mode, { composer: coll_comp, profiles_dir: profiles_dir });
let coll_q_enabled = cc.query_nodes(uci_unset_mode, {
	composer: coll_comp,
	profiles_dir: profiles_dir,
	profile_id: 'sub_b'
});
check(coll_compose.ok === true && coll_q_enabled.ok === true &&
	length(coll_q_enabled.nodes) == 2 &&
	!exists(coll_q_enabled.per_source_counts, 'sub_a') &&
	coll_q_enabled.per_source_counts.sub_b == 2 &&
	coll_q_enabled.nodes[0].profile_id == 'sub_b' &&
	coll_q_enabled.nodes[0].tag == '[A] HK-01 #2' &&
	coll_q_enabled.nodes[1].tag == '[A] JP-01',
	'query_nodes({ profile_id: "sub_b" }) preserves #2 deduplication against preceding enabled sub_a');

let coll_comp_dis = cc.deep_clone(coll_comp);
coll_comp_dis.sources.sub_b.enabled = false;
let coll_q_disabled = cc.query_nodes(uci_unset_mode, {
	composer: coll_comp_dis,
	profiles_dir: profiles_dir,
	profile_id: 'sub_b'
});
check(coll_q_disabled.ok === true &&
	length(coll_q_disabled.nodes) == 2 &&
	coll_q_disabled.nodes[0].tag == '[A] HK-01 #2',
	'query_nodes({ profile_id: "sub_b" }) reserves tags from enabled sources when sub_b is disabled');

// 14. Regression: import_from_singbox strips auto_tags inbound rules (including logical) & re-composes with dns.mode='none'
let uci_dns_sb = make_composer_uci('composer');
uci_dns_sb.dns.mode = 'singbox';
let uci_dns_none = make_composer_uci('composer');
uci_dns_none.dns.mode = 'none';

let auto_rules_comp = cc.deep_clone(custom_comp);
auto_rules_comp.inbounds = [
	{ id: 'in_mix', enabled: true, type: 'mixed', tag: 'mixed-in', remark: '', config: { listen: '127.0.0.1', listen_port: 17890 } }
];
auto_rules_comp.route.rules = [
	{ id: 'rr_dns', enabled: true, remark: '', action: 'hijack-dns', outbound: '', config: { protocol: 'dns' } },
	{ id: 'rr_priv', enabled: true, remark: '', action: 'route', outbound: 'direct', config: { ip_is_private: true } }
];
let auto_rules_build = cb.build_config({
	uci: uci_dns_sb,
	composer: auto_rules_comp,
	profiles_dir: profiles_dir,
	bin_path: singbox_bin,
	check_dir: check_dir,
	validate_only: true
});
check(auto_rules_build.ok === true, 'build effective config with auto-injected dns & sniff inbound rules');

let imp_auto = cc.import_from_singbox(auto_rules_build.config);
let imp_auto_recompose = cb.build_config({
	uci: uci_dns_none,
	composer: imp_auto.composer,
	profiles_dir: profiles_dir,
	bin_path: singbox_bin,
	check_dir: check_dir,
	validate_only: true
});
check(imp_auto.ok === true &&
	imp_auto_recompose.ok === true &&
	length(filter(imp_auto.warnings, (w) => index(w, 'nimbus-dns-in') >= 0)) >= 2 &&
	length(filter(imp_auto.warnings, (w) => index(w, 'nimbus-redirect-in') >= 0)) >= 2,
	'import_from_singbox strips auto-injected nimbus-dns-in/nimbus-redirect-in rules so re-compose with dns.mode=none passes sing-box check');

let eff_with_mixed = cc.deep_clone(auto_rules_build.config);
push(eff_with_mixed.dns.rules, { inbound: [ 'nimbus-dns-in' ], action: 'route', server: 'dns-direct' });
push(eff_with_mixed.dns.rules, { inbound: [ 'mixed-in', 'nimbus-dns-in' ], domain_suffix: [ 'test.local' ], action: 'route', server: 'dns-direct' });
push(eff_with_mixed.route.rules, { inbound: [ 'mixed-in', 'nimbus-redirect-in' ], action: 'sniff' });
push(eff_with_mixed.route.rules, {
	type: 'logical',
	mode: 'and',
	rules: [
		{ inbound: [ 'nimbus-tproxy-in' ], network: [ 'udp' ] },
		{ domain_suffix: [ 'example.org' ] }
	],
	action: 'route',
	outbound: 'direct'
});
push(eff_with_mixed.route.rules, {
	type: 'logical',
	mode: 'or',
	rules: [
		{ inbound: 'nimbus-dns-in' },
		{ inbound: [ 'nimbus-redirect-in' ] }
	],
	action: 'reject'
});

let imp_stripped = cc.import_from_singbox(eff_with_mixed);
let imp_mixed_rr = filter(imp_stripped.composer.route.rules, (r) => r.action == 'sniff');
let imp_logical_rr = filter(imp_stripped.composer.route.rules, (r) => r.config?.type == 'logical');
let imp_mixed_dr = filter(imp_stripped.composer.dns.rules, (r) => length(r.config?.domain_suffix || []) == 1 && r.config.domain_suffix[0] == 'test.local');
check(imp_stripped.ok === true &&
	length(imp_mixed_rr) == 1 &&
	length(imp_mixed_rr[0].config?.inbound || []) == 1 &&
	imp_mixed_rr[0].config.inbound[0] == 'mixed-in' &&
	length(imp_logical_rr) == 1 &&
	length(imp_logical_rr[0].config?.rules || []) == 1 &&
	imp_logical_rr[0].config.rules[0].domain_suffix[0] == 'example.org' &&
	length(imp_mixed_dr) == 1 &&
	length(imp_mixed_dr[0].config?.inbound || []) == 1 &&
	imp_mixed_dr[0].config.inbound[0] == 'mixed-in' &&
	length(filter(imp_stripped.composer.route.rules, (r) => index(r.config?.inbound || [], 'nimbus-dns-in') >= 0 || index(r.config?.inbound || [], 'nimbus-redirect-in') >= 0)) == 0 &&
	length(filter(imp_stripped.composer.dns.rules, (r) => index(r.config?.inbound || [], 'nimbus-dns-in') >= 0)) == 0,
	'import_from_singbox recursively strips auto_tags from route/dns/logical rules while preserving mixed non-auto inbound rules');

let recompose_none = cb.build_config({
	uci: uci_dns_none,
	composer: imp_stripped.composer,
	profiles_dir: profiles_dir,
	bin_path: singbox_bin,
	check_dir: check_dir,
	validate_only: true
});
check(recompose_none.ok === true,
	're-composing stripped imported draft with dns.mode=none passes real sing-box 1.14.4 check');

// Verify all fixture files remained strictly read-only
for (let name in fixture_names) {
	check(common.sha256_file(fixtures_dir + '/' + name) == fixture_hashes[name],
		'fixture remained read-only: ' + name);
}

printf('test_config_composer.uc: %d assertions passed\n', passed);
