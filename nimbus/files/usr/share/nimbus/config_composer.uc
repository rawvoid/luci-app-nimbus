'use strict';

import * as fs from 'fs';
import * as common from 'common';

const SCHEMA_VERSION = 1;
const DEFAULT_EXCLUDE_TYPES = [ 'selector', 'urltest', 'direct', 'block', 'dns' ];
const DEFAULT_STRIP_FIELDS = [ 'domain_resolver', 'routing_mark' ];

function fail(code, error, extra) {
	return {
		ok: false,
		code: code || common.ERR_VALIDATE_FAILED,
		error: error,
		...(extra || {})
	};
}

function deep_clone(v) {
	if (type(v) == 'array') {
		let arr = [];
		for (let item in v)
			push(arr, deep_clone(item));
		return arr;
	}
	if (type(v) == 'object') {
		let obj = {};
		for (let k, val in v)
			obj[k] = deep_clone(val);
		return obj;
	}
	return v;
}

function merge_patch(target, patch) {
	if (type(patch) != 'object')
		return deep_clone(patch);

	let result = (type(target) == 'object') ? deep_clone(target) : {};
	for (let k, v in patch) {
		if (v === null)
			delete result[k];
		else
			result[k] = merge_patch(result[k], v);
	}
	return result;
}

function create_empty_composer() {
	return {
		schema_version: SCHEMA_VERSION,
		sources: {},
		inbounds: [],
		outbound_groups: [
			{
				id: 'grp_proxy',
				enabled: true,
				type: 'selector',
				tag: 'Proxy',
				remark: 'Main Proxy',
				outbounds: [ 'direct' ],
				providers: [
					{
						profile_id: '*',
						include_regex: '',
						exclude_regex: ''
					}
				],
				fallback_outbound: 'direct',
				config: {}
			}
		],
		outbounds: [
			{
				id: 'out_direct',
				enabled: true,
				type: 'direct',
				tag: 'direct',
				remark: 'Direct',
				config: {}
			}
		],
		dns: {
			final: 'dns-direct',
			strategy: '',
			extra: {},
			servers: [
				{
					id: 'dns_direct',
					enabled: true,
					type: 'udp',
					tag: 'dns-direct',
					remark: 'Direct DNS',
					config: {
						server: '223.5.5.5'
					}
				}
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
		override: {}
	};
}

function create_standard_114_preset() {
	return {
		schema_version: SCHEMA_VERSION,
		sources: {},
		inbounds: [
			{
				id: 'in_mixed',
				enabled: true,
				type: 'mixed',
				tag: 'mixed-in',
				remark: 'LAN Mixed Proxy',
				config: {
					listen: '::',
					listen_port: 7890
				}
			}
		],
		outbound_groups: [
			{
				id: 'grp_proxy',
				enabled: true,
				type: 'selector',
				tag: 'Proxy',
				remark: 'Manual Select',
				outbounds: [ 'Auto', 'direct' ],
				providers: [
					{
						profile_id: '*',
						include_regex: '',
						exclude_regex: ''
					}
				],
				fallback_outbound: 'direct',
				config: {
					default: 'Auto'
				}
			},
			{
				id: 'grp_auto',
				enabled: true,
				type: 'urltest',
				tag: 'Auto',
				remark: 'Auto Best',
				outbounds: [],
				providers: [
					{
						profile_id: '*',
						include_regex: '',
						exclude_regex: ''
					}
				],
				fallback_outbound: 'direct',
				config: {
					url: 'https://www.gstatic.com/generate_204',
					interval: '5m',
					tolerance: 50
				}
			}
		],
		outbounds: [
			{
				id: 'out_direct',
				enabled: true,
				type: 'direct',
				tag: 'direct',
				remark: 'Direct',
				config: {}
			}
		],
		dns: {
			final: 'dns-proxy',
			strategy: '',
			extra: {},
			servers: [
				{
					id: 'dns_cn',
					enabled: true,
					type: 'udp',
					tag: 'dns-cn',
					remark: 'China Direct DNS',
					config: {
						server: '223.5.5.5'
					}
				},
				{
					id: 'dns_proxy',
					enabled: true,
					type: 'https',
					tag: 'dns-proxy',
					remark: 'Proxy DoH',
					config: {
						server: '1.1.1.1',
						detour: 'Proxy'
					}
				},
				{
					id: 'dns_fakeip',
					enabled: true,
					type: 'fakeip',
					tag: 'dns-fakeip',
					remark: 'Fake-IP Pool',
					config: {
						inet4_range: '198.18.0.0/15',
						inet6_range: 'fc00::/18'
					}
				}
			],
			rules: [
				{
					id: 'dr_cn',
					enabled: true,
					remark: 'China domains direct',
					action: 'route',
					server: 'dns-cn',
					config: {
						rule_set: [ 'geosite-cn' ]
					}
				},
				{
					id: 'dr_fakeip',
					enabled: true,
					remark: 'Fake-IP A/AAAA',
					action: 'route',
					server: 'dns-fakeip',
					config: {
						query_type: [ 'A', 'AAAA' ]
					}
				}
			]
		},
		rule_sets: [
			{
				id: 'rs_geosite_cn',
				enabled: true,
				type: 'remote',
				tag: 'geosite-cn',
				format: 'binary',
				remark: 'China Domain Rule Set',
				config: {
					url: 'https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs',
					http_client: {
						detour: 'Proxy'
					},
					update_interval: '1d'
				}
			},
			{
				id: 'rs_geoip_cn',
				enabled: true,
				type: 'remote',
				tag: 'geoip-cn',
				format: 'binary',
				remark: 'China IP Rule Set',
				config: {
					url: 'https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs',
					http_client: {
						detour: 'Proxy'
					},
					update_interval: '1d'
				}
			}
		],
		route: {
			final: 'Proxy',
			default_domain_resolver: 'dns-cn',
			extra: {},
			rules: [
				{
					id: 'rr_sniff',
					enabled: true,
					remark: 'Protocol Sniff',
					action: 'sniff',
					outbound: '',
					config: {}
				},
				{
					id: 'rr_dns',
					enabled: true,
					remark: 'Hijack DNS',
					action: 'hijack-dns',
					outbound: '',
					config: {
						protocol: 'dns'
					}
				},
				{
					id: 'rr_private',
					enabled: true,
					remark: 'Private IP Direct',
					action: 'route',
					outbound: 'direct',
					config: {
						ip_is_private: true
					}
				},
				{
					id: 'rr_cn',
					enabled: true,
					remark: 'China Traffic Direct',
					action: 'route',
					outbound: 'direct',
					config: {
						rule_set: [ 'geosite-cn', 'geoip-cn' ]
					}
				}
			]
		},
		override: {
			services: [
				{
					type: 'api',
					tag: 'api',
					listen: '::',
					listen_port: 9091,
					dashboard: true
				}
			],
			experimental: {
				cache_file: {
					enabled: true,
					store_fakeip: true
				}
			}
		}
	};
}

function compile_regex(pattern, field_label) {
	if (pattern == null)
		return null;
	if (type(pattern) != 'string')
		return fail(common.ERR_VALIDATE_FAILED, sprintf('%s must be a string', field_label || 'regex'));
	if (length(trim(pattern)) == 0)
		return null;

	try {
		return regexp(pattern, 'i');
	} catch (e) {
		return fail(common.ERR_VALIDATE_FAILED,
			sprintf('invalid regular expression in %s ("%s"): %s',
				field_label || 'regex', pattern, e?.message || ('' + e)));
	}
}

function is_regex_err(re) {
	return (type(re) == 'object' && re.ok === false);
}

function parse_bool(val, fallback, label) {
	if (val == null)
		return { ok: true, value: fallback };
	if (val === true || val === '1' || val === 1)
		return { ok: true, value: true };
	if (val === false || val === '0' || val === 0)
		return { ok: true, value: false };
	return fail(common.ERR_VALIDATE_FAILED, sprintf('%s must be a boolean', label));
}

function parse_str(val, fallback, label) {
	if (val == null)
		return { ok: true, value: fallback };
	if (type(val) != 'string')
		return fail(common.ERR_VALIDATE_FAILED, sprintf('%s must be a string', label));
	return { ok: true, value: val };
}

function parse_obj(val, label) {
	if (val == null)
		return { ok: true, value: {} };
	if (type(val) != 'object')
		return fail(common.ERR_VALIDATE_FAILED, sprintf('%s must be a JSON object', label));
	return { ok: true, value: deep_clone(val) };
}

function parse_str_array(val, fallback, label) {
	if (val == null)
		return { ok: true, value: [ ...fallback ] };
	if (type(val) != 'array')
		return fail(common.ERR_VALIDATE_FAILED, sprintf('%s must be an array of strings', label));
	let out = [];
	for (let item in val) {
		if (type(item) != 'string')
			return fail(common.ERR_VALIDATE_FAILED, sprintf('%s items must be strings', label));
		push(out, item);
	}
	return { ok: true, value: out };
}

function pick_str(primary, secondary, fallback) {
	if (primary != null && primary !== '')
		return primary;
	if (secondary != null && secondary !== '')
		return secondary;
	return fallback;
}

function normalize_typed_item(item, idx, prefix, opts) {
	let options = opts || {};
	let label = options.label || prefix;
	if (type(item) != 'object')
		return fail(common.ERR_VALIDATE_FAILED, sprintf('%s[%d] must be an object', label, idx));

	let en = parse_bool(item.enabled, true, sprintf('%s[%d].enabled', label, idx));
	if (!en.ok)
		return en;

	let cfg = parse_obj(item.config, sprintf('%s[%d].config', label, idx));
	if (!cfg.ok)
		return cfg;

	let id_r = parse_str(item.id, sprintf('%s_%d', prefix, idx + 1), sprintf('%s[%d].id', label, idx));
	if (!id_r.ok)
		return id_r;
	let id_val = length(trim(id_r.value)) > 0 ? id_r.value : sprintf('%s_%d', prefix, idx + 1);

	let rem_r = parse_str(item.remark, '', sprintf('%s[%d].remark', label, idx));
	if (!rem_r.ok)
		return rem_r;

	let raw_type = pick_str(item.type, cfg.value.type, '');
	let type_r = parse_str(raw_type, '', sprintf('%s[%d].type', label, idx));
	if (!type_r.ok)
		return type_r;
	let item_type = trim(type_r.value);
	if (exists(cfg.value, 'type'))
		delete cfg.value.type;

	let raw_tag = pick_str(item.tag, cfg.value.tag, '');
	let tag_r = parse_str(raw_tag, '', sprintf('%s[%d].tag', label, idx));
	if (!tag_r.ok)
		return tag_r;
	let item_tag = trim(tag_r.value);
	if (exists(cfg.value, 'tag'))
		delete cfg.value.tag;

	if (en.value) {
		if (length(item_type) == 0)
			return fail(common.ERR_VALIDATE_FAILED, sprintf('%s[%d].type is required when enabled', label, idx));
		if (options.allowed_types && index(options.allowed_types, item_type) < 0)
			return fail(common.ERR_VALIDATE_FAILED,
				sprintf('%s[%d].type "%s" must be one of: %s', label, idx, item_type, join(', ', options.allowed_types)));
		if (length(item_tag) == 0)
			return fail(common.ERR_VALIDATE_FAILED, sprintf('%s[%d].tag is required when enabled', label, idx));
	} else if (options.allowed_types && length(item_type) > 0 && index(options.allowed_types, item_type) < 0) {
		return fail(common.ERR_VALIDATE_FAILED,
			sprintf('%s[%d].type "%s" must be one of: %s', label, idx, item_type, join(', ', options.allowed_types)));
	}

	return {
		ok: true,
		item: {
			id: id_val,
			enabled: en.value,
			type: item_type,
			tag: item_tag,
			remark: rem_r.value,
			config: cfg.value
		}
	};
}

function normalize_rule_item(item, idx, prefix, target_key, label) {
	if (type(item) != 'object')
		return fail(common.ERR_VALIDATE_FAILED, sprintf('%s[%d] must be an object', label, idx));

	let en = parse_bool(item.enabled, true, sprintf('%s[%d].enabled', label, idx));
	if (!en.ok)
		return en;

	let cfg = parse_obj(item.config, sprintf('%s[%d].config', label, idx));
	if (!cfg.ok)
		return cfg;

	let id_r = parse_str(item.id, sprintf('%s_%d', prefix, idx + 1), sprintf('%s[%d].id', label, idx));
	if (!id_r.ok)
		return id_r;
	let id_val = length(trim(id_r.value)) > 0 ? id_r.value : sprintf('%s_%d', prefix, idx + 1);

	let rem_r = parse_str(item.remark, '', sprintf('%s[%d].remark', label, idx));
	if (!rem_r.ok)
		return rem_r;

	let raw_act = pick_str(item.action, cfg.value.action, '');
	let act_r = parse_str(raw_act, '', sprintf('%s[%d].action', label, idx));
	if (!act_r.ok)
		return act_r;
	if (exists(cfg.value, 'action'))
		delete cfg.value.action;

	let raw_tgt = pick_str(item[target_key], cfg.value[target_key], '');
	let tgt_r = parse_str(raw_tgt, '', sprintf('%s[%d].%s', label, idx, target_key));
	if (!tgt_r.ok)
		return tgt_r;
	if (exists(cfg.value, target_key))
		delete cfg.value[target_key];

	return {
		ok: true,
		item: {
			id: id_val,
			enabled: en.value,
			remark: rem_r.value,
			action: trim(act_r.value),
			[target_key]: trim(tgt_r.value),
			config: cfg.value
		}
	};
}

function normalize_composer(raw) {
	if (type(raw) != 'object')
		return fail(common.ERR_VALIDATE_FAILED, 'composer configuration must be a JSON object');

	let schema_ver = SCHEMA_VERSION;
	if (exists(raw, 'schema_version') && raw.schema_version != null) {
		if (type(raw.schema_version) != 'int' || raw.schema_version != SCHEMA_VERSION)
			return fail(common.ERR_VALIDATE_FAILED,
				sprintf('unsupported composer schema_version: %s', '' + raw.schema_version));
		schema_ver = raw.schema_version;
	}

	// sources
	let norm_sources = {};
	if (exists(raw, 'sources') && raw.sources != null) {
		if (type(raw.sources) != 'object')
			return fail(common.ERR_VALIDATE_FAILED, 'composer.sources must be an object');

		for (let sid, src in raw.sources) {
			if (type(src) != 'object')
				return fail(common.ERR_VALIDATE_FAILED, sprintf('composer.sources.%s must be an object', sid));

			let en = parse_bool(src.enabled, false, sprintf('sources.%s.enabled', sid));
			if (!en.ok)
				return en;

			let pfx = parse_str(src.tag_prefix, '', sprintf('sources.%s.tag_prefix', sid));
			if (!pfx.ok)
				return pfx;

			let inc = parse_str(src.include_regex, '', sprintf('sources.%s.include_regex', sid));
			if (!inc.ok)
				return inc;
			let re_inc = compile_regex(inc.value, sprintf('sources.%s.include_regex', sid));
			if (is_regex_err(re_inc))
				return re_inc;

			let exc = parse_str(src.exclude_regex, '', sprintf('sources.%s.exclude_regex', sid));
			if (!exc.ok)
				return exc;
			let re_exc = compile_regex(exc.value, sprintf('sources.%s.exclude_regex', sid));
			if (is_regex_err(re_exc))
				return re_exc;

			let ext = parse_str_array(src.exclude_types, DEFAULT_EXCLUDE_TYPES, sprintf('sources.%s.exclude_types', sid));
			if (!ext.ok)
				return ext;

			let stf = parse_str_array(src.strip_fields, DEFAULT_STRIP_FIELDS, sprintf('sources.%s.strip_fields', sid));
			if (!stf.ok)
				return stf;

			let nov = parse_obj(src.node_override, sprintf('sources.%s.node_override', sid));
			if (!nov.ok)
				return nov;

			norm_sources[sid] = {
				enabled: en.value,
				tag_prefix: pfx.value,
				include_regex: inc.value,
				exclude_regex: exc.value,
				exclude_types: ext.value,
				strip_fields: stf.value,
				node_override: nov.value
			};
		}
	}

	// inbounds
	let norm_inbounds = [];
	if (exists(raw, 'inbounds') && raw.inbounds != null) {
		if (type(raw.inbounds) != 'array')
			return fail(common.ERR_VALIDATE_FAILED, 'composer.inbounds must be an array');
		for (let i = 0; i < length(raw.inbounds); i++) {
			let res = normalize_typed_item(raw.inbounds[i], i, 'in', { label: 'composer.inbounds' });
			if (!res.ok)
				return res;
			push(norm_inbounds, res.item);
		}
	}

	// outbound_groups
	let norm_groups = [];
	if (exists(raw, 'outbound_groups') && raw.outbound_groups != null) {
		if (type(raw.outbound_groups) != 'array')
			return fail(common.ERR_VALIDATE_FAILED, 'composer.outbound_groups must be an array');
		for (let i = 0; i < length(raw.outbound_groups); i++) {
			let g_raw = raw.outbound_groups[i];
			let base = normalize_typed_item(g_raw, i, 'grp', {
				label: 'composer.outbound_groups',
				allowed_types: [ 'selector', 'urltest' ]
			});
			if (!base.ok)
				return base;

			let st_out = parse_str_array(g_raw.outbounds, [], sprintf('composer.outbound_groups[%d].outbounds', i));
			if (!st_out.ok)
				return st_out;

			let fb = 'direct';
			if (exists(g_raw, 'fallback_outbound') && g_raw.fallback_outbound != null) {
				if (type(g_raw.fallback_outbound) != 'string')
					return fail(common.ERR_VALIDATE_FAILED,
						sprintf('composer.outbound_groups[%d].fallback_outbound must be a string', i));
				fb = g_raw.fallback_outbound;
			}

			let norm_provs = [];
			if (exists(g_raw, 'providers') && g_raw.providers != null) {
				if (type(g_raw.providers) != 'array')
					return fail(common.ERR_VALIDATE_FAILED,
						sprintf('composer.outbound_groups[%d].providers must be an array', i));
				for (let j = 0; j < length(g_raw.providers); j++) {
					let p = g_raw.providers[j];
					if (type(p) != 'object')
						return fail(common.ERR_VALIDATE_FAILED,
							sprintf('composer.outbound_groups[%d].providers[%d] must be an object', i, j));

					let pid_r = parse_str(p.profile_id, '*',
						sprintf('outbound_groups[%d].providers[%d].profile_id', i, j));
					if (!pid_r.ok)
						return pid_r;

					let pinc_r = parse_str(p.include_regex, '',
						sprintf('outbound_groups[%d].providers[%d].include_regex', i, j));
					if (!pinc_r.ok)
						return pinc_r;
					let re_pinc = compile_regex(pinc_r.value,
						sprintf('outbound_groups[%d].providers[%d].include_regex', i, j));
					if (is_regex_err(re_pinc))
						return re_pinc;

					let pexc_r = parse_str(p.exclude_regex, '',
						sprintf('outbound_groups[%d].providers[%d].exclude_regex', i, j));
					if (!pexc_r.ok)
						return pexc_r;
					let re_pexc = compile_regex(pexc_r.value,
						sprintf('outbound_groups[%d].providers[%d].exclude_regex', i, j));
					if (is_regex_err(re_pexc))
						return re_pexc;

					push(norm_provs, {
						profile_id: length(trim(pid_r.value)) > 0 ? trim(pid_r.value) : '*',
						include_regex: pinc_r.value,
						exclude_regex: pexc_r.value
					});
				}
			}

			push(norm_groups, {
				id: base.item.id,
				enabled: base.item.enabled,
				type: base.item.type,
				tag: base.item.tag,
				remark: base.item.remark,
				outbounds: st_out.value,
				providers: norm_provs,
				fallback_outbound: fb,
				config: base.item.config
			});
		}
	}

	// outbounds
	let norm_outbounds = [];
	if (exists(raw, 'outbounds') && raw.outbounds != null) {
		if (type(raw.outbounds) != 'array')
			return fail(common.ERR_VALIDATE_FAILED, 'composer.outbounds must be an array');
		for (let i = 0; i < length(raw.outbounds); i++) {
			let res = normalize_typed_item(raw.outbounds[i], i, 'out', { label: 'composer.outbounds' });
			if (!res.ok)
				return res;
			push(norm_outbounds, res.item);
		}
	}

	// dns
	let norm_dns = { final: '', strategy: '', extra: {}, servers: [], rules: [] };
	if (exists(raw, 'dns') && raw.dns != null) {
		if (type(raw.dns) != 'object')
			return fail(common.ERR_VALIDATE_FAILED, 'composer.dns must be an object');

		let dfinal = parse_str(raw.dns.final, '', 'composer.dns.final');
		if (!dfinal.ok)
			return dfinal;
		let dstrat = parse_str(raw.dns.strategy, '', 'composer.dns.strategy');
		if (!dstrat.ok)
			return dstrat;
		let dextra = parse_obj(raw.dns.extra, 'composer.dns.extra');
		if (!dextra.ok)
			return dextra;

		norm_dns.final = dfinal.value;
		norm_dns.strategy = dstrat.value;
		norm_dns.extra = dextra.value;

		if (exists(raw.dns, 'servers') && raw.dns.servers != null) {
			if (type(raw.dns.servers) != 'array')
				return fail(common.ERR_VALIDATE_FAILED, 'composer.dns.servers must be an array');
			for (let i = 0; i < length(raw.dns.servers); i++) {
				let res = normalize_typed_item(raw.dns.servers[i], i, 'dns', { label: 'composer.dns.servers' });
				if (!res.ok)
					return res;
				push(norm_dns.servers, res.item);
			}
		}

		if (exists(raw.dns, 'rules') && raw.dns.rules != null) {
			if (type(raw.dns.rules) != 'array')
				return fail(common.ERR_VALIDATE_FAILED, 'composer.dns.rules must be an array');
			for (let i = 0; i < length(raw.dns.rules); i++) {
				let res = normalize_rule_item(raw.dns.rules[i], i, 'dr', 'server', 'composer.dns.rules');
				if (!res.ok)
					return res;
				push(norm_dns.rules, res.item);
			}
		}
	}

	// rule_sets
	let norm_rule_sets = [];
	if (exists(raw, 'rule_sets') && raw.rule_sets != null) {
		if (type(raw.rule_sets) != 'array')
			return fail(common.ERR_VALIDATE_FAILED, 'composer.rule_sets must be an array');
		for (let i = 0; i < length(raw.rule_sets); i++) {
			let rs_raw = raw.rule_sets[i];
			let base = normalize_typed_item(rs_raw, i, 'rs', { label: 'composer.rule_sets' });
			if (!base.ok)
				return base;

			let raw_fmt = pick_str(rs_raw.format, base.item.config.format, '');
			let fmt_r = parse_str(raw_fmt, '', sprintf('composer.rule_sets[%d].format', i));
			if (!fmt_r.ok)
				return fmt_r;
			if (exists(base.item.config, 'format'))
				delete base.item.config.format;

			push(norm_rule_sets, {
				id: base.item.id,
				enabled: base.item.enabled,
				type: base.item.type,
				tag: base.item.tag,
				format: trim(fmt_r.value),
				remark: base.item.remark,
				config: base.item.config
			});
		}
	}

	// route
	let norm_route = { final: '', default_domain_resolver: '', extra: {}, rules: [] };
	if (exists(raw, 'route') && raw.route != null) {
		if (type(raw.route) != 'object')
			return fail(common.ERR_VALIDATE_FAILED, 'composer.route must be an object');

		let rfinal = parse_str(raw.route.final, '', 'composer.route.final');
		if (!rfinal.ok)
			return rfinal;
		let rddr = parse_str(raw.route.default_domain_resolver, '', 'composer.route.default_domain_resolver');
		if (!rddr.ok)
			return rddr;
		let rextra = parse_obj(raw.route.extra, 'composer.route.extra');
		if (!rextra.ok)
			return rextra;

		norm_route.final = rfinal.value;
		norm_route.default_domain_resolver = rddr.value;
		norm_route.extra = rextra.value;

		if (exists(raw.route, 'rules') && raw.route.rules != null) {
			if (type(raw.route.rules) != 'array')
				return fail(common.ERR_VALIDATE_FAILED, 'composer.route.rules must be an array');
			for (let i = 0; i < length(raw.route.rules); i++) {
				let res = normalize_rule_item(raw.route.rules[i], i, 'rr', 'outbound', 'composer.route.rules');
				if (!res.ok)
					return res;
				push(norm_route.rules, res.item);
			}
		}
	}

	// override
	let ov_r = parse_obj(raw.override, 'composer.override');
	if (!ov_r.ok)
		return ov_r;

	return {
		ok: true,
		composer: {
			schema_version: schema_ver,
			sources: norm_sources,
			inbounds: norm_inbounds,
			outbound_groups: norm_groups,
			outbounds: norm_outbounds,
			dns: norm_dns,
			rule_sets: norm_rule_sets,
			route: norm_route,
			override: ov_r.value
		}
	};
}

function read_composer(path) {
	let target = path || common.COMPOSER_FILE;
	let raw = common.read_json(target);
	if (raw == null)
		return null;
	let norm = normalize_composer(raw);
	return norm.ok ? norm.composer : null;
}

function save_composer(composer, path) {
	let norm = normalize_composer(composer);
	if (!norm.ok)
		return norm;

	let target = path || common.COMPOSER_FILE;
	let text = sprintf('%.2J\n', norm.composer);
	let new_sha = common.sha256_str(text);
	if (!new_sha)
		return fail(common.ERR_INTERNAL, 'failed to compute composer SHA256');

	let st_old = fs.stat(target);
	if (st_old && st_old.type == 'file') {
		let old_sha = common.sha256_file(target);
		if (old_sha != null && old_sha == new_sha) {
			return {
				ok: true,
				changed: false,
				mtime: st_old.mtime,
				sha256: new_sha,
				composer: norm.composer
			};
		}
	}

	if (!common.atomic_write(target, text, 0600))
		return fail(common.ERR_INTERNAL, sprintf('failed to save composer file: %s', target));

	let st_new = fs.stat(target);
	return {
		ok: true,
		changed: true,
		mtime: st_new ? st_new.mtime : time(),
		sha256: new_sha,
		composer: norm.composer
	};
}

function extract_source_nodes(doc, source_cfg, existing_tags_map) {
	let raw_arr = null;
	if (type(doc) == 'array')
		raw_arr = doc;
	else if (type(doc) == 'object' && type(doc.outbounds) == 'array')
		raw_arr = doc.outbounds;
	else
		return fail(common.ERR_VALIDATE_FAILED, 'source document must be a JSON array of outbounds or an object with outbounds array');

	let src = (type(source_cfg) == 'object') ? source_cfg : {};
	let tag_prefix = (type(src.tag_prefix) == 'string') ? src.tag_prefix : '';
	let exclude_types = (type(src.exclude_types) == 'array') ? src.exclude_types : DEFAULT_EXCLUDE_TYPES;
	let strip_fields = (type(src.strip_fields) == 'array') ? src.strip_fields : DEFAULT_STRIP_FIELDS;
	let node_override = (type(src.node_override) == 'object') ? src.node_override : null;

	let re_inc = compile_regex(src.include_regex ?? '', 'source.include_regex');
	if (is_regex_err(re_inc))
		return re_inc;

	let re_exc = compile_regex(src.exclude_regex ?? '', 'source.exclude_regex');
	if (is_regex_err(re_exc))
		return re_exc;

	let tags_map = (type(existing_tags_map) == 'object') ? existing_tags_map : {};
	let tag_map = {};
	let nodes = [];
	let meta_nodes = [];
	let warnings = [];
	let total_raw = length(raw_arr);
	let filtered_out = 0;

	for (let item in raw_arr) {
		if (type(item) != 'object' ||
			type(item.type) != 'string' || length(trim(item.type)) == 0 ||
			type(item.tag) != 'string' || length(trim(item.tag)) == 0) {
			filtered_out++;
			continue;
		}

		if (index(exclude_types, item.type) >= 0) {
			filtered_out++;
			continue;
		}

		let original_tag = item.tag;
		if (re_inc && !match(original_tag, re_inc)) {
			filtered_out++;
			continue;
		}
		if (re_exc && match(original_tag, re_exc)) {
			filtered_out++;
			continue;
		}

		let node = deep_clone(item);
		for (let f in strip_fields)
			delete node[f];

		if (node_override && length(keys(node_override)) > 0)
			node = merge_patch(node, node_override);

		let base_tag = tag_prefix + original_tag;
		let final_tag = base_tag;
		if (exists(tags_map, final_tag)) {
			let seq = 2;
			while (exists(tags_map, sprintf('%s #%d', base_tag, seq)))
				seq++;
			final_tag = sprintf('%s #%d', base_tag, seq);
			push(warnings, sprintf('duplicate outbound tag "%s" renamed to "%s"', base_tag, final_tag));
		}

		tags_map[final_tag] = true;
		if (!exists(tag_map, original_tag))
			tag_map[original_tag] = final_tag;

		node.type = item.type;
		node.tag = final_tag;
		push(nodes, node);
		push(meta_nodes, {
			original_tag: original_tag,
			tag: final_tag,
			type: node.type,
			server: node.server ?? null,
			server_port: node.server_port ?? null
		});
	}

	// Second pass: remap chained detour references pointing to sibling extracted nodes
	for (let node in nodes) {
		if (type(node.detour) == 'string' && exists(tag_map, node.detour))
			node.detour = tag_map[node.detour];
	}

	return {
		ok: true,
		nodes: nodes,
		meta_nodes: meta_nodes,
		total_raw: total_raw,
		filtered_out: filtered_out,
		warnings: warnings
	};
}

function get_ordered_profiles(uci_cfg) {
	let out = [];
	if (type(uci_cfg) != 'object')
		return out;

	for (let k, sec in uci_cfg) {
		if (type(sec) != 'object' || sec['.type'] != 'profile')
			continue;
		let raw_idx = sec['.index'];
		let ord = (type(raw_idx) == 'int') ? raw_idx : 999999;
		if (type(raw_idx) == 'string' && match(trim(raw_idx), /^[0-9]+$/)) {
			let n = int(trim(raw_idx), 10);
			if (!common.isnan(n))
				ord = n;
		}
		push(out, {
			id: sec['.name'] || k,
			section: sec,
			_order: ord
		});
	}

	sort(out, (a, b) => {
		if (a._order != b._order)
			return a._order - b._order;
		if (a.id < b.id)
			return -1;
		if (a.id > b.id)
			return 1;
		return 0;
	});

	let clean = [];
	for (let item in out)
		push(clean, { id: item.id, section: item.section });
	return clean;
}

function load_source_doc(id, sec, options, profiles_dir) {
	if (type(options.override_profile_docs) == 'object' && exists(options.override_profile_docs, id)) {
		let ov = options.override_profile_docs[id];
		if (type(ov) == 'string') {
			try {
				return json(ov);
			} catch (e) {
				return null;
			}
		}
		return ov;
	}

	if (!common.is_valid_profile_filename(sec.filename))
		return null;

	return common.read_json(profiles_dir + '/' + sec.filename);
}

function load_normalized_composer(options) {
	if (options.composer != null)
		return normalize_composer(options.composer);

	let cpath = options.composer_file || common.COMPOSER_FILE;
	let st = fs.stat(cpath);
	if (!st)
		return fail(common.ERR_NOT_FOUND, 'composer configuration not initialized; save configuration in Config page first');

	let raw = common.read_json(cpath);
	if (raw == null)
		return fail(common.ERR_VALIDATE_FAILED, sprintf('failed to parse composer configuration: %s', cpath));

	return normalize_composer(raw);
}

function compose(uci_cfg, opts) {
	let options = opts || {};
	let norm = load_normalized_composer(options);
	if (!norm.ok)
		return norm;

	let comp = norm.composer;
	let warnings = [];
	let existing_tags_map = {};

	for (let g in comp.outbound_groups) {
		if (g.enabled)
			existing_tags_map[g.tag] = true;
	}
	for (let o in comp.outbounds) {
		if (o.enabled)
			existing_tags_map[o.tag] = true;
	}

	let ordered_profiles = get_ordered_profiles(uci_cfg);
	let profile_lookup = {};
	for (let p in ordered_profiles)
		profile_lookup[p.id] = p.section;

	for (let sid, src_cfg in comp.sources) {
		if (src_cfg.enabled === true && !exists(profile_lookup, sid))
			push(warnings, sprintf('enabled source "%s" references missing UCI profile section', sid));
	}

	let profiles_dir = options.profiles_dir || common.PROFILES_DIR;
	let enabled_sources = 0;
	let enabled_source_ids = [];
	let per_source_nodes = {};
	let per_source_counts = {};
	let all_extracted_nodes = [];

	for (let item in ordered_profiles) {
		let id = item.id;
		let sec = item.section;
		let src_cfg = comp.sources[id];
		if (!src_cfg || src_cfg.enabled !== true)
			continue;

		enabled_sources++;
		push(enabled_source_ids, id);

		let doc = load_source_doc(id, sec, options, profiles_dir);
		if (doc == null) {
			push(warnings, sprintf('enabled source "%s" file not found or invalid JSON: %s', id, sec.filename || id));
			per_source_nodes[id] = [];
			per_source_counts[id] = 0;
			continue;
		}

		let ext = extract_source_nodes(doc, src_cfg, existing_tags_map);
		if (!ext.ok)
			return fail(ext.code, ext.error, { warnings: warnings });

		for (let w in ext.warnings)
			push(warnings, w);

		per_source_nodes[id] = ext.meta_nodes;
		per_source_counts[id] = length(ext.nodes);
		for (let n in ext.nodes)
			push(all_extracted_nodes, n);
	}

	let compiled_groups = [];
	for (let g in comp.outbound_groups) {
		if (!g.enabled)
			continue;

		let members = [];
		let seen = {};
		let add_member = (tag) => {
			if (type(tag) != 'string' || length(trim(tag)) == 0 || exists(seen, tag))
				return;
			seen[tag] = true;
			push(members, tag);
		};

		for (let m in g.outbounds)
			add_member(m);

		for (let prov in g.providers) {
			let pid = prov.profile_id;
			let target_ids = [];
			if (pid == '*')
				target_ids = enabled_source_ids;
			else if (comp.sources[pid]?.enabled === true && exists(per_source_nodes, pid))
				target_ids = [ pid ];

			let p_inc = compile_regex(prov.include_regex, sprintf('outbound_groups[%s].provider.include_regex', g.tag));
			if (is_regex_err(p_inc))
				return fail(p_inc.code, p_inc.error, { warnings: warnings });

			let p_exc = compile_regex(prov.exclude_regex, sprintf('outbound_groups[%s].provider.exclude_regex', g.tag));
			if (is_regex_err(p_exc))
				return fail(p_exc.code, p_exc.error, { warnings: warnings });

			for (let sid in target_ids) {
				for (let meta in (per_source_nodes[sid] || [])) {
					if (p_inc && !match(meta.tag, p_inc))
						continue;
					if (p_exc && match(meta.tag, p_exc))
						continue;
					add_member(meta.tag);
				}
			}
		}

		if (length(members) == 0) {
			let fb = trim('' + (g.fallback_outbound ?? 'direct'));
			if (length(fb) > 0) {
				push(members, fb);
				push(warnings, sprintf('outbound group "%s" had no matching nodes; fell back to "%s"', g.tag, fb));
			} else {
				return fail(common.ERR_VALIDATE_FAILED,
					sprintf('outbound group "%s" resolved to 0 members and fallback_outbound is empty', g.tag),
					{ warnings: warnings });
			}
		}

		let gobj = {
			...(g.config || {}),
			type: g.type,
			tag: g.tag,
			outbounds: members
		};

		if (g.type == 'selector' && type(gobj.default) == 'string' && length(gobj.default) > 0 &&
			index(members, gobj.default) < 0) {
			push(warnings, sprintf('outbound group "%s" default "%s" is not in resolved members and was removed',
				g.tag, gobj.default));
			delete gobj.default;
		}

		push(compiled_groups, gobj);
	}

	let compiled_manual = [];
	for (let o in comp.outbounds) {
		if (!o.enabled)
			continue;
		push(compiled_manual, {
			...(o.config || {}),
			type: o.type,
			tag: o.tag
		});
	}

	let compiled_inbounds = [];
	for (let inb in comp.inbounds) {
		if (!inb.enabled)
			continue;
		push(compiled_inbounds, {
			...(inb.config || {}),
			type: inb.type,
			tag: inb.tag
		});
	}

	let compiled_dns_servers = [];
	for (let srv in comp.dns.servers) {
		if (!srv.enabled)
			continue;
		push(compiled_dns_servers, {
			...(srv.config || {}),
			type: srv.type,
			tag: srv.tag
		});
	}

	let compiled_dns_rules = [];
	for (let r in comp.dns.rules) {
		if (!r.enabled)
			continue;
		let robj = { ...(r.config || {}) };
		if (length(r.action || '') > 0)
			robj.action = r.action;
		if (length(r.server || '') > 0)
			robj.server = r.server;
		push(compiled_dns_rules, robj);
	}

	let dns_obj = { ...(comp.dns.extra || {}) };
	if (length(comp.dns.final || '') > 0)
		dns_obj.final = comp.dns.final;
	if (length(comp.dns.strategy || '') > 0)
		dns_obj.strategy = comp.dns.strategy;
	dns_obj.servers = compiled_dns_servers;
	dns_obj.rules = compiled_dns_rules;

	let compiled_rule_sets = [];
	for (let rs in comp.rule_sets) {
		if (!rs.enabled)
			continue;
		let rsobj = {
			...(rs.config || {}),
			type: rs.type,
			tag: rs.tag
		};
		if (rs.type == 'inline')
			delete rsobj.format;
		else if (length(rs.format || '') > 0)
			rsobj.format = rs.format;
		push(compiled_rule_sets, rsobj);
	}

	let compiled_route_rules = [];
	for (let r in comp.route.rules) {
		if (!r.enabled)
			continue;
		let robj = { ...(r.config || {}) };
		if (length(r.action || '') > 0)
			robj.action = r.action;
		if (length(r.outbound || '') > 0)
			robj.outbound = r.outbound;
		push(compiled_route_rules, robj);
	}

	let route_obj = { ...(comp.route.extra || {}) };
	if (length(comp.route.final || '') > 0)
		route_obj.final = comp.route.final;
	if (length(comp.route.default_domain_resolver || '') > 0)
		route_obj.default_domain_resolver = comp.route.default_domain_resolver;
	if (length(compiled_rule_sets) > 0)
		route_obj.rule_set = compiled_rule_sets;
	route_obj.rules = compiled_route_rules;

	let cfg = {
		inbounds: compiled_inbounds,
		outbounds: [ ...compiled_groups, ...compiled_manual, ...all_extracted_nodes ],
		dns: dns_obj,
		route: route_obj
	};

	if (type(comp.override) == 'object' && length(keys(comp.override)) > 0)
		cfg = merge_patch(cfg, comp.override);

	return {
		ok: true,
		config: cfg,
		warnings: warnings,
		per_source_counts: per_source_counts,
		summary: {
			initialized: true,
			enabled_sources: enabled_sources,
			extracted_nodes: length(all_extracted_nodes),
			groups: length(compiled_groups),
			manual_outbounds: length(compiled_manual),
			inbounds: length(cfg.inbounds || []),
			dns_servers: length(cfg.dns?.servers || []),
			route_rules: length(cfg.route?.rules || []),
			rule_sets: length(cfg.route?.rule_set || [])
		}
	};
}

function query_nodes(uci_cfg, opts) {
	let options = opts || {};
	let comp = null;
	if (options.composer != null) {
		let norm = normalize_composer(options.composer);
		if (!norm.ok)
			return norm;
		comp = norm.composer;
	} else {
		comp = read_composer(options.composer_file || common.COMPOSER_FILE) || create_empty_composer();
	}

	let re_inc = compile_regex(options.include_regex ?? '', 'include_regex');
	if (is_regex_err(re_inc))
		return re_inc;

	let re_exc = compile_regex(options.exclude_regex ?? '', 'exclude_regex');
	if (is_regex_err(re_exc))
		return re_exc;

	let existing_tags_map = {};
	for (let g in comp.outbound_groups) {
		if (g.enabled)
			existing_tags_map[g.tag] = true;
	}
	for (let o in comp.outbounds) {
		if (o.enabled)
			existing_tags_map[o.tag] = true;
	}

	let profiles_dir = options.profiles_dir || common.PROFILES_DIR;
	let ordered = get_ordered_profiles(uci_cfg);
	let want_id = trim('' + (options.profile_id ?? ''));
	let targets = [];
	if (length(want_id) > 0 && want_id != '*') {
		let target_idx = -1;
		for (let i = 0; i < length(ordered); i++) {
			if (ordered[i].id == want_id) {
				target_idx = i;
				break;
			}
		}
		if (target_idx < 0)
			return fail(common.ERR_NOT_FOUND, sprintf('profile "%s" not found', want_id));

		let want_enabled = (comp.sources[want_id]?.enabled === true);
		for (let i = 0; i < length(ordered); i++) {
			if (want_enabled && i >= target_idx)
				break;
			let p = ordered[i];
			if (p.id == want_id || comp.sources[p.id]?.enabled !== true)
				continue;
			let pre_doc = load_source_doc(p.id, p.section, options, profiles_dir);
			if (pre_doc != null)
				extract_source_nodes(pre_doc, comp.sources[p.id], existing_tags_map);
		}

		push(targets, ordered[target_idx]);
	} else {
		for (let p in ordered) {
			if (comp.sources[p.id]?.enabled === true)
				push(targets, p);
		}
	}

	let nodes = [];
	let per_source_counts = {};
	let warnings = [];

	for (let item in targets) {
		let id = item.id;
		let sec = item.section;
		let src_cfg = comp.sources[id] || {};
		let doc = load_source_doc(id, sec, options, profiles_dir);
		if (doc == null) {
			push(warnings, sprintf('source "%s" file not found or invalid JSON: %s', id, sec.filename || id));
			per_source_counts[id] = 0;
			continue;
		}

		let ext = extract_source_nodes(doc, src_cfg, existing_tags_map);
		if (!ext.ok)
			return fail(ext.code, ext.error, { warnings: warnings });

		for (let w in ext.warnings)
			push(warnings, w);

		per_source_counts[id] = length(ext.nodes);
		for (let m in ext.meta_nodes) {
			if (re_inc && !match(m.tag, re_inc))
				continue;
			if (re_exc && match(m.tag, re_exc))
				continue;
			push(nodes, {
				profile_id: id,
				original_tag: m.original_tag,
				tag: m.tag,
				type: m.type,
				server: m.server,
				server_port: m.server_port
			});
		}
	}

	return {
		ok: true,
		nodes: nodes,
		per_source_counts: per_source_counts,
		warnings: warnings
	};
}

function sanitize_imported_rule(rule, auto_tags, rule_path, warnings) {
	if (type(rule) != 'object')
		return null;

	let rc = deep_clone(rule);
	if (type(rc.inbound) == 'string') {
		let itag = trim(rc.inbound);
		if (index(auto_tags, itag) >= 0) {
			push(warnings, sprintf('excluded %s targeting auto-injected inbound "%s"', rule_path, itag));
			return null;
		}
	} else if (type(rc.inbound) == 'array') {
		let kept = [];
		let removed = [];
		for (let item in rc.inbound) {
			let itag = (type(item) == 'string') ? trim(item) : '';
			if (length(itag) > 0 && index(auto_tags, itag) >= 0)
				push(removed, itag);
			else
				push(kept, item);
		}
		if (length(removed) > 0) {
			if (length(kept) == 0) {
				push(warnings, sprintf('excluded %s targeting auto-injected inbound(s) only: %s',
					rule_path, join(', ', removed)));
				return null;
			}
			rc.inbound = kept;
			push(warnings, sprintf('stripped auto-injected inbound(s) (%s) from %s',
				join(', ', removed), rule_path));
		}
	}

	if (type(rc.rules) == 'array') {
		let had_sub = (length(rc.rules) > 0);
		let new_subs = [];
		for (let i = 0; i < length(rc.rules); i++) {
			let sub = sanitize_imported_rule(rc.rules[i], auto_tags, sprintf('%s.rules[%d]', rule_path, i), warnings);
			if (sub != null)
				push(new_subs, sub);
		}
		if (had_sub && length(new_subs) == 0) {
			push(warnings, sprintf('excluded empty logical %s after stripping auto-injected inbound sub-rules', rule_path));
			return null;
		}
		rc.rules = new_subs;
	}

	return rc;
}

function import_from_singbox(raw_cfg) {
	let src = raw_cfg;
	if (type(src) == 'string') {
		try {
			src = json(src);
		} catch (e) {
			return fail(common.ERR_VALIDATE_FAILED, sprintf('invalid sing-box JSON: %s', '' + e));
		}
	}

	if (type(src) != 'object')
		return fail(common.ERR_VALIDATE_FAILED, 'source sing-box configuration must be a JSON object');

	let cfg = deep_clone(src);
	let warnings = [];
	let auto_tags = [ common.TAG_REDIRECT_IN, common.TAG_TPROXY_IN, common.TAG_DNS_IN ];

	let comp = {
		schema_version: SCHEMA_VERSION,
		sources: {},
		inbounds: [],
		outbound_groups: [],
		outbounds: [],
		dns: {
			final: '',
			strategy: '',
			extra: {},
			servers: [],
			rules: []
		},
		rule_sets: [],
		route: {
			final: '',
			default_domain_resolver: '',
			extra: {},
			rules: []
		},
		override: {}
	};

	if (type(cfg.inbounds) == 'array') {
		for (let i = 0; i < length(cfg.inbounds); i++) {
			let inb = cfg.inbounds[i];
			if (type(inb) != 'object')
				continue;

			let itag = (type(inb.tag) == 'string') ? trim(inb.tag) : '';
			if (index(auto_tags, itag) >= 0) {
				push(warnings, sprintf('excluded auto-injected inbound "%s"', itag));
				continue;
			}

			let cobj = deep_clone(inb);
			let itype = (type(cobj.type) == 'string') ? trim(cobj.type) : '';
			delete cobj.type;
			delete cobj.tag;

			if (length(itype) > 0 && length(itag) == 0) {
				itag = sprintf('%s-%d', itype, length(comp.inbounds) + 1);
				push(warnings, sprintf('inbound[%d] ("%s") had no tag; assigned "%s"', i, itype, itag));
			}

			push(comp.inbounds, {
				id: sprintf('in_%d', length(comp.inbounds) + 1),
				enabled: (length(itype) > 0 && length(itag) > 0),
				type: itype,
				tag: itag,
				remark: '',
				config: cobj
			});
		}
	}

	if (type(cfg.outbounds) == 'array') {
		for (let i = 0; i < length(cfg.outbounds); i++) {
			let outb = cfg.outbounds[i];
			if (type(outb) != 'object')
				continue;

			let cobj = deep_clone(outb);
			let otype = (type(cobj.type) == 'string') ? trim(cobj.type) : '';
			let otag = (type(cobj.tag) == 'string') ? trim(cobj.tag) : '';
			delete cobj.type;
			delete cobj.tag;

			if (length(otype) > 0 && length(otag) == 0) {
				otag = sprintf('%s-%d', otype, i + 1);
				push(warnings, sprintf('outbound[%d] ("%s") had no tag; assigned "%s"', i, otype, otag));
			}

			if (otype == 'selector' || otype == 'urltest') {
				let members = [];
				if (type(cobj.outbounds) == 'array') {
					for (let m in cobj.outbounds) {
						if (type(m) == 'string' && length(m) > 0)
							push(members, m);
					}
				}
				delete cobj.outbounds;

				push(comp.outbound_groups, {
					id: sprintf('grp_%d', length(comp.outbound_groups) + 1),
					enabled: (length(otag) > 0),
					type: otype,
					tag: otag,
					remark: '',
					outbounds: members,
					providers: [],
					fallback_outbound: 'direct',
					config: cobj
				});
			} else {
				push(comp.outbounds, {
					id: sprintf('out_%d', length(comp.outbounds) + 1),
					enabled: (length(otype) > 0 && length(otag) > 0),
					type: otype,
					tag: otag,
					remark: '',
					config: cobj
				});
			}
		}
	}

	if (type(cfg.dns) == 'object') {
		let d = deep_clone(cfg.dns);
		if (type(d.final) == 'string')
			comp.dns.final = d.final;
		delete d.final;
		if (type(d.strategy) == 'string')
			comp.dns.strategy = d.strategy;
		delete d.strategy;

		if (type(d.servers) == 'array') {
			for (let i = 0; i < length(d.servers); i++) {
				let srv = d.servers[i];
				if (type(srv) != 'object')
					continue;
				let sc = deep_clone(srv);
				let stype = (type(sc.type) == 'string') ? trim(sc.type) : '';
				let stag = (type(sc.tag) == 'string') ? trim(sc.tag) : '';
				delete sc.type;
				delete sc.tag;

				if (length(stype) == 0)
					push(warnings, sprintf('dns.servers[%d] ("%s") lacks modern 1.12+ "type" field and was imported disabled', i, stag || '?'));
				else if (length(stag) == 0) {
					stag = sprintf('dns-%d', length(comp.dns.servers) + 1);
					push(warnings, sprintf('dns.servers[%d] had no tag; assigned "%s"', i, stag));
				}

				push(comp.dns.servers, {
					id: sprintf('dns_%d', length(comp.dns.servers) + 1),
					enabled: (length(stype) > 0 && length(stag) > 0),
					type: stype,
					tag: stag,
					remark: '',
					config: sc
				});
			}
		}
		delete d.servers;

		if (type(d.rules) == 'array') {
			for (let i = 0; i < length(d.rules); i++) {
				let rc = sanitize_imported_rule(d.rules[i], auto_tags, sprintf('dns.rules[%d]', i), warnings);
				if (!rc)
					continue;
				let act = (type(rc.action) == 'string') ? trim(rc.action) : '';
				let srv = (type(rc.server) == 'string') ? trim(rc.server) : '';
				delete rc.action;
				delete rc.server;

				push(comp.dns.rules, {
					id: sprintf('dr_%d', length(comp.dns.rules) + 1),
					enabled: true,
					remark: '',
					action: act,
					server: srv,
					config: rc
				});
			}
		}
		delete d.rules;
		comp.dns.extra = d;
	}

	if (type(cfg.route) == 'object') {
		let rt = deep_clone(cfg.route);
		if (type(rt.final) == 'string')
			comp.route.final = rt.final;
		delete rt.final;
		if (type(rt.default_domain_resolver) == 'string')
			comp.route.default_domain_resolver = rt.default_domain_resolver;
		delete rt.default_domain_resolver;

		if (type(rt.rule_set) == 'array') {
			for (let i = 0; i < length(rt.rule_set); i++) {
				let rs = rt.rule_set[i];
				if (type(rs) != 'object')
					continue;
				let rsc = deep_clone(rs);
				let rstype = (type(rsc.type) == 'string') ? trim(rsc.type) : '';
				let rstag = (type(rsc.tag) == 'string') ? trim(rsc.tag) : '';
				let rsfmt = (type(rsc.format) == 'string') ? trim(rsc.format) : '';
				delete rsc.type;
				delete rsc.tag;
				delete rsc.format;

				if (length(rstype) > 0 && length(rstag) == 0) {
					rstag = sprintf('rs-%d', length(comp.rule_sets) + 1);
					push(warnings, sprintf('route.rule_set[%d] had no tag; assigned "%s"', i, rstag));
				}

				push(comp.rule_sets, {
					id: sprintf('rs_%d', length(comp.rule_sets) + 1),
					enabled: (length(rstype) > 0 && length(rstag) > 0),
					type: rstype,
					tag: rstag,
					format: rsfmt,
					remark: '',
					config: rsc
				});
			}
		}
		delete rt.rule_set;

		if (type(rt.rules) == 'array') {
			for (let i = 0; i < length(rt.rules); i++) {
				let rc = sanitize_imported_rule(rt.rules[i], auto_tags, sprintf('route.rules[%d]', i), warnings);
				if (!rc)
					continue;
				let act = (type(rc.action) == 'string') ? trim(rc.action) : '';
				let outb = (type(rc.outbound) == 'string') ? trim(rc.outbound) : '';
				delete rc.action;
				delete rc.outbound;

				push(comp.route.rules, {
					id: sprintf('rr_%d', length(comp.route.rules) + 1),
					enabled: true,
					remark: '',
					action: act,
					outbound: outb,
					config: rc
				});
			}
		}
		delete rt.rules;
		comp.route.extra = rt;
	}

	for (let k, v in cfg) {
		if (k == 'log' || k == 'inbounds' || k == 'outbounds' || k == 'dns' || k == 'route')
			continue;
		comp.override[k] = v;
	}

	let norm = normalize_composer(comp);
	if (!norm.ok)
		return norm;

	return {
		ok: true,
		composer: norm.composer,
		warnings: warnings
	};
}

function summarize_composer(uci_cfg, opts) {
	let options = opts || {};
	let empty_summary = {
		initialized: false,
		enabled_sources: 0,
		extracted_nodes: 0,
		groups: 0,
		manual_outbounds: 0,
		inbounds: 0,
		dns_servers: 0,
		route_rules: 0,
		rule_sets: 0
	};

	let comp = null;
	if (options.composer != null) {
		let norm = normalize_composer(options.composer);
		if (!norm.ok)
			return empty_summary;
		comp = norm.composer;
	} else {
		let cpath = options.composer_file || common.COMPOSER_FILE;
		if (!fs.stat(cpath))
			return empty_summary;
		comp = read_composer(cpath);
		if (!comp)
			return empty_summary;
	}

	let res = compose(uci_cfg, { ...options, composer: comp });
	if (res.ok)
		return res.summary;

	let cnt_enabled = (arr) => {
		let n = 0;
		for (let item in (arr || [])) {
			if (item.enabled)
				n++;
		}
		return n;
	};

	let q = query_nodes(uci_cfg, { ...options, composer: comp });
	let en_src = 0;
	for (let p in get_ordered_profiles(uci_cfg)) {
		if (comp.sources[p.id]?.enabled === true)
			en_src++;
	}

	return {
		initialized: true,
		enabled_sources: en_src,
		extracted_nodes: q.ok ? length(q.nodes) : 0,
		groups: cnt_enabled(comp.outbound_groups),
		manual_outbounds: cnt_enabled(comp.outbounds),
		inbounds: cnt_enabled(comp.inbounds),
		dns_servers: cnt_enabled(comp.dns?.servers),
		route_rules: cnt_enabled(comp.route?.rules),
		rule_sets: cnt_enabled(comp.rule_sets)
	};
}

export {
	SCHEMA_VERSION,
	DEFAULT_EXCLUDE_TYPES,
	DEFAULT_STRIP_FIELDS,
	deep_clone,
	merge_patch,
	create_empty_composer,
	create_standard_114_preset,
	compile_regex,
	normalize_composer,
	read_composer,
	save_composer,
	extract_source_nodes,
	get_ordered_profiles,
	compose,
	query_nodes,
	import_from_singbox,
	summarize_composer
};
