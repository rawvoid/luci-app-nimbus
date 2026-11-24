'use strict';

import * as fs from 'fs';
import * as ubus from 'ubus';
import * as common from 'common';
import * as cc from 'config_composer';

const DEPRECATED_INBOUND_FIELDS = [
	'sniff',
	'sniff_override_destination',
	'sniff_timeout',
	'domain_strategy',
	'udp_disable_domain_unmapping'
];

const VALID_LOG_LEVELS = [
	'trace',
	'debug',
	'info',
	'warn',
	'error',
	'fatal',
	'panic'
];

const CHECK_TIMEOUT_MS = 15000;

let _cb_seq = 0;

function fail(code, error, warnings) {
	return {
		ok: false,
		code: code || common.ERR_VALIDATE_FAILED,
		error: error,
		warnings: warnings || []
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

function push_unique(arr, val) {
	if (index(arr, val) < 0)
		push(arr, val);
}

function parse_port(val, fallback) {
	if (val == null || val === '')
		return fallback;

	if (type(val) == 'int')
		return (val >= 1 && val <= 65535) ? val : null;

	if (type(val) != 'string')
		return null;

	let s = trim(val);
	if (!match(s, /^[0-9]+$/))
		return null;

	let n = int(s, 10);
	if (common.isnan(n) || n < 1 || n > 65535)
		return null;

	return n;
}

function is_valid_cidr(cidr, family) {
	if (type(cidr) != 'string')
		return false;

	let parts = split(trim(cidr), '/');
	if (length(parts) != 2)
		return false;

	let ip_bytes = iptoarr(parts[0]);
	if (!ip_bytes)
		return false;

	if (!match(parts[1], /^[0-9]+$/))
		return false;

	let prefix = int(parts[1], 10);
	if (common.isnan(prefix))
		return false;

	if (family == 4)
		return (length(ip_bytes) == 4 && prefix >= 1 && prefix <= 32);

	if (family == 6)
		return (length(ip_bytes) == 16 && prefix >= 1 && prefix <= 128);

	return false;
}

function supports_udp(inb) {
	if (!exists(inb, 'network') || inb.network == null || inb.network === '')
		return true;

	if (type(inb.network) == 'string')
		return (inb.network == 'udp');

	if (type(inb.network) == 'array')
		return (index(inb.network, 'udp') >= 0);

	return false;
}

function is_loopback_addr(addr) {
	return (addr == '127.0.0.1' || addr == '::1');
}

function is_ipv6_listen(addr) {
	return (type(addr) == 'string' && index(addr, ':') >= 0);
}

function is_ipv4_loopback_reachable(addr) {
	return (addr == '127.0.0.1' || addr == '0.0.0.0' || addr == '::');
}

function validate_upstream_ip(raw_ip, own_ips, ipv6_enable) {
	if (type(raw_ip) != 'string')
		return null;
	let s = trim(raw_ip);
	if (length(s) == 0 || index(s, '%') >= 0 || index(s, '/') >= 0 || match(s, /[ \t\r\n]/))
		return null;

	let bytes = iptoarr(s);
	if (!bytes)
		return null;

	if (length(bytes) == 4) {
		if (bytes[0] == 0 || bytes[0] == 127 || bytes[0] >= 224)
			return null;
		if (bytes[0] == 169 && bytes[1] == 254)
			return null;
		let canon = arrtoip(bytes);
		if (own_ips && exists(own_ips, canon))
			return null;
		return { family: 4, ip: canon };
	}

	if (length(bytes) == 16) {
		if (!ipv6_enable)
			return null;
		let all_zero = true;
		for (let i = 0; i < 15; i++) {
			if (bytes[i] != 0) {
				all_zero = false;
				break;
			}
		}
		if (all_zero && (bytes[15] == 0 || bytes[15] == 1))
			return null;
		if (bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80)
			return null;
		if (bytes[0] == 0xff)
			return null;
		let canon = arrtoip(bytes);
		if (own_ips && exists(own_ips, canon))
			return null;
		return { family: 6, ip: canon };
	}

	return null;
}

function parse_v4_cidr(cidr) {
	if (type(cidr) != 'string')
		return null;
	let parts = split(trim(cidr), '/');
	if (length(parts) != 2 || !match(parts[1], /^[0-9]+$/))
		return null;
	let bytes = iptoarr(parts[0]);
	let prefix = int(parts[1], 10);
	if (!bytes || length(bytes) != 4 || common.isnan(prefix) || prefix < 0 || prefix > 32)
		return null;
	return { bytes: bytes, prefix: prefix };
}

function ip_in_v4_cidr(ip_bytes, net_bytes, prefix) {
	if (!ip_bytes || !net_bytes || length(ip_bytes) != 4 || length(net_bytes) != 4)
		return false;
	let full = int(prefix / 8);
	let rem = prefix % 8;
	for (let i = 0; i < full; i++) {
		if (ip_bytes[i] != net_bytes[i])
			return false;
	}
	if (rem > 0) {
		let mask = (0xff << (8 - rem)) & 0xff;
		if ((ip_bytes[full] & mask) != (net_bytes[full] & mask))
			return false;
	}
	return true;
}

function to_name_list(val, fallback) {
	if (type(val) == 'array') {
		let out = [];
		for (let item in val) {
			let s = trim('' + (item ?? ''));
			if (length(s) > 0)
				push_unique(out, s);
		}
		return length(out) > 0 ? out : fallback;
	}
	if (type(val) == 'string' && length(trim(val)) > 0) {
		let out = [];
		for (let part in split(trim(val), /[ \t\r\n,]+/)) {
			if (length(part) > 0)
				push_unique(out, part);
		}
		return length(out) > 0 ? out : fallback;
	}
	return fallback;
}

function resolve_wan_upstream_dns(uci_cfg, opts) {
	let options = opts || {};
	let g = uci_cfg?.global || {};
	let topology = (g.topology == 'side') ? 'side' : 'main';
	let ipv6_enable = (g.ipv6_enable != '0' && options.ipv6_enable !== false);
	let lan_names = to_name_list(g.lan_interfaces, [ 'lan' ]);
	let wan_names = to_name_list(g.wan_interfaces, [ 'wan', 'wan6' ]);

	let dump = options.ubus_dump;
	if (dump == null && options.skip_ubus !== true) {
		try {
			let ub = ubus.connect();
			if (ub) {
				dump = ub.call('network.interface', 'dump');
				ub.disconnect();
			}
		} catch (e) {
			dump = null;
		}
	}

	let own_ips = {};
	let lan_v4_nets = [];
	let ubus_ifaces = {};
	if (type(dump?.interface) == 'array') {
		for (let item in dump.interface) {
			if (type(item) != 'object' || type(item.interface) != 'string')
				continue;
			ubus_ifaces[item.interface] = item;
			let is_lan = (index(lan_names, item.interface) >= 0);

			for (let k4 in [ 'ipv4-address' ]) {
				if (type(item[k4]) != 'array')
					continue;
				for (let a4 in item[k4]) {
					let ipb = iptoarr('' + (a4?.address ?? ''));
					if (ipb && length(ipb) == 4) {
						own_ips[arrtoip(ipb)] = true;
						if (is_lan && a4?.mask != null) {
							let p = parse_v4_cidr(sprintf('%s/%s', arrtoip(ipb), '' + a4.mask));
							if (p)
								push(lan_v4_nets, p);
						}
					}
				}
			}
			for (let k6 in [ 'ipv6-address', 'ipv6-prefix-assignment' ]) {
				if (type(item[k6]) != 'array')
					continue;
				for (let a6 in item[k6]) {
					let ipb = iptoarr('' + (a6?.address ?? ''));
					if (ipb && length(ipb) == 16)
						own_ips[arrtoip(ipb)] = true;
				}
			}
		}
	}

	if (options.skip_network_uci !== true) {
		let net_uci = common.uci_get_all('network', options.uci_confdir, options.uci_savedir);
		if (type(net_uci) == 'object') {
			for (let ifname, sec in net_uci) {
				if (type(sec) != 'object')
					continue;
				let is_lan = (index(lan_names, ifname) >= 0);
				for (let raw in to_name_list(sec.ipaddr, [])) {
					let p = parse_v4_cidr(raw);
					if (p) {
						own_ips[arrtoip(p.bytes)] = true;
						if (is_lan)
							push(lan_v4_nets, p);
					} else {
						let ipb = iptoarr(raw);
						if (ipb && length(ipb) == 4)
							own_ips[arrtoip(ipb)] = true;
					}
				}
				for (let raw6 in to_name_list(sec.ip6addr, [])) {
					let base6 = split(raw6, '/')[0];
					let ipb6 = iptoarr(base6);
					if (ipb6 && length(ipb6) == 16)
						own_ips[arrtoip(ipb6)] = true;
				}
			}
		}
	}

	let candidates = [];
	if (type(options.wan_dns_servers) == 'array') {
		for (let c in options.wan_dns_servers)
			push_unique(candidates, '' + c);
	} else {
		for (let wname in wan_names) {
			let uitem = ubus_ifaces[wname];
			if (type(uitem?.['dns-server']) == 'array') {
				for (let ds in uitem['dns-server'])
					push_unique(candidates, '' + ds);
			}
		}
		for (let ifname, uitem in ubus_ifaces) {
			if (ifname == 'loopback' || index(wan_names, ifname) >= 0)
				continue;
			if (!(topology == 'side' && index(lan_names, ifname) >= 0) && uitem?.up !== true)
				continue;
			if (uitem?.up === true && type(uitem?.['dns-server']) == 'array') {
				for (let ds in uitem['dns-server'])
					push_unique(candidates, '' + ds);
			}
		}
		let resolv_path = options.resolv_auto_path || '/tmp/resolv.conf.d/resolv.conf.auto';
		let rtxt = fs.readfile(resolv_path);
		if (type(rtxt) == 'string') {
			for (let line in split(rtxt, '\n')) {
				let m = match(trim(line), /^nameserver[ \t]+([^ \t\r\n#;]+)/);
				if (m)
					push_unique(candidates, m[1]);
			}
		}
	}

	let safe_v4 = [];
	let safe_v6 = [];
	for (let cand in candidates) {
		let v = validate_upstream_ip(cand, own_ips, ipv6_enable);
		if (!v)
			continue;
		if (v.family == 4)
			push_unique(safe_v4, v.ip);
		else
			push_unique(safe_v6, v.ip);
	}

	let chosen = (length(safe_v4) > 0) ? safe_v4[0] : ((length(safe_v6) > 0) ? safe_v6[0] : null);
	let side_lan_risk = false;
	if (topology == 'side' && chosen) {
		let cb = iptoarr(chosen);
		if (cb && length(cb) == 4) {
			for (let net in lan_v4_nets) {
				if (ip_in_v4_cidr(cb, net.bytes, net.prefix)) {
					side_lan_risk = true;
					break;
				}
			}
		}
	}

	return {
		server: chosen,
		candidates_v4: safe_v4,
		candidates_v6: safe_v6,
		side_lan_risk: side_lan_risk
	};
}

function remove_tree(path) {
	if (type(path) != 'string' || length(path) == 0)
		return true;

	let st = fs.lstat(path);
	if (!st)
		return true;

	if (st.type != 'directory')
		return fs.unlink(path);

	let entries = fs.lsdir(path);
	if (entries) {
		for (let entry in entries) {
			if (entry == '.' || entry == '..')
				continue;
			remove_tree(path + '/' + entry);
		}
	}

	return fs.rmdir(path);
}

function make_tmp_file_path(dir, prefix) {
	_cb_seq++;
	let pid_link = fs.readlink('/proc/self');
	let pid = (type(pid_link) == 'string' && length(pid_link) > 0) ? pid_link : '0';
	return sprintf('%s/%s.%s.%d.tmp', dir, prefix, pid, _cb_seq);
}

function run_cmd_capture(argv, timeout_ms) {
	let tmp_dir = getenv('TMPDIR') || '/tmp';
	common.ensure_dir(tmp_dir, 0755);

	let out_path = make_tmp_file_path(tmp_dir, 'nimbus-cmd');
	let fh = fs.open(out_path, 'wx', 0600);
	if (!fh)
		return { rc: -1, output: 'failed to create temporary output file' };
	fh.close();

	let sh_argv = [ '/bin/sh', '-c', 'out=$1; shift; exec "$@" >"$out" 2>&1', 'sh', out_path ];
	for (let a in argv)
		push(sh_argv, a);

	let rc = system(sh_argv, timeout_ms || CHECK_TIMEOUT_MS);
	let output = fs.readfile(out_path) || '';
	fs.unlink(out_path);

	return { rc: rc, output: trim(output) };
}

function probe_core_version(bin_path) {
	if (type(bin_path) != 'string' || length(bin_path) == 0)
		return fail(common.ERR_INVALID_ARG, 'sing-box bin_path is empty');

	let st = fs.stat(bin_path);
	if (!st || st.type != 'file' || !fs.access(bin_path, 'x'))
		return fail(common.ERR_NOT_FOUND, sprintf('sing-box binary not found or not executable: %s', bin_path));

	let res = run_cmd_capture([ bin_path, 'version' ], 10000);
	if (res.rc != 0)
		return fail(common.ERR_VALIDATE_FAILED, sprintf('sing-box version failed (rc=%d): %s', res.rc, res.output));

	let m = match(res.output, /sing-box\s+version\s+([0-9]+\.[0-9]+\.[0-9]+)/) ||
		match(res.output, /([0-9]+\.[0-9]+\.[0-9]+)/);
	if (!m)
		return fail(common.ERR_VALIDATE_FAILED, 'unable to parse sing-box version output');

	return { ok: true, version: m[1] };
}

function extract_fakeip(cfg) {
	let ipv4 = [];
	let ipv6 = [];
	let servers = cfg?.dns?.servers;

	if (type(servers) != 'array')
		return { ok: true, ipv4: ipv4, ipv6: ipv6 };

	for (let srv in servers) {
		if (type(srv) != 'object' || srv.type != 'fakeip')
			continue;

		if (exists(srv, 'inet4_range') && srv.inet4_range != null && srv.inet4_range !== '') {
			if (!is_valid_cidr(srv.inet4_range, 4))
				return fail(common.ERR_VALIDATE_FAILED, sprintf('invalid fakeip inet4_range: %s', '' + srv.inet4_range));
			push_unique(ipv4, trim(srv.inet4_range));
		}

		if (exists(srv, 'inet6_range') && srv.inet6_range != null && srv.inet6_range !== '') {
			if (!is_valid_cidr(srv.inet6_range, 6))
				return fail(common.ERR_VALIDATE_FAILED, sprintf('invalid fakeip inet6_range: %s', '' + srv.inet6_range));
			push_unique(ipv6, trim(srv.inet6_range));
		}
	}

	return { ok: true, ipv4: ipv4, ipv6: ipv6 };
}

function parse_clash_controller(ctrl) {
	let s = trim(ctrl);
	let m6 = match(s, /^\[([^\]]+)\]:([0-9]+)$/);
	if (m6) {
		let p = parse_port(m6[2], null);
		if (p == null)
			return null;
		return { listen: length(m6[1]) > 0 ? m6[1] : '::', port: p };
	}

	let m4 = match(s, /^([^:]*):([0-9]+)$/);
	if (m4) {
		let p = parse_port(m4[2], null);
		if (p == null)
			return null;
		return { listen: length(m4[1]) > 0 ? m4[1] : '::', port: p };
	}

	return null;
}

function probe_apis_internal(cfg) {
	let sb = {
		detected: false,
		scheme: null,
		listen: null,
		port: null,
		has_secret: false,
		dashboard_enabled: false,
		dashboard_path: null,
		loopback_only: false,
		no_secret: false
	};
	let sb_secret = null;

	if (type(cfg?.services) == 'array') {
		for (let svc in cfg.services) {
			if (type(svc) != 'object' || svc.type != 'api')
				continue;

			let listen = (type(svc.listen) == 'string' && length(trim(svc.listen)) > 0)
				? trim(svc.listen)
				: '127.0.0.1';
			let port = parse_port(svc.listen_port, null);
			let has_tls = (type(svc.tls) == 'object' && svc.tls.enabled === true);
			let secret = (type(svc.secret) == 'string' && length(svc.secret) > 0) ? svc.secret : null;
			let has_secret = (secret != null);

			let dash_enabled = false;
			if (svc.dashboard === true)
				dash_enabled = true;
			else if (type(svc.dashboard) == 'string' && length(trim(svc.dashboard)) > 0)
				dash_enabled = true;
			else if (type(svc.dashboard) == 'object' && svc.dashboard.enabled === true)
				dash_enabled = true;

			let loopback = is_loopback_addr(listen);
			sb = {
				detected: true,
				scheme: has_tls ? 'https' : 'http',
				listen: listen,
				port: port,
				has_secret: has_secret,
				dashboard_enabled: dash_enabled,
				dashboard_path: dash_enabled ? '/dashboard/' : null,
				loopback_only: loopback,
				no_secret: (!loopback && !has_secret)
			};
			sb_secret = secret;
			break;
		}
	}

	let clash = {
		detected: false,
		listen: null,
		port: null,
		has_secret: false,
		external_ui: false,
		loopback_only: false,
		no_secret: false
	};
	let clash_secret = null;

	let ca = cfg?.experimental?.clash_api;
	if (type(ca) == 'object' && type(ca.external_controller) == 'string' && length(trim(ca.external_controller)) > 0) {
		let parsed = parse_clash_controller(ca.external_controller);
		if (parsed) {
			let secret = (type(ca.secret) == 'string' && length(ca.secret) > 0) ? ca.secret : null;
			let has_secret = (secret != null);
			let has_ui = (type(ca.external_ui) == 'string' && length(trim(ca.external_ui)) > 0);
			let loopback = is_loopback_addr(parsed.listen);
			clash = {
				detected: true,
				listen: parsed.listen,
				port: parsed.port,
				has_secret: has_secret,
				external_ui: has_ui,
				loopback_only: loopback,
				no_secret: (!loopback && !has_secret)
			};
			clash_secret = secret;
		}
	}

	return {
		apis: {
			singbox_api: sb,
			clash_api: clash
		},
		secrets: {
			singbox_api_secret: sb_secret,
			clash_api_secret: clash_secret
		}
	};
}

function probe_apis(cfg) {
	return probe_apis_internal(cfg).apis;
}

function extract_api_secrets(cfg) {
	return probe_apis_internal(cfg).secrets;
}

function inbound_has_tag(inbound_val, tag) {
	if (type(inbound_val) == 'string')
		return (inbound_val == tag);

	if (type(inbound_val) == 'array')
		return (index(inbound_val, tag) >= 0);

	return false;
}

function has_hijack_dns_for_tag(rules, tag) {
	if (type(rules) != 'array')
		return false;

	for (let r in rules) {
		if (type(r) != 'object')
			continue;

		if (r.action == 'hijack-dns' && inbound_has_tag(r.inbound, tag))
			return true;

		if (r.type == 'logical' && type(r.rules) == 'array' && has_hijack_dns_for_tag(r.rules, tag))
			return true;
	}

	return false;
}

function remap_rules_recursive(rules, stripped_tags, replacement) {
	let out = [];
	for (let r in rules) {
		if (type(r) != 'object')
			continue;

		if (r.type == 'logical' && type(r.rules) == 'array') {
			r.rules = remap_rules_recursive(r.rules, stripped_tags, replacement);
			if (length(r.rules) == 0)
				continue;
		}

		if (exists(r, 'inbound')) {
			if (type(r.inbound) == 'string') {
				if (index(stripped_tags, r.inbound) >= 0) {
					r.inbound = deep_clone(replacement);
				} else if (length(r.inbound) == 0) {
					continue;
				}
			} else if (type(r.inbound) == 'array') {
				let mapped = [];
				for (let tag in r.inbound) {
					if (type(tag) != 'string' || length(tag) == 0)
						continue;
					if (index(stripped_tags, tag) >= 0) {
						for (let rep in replacement)
							push_unique(mapped, rep);
					} else {
						push_unique(mapped, tag);
					}
				}
				if (length(mapped) == 0)
					continue;
				r.inbound = mapped;
			}
		}

		push(out, r);
	}
	return out;
}

function has_other_ipv6_inbound(inbounds, kind, skip_idx) {
	for (let i = 0; i < length(inbounds); i++) {
		if (i == skip_idx)
			continue;
		let inb = inbounds[i];
		if (type(inb) != 'object' || inb.type != kind)
			continue;
		if (kind == 'tproxy' && !supports_udp(inb))
			continue;
		if (is_ipv6_listen(inb.listen))
			return true;
	}
	return false;
}

function has_quic_reject_rule(rules) {
	for (let r in rules) {
		if (type(r) != 'object' || r.action != 'reject')
			continue;
		if (r.protocol == 'quic')
			return true;
		if (type(r.protocol) == 'array' && index(r.protocol, 'quic') >= 0)
			return true;
	}
	return false;
}

function transform_config(raw_cfg, uci_cfg, opts) {
	if (type(raw_cfg) != 'object')
		return fail(common.ERR_VALIDATE_FAILED, 'source configuration top-level must be a JSON object');

	let options = opts || {};
	let cfg = deep_clone(raw_cfg);
	let g = uci_cfg?.global || {};
	let p = uci_cfg?.proxy || {};
	let d = uci_cfg?.dns || {};
	let warnings = [];

	let proxy_mode = g.proxy_mode || 'tproxy_redirect';
	if (proxy_mode != 'tproxy_redirect')
		return fail(common.ERR_VALIDATE_FAILED, sprintf('unsupported proxy_mode "%s" in v1.0', '' + proxy_mode));

	let ipv4_enable = (g.ipv4_enable != '0');
	let ipv6_enable = (g.ipv6_enable != '0');
	if (!ipv4_enable && !ipv6_enable)
		return fail(common.ERR_VALIDATE_FAILED, 'global.ipv4_enable and global.ipv6_enable cannot both be 0');

	let outbound_mark = common.hex_u32_parse(p.outbound_mark ?? common.DEFAULT_OUTBOUND_MARK);
	if (outbound_mark == null)
		return fail(common.ERR_VALIDATE_FAILED, sprintf('invalid proxy.outbound_mark: %s', '' + p.outbound_mark));

	let proxy_mark = common.hex_u32_parse(p.proxy_mark ?? common.DEFAULT_PROXY_MARK);
	if (proxy_mark == null)
		return fail(common.ERR_VALIDATE_FAILED, sprintf('invalid proxy.proxy_mark: %s', '' + p.proxy_mark));

	if (outbound_mark == proxy_mark)
		return fail(common.ERR_VALIDATE_FAILED, 'proxy.outbound_mark and proxy.proxy_mark must not be equal');

	let cfg_redirect_port = parse_port(p.redirect_port, common.DEFAULT_REDIRECT_PORT);
	if (cfg_redirect_port == null)
		return fail(common.ERR_VALIDATE_FAILED, sprintf('invalid proxy.redirect_port: %s', '' + p.redirect_port));

	let cfg_tproxy_port = parse_port(p.tproxy_port, common.DEFAULT_TPROXY_PORT);
	if (cfg_tproxy_port == null)
		return fail(common.ERR_VALIDATE_FAILED, sprintf('invalid proxy.tproxy_port: %s', '' + p.tproxy_port));

	let cfg_dns_port = parse_port(d.singbox_dns_port ?? d.listen_port, common.DEFAULT_DNS_PORT);
	if (cfg_dns_port == null)
		return fail(common.ERR_VALIDATE_FAILED, sprintf('invalid dns.singbox_dns_port: %s', '' + (d.singbox_dns_port ?? d.listen_port)));

	// Step 2: logging, route.default_mark, route.final
	let log_level = (type(g.log_level) == 'string' && index(VALID_LOG_LEVELS, g.log_level) >= 0)
		? g.log_level
		: 'warn';
	if (type(cfg.log) != 'object')
		cfg.log = {};
	cfg.log.disabled = false;
	cfg.log.level = log_level;
	cfg.log.output = common.LOG_FILE;
	cfg.log.timestamp = true;

	if (type(cfg.route) != 'object')
		cfg.route = {};
	if (type(cfg.route.rules) != 'array')
		cfg.route.rules = [];

	let effective_outbound_mark = outbound_mark;
	let raw_default_mark = cfg.route.default_mark;
	let is_unset_mark = (raw_default_mark == null || raw_default_mark === 0 ||
		raw_default_mark === '0' || raw_default_mark === '0x0' || raw_default_mark === '0X0');

	if (!is_unset_mark) {
		let parsed_dm = common.hex_u32_parse(raw_default_mark);
		if (parsed_dm == null)
			return fail(common.ERR_VALIDATE_FAILED, sprintf('invalid route.default_mark: %s', '' + raw_default_mark));
		if (parsed_dm == proxy_mark)
			return fail(common.ERR_VALIDATE_FAILED,
				sprintf('route.default_mark (%s) collides with proxy.proxy_mark (%s)',
					common.format_hex_u32(parsed_dm), common.format_hex_u32(proxy_mark)));
		effective_outbound_mark = parsed_dm;
	} else {
		cfg.route.default_mark = outbound_mark;
	}

	if (type(cfg.route.final) != 'string' || length(trim(cfg.route.final)) == 0) {
		if (type(cfg.outbounds) == 'array' && length(cfg.outbounds) > 0 &&
			type(cfg.outbounds[0]) == 'object' && type(cfg.outbounds[0].tag) == 'string' &&
			length(cfg.outbounds[0].tag) > 0) {
			cfg.route.final = cfg.outbounds[0].tag;
		}
	}

	// Step 3: transparent inbound reuse / auto-fill & tun conflict isolation
	let default_listen = ipv6_enable ? '::' : '0.0.0.0';
	let raw_inbounds = (type(cfg.inbounds) == 'array') ? cfg.inbounds : [];
	let surviving_inbounds = [];
	let stripped_tags = [];
	let migrated_sniff_tags = [];
	let used_ports = {};

	for (let inb in raw_inbounds) {
		if (type(inb) != 'object')
			continue;

		if (inb.type == 'tun') {
			if (type(inb.tag) == 'string' && length(inb.tag) > 0)
				push_unique(stripped_tags, inb.tag);
			continue;
		}

		let had_sniff = (inb.sniff === true);
		for (let df in DEPRECATED_INBOUND_FIELDS) {
			if (exists(inb, df))
				delete inb[df];
		}

		if (had_sniff && type(inb.tag) == 'string' && length(inb.tag) > 0)
			push_unique(migrated_sniff_tags, inb.tag);

		let lp = parse_port(inb.listen_port, null);
		if (lp != null)
			used_ports['' + lp] = inb.tag || inb.type;

		push(surviving_inbounds, inb);
	}
	cfg.inbounds = surviving_inbounds;

	let injected_tags = [];
	let inbound_sources = { redirect: null, tproxy: null, tun: null };
	let redirect_tag = null;
	let effective_redirect_port = null;
	let tproxy_tag = null;
	let effective_tproxy_port = null;

	// Find or inject redirect inbound
	let redir_idx = -1;
	for (let i = 0; i < length(cfg.inbounds); i++) {
		if (cfg.inbounds[i].type == 'redirect') {
			redir_idx = i;
			break;
		}
	}

	if (redir_idx >= 0) {
		let r_inb = cfg.inbounds[redir_idx];
		let r_port = parse_port(r_inb.listen_port, null);
		if (r_port == null)
			return fail(common.ERR_VALIDATE_FAILED, 'existing redirect inbound has invalid listen_port');

		if (type(r_inb.tag) != 'string' || length(r_inb.tag) == 0)
			r_inb.tag = common.TAG_REDIRECT_IN;
		redirect_tag = r_inb.tag;
		effective_redirect_port = r_port;
		inbound_sources.redirect = 'user';

		if (is_loopback_addr(r_inb.listen)) {
			push(warnings, sprintf('redirect inbound "%s" loopback listen "%s" rewritten to "%s"',
				redirect_tag, r_inb.listen, default_listen));
			r_inb.listen = default_listen;
		} else if (ipv6_enable && r_inb.listen == '0.0.0.0' && !has_other_ipv6_inbound(cfg.inbounds, 'redirect', redir_idx)) {
			push(warnings, sprintf('redirect inbound "%s" listens on "0.0.0.0" while ipv6_enable=1; IPv6 TCP redirect is not covered',
				redirect_tag));
		}
	} else {
		if (exists(used_ports, '' + cfg_redirect_port))
			return fail(common.ERR_VALIDATE_FAILED,
				sprintf('proxy.redirect_port (%d) collides with existing inbound "%s"',
					cfg_redirect_port, used_ports['' + cfg_redirect_port]));

		push(cfg.inbounds, {
			type: 'redirect',
			tag: common.TAG_REDIRECT_IN,
			listen: default_listen,
			listen_port: cfg_redirect_port
		});
		used_ports['' + cfg_redirect_port] = common.TAG_REDIRECT_IN;
		redirect_tag = common.TAG_REDIRECT_IN;
		effective_redirect_port = cfg_redirect_port;
		inbound_sources.redirect = 'auto';
		push(injected_tags, redirect_tag);
	}

	// Find or inject UDP-capable tproxy inbound
	let tp_idx = -1;
	for (let i = 0; i < length(cfg.inbounds); i++) {
		let inb = cfg.inbounds[i];
		if (inb.type == 'tproxy' && supports_udp(inb)) {
			tp_idx = i;
			break;
		}
	}

	if (tp_idx >= 0) {
		let t_inb = cfg.inbounds[tp_idx];
		let t_port = parse_port(t_inb.listen_port, null);
		if (t_port == null)
			return fail(common.ERR_VALIDATE_FAILED, 'existing tproxy inbound has invalid listen_port');

		if (type(t_inb.tag) != 'string' || length(t_inb.tag) == 0)
			t_inb.tag = common.TAG_TPROXY_IN;
		tproxy_tag = t_inb.tag;
		effective_tproxy_port = t_port;
		inbound_sources.tproxy = 'user';

		if (is_loopback_addr(t_inb.listen)) {
			push(warnings, sprintf('tproxy inbound "%s" loopback listen "%s" rewritten to "%s"',
				tproxy_tag, t_inb.listen, default_listen));
			t_inb.listen = default_listen;
		} else if (ipv6_enable && t_inb.listen == '0.0.0.0' && !has_other_ipv6_inbound(cfg.inbounds, 'tproxy', tp_idx)) {
			push(warnings, sprintf('tproxy inbound "%s" listens on "0.0.0.0" while ipv6_enable=1; IPv6 UDP tproxy is not covered',
				tproxy_tag));
		}
	} else {
		if (exists(used_ports, '' + cfg_tproxy_port))
			return fail(common.ERR_VALIDATE_FAILED,
				sprintf('proxy.tproxy_port (%d) collides with existing inbound "%s"',
					cfg_tproxy_port, used_ports['' + cfg_tproxy_port]));

		push(cfg.inbounds, {
			type: 'tproxy',
			tag: common.TAG_TPROXY_IN,
			listen: default_listen,
			listen_port: cfg_tproxy_port,
			network: 'udp'
		});
		used_ports['' + cfg_tproxy_port] = common.TAG_TPROXY_IN;
		tproxy_tag = common.TAG_TPROXY_IN;
		effective_tproxy_port = cfg_tproxy_port;
		inbound_sources.tproxy = 'auto';
		push(injected_tags, tproxy_tag);
	}

	if (length(stripped_tags) > 0) {
		let rep_tags = [ redirect_tag, tproxy_tag ];
		cfg.route.rules = remap_rules_recursive(cfg.route.rules, stripped_tags, rep_tags);
		if (type(cfg.dns) == 'object' && type(cfg.dns.rules) == 'array')
			cfg.dns.rules = remap_rules_recursive(cfg.dns.rules, stripped_tags, rep_tags);
	}

	// Step 4: local DNS inbound & DNS loop prevention (when dns.mode == 'singbox' or global.proxy_local == '1')
	let effective_dns_port = null;
	let local_dns_source = 'none';
	let local_dns_server = null;
	let dns_mode = d.mode || 'none';
	let hijack_lan_dns = (d.hijack_lan_dns == '1' || d.hijack_lan_dns === 1 || d.hijack_lan_dns === true);
	if (hijack_lan_dns && dns_mode == 'none') {
		push(warnings,
			'dns.hijack_lan_dns="1" is enabled while dns.mode="none": intercepted LAN DNS queries go to system dnsmasq using unproxied upstream resolvers unless dnsmasq is externally configured'
		);
	}
	let proxy_local = (g.proxy_local == '1' || g.proxy_local === 1 || g.proxy_local === true ||
		g.router_proxy == '1' || g.router_proxy === 1 || g.router_proxy === true);

	let dns_servers = cfg?.dns?.servers;
	if (dns_mode == 'singbox' && (type(dns_servers) != 'array' || length(dns_servers) == 0))
		return fail(common.ERR_VALIDATE_FAILED, 'dns.servers must be non-empty when dns.mode is "singbox"', warnings);

	if ((dns_mode == 'singbox' || proxy_local) && type(dns_servers) == 'array' && length(dns_servers) > 0) {
		let local_servers = [];
		for (let srv in dns_servers) {
			if (type(srv) == 'object' && (srv.type == 'local' || srv.address == 'local'))
				push(local_servers, srv);
		}

		if (length(local_servers) > 0) {
			let local_policy = lc(trim('' + (d.local_dns_policy || 'auto')));
			if (local_policy != 'auto' && local_policy != 'fallback' && local_policy != 'reject')
				local_policy = 'auto';

			if (local_policy == 'reject') {
				let loop_msg = (dns_mode == 'singbox')
					? 'dns.servers contains type "local" upstream which causes a DNS loopback loop with dnsmasq when dns.mode="singbox"'
					: 'dns.servers contains type "local" upstream which causes an output_udp/dnsmasq bootstrap loop when global.proxy_local="1"';
				push(warnings, loop_msg);
				return fail(common.ERR_VALIDATE_FAILED, loop_msg, warnings);
			}

			let raw_fb = exists(d, 'local_fallback_server') ? trim('' + (d.local_fallback_server ?? '')) : '223.5.5.5';
			let fb_res = null;
			if (length(raw_fb) > 0) {
				fb_res = validate_upstream_ip(raw_fb, null, ipv6_enable);
				if (!fb_res) {
					return fail(common.ERR_VALIDATE_FAILED,
						sprintf('dns.local_fallback_server "%s" is not a valid non-loopback unicast IP for current IPv4/IPv6 settings', raw_fb),
						warnings);
				}
			}

			if (local_policy == 'fallback') {
				if (!fb_res)
					return fail(common.ERR_VALIDATE_FAILED,
						'dns.local_fallback_server is required when dns.local_dns_policy="fallback"',
						warnings);
				local_dns_server = fb_res.ip;
				local_dns_source = 'fallback';
				push(warnings, sprintf('rewrote "local" DNS server(s) to configured direct DNS "%s"', local_dns_server));
			} else {
				let wan_res = resolve_wan_upstream_dns(uci_cfg, options);
				if (wan_res.server) {
					local_dns_server = wan_res.server;
					local_dns_source = 'wan';
					push(warnings, sprintf('rewrote "local" DNS server(s) to detected WAN upstream "%s"', local_dns_server));
					if (wan_res.side_lan_risk) {
						push(warnings, sprintf(
							'side-router mode uses LAN-subnet upstream DNS "%s"; ensure your main router DNS does not forward back to this device to avoid a DNS loop',
							local_dns_server));
					}
				} else if (fb_res) {
					local_dns_server = fb_res.ip;
					local_dns_source = 'fallback';
					push(warnings, sprintf(
						'no safe non-loopback WAN DNS detected; using fallback DNS "%s" for "local" server(s)',
						local_dns_server));
				} else {
					let loop_msg = 'dns.servers contains type "local" upstream, no safe non-loopback WAN DNS was found, and dns.local_fallback_server is empty';
					push(warnings, loop_msg);
					return fail(common.ERR_VALIDATE_FAILED, loop_msg, warnings);
				}
			}

			for (let srv in local_servers) {
				srv.type = 'udp';
				srv.server = local_dns_server;
				delete srv.address;
				delete srv.prefer_go;
				delete srv.address_resolver;
				delete srv.strategy;
			}
		}
	}

	if (dns_mode == 'singbox') {
		let reused_dns = null;
		for (let inb in cfg.inbounds) {
			if (inb.type != 'direct')
				continue;
			if (!is_ipv4_loopback_reachable(inb.listen) || !supports_udp(inb))
				continue;
			if (type(inb.tag) != 'string' || length(inb.tag) == 0)
				continue;
			if (has_hijack_dns_for_tag(cfg.route.rules, inb.tag)) {
				reused_dns = inb;
				break;
			}
		}

		if (reused_dns) {
			let d_port = parse_port(reused_dns.listen_port, null);
			if (d_port == null)
				return fail(common.ERR_VALIDATE_FAILED, 'existing direct DNS inbound has invalid listen_port', warnings);
			effective_dns_port = d_port;
		} else {
			if (exists(used_ports, '' + cfg_dns_port))
				return fail(common.ERR_VALIDATE_FAILED,
					sprintf('dns.singbox_dns_port (%d) collides with existing inbound "%s"',
						cfg_dns_port, used_ports['' + cfg_dns_port]),
					warnings);

			push(cfg.inbounds, {
				type: 'direct',
				tag: common.TAG_DNS_IN,
				listen: '127.0.0.1',
				listen_port: cfg_dns_port
			});
			used_ports['' + cfg_dns_port] = common.TAG_DNS_IN;
			splice(cfg.route.rules, 0, 0, {
				inbound: [ common.TAG_DNS_IN ],
				action: 'hijack-dns'
			});
			effective_dns_port = cfg_dns_port;
		}
	}

	// Step 5: modern route rule actions (sniff & block_quic)
	let has_global_sniff = false;
	let covered_sniff_tags = {};
	for (let r in cfg.route.rules) {
		if (type(r) != 'object' || r.action != 'sniff')
			continue;
		if (!exists(r, 'inbound') || r.inbound == null ||
			(type(r.inbound) == 'array' && length(r.inbound) == 0)) {
			has_global_sniff = true;
			break;
		}
		if (type(r.inbound) == 'string' && length(r.inbound) > 0)
			covered_sniff_tags[r.inbound] = true;
		else if (type(r.inbound) == 'array') {
			for (let t in r.inbound) {
				if (type(t) == 'string' && length(t) > 0)
					covered_sniff_tags[t] = true;
			}
		}
	}

	let want_sniff_tags = [];
	for (let t in injected_tags)
		push_unique(want_sniff_tags, t);
	if (p.block_quic == '1' || p.sniff == '1') {
		push_unique(want_sniff_tags, redirect_tag);
		push_unique(want_sniff_tags, tproxy_tag);
	}
	for (let t in migrated_sniff_tags)
		push_unique(want_sniff_tags, t);

	let uncovered_sniff = [];
	if (!has_global_sniff) {
		for (let t in want_sniff_tags) {
			if (!exists(covered_sniff_tags, t))
				push_unique(uncovered_sniff, t);
		}
	}

	let ins_idx = 0;
	while (ins_idx < length(cfg.route.rules) &&
		type(cfg.route.rules[ins_idx]) == 'object' &&
		cfg.route.rules[ins_idx].action == 'hijack-dns') {
		ins_idx++;
	}

	if (length(uncovered_sniff) > 0) {
		splice(cfg.route.rules, ins_idx, 0, {
			inbound: uncovered_sniff,
			action: 'sniff'
		});
		ins_idx++;
	} else if (ins_idx < length(cfg.route.rules) &&
		type(cfg.route.rules[ins_idx]) == 'object' &&
		cfg.route.rules[ins_idx].action == 'sniff') {
		ins_idx++;
	}

	if (p.block_quic == '1' && !has_quic_reject_rule(cfg.route.rules)) {
		splice(cfg.route.rules, ins_idx, 0, {
			protocol: 'quic',
			action: 'reject'
		});
	}

	// Step 6: extract Fake-IP ranges & emit Fake-IP interaction warnings
	let fakeip_res = extract_fakeip(cfg);
	if (!fakeip_res.ok)
		return fail(common.ERR_VALIDATE_FAILED, fakeip_res.error, warnings);

	let has_active_fakeip = (ipv4_enable && length(fakeip_res.ipv4) > 0) ||
		(ipv6_enable && length(fakeip_res.ipv6) > 0);
	if (has_active_fakeip) {
		let port_mode = trim('' + (p.port_filter_mode || 'all'));
		if (port_mode == 'include' || port_mode == 'exclude') {
			push(warnings, sprintf(
				'Fake-IP is enabled with proxy.port_filter_mode="%s": Fake-IP domain connections must enter sing-box to resolve virtual IPs; kernel port filtering applies only to real-IP traffic',
				port_mode
			));
		}

		if (dns_mode == 'singbox') {
			let raw_lm = lc(trim('' + (p.lan_device_mode ?? p.lan_proxy_mode ?? g.lan_device_mode ?? g.lan_proxy_mode ?? 'default_proxy')));
			let has_bypass_dev = (raw_lm == 'default_bypass' || raw_lm == 'proxy_listed');
			if (!has_bypass_dev) {
				for (let k, sec in uci_cfg) {
					if (type(sec) != 'object' || sec['.type'] != 'lan_device')
						continue;
					if (sec.enabled == '0' || sec.enabled === false)
						continue;
					let pol = lc(trim('' + (sec.policy ?? 'bypass')));
					if (pol == '' || pol == 'bypass') {
						has_bypass_dev = true;
						break;
					}
				}
			}
			if (has_bypass_dev) {
				push(warnings,
					'Fake-IP is active with dns.mode="singbox" and direct-bypass LAN device policy: bypassed devices querying router DNS will receive non-routable Fake-IPs unless assigned a real upstream DNS or excluded via sing-box dns.rules'
				);
			}
		}
	}

	// Step 7: dual API & dashboard probe
	let apis = probe_apis(cfg);

	return {
		ok: true,
		config: cfg,
		context: {
			core_version: options.core_version || null,
			effective_outbound_mark: effective_outbound_mark,
			effective_redirect_port: effective_redirect_port,
			effective_tproxy_port: effective_tproxy_port,
			effective_tun_iface: null,
			effective_dns_port: effective_dns_port,
			local_dns_source: local_dns_source,
			local_dns_server: local_dns_server,
			inbound_sources: inbound_sources,
			fakeip: {
				ipv4: fakeip_res.ipv4,
				ipv6: fakeip_res.ipv6
			},
			apis: apis,
			warnings: warnings
		}
	};
}

function run_singbox_check(bin_path, config_path, check_dir) {
	if (type(bin_path) != 'string' || length(bin_path) == 0 || !fs.access(bin_path, 'x'))
		return fail(common.ERR_NOT_FOUND, sprintf('sing-box binary not found or not executable: %s', '' + bin_path));

	let cdir = check_dir || common.CHECK_DIR;
	remove_tree(cdir);
	if (!common.ensure_dir(cdir, 0700))
		return fail(common.ERR_INTERNAL, sprintf('failed to prepare check directory: %s', cdir));

	let res = run_cmd_capture([ bin_path, 'check', '-c', config_path, '-D', cdir ], CHECK_TIMEOUT_MS);
	remove_tree(cdir);

	if (res.rc != 0) {
		return fail(common.ERR_VALIDATE_FAILED,
			length(res.output) > 0 ? res.output : sprintf('sing-box check exited with code %d', res.rc));
	}

	return { ok: true };
}

function build_config(opts) {
	let options = opts || {};
	let uci_cfg = options.uci || common.uci_get_all('nimbus', options.uci_confdir, options.uci_savedir);
	let bin_path = options.bin_path || uci_cfg?.core?.bin_path || '/etc/nimbus/bin/sing-box';
	let validate_only = (options.validate_only === true);
	let skip_check = (options.skip_check === true);

	let core_version = options.core_version || null;
	if (!skip_check || !core_version) {
		let ver = probe_core_version(bin_path);
		if (!ver.ok) {
			if (!skip_check)
				return ver;
		} else {
			core_version = ver.version;
		}
	}

	let has_raw_config = (exists(options, 'raw_config') && options.raw_config != null);
	let has_profile_path = (type(options.profile_path) == 'string' && length(options.profile_path) > 0);
	let explicit_composer = (options.compose_from_composer === true ||
		options.composer != null ||
		(type(options.composer_file) == 'string' && length(options.composer_file) > 0) ||
		(type(options.composer_id) == 'string' && length(options.composer_id) > 0));

	let use_composer = explicit_composer;
	let resolved_target = null;
	if (!explicit_composer && !has_raw_config && !has_profile_path) {
		resolved_target = common.resolve_active_target(uci_cfg, {
			composers_dir: options.composers_dir,
			profiles_dir: options.profiles_dir
		});
		if (!resolved_target.ok)
			return resolved_target;
		use_composer = (resolved_target.kind == 'composer');
	}

	let raw_cfg = null;
	let stage_a_warnings = [];
	let composer_summary = null;
	let composed_snapshot = null;

	if (use_composer) {
		let comp_res = cc.compose(uci_cfg, {
			composer: options.composer,
			composer_file: options.composer_file || (resolved_target ? resolved_target.path : null),
			composer_id: options.composer_id,
			composers_dir: options.composers_dir,
			profiles_dir: options.profiles_dir,
			override_profile_docs: options.override_profile_docs
		});
		if (!comp_res.ok)
			return comp_res;
		raw_cfg = comp_res.config;
		stage_a_warnings = comp_res.warnings || [];
		composer_summary = comp_res.summary || null;
		composed_snapshot = cc.deep_clone(raw_cfg);
	} else if (has_raw_config) {
		if (type(options.raw_config) == 'string') {
			try {
				raw_cfg = json(options.raw_config);
			} catch (e) {
				return fail(common.ERR_VALIDATE_FAILED, sprintf('invalid source JSON: %s', '' + e));
			}
		} else {
			raw_cfg = options.raw_config;
		}
	} else {
		let p_path = has_profile_path ? options.profile_path : resolved_target.path;
		let raw_text = fs.readfile(p_path);
		if (raw_text == null)
			return fail(common.ERR_NOT_FOUND, sprintf('failed to read profile: %s', p_path));

		try {
			raw_cfg = json(raw_text);
		} catch (e) {
			return fail(common.ERR_VALIDATE_FAILED, sprintf('invalid profile JSON (%s): %s', p_path, '' + e));
		}
	}

	let tr = transform_config(raw_cfg, uci_cfg, {
		core_version: core_version,
		uci_confdir: options.uci_confdir,
		uci_savedir: options.uci_savedir,
		wan_dns_servers: options.wan_dns_servers,
		resolv_auto_path: options.resolv_auto_path,
		ubus_dump: options.ubus_dump,
		skip_ubus: options.skip_ubus,
		skip_network_uci: options.skip_network_uci
	});
	if (!tr.ok) {
		if (length(stage_a_warnings) > 0)
			tr.warnings = [ ...stage_a_warnings, ...(tr.warnings || []) ];
		return tr;
	}

	if (length(stage_a_warnings) > 0)
		tr.context.warnings = [ ...stage_a_warnings, ...(tr.context.warnings || []) ];
	tr.context.active_kind = use_composer ? 'composer' : 'profile';
	tr.context.composer = use_composer ? composer_summary : null;
	if (use_composer) {
		tr.composed_config = composed_snapshot;
		tr.composer_summary = composer_summary;
	}

	if (skip_check && validate_only)
		return tr;

	let output_path = options.output_path || common.CONFIG_FILE;
	let tmp_dir = validate_only ? (getenv('TMPDIR') || '/tmp') : fs.dirname(output_path);
	if (!common.ensure_dir(tmp_dir, 0755))
		return fail(common.ERR_INTERNAL, sprintf('failed to create directory: %s', tmp_dir));

	let tmp_path = validate_only
		? make_tmp_file_path(tmp_dir, 'nimbus-validate')
		: make_tmp_file_path(tmp_dir, fs.basename(output_path));

	let fh = fs.open(tmp_path, 'wx', 0600);
	if (!fh)
		return fail(common.ERR_INTERNAL, sprintf('failed to create temp config file: %s', tmp_path));

	let payload = sprintf('%.2J\n', tr.config);
	let written = fh.write(payload);
	if (written == null || written != length(payload) || fh.flush() === false) {
		fh.close();
		fs.unlink(tmp_path);
		return fail(common.ERR_INTERNAL, 'failed to write temp config file');
	}
	if (!fh.close()) {
		fs.unlink(tmp_path);
		return fail(common.ERR_INTERNAL, 'failed to close temp config file');
	}
	fs.chmod(tmp_path, 0600);

	if (!skip_check) {
		let chk = run_singbox_check(bin_path, tmp_path, options.check_dir);
		if (!chk.ok) {
			fs.unlink(tmp_path);
			let err_res = fail(chk.code, chk.error, tr.context.warnings);
			if (use_composer) {
				err_res.composed_config = composed_snapshot;
				err_res.effective_config = tr.config;
				err_res.summary = composer_summary;
			}
			return err_res;
		}
	}

	if (validate_only) {
		fs.unlink(tmp_path);
		return tr;
	}

	if (!fs.chmod(tmp_path, 0600) || !fs.rename(tmp_path, output_path)) {
		fs.unlink(tmp_path);
		return fail(common.ERR_INTERNAL, sprintf('failed to publish runtime config to %s', output_path));
	}

	tr.output_path = output_path;
	return tr;
}

export {
	probe_core_version,
	resolve_wan_upstream_dns,
	extract_fakeip,
	probe_apis,
	extract_api_secrets,
	transform_config,
	run_singbox_check,
	build_config
};
