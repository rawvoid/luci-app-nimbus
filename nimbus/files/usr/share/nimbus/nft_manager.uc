'use strict';

import * as fs from 'fs';
import * as ubus from 'ubus';
import * as common from 'common';

const DEFAULT_NFT_BIN = '/usr/sbin/nft';
const NFT_TIMEOUT_MS = 10000;

const RELOADABLE_SETS = [
	'lan_ifaces',
	'bypass_v4',
	'bypass_v6',
	'lan_v4',
	'lan_v6',
	'wan_v4',
	'wan_v6',
	'fakeip_v4',
	'fakeip_v6',
	'filter_tcp_ports',
	'filter_udp_ports'
];

let _nft_seq = 0;

function push_unique(arr, val) {
	if (val != null && val !== '' && index(arr, val) < 0)
		push(arr, val);
}

function to_list(val, fallback) {
	if (type(val) == 'array') {
		let out = [];
		for (let item in val) {
			if (item != null && length(trim('' + item)) > 0)
				push_unique(out, trim('' + item));
		}
		return length(out) > 0 ? out : (fallback || []);
	}

	if (type(val) == 'string' && length(trim(val)) > 0) {
		let out = [];
		for (let part in split(trim(val), /[ \t\r\n,]+/)) {
			if (length(part) > 0)
				push_unique(out, part);
		}
		return length(out) > 0 ? out : (fallback || []);
	}

	return fallback || [];
}

function parse_port_num(s) {
	if (type(s) == 'int')
		return (s >= 1 && s <= 65535) ? s : null;
	if (type(s) != 'string' || !match(s, /^[0-9]+$/))
		return null;
	let n = int(s, 10);
	return (!common.isnan(n) && n >= 1 && n <= 65535) ? n : null;
}

function parse_port_elements(val) {
	let items = to_list(val, []);
	let out = [];

	for (let raw in items) {
		let s = trim('' + raw);
		let mr = match(s, /^([0-9]+)-([0-9]+)$/);
		if (mr) {
			let p1 = parse_port_num(mr[1]);
			let p2 = parse_port_num(mr[2]);
			if (p1 != null && p2 != null && p1 <= p2)
				push_unique(out, (p1 == p2) ? ('' + p1) : sprintf('%d-%d', p1, p2));
			continue;
		}

		let p = parse_port_num(s);
		if (p != null)
			push_unique(out, '' + p);
	}

	return out;
}

function is_valid_mac(mac) {
	return (type(mac) == 'string' && match(trim(mac), /^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$/) != null);
}

function is_valid_ifname(name) {
	if (type(name) != 'string')
		return false;
	let s = trim(name);
	if (length(s) < 1 || length(s) > 15 || s == '.' || s == '..')
		return false;
	return (match(s, /^[A-Za-z0-9_.+-]+$/) != null);
}

function filter_ifname_list(list) {
	let out = [];
	for (let item in to_list(list, [])) {
		if (is_valid_ifname(item))
			push_unique(out, trim(item));
	}
	return out;
}

function classify_ip_or_cidr(text) {
	if (type(text) != 'string')
		return null;

	let s = trim(text);
	if (length(s) == 0)
		return null;

	let parts = split(s, '/');
	if (length(parts) > 2)
		return null;

	let bytes = iptoarr(parts[0]);
	if (!bytes)
		return null;

	let fam = (length(bytes) == 4) ? 4 : ((length(bytes) == 16) ? 6 : 0);
	if (fam == 0)
		return null;

	let canon_ip = arrtoip(bytes);
	if (!canon_ip)
		return null;

	if (length(parts) == 2) {
		if (!match(parts[1], /^[0-9]+$/))
			return null;
		let plen = int(parts[1], 10);
		let max_plen = (fam == 4) ? 32 : 128;
		if (common.isnan(plen) || plen <= 0 || plen > max_plen)
			return null;
		return { family: fam, value: sprintf('%s/%d', canon_ip, plen) };
	}

	return { family: fam, value: canon_ip };
}

function filter_ip_list(list, family) {
	let out = [];
	for (let item in to_list(list, [])) {
		let c = classify_ip_or_cidr(item);
		if (c && c.family == family)
			push_unique(out, c.value);
	}
	return out;
}

function filter_mac_list(list) {
	let out = [];
	for (let item in to_list(list, [])) {
		if (is_valid_mac(item))
			push_unique(out, lc(trim(item)));
	}
	return out;
}

function netmask_to_prefix(mask_str) {
	let b = iptoarr(mask_str);
	if (!b || length(b) != 4)
		return null;

	let bits = 0;
	let seen_zero = false;
	for (let byte in b) {
		for (let bit = 7; bit >= 0; bit--) {
			if ((byte & (1 << bit)) != 0) {
				if (seen_zero)
					return null;
				bits++;
			} else {
				seen_zero = true;
			}
		}
	}
	return bits;
}

function normalize_lan_mode(raw) {
	let m = lc(trim('' + (raw || 'default_proxy')));
	if (m == 'default_bypass' || m == 'proxy_listed')
		return 'default_bypass';
	return 'default_proxy';
}

function normalize_port_mode(raw) {
	let m = trim('' + (raw || 'all'));
	if (m == 'include' || m == 'exclude')
		return m;
	return 'all';
}

function resolve_uci_iface_devices(ifname, net_uci, depth) {
	if ((depth ?? 0) > 3 || type(net_uci) != 'object' || type(ifname) != 'string')
		return [];

	let sec = net_uci[ifname];
	if (type(sec) != 'object')
		return [];

	let out = [];
	let raw_dev = sec.device || sec.ifname;
	for (let tok in to_list(raw_dev, [])) {
		if (substr(tok, 0, 1) == '@') {
			let target = substr(tok, 1);
			if (length(target) > 0 && target != ifname) {
				for (let sub in resolve_uci_iface_devices(target, net_uci, (depth ?? 0) + 1))
					push_unique(out, sub);
			}
		} else if (is_valid_ifname(tok)) {
			push_unique(out, trim(tok));
		}
	}
	return out;
}

function query_network_context_sources(lan_names, wan_names, topology, opts) {
	let options = opts || {};
	let net_uci = common.uci_get_all('network', options.uci_confdir, options.uci_savedir);
	let lan_ifaces = [];
	let lan_v4 = [];
	let lan_v6 = [];
	let wan_v4 = [];
	let wan_v6 = [];

	let dump = options.ubus_dump;
	if (dump == null) {
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

	let ubus_ifaces = {};
	if (type(dump?.interface) == 'array') {
		for (let item in dump.interface) {
			if (type(item) == 'object' && type(item.interface) == 'string')
				ubus_ifaces[item.interface] = item;
		}
	}

	for (let lname in lan_names) {
		let uitem = ubus_ifaces[lname];
		let resolved_dev = false;
		let has_ubus_lan_ips = false;
		if (type(uitem) == 'object') {
			let ldev = uitem.l3_device || uitem.device;
			if (is_valid_ifname(ldev)) {
				push_unique(lan_ifaces, trim(ldev));
				resolved_dev = true;
			}
			if (type(uitem['ipv4-address']) == 'array') {
				for (let a4 in uitem['ipv4-address']) {
					let c = classify_ip_or_cidr(sprintf('%s/%s', '' + a4?.address, '' + (a4?.mask ?? 24)));
					if (c && c.family == 4) {
						push_unique(lan_v4, c.value);
						has_ubus_lan_ips = true;
					}
				}
			}
			for (let k6 in [ 'ipv6-address', 'ipv6-prefix-assignment' ]) {
				if (type(uitem[k6]) != 'array')
					continue;
				for (let a6 in uitem[k6]) {
					let c = classify_ip_or_cidr(sprintf('%s/%s', '' + a6?.address, '' + (a6?.mask ?? 64)));
					if (c && c.family == 6) {
						push_unique(lan_v6, c.value);
						has_ubus_lan_ips = true;
					}
				}
			}
			if (uitem.up === true)
				has_ubus_lan_ips = true;
		}

		let sec = net_uci?.[lname];
		let has_uci_dev = false;
		if (type(sec) == 'object') {
			let raw_dev = sec.device || sec.ifname;
			has_uci_dev = (type(raw_dev) == 'string' && length(trim(raw_dev)) > 0);
			if (!resolved_dev && has_uci_dev) {
				for (let d in resolve_uci_iface_devices(lname, net_uci, 0)) {
					push_unique(lan_ifaces, d);
					resolved_dev = true;
				}
			}
			if (!has_ubus_lan_ips) {
				for (let ip4 in to_list(sec.ipaddr, [])) {
					if (index(ip4, '/') >= 0) {
						let c = classify_ip_or_cidr(ip4);
						if (c && c.family == 4)
							push_unique(lan_v4, c.value);
					} else {
						let plen = netmask_to_prefix(sec.netmask || '255.255.255.0') ?? 24;
						let c = classify_ip_or_cidr(sprintf('%s/%d', ip4, plen));
						if (c && c.family == 4)
							push_unique(lan_v4, c.value);
					}
				}
				for (let ip6 in to_list(sec.ip6addr, [])) {
					let c = classify_ip_or_cidr(ip6);
					if (c && c.family == 6)
						push_unique(lan_v6, c.value);
				}
			}
		}

		if (!resolved_dev && !has_uci_dev) {
			let fb_dev = (lname == 'lan') ? 'br-lan' : trim('' + lname);
			if (is_valid_ifname(fb_dev))
				push_unique(lan_ifaces, fb_dev);
		}
	}

	if (topology == 'main') {
		for (let wname in wan_names) {
			let uitem = ubus_ifaces[wname];
			let has_ubus_wan = false;
			if (type(uitem) == 'object') {
				if (type(uitem['ipv4-address']) == 'array') {
					for (let a4 in uitem['ipv4-address']) {
						let c = classify_ip_or_cidr('' + a4?.address);
						if (c && c.family == 4) {
							push_unique(wan_v4, c.value);
							has_ubus_wan = true;
						}
					}
				}
				if (type(uitem['ipv6-address']) == 'array') {
					for (let a6 in uitem['ipv6-address']) {
						let c = classify_ip_or_cidr('' + a6?.address);
						if (c && c.family == 6) {
							push_unique(wan_v6, c.value);
							has_ubus_wan = true;
						}
					}
				}
				for (let k6 in [ 'ipv6-prefix', 'ipv6-prefix-assignment' ]) {
					if (type(uitem[k6]) != 'array')
						continue;
					for (let p6 in uitem[k6]) {
						let c = classify_ip_or_cidr(sprintf('%s/%s', '' + p6?.address, '' + (p6?.mask ?? 64)));
						if (c && c.family == 6) {
							push_unique(wan_v6, c.value);
							has_ubus_wan = true;
						}
					}
				}
				if (uitem.up === true)
					has_ubus_wan = true;
			}

			if (has_ubus_wan)
				continue;

			let sec = net_uci?.[wname];
			if (type(sec) != 'object')
				continue;
			for (let ip4 in to_list(sec.ipaddr, [])) {
				let raw4 = (index(ip4, '/') >= 0) ? split(ip4, '/')[0] : ip4;
				let c = classify_ip_or_cidr(raw4);
				if (c && c.family == 4)
					push_unique(wan_v4, c.value);
			}
			for (let ip6 in to_list(sec.ip6addr, [])) {
				let raw6 = (index(ip6, '/') >= 0) ? split(ip6, '/')[0] : ip6;
				let c = classify_ip_or_cidr(raw6);
				if (c && c.family == 6)
					push_unique(wan_v6, c.value);
			}
			for (let p6 in to_list(sec.ip6prefix, [])) {
				let c = classify_ip_or_cidr(p6);
				if (c && c.family == 6)
					push_unique(wan_v6, c.value);
			}
		}
	}

	if (length(lan_ifaces) == 0)
		push(lan_ifaces, 'br-lan');

	return {
		lan_ifaces: lan_ifaces,
		lan_v4: lan_v4,
		lan_v6: lan_v6,
		wan_v4: wan_v4,
		wan_v6: wan_v6
	};
}

function resolve_network_context(uci_cfg, opts) {
	let options = opts || {};
	let g = uci_cfg?.global || {};
	let topology = (options.topology || g.topology || 'main') == 'side' ? 'side' : 'main';
	let lan_names = to_list(options.lan_interfaces ?? g.lan_interfaces, [ 'lan' ]);
	let wan_names = (topology == 'main')
		? to_list(options.wan_interfaces ?? g.wan_interfaces, [ 'wan', 'wan6' ])
		: [];

	let base = query_network_context_sources(lan_names, wan_names, topology, options);

	let lan_ifaces = (options.lan_ifaces != null) ? filter_ifname_list(options.lan_ifaces) : base.lan_ifaces;
	if (length(lan_ifaces) == 0)
		lan_ifaces = [ 'br-lan' ];

	let lan_v4 = (options.lan_v4 != null) ? filter_ip_list(options.lan_v4, 4) : base.lan_v4;
	let lan_v6 = (options.lan_v6 != null) ? filter_ip_list(options.lan_v6, 6) : base.lan_v6;
	let wan_v4 = (topology == 'main')
		? ((options.wan_v4 != null) ? filter_ip_list(options.wan_v4, 4) : base.wan_v4)
		: [];
	let wan_v6 = (topology == 'main')
		? ((options.wan_v6 != null) ? filter_ip_list(options.wan_v6, 6) : base.wan_v6)
		: [];

	return {
		topology: topology,
		lan_ifaces: lan_ifaces,
		lan_v4: lan_v4,
		lan_v6: lan_v6,
		wan_v4: wan_v4,
		wan_v6: wan_v6
	};
}

function collect_ordered_lan_devices(uci_cfg, opts) {
	let options = opts || {};

	if (type(options.lan_devices) == 'array') {
		let explicit = [];
		for (let d in options.lan_devices)
			push(explicit, d);
		return explicit;
	}

	let entries = [];
	if (type(uci_cfg) == 'object') {
		if (type(uci_cfg.lan_devices) == 'array') {
			for (let d in uci_cfg.lan_devices)
				push(entries, d);
		}
		let sec_objs = [];
		for (let k, sec in uci_cfg) {
			if (type(sec) == 'object' && sec['.type'] == 'lan_device')
				push(sec_objs, { seq: length(sec_objs), sec: sec });
		}
		sort(sec_objs, (a, b) => {
			let ai = (type(a.sec['.index']) == 'int') ? a.sec['.index'] : null;
			let bi = (type(b.sec['.index']) == 'int') ? b.sec['.index'] : null;
			if (ai != null && bi != null)
				return (ai != bi) ? (ai - bi) : (a.seq - b.seq);
			if (ai != null)
				return -1;
			if (bi != null)
				return 1;
			return a.seq - b.seq;
		});
		for (let item in sec_objs)
			push(entries, item.sec);
	}

	if (length(entries) == 0) {
		let leg_direct = {
			enabled: '1',
			policy: 'bypass',
			mac: options.lan_dev_direct_mac,
			ip: [ ...(to_list(options.lan_dev_direct_v4, [])), ...(to_list(options.lan_dev_direct_v6, [])) ]
		};
		if (length(to_list(leg_direct.mac, [])) > 0 || length(leg_direct.ip) > 0)
			push(entries, leg_direct);

		let leg_proxy = {
			enabled: '1',
			policy: 'proxy',
			mac: options.lan_dev_proxy_mac,
			ip: [ ...(to_list(options.lan_dev_proxy_v4, [])), ...(to_list(options.lan_dev_proxy_v6, [])) ]
		};
		if (length(to_list(leg_proxy.mac, [])) > 0 || length(leg_proxy.ip) > 0)
			push(entries, leg_proxy);
	}

	return entries;
}

/**
 * Parse enabled `lan_device` UCI entries into ordered first-match rules.
 */
function parse_device_rules(uci_cfg, opts) {
	let dev_entries = collect_ordered_lan_devices(uci_cfg, opts);
	let rules = [];

	for (let dev in dev_entries) {
		if (type(dev) != 'object' || dev.enabled == '0' || dev.enabled === false)
			continue;

		let raw_pol = trim('' + (dev.policy ?? ''));
		let pol = (length(raw_pol) > 0) ? lc(raw_pol) : 'bypass';
		if (pol != 'bypass' && pol != 'proxy')
			continue;

		let macs = filter_mac_list(dev.mac);
		let v4 = filter_ip_list(dev.ip, 4);
		let v6 = filter_ip_list(dev.ip, 6);
		if (length(macs) == 0 && length(v4) == 0 && length(v6) == 0)
			continue;

		push(rules, {
			policy: pol,
			macs: macs,
			v4: v4,
			v6: v6
		});
	}

	return rules;
}

function has_active_proxy_device_rules(dev_rules, ipv4_enable, ipv6_enable) {
	for (let r in dev_rules) {
		if (r.policy != 'proxy')
			continue;
		if (length(r.macs) > 0)
			return true;
		if (ipv4_enable && length(r.v4) > 0)
			return true;
		if (ipv6_enable && length(r.v6) > 0)
			return true;
	}
	return false;
}

function append_device_filter_rules(out, dev_rules, lan_mode, ipv4_enable, ipv6_enable, bypass_verdict, proxy_target_chain) {
	for (let r in dev_rules) {
		let action = bypass_verdict;
		if (r.policy == 'proxy') {
			if (!proxy_target_chain)
				continue;
			action = 'goto ' + proxy_target_chain;
		}
		for (let mac in r.macs)
			push(out, sprintf('\t\tether saddr %s %s', mac, action));
		if (ipv4_enable) {
			for (let ip4 in r.v4)
				push(out, sprintf('\t\tip saddr %s %s', ip4, action));
		}
		if (ipv6_enable) {
			for (let ip6 in r.v6)
				push(out, sprintf('\t\tip6 saddr %s %s', ip6, action));
		}
	}

	if (lan_mode == 'default_bypass') {
		push(out, '\t\t' + bypass_verdict);
	} else if (proxy_target_chain) {
		push(out, '\t\tgoto ' + proxy_target_chain);
	}
}

function append_daddr_bypass_lines(out, ipv4_enable, ipv6_enable, verdict) {
	for (let set_prefix in [ 'reserved', 'lan', 'wan', 'bypass' ]) {
		if (ipv4_enable)
			push(out, sprintf('\t\tip daddr @%s_v4 %s', set_prefix, verdict));
		if (ipv6_enable)
			push(out, sprintf('\t\tip6 daddr @%s_v6 %s', set_prefix, verdict));
	}
}

function build_lockdown_tail_lines(ipv4_enable, ipv6_enable) {
	let lines = [];
	append_daddr_bypass_lines(lines, ipv4_enable, ipv6_enable, 'return');
	push(lines, '\t\tcounter name "lockdown_dropped" reject with icmpx type admin-prohibited');
	return lines;
}

function build_tcp_tail_lines(ipv4_enable, ipv6_enable, port_mode, filter_tcp_ports, redirect_port) {
	let lines = [];

	if (ipv4_enable)
		push(lines, sprintf('\t\tip daddr @fakeip_v4 meta l4proto tcp counter name "tcp_proxied" redirect to :%d', redirect_port));
	if (ipv6_enable)
		push(lines, sprintf('\t\tip6 daddr @fakeip_v6 meta l4proto tcp counter name "tcp_proxied" redirect to :%d', redirect_port));

	if (port_mode == 'include') {
		if (length(filter_tcp_ports) == 0)
			push(lines, '\t\treturn');
		else
			push(lines, '\t\ttcp dport != @filter_tcp_ports return');
	} else if (port_mode == 'exclude' && length(filter_tcp_ports) > 0) {
		push(lines, '\t\ttcp dport @filter_tcp_ports return');
	}

	append_daddr_bypass_lines(lines, ipv4_enable, ipv6_enable, 'return');

	if (ipv4_enable)
		push(lines, sprintf('\t\tmeta nfproto ipv4 meta l4proto tcp counter name "tcp_proxied" redirect to :%d', redirect_port));
	if (ipv6_enable)
		push(lines, sprintf('\t\tmeta nfproto ipv6 meta l4proto tcp counter name "tcp_proxied" redirect to :%d', redirect_port));

	return lines;
}

function build_udp_tail_lines(ipv4_enable, ipv6_enable, port_mode, filter_udp_ports, proxy_mark_hex, tproxy_port) {
	let lines = [];

	if (ipv4_enable)
		push(lines, sprintf('\t\tip daddr @fakeip_v4 ct mark set ct mark & 0xffffffcf | 0x20 meta l4proto udp meta mark set %s counter name "udp_proxied" tproxy ip to :%d accept', proxy_mark_hex, tproxy_port));
	if (ipv6_enable)
		push(lines, sprintf('\t\tip6 daddr @fakeip_v6 ct mark set ct mark & 0xffffffcf | 0x20 meta l4proto udp meta mark set %s counter name "udp_proxied" tproxy ip6 to :%d accept', proxy_mark_hex, tproxy_port));

	if (port_mode == 'include') {
		if (length(filter_udp_ports) == 0)
			push(lines, '\t\tct mark set ct mark & 0xffffffcf | 0x10 return');
		else
			push(lines, '\t\tudp dport != @filter_udp_ports ct mark set ct mark & 0xffffffcf | 0x10 return');
	} else if (port_mode == 'exclude' && length(filter_udp_ports) > 0) {
		push(lines, '\t\tudp dport @filter_udp_ports ct mark set ct mark & 0xffffffcf | 0x10 return');
	}

	append_daddr_bypass_lines(lines, ipv4_enable, ipv6_enable, 'ct mark set ct mark & 0xffffffcf | 0x10 return');

	if (ipv4_enable)
		push(lines, sprintf('\t\tmeta nfproto ipv4 ct mark set ct mark & 0xffffffcf | 0x20 meta l4proto udp meta mark set %s counter name "udp_proxied" tproxy ip to :%d accept', proxy_mark_hex, tproxy_port));
	if (ipv6_enable)
		push(lines, sprintf('\t\tmeta nfproto ipv6 ct mark set ct mark & 0xffffffcf | 0x20 meta l4proto udp meta mark set %s counter name "udp_proxied" tproxy ip6 to :%d accept', proxy_mark_hex, tproxy_port));

	return lines;
}

function append_nfproto_guard(out, ipv4_enable, ipv6_enable) {
	if (!ipv6_enable)
		push(out, '\t\tmeta nfproto != ipv4 return');
	else if (!ipv4_enable)
		push(out, '\t\tmeta nfproto != ipv6 return');
}

function append_subchain(out, chain_name, body_lines) {
	push(out, '');
	push(out, sprintf('\tchain %s {', chain_name));
	for (let line in body_lines)
		push(out, line);
	push(out, '\t}');
}

function format_set_block(name, set_type, flags_line, elements, quote_elems) {
	let lines = [];
	push(lines, sprintf('\tset %s {', name));
	push(lines, sprintf('\t\ttype %s', set_type));
	if (flags_line) {
		for (let fl in flags_line)
			push(lines, sprintf('\t\t%s', fl));
	}
	if (type(elements) == 'array' && length(elements) > 0) {
		let formatted = [];
		for (let el in elements)
			push(formatted, quote_elems ? sprintf('"%s"', el) : ('' + el));
		push(lines, sprintf('\t\telements = { %s }', join(', ', formatted)));
	}
	push(lines, '\t}');
	return join('\n', lines);
}

function generate_rules(opts) {
	let options = opts || {};
	let uci_cfg = options.uci || common.uci_get_all('nimbus', options.uci_confdir, options.uci_savedir);
	let g = uci_cfg?.global || {};
	let p = uci_cfg?.proxy || {};
	let d = uci_cfg?.dns || {};
	let ctx = options.context || {};

	let raw_mode = lc(trim('' + (options.mode || options.state || g.proxy_mode || 'tproxy_redirect')));
	let is_lockdown = (raw_mode == 'lockdown');

	let ipv4_enable = ((options.ipv4_enable ?? g.ipv4_enable ?? '1') != '0' && options.ipv4_enable !== false);
	let ipv6_enable = ((options.ipv6_enable ?? g.ipv6_enable ?? '1') != '0' && options.ipv6_enable !== false);
	if (!ipv4_enable && !ipv6_enable)
		ipv4_enable = true;

	let router_proxy_raw = options.router_proxy ?? options.proxy_local ??
		g.proxy_local ?? g.router_proxy ?? p.proxy_local ?? p.router_proxy ?? '0';
	let proxy_local = (router_proxy_raw == '1' || router_proxy_raw === 1 || router_proxy_raw === true);

	let hijack_dns_raw = options.hijack_lan_dns ?? d.hijack_lan_dns ?? '0';
	let hijack_lan_dns = (hijack_dns_raw == '1' || hijack_dns_raw === 1 || hijack_dns_raw === true);

	let lan_mode = normalize_lan_mode(
		options.lan_proxy_mode ?? options.lan_device_mode ??
		p.lan_device_mode ?? p.lan_proxy_mode ??
		g.lan_device_mode ?? g.lan_proxy_mode ?? 'default_proxy'
	);

	let port_mode = normalize_port_mode(
		options.port_filter_mode ?? p.port_filter_mode ?? 'all'
	);

	let outbound_mark_int = common.hex_u32_parse(
		options.outbound_mark ?? ctx.effective_outbound_mark ?? p.outbound_mark ?? common.DEFAULT_OUTBOUND_MARK
	) ?? common.DEFAULT_OUTBOUND_MARK;
	let proxy_mark_int = common.hex_u32_parse(
		options.proxy_mark ?? p.proxy_mark ?? common.DEFAULT_PROXY_MARK
	) ?? common.DEFAULT_PROXY_MARK;

	let outbound_mark_hex = common.format_hex_u32(outbound_mark_int);
	let proxy_mark_hex = common.format_hex_u32(proxy_mark_int);

	let redirect_port = parse_port_num(
		'' + (options.redirect_port ?? ctx.effective_redirect_port ?? p.redirect_port ?? common.DEFAULT_REDIRECT_PORT)
	) ?? common.DEFAULT_REDIRECT_PORT;
	let tproxy_port = parse_port_num(
		'' + (options.tproxy_port ?? ctx.effective_tproxy_port ?? p.tproxy_port ?? common.DEFAULT_TPROXY_PORT)
	) ?? common.DEFAULT_TPROXY_PORT;

	let net_ctx = resolve_network_context(uci_cfg, options);
	let dev_rules = parse_device_rules(uci_cfg, options);

	let fakeip_v4 = filter_ip_list(options.fakeip_v4 ?? ctx?.fakeip?.ipv4, 4);
	let fakeip_v6 = filter_ip_list(options.fakeip_v6 ?? ctx?.fakeip?.ipv6, 6);
	let bypass_v4 = filter_ip_list(options.bypass_v4, 4);
	let bypass_v6 = filter_ip_list(options.bypass_v6, 6);

	let filter_tcp_ports = (port_mode != 'all')
		? parse_port_elements(options.filter_tcp_ports ?? options.proxy_tcp_ports ?? p.proxy_tcp_ports)
		: [];
	let filter_udp_ports = (port_mode != 'all')
		? parse_port_elements(options.filter_udp_ports ?? options.proxy_udp_ports ?? p.proxy_udp_ports)
		: [];

	let interval_flags = [ 'flags interval', 'auto-merge' ];
	let out = [];

	push(out, 'table inet nimbus');
	push(out, 'delete table inet nimbus');
	push(out, '');
	push(out, 'table inet nimbus {');

	// Sets per docs/dataplane-and-singbox-spec.md
	push(out, format_set_block('lan_ifaces', 'ifname', null, net_ctx.lan_ifaces, true));
	push(out, format_set_block('reserved_v4', 'ipv4_addr', interval_flags, common.RESERVED_V4, false));
	push(out, format_set_block('reserved_v6', 'ipv6_addr', interval_flags, common.RESERVED_V6, false));
	push(out, format_set_block('lan_v4', 'ipv4_addr', interval_flags, net_ctx.lan_v4, false));
	push(out, format_set_block('lan_v6', 'ipv6_addr', interval_flags, net_ctx.lan_v6, false));
	push(out, format_set_block('wan_v4', 'ipv4_addr', interval_flags, net_ctx.wan_v4, false));
	push(out, format_set_block('wan_v6', 'ipv6_addr', interval_flags, net_ctx.wan_v6, false));
	push(out, format_set_block('fakeip_v4', 'ipv4_addr', interval_flags, fakeip_v4, false));
	push(out, format_set_block('fakeip_v6', 'ipv6_addr', interval_flags, fakeip_v6, false));
	push(out, format_set_block('bypass_v4', 'ipv4_addr', interval_flags, bypass_v4, false));
	push(out, format_set_block('bypass_v6', 'ipv6_addr', interval_flags, bypass_v6, false));

	push(out, format_set_block('filter_tcp_ports', 'inet_service', interval_flags, filter_tcp_ports, false));
	push(out, format_set_block('filter_udp_ports', 'inet_service', interval_flags, filter_udp_ports, false));

	push(out, '\tcounter tcp_proxied {}');
	push(out, '\tcounter udp_proxied {}');
	push(out, '\tcounter lockdown_dropped {}');

	let use_proxy_subchain = has_active_proxy_device_rules(dev_rules, ipv4_enable, ipv6_enable);
	let short_circuit_bypass = (!use_proxy_subchain && lan_mode == 'default_bypass');

	if (is_lockdown) {
		let lockdown_tail = null;
		if (!short_circuit_bypass) {
			lockdown_tail = build_lockdown_tail_lines(ipv4_enable, ipv6_enable);
			if (use_proxy_subchain)
				append_subchain(out, 'forward_lockdown_enforce', lockdown_tail);
		}

		push(out, '');
		push(out, '\tchain forward_lockdown {');
		push(out, '\t\ttype filter hook forward priority filter - 1; policy accept;');
		push(out, '\t\tiifname != @lan_ifaces return');
		append_nfproto_guard(out, ipv4_enable, ipv6_enable);
		push(out, '\t\tct status dnat return');
		push(out, '\t\tct direction reply return');
		if (ipv6_enable)
			push(out, '\t\tmeta l4proto icmpv6 icmpv6 type { 1, 2, 3, 4, 133, 134, 135, 136, 137 } return');

		if (short_circuit_bypass) {
			push(out, '\t\treturn');
		} else {
			append_device_filter_rules(
				out, dev_rules, lan_mode, ipv4_enable, ipv6_enable,
				'return', use_proxy_subchain ? 'forward_lockdown_enforce' : null
			);
			if (!use_proxy_subchain) {
				for (let line in lockdown_tail)
					push(out, line);
			}
		}
		push(out, '\t}');
		push(out, '}');
		return join('\n', out) + '\n';
	}

	// tproxy_redirect mode
	if (hijack_lan_dns) {
		let dns_tail = [ '\t\tmeta l4proto { tcp, udp } th dport 53 counter redirect to :53' ];
		if (!short_circuit_bypass && use_proxy_subchain)
			append_subchain(out, 'prerouting_dns_hijack', dns_tail);

		push(out, '');
		push(out, '\tchain prerouting_dns {');
		push(out, '\t\ttype nat hook prerouting priority dstnat + 1; policy accept;');
		push(out, '\t\tiifname != @lan_ifaces return');
		append_nfproto_guard(out, ipv4_enable, ipv6_enable);
		push(out, '\t\tmeta l4proto != { tcp, udp } return');
		push(out, '\t\tth dport != 53 return');
		push(out, sprintf('\t\tmeta mark %s return', outbound_mark_hex));
		push(out, '\t\tct status dnat return');
		push(out, '\t\tfib daddr type local return');

		if (short_circuit_bypass) {
			push(out, '\t\treturn');
		} else {
			append_device_filter_rules(
				out, dev_rules, lan_mode, ipv4_enable, ipv6_enable,
				'return', use_proxy_subchain ? 'prerouting_dns_hijack' : null
			);
			if (!use_proxy_subchain) {
				for (let line in dns_tail)
					push(out, line);
			}
		}
		push(out, '\t}');
	}

	// prerouting_tcp
	let tcp_tail = null;
	if (!short_circuit_bypass) {
		tcp_tail = build_tcp_tail_lines(ipv4_enable, ipv6_enable, port_mode, filter_tcp_ports, redirect_port);
		if (use_proxy_subchain)
			append_subchain(out, 'prerouting_tcp_proxy', tcp_tail);
	}

	push(out, '');
	push(out, '\tchain prerouting_tcp {');
	push(out, '\t\ttype nat hook prerouting priority dstnat + 2; policy accept;');
	push(out, '\t\tiifname != @lan_ifaces return');
	append_nfproto_guard(out, ipv4_enable, ipv6_enable);
	push(out, '\t\tmeta l4proto != tcp return');
	push(out, sprintf('\t\tmeta mark %s return', outbound_mark_hex));
	push(out, '\t\tct status dnat return');
	push(out, '\t\tfib daddr type local return');

	if (short_circuit_bypass) {
		push(out, '\t\treturn');
	} else {
		append_device_filter_rules(
			out, dev_rules, lan_mode, ipv4_enable, ipv6_enable,
			'return', use_proxy_subchain ? 'prerouting_tcp_proxy' : null
		);
		if (!use_proxy_subchain) {
			for (let line in tcp_tail)
				push(out, line);
		}
	}
	push(out, '\t}');

	// prerouting_udp
	let udp_tail = null;
	if (!short_circuit_bypass) {
		udp_tail = build_udp_tail_lines(ipv4_enable, ipv6_enable, port_mode, filter_udp_ports, proxy_mark_hex, tproxy_port);
		if (use_proxy_subchain)
			append_subchain(out, 'prerouting_udp_proxy', udp_tail);
	}

	push(out, '');
	push(out, '\tchain prerouting_udp {');
	push(out, '\t\ttype filter hook prerouting priority mangle; policy accept;');

	if (proxy_local) {
		if (ipv4_enable)
			push(out, sprintf('\t\tiifname "lo" meta mark %s meta l4proto udp meta nfproto ipv4 counter name "udp_proxied" tproxy ip to :%d accept', proxy_mark_hex, tproxy_port));
		if (ipv6_enable)
			push(out, sprintf('\t\tiifname "lo" meta mark %s meta l4proto udp meta nfproto ipv6 counter name "udp_proxied" tproxy ip6 to :%d accept', proxy_mark_hex, tproxy_port));
	}

	push(out, '\t\tiifname != @lan_ifaces return');
	append_nfproto_guard(out, ipv4_enable, ipv6_enable);
	push(out, '\t\tmeta l4proto != udp return');
	push(out, sprintf('\t\tmeta mark %s return', outbound_mark_hex));
	push(out, '\t\tfib daddr type local return');
	push(out, '\t\tct status dnat return');
	push(out, '\t\tct direction reply return');

	if (hijack_lan_dns)
		push(out, '\t\tudp dport 53 return');

	push(out, '\t\tct mark & 0x30 == 0x10 return');
	if (!short_circuit_bypass) {
		if (ipv4_enable)
			push(out, sprintf('\t\tct mark & 0x30 == 0x20 meta nfproto ipv4 meta l4proto udp meta mark set %s counter name "udp_proxied" tproxy ip to :%d accept', proxy_mark_hex, tproxy_port));
		if (ipv6_enable)
			push(out, sprintf('\t\tct mark & 0x30 == 0x20 meta nfproto ipv6 meta l4proto udp meta mark set %s counter name "udp_proxied" tproxy ip6 to :%d accept', proxy_mark_hex, tproxy_port));
	}

	if (short_circuit_bypass) {
		push(out, '\t\tct mark set ct mark & 0xffffffcf | 0x10 return');
	} else {
		append_device_filter_rules(
			out, dev_rules, lan_mode, ipv4_enable, ipv6_enable,
			'ct mark set ct mark & 0xffffffcf | 0x10 return', use_proxy_subchain ? 'prerouting_udp_proxy' : null
		);
		if (!use_proxy_subchain) {
			for (let line in udp_tail)
				push(out, line);
		}
	}
	push(out, '\t}');

	if (proxy_local) {
		push(out, '');
		push(out, '\tchain output_tcp {');
		push(out, '\t\ttype nat hook output priority -100; policy accept;');
		push(out, '\t\toifname "lo" return');
		append_nfproto_guard(out, ipv4_enable, ipv6_enable);
		push(out, '\t\tmeta l4proto != tcp return');
		push(out, sprintf('\t\tmeta mark %s return', outbound_mark_hex));
		push(out, '\t\tfib daddr type local return');
		if (ipv4_enable)
			push(out, sprintf('\t\tip daddr @fakeip_v4 meta l4proto tcp counter name "tcp_proxied" redirect to :%d', redirect_port));
		if (ipv6_enable)
			push(out, sprintf('\t\tip6 daddr @fakeip_v6 meta l4proto tcp counter name "tcp_proxied" redirect to :%d', redirect_port));
		if (ipv4_enable)
			push(out, '\t\tip daddr @reserved_v4 return');
		if (ipv6_enable)
			push(out, '\t\tip6 daddr @reserved_v6 return');
		if (ipv4_enable)
			push(out, '\t\tip daddr @lan_v4 return');
		if (ipv6_enable)
			push(out, '\t\tip6 daddr @lan_v6 return');
		if (ipv4_enable)
			push(out, '\t\tip daddr @wan_v4 return');
		if (ipv6_enable)
			push(out, '\t\tip6 daddr @wan_v6 return');
		if (ipv4_enable)
			push(out, '\t\tip daddr @bypass_v4 return');
		if (ipv6_enable)
			push(out, '\t\tip6 daddr @bypass_v6 return');
		if (ipv4_enable)
			push(out, sprintf('\t\tmeta nfproto ipv4 meta l4proto tcp counter name "tcp_proxied" redirect to :%d', redirect_port));
		if (ipv6_enable)
			push(out, sprintf('\t\tmeta nfproto ipv6 meta l4proto tcp counter name "tcp_proxied" redirect to :%d', redirect_port));
		push(out, '\t}');

		push(out, '');
		push(out, '\tchain output_udp {');
		push(out, '\t\ttype route hook output priority mangle; policy accept;');
		push(out, '\t\toifname "lo" return');
		append_nfproto_guard(out, ipv4_enable, ipv6_enable);
		push(out, '\t\tmeta l4proto != udp return');
		push(out, sprintf('\t\tmeta mark %s return', outbound_mark_hex));
		push(out, '\t\tfib daddr type local return');
		push(out, '\t\tct status dnat return');
		push(out, '\t\tct direction reply return');
		if (ipv4_enable)
			push(out, '\t\tmeta nfproto ipv4 udp sport 68 udp dport 67 return');
		if (ipv6_enable)
			push(out, '\t\tmeta nfproto ipv6 udp sport 546 udp dport 547 return');
		if (ipv4_enable)
			push(out, sprintf('\t\tip daddr @fakeip_v4 meta mark set %s accept', proxy_mark_hex));
		if (ipv6_enable)
			push(out, sprintf('\t\tip6 daddr @fakeip_v6 meta mark set %s accept', proxy_mark_hex));
		if (ipv4_enable)
			push(out, '\t\tip daddr @reserved_v4 return');
		if (ipv6_enable)
			push(out, '\t\tip6 daddr @reserved_v6 return');
		if (ipv4_enable)
			push(out, '\t\tip daddr @lan_v4 return');
		if (ipv6_enable)
			push(out, '\t\tip6 daddr @lan_v6 return');
		if (ipv4_enable)
			push(out, '\t\tip daddr @wan_v4 return');
		if (ipv6_enable)
			push(out, '\t\tip6 daddr @wan_v6 return');
		if (ipv4_enable)
			push(out, '\t\tip daddr @bypass_v4 return');
		if (ipv6_enable)
			push(out, '\t\tip6 daddr @bypass_v6 return');
		if (ipv4_enable)
			push(out, sprintf('\t\tmeta nfproto ipv4 meta mark set %s accept', proxy_mark_hex));
		if (ipv6_enable)
			push(out, sprintf('\t\tmeta nfproto ipv6 meta mark set %s accept', proxy_mark_hex));
		push(out, '\t}');
	}

	push(out, '}');
	return join('\n', out) + '\n';
}

function run_nft_cmd(argv, opts) {
	let options = opts || {};
	if (type(options.runner) == 'function')
		return options.runner(argv);

	let tmp_dir = getenv('TMPDIR') || '/tmp';
	common.ensure_dir(tmp_dir, 0755);
	_nft_seq++;
	let pid = fs.readlink('/proc/self') || '0';
	let out_path = sprintf('%s/nimbus-nft.%s.%d.tmp', tmp_dir, pid, _nft_seq);
	let fh = fs.open(out_path, 'wx', 0600);
	if (!fh)
		return { rc: -1, output: 'failed to create temporary output file' };
	fh.close();

	let sh_argv = [ '/bin/sh', '-c', 'out=$1; shift; exec "$@" >"$out" 2>&1', 'sh', out_path ];
	for (let a in argv)
		push(sh_argv, a);

	let rc = system(sh_argv, options.timeout_ms || NFT_TIMEOUT_MS);
	let output = fs.readfile(out_path) || '';
	fs.unlink(out_path);

	return { rc: rc, output: trim(output) };
}

function get_nft_bin(opts) {
	return opts?.nft_bin || getenv('NFT_BIN') || DEFAULT_NFT_BIN;
}

function parse_set_elem_count(raw_input, expected_name) {
	let parsed = null;
	if (type(raw_input) == 'string') {
		if (length(trim(raw_input)) == 0)
			return { ok: false, count: null };
		try {
			parsed = json(raw_input);
		} catch (e) {
			return { ok: false, count: null };
		}
	} else if (type(raw_input) == 'object') {
		parsed = raw_input;
	} else {
		return { ok: false, count: null };
	}

	let entries = parsed?.nftables;
	if (type(entries) != 'array')
		return { ok: false, count: null };

	for (let entry in entries) {
		let s = entry?.set;
		if (type(s) != 'object')
			continue;
		if (s.table != null && s.table != 'nimbus')
			continue;
		if (expected_name != null && s.name != expected_name)
			continue;
		let count = (type(s.elem) == 'array') ? length(s.elem) : 0;
		return { ok: true, count: count };
	}

	return { ok: false, count: null };
}

function get_bypass_set_counts(opts) {
	let options = opts || {};
	let nft_bin = get_nft_bin(options);

	let r4 = run_nft_cmd([ nft_bin, '-j', 'list', 'set', 'inet', 'nimbus', 'bypass_v4' ], options);
	if (r4.rc != 0)
		return { ok: false, v4_count: null, v6_count: null };
	let p4 = parse_set_elem_count(r4.output, 'bypass_v4');
	if (!p4.ok)
		return { ok: false, v4_count: null, v6_count: null };

	let r6 = run_nft_cmd([ nft_bin, '-j', 'list', 'set', 'inet', 'nimbus', 'bypass_v6' ], options);
	if (r6.rc != 0)
		return { ok: false, v4_count: null, v6_count: null };
	let p6 = parse_set_elem_count(r6.output, 'bypass_v6');
	if (!p6.ok)
		return { ok: false, v4_count: null, v6_count: null };

	return {
		ok: true,
		v4_count: p4.count,
		v6_count: p6.count
	};
}

function replay_rules_file(file_path, opts) {
	let options = opts || {};
	if (type(file_path) != 'string' || length(file_path) == 0 || !fs.stat(file_path)) {
		return {
			ok: false,
			code: common.ERR_NOT_FOUND,
			error: sprintf('nftables rules file not found: %s', '' + file_path)
		};
	}

	if (options.dry_run === true)
		return { ok: true, output_path: file_path };

	let nft_bin = get_nft_bin(options);
	let argv = options.check_only
		? [ nft_bin, '-c', '-f', file_path ]
		: [ nft_bin, '-f', file_path ];
	let res = run_nft_cmd(argv, options);
	if (res.rc != 0) {
		return {
			ok: false,
			code: common.ERR_INTERNAL,
			error: length(res.output) > 0 ? res.output : sprintf('nft replay exited with code %d', res.rc),
			output_path: file_path
		};
	}

	return { ok: true, output_path: file_path };
}

function apply_rules(opts) {
	let options = opts || {};
	let script = generate_rules(options);
	let out_path = options.output_path || common.RULES_NFT_FILE;

	if (!common.atomic_write(out_path, script, 0600)) {
		return {
			ok: false,
			code: common.ERR_INTERNAL,
			error: sprintf('failed to write nftables rules to %s', out_path)
		};
	}

	if (options.dry_run === true)
		return { ok: true, rules: script, output_path: out_path, loaded_counts: null };

	let nft_bin = get_nft_bin(options);
	let argv = options.check_only
		? [ nft_bin, '-c', '-f', out_path ]
		: [ nft_bin, '-f', out_path ];
	let res = run_nft_cmd(argv, options);
	if (res.rc != 0) {
		return {
			ok: false,
			code: common.ERR_INTERNAL,
			error: length(res.output) > 0 ? res.output : sprintf('nft exited with code %d', res.rc),
			rules: script,
			output_path: out_path
		};
	}

	let loaded_counts = null;
	if (!options.check_only && type(options.runner) != 'function') {
		let cnt = get_bypass_set_counts(options);
		if (cnt.ok)
			loaded_counts = { bypass_v4: cnt.v4_count, bypass_v6: cnt.v6_count };
	}

	return { ok: true, rules: script, output_path: out_path, loaded_counts: loaded_counts };
}

function build_emergency_lockdown_rules() {
	return join('\n', [
		'table inet nimbus',
		'delete table inet nimbus',
		'',
		'table inet nimbus {',
		'\tcounter lockdown_dropped {}',
		'',
		'\tchain forward_lockdown {',
		'\t\ttype filter hook forward priority filter - 1; policy accept;',
		'\t\tct status dnat return',
		'\t\tct direction reply return',
		'\t\tmeta l4proto icmpv6 icmpv6 type { 1, 2, 3, 4, 133, 134, 135, 136, 137 } return',
		'\t\tip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } return',
		'\t\tip6 daddr { fc00::/7, fe80::/10, ff00::/8 } return',
		'\t\tcounter name "lockdown_dropped" reject with icmpx type admin-prohibited',
		'\t}',
		'}',
		''
	]);
}

function apply_emergency_lockdown(opts) {
	let options = opts || {};
	let script = build_emergency_lockdown_rules();
	let out_path = options.output_path || common.RULES_NFT_FILE;

	if (!common.atomic_write(out_path, script, 0600)) {
		return {
			ok: false,
			code: common.ERR_INTERNAL,
			error: sprintf('failed to write emergency lockdown rules to %s', out_path)
		};
	}

	if (options.dry_run === true)
		return { ok: true, rules: script, output_path: out_path, emergency: true };

	let nft_bin = get_nft_bin(options);
	let argv = options.check_only
		? [ nft_bin, '-c', '-f', out_path ]
		: [ nft_bin, '-f', out_path ];
	let res = run_nft_cmd(argv, options);
	if (res.rc != 0) {
		return {
			ok: false,
			code: common.ERR_INTERNAL,
			error: length(res.output) > 0 ? res.output : sprintf('nft emergency lockdown exited with code %d', res.rc),
			rules: script,
			output_path: out_path
		};
	}

	return { ok: true, rules: script, output_path: out_path, emergency: true };
}

function apply_lockdown(opts) {
	let options = { ...(opts || {}), mode: 'lockdown' };
	return apply_rules(options);
}

function delete_table(opts) {
	let options = opts || {};
	if (options.dry_run === true)
		return { ok: true };

	let tmp_dir = getenv('TMPDIR') || '/tmp';
	common.ensure_dir(tmp_dir, 0755);
	_nft_seq++;
	let pid = fs.readlink('/proc/self') || '0';
	let del_path = sprintf('%s/nimbus-del.%s.%d.nft', tmp_dir, pid, _nft_seq);
	if (!common.atomic_write(del_path, 'table inet nimbus\ndelete table inet nimbus\n', 0600)) {
		return {
			ok: false,
			code: common.ERR_INTERNAL,
			error: sprintf('failed to stage delete script at %s', del_path)
		};
	}

	let nft_bin = get_nft_bin(options);
	let res = run_nft_cmd([ nft_bin, '-f', del_path ], options);
	fs.unlink(del_path);

	if (res.rc != 0) {
		return {
			ok: false,
			code: common.ERR_INTERNAL,
			error: length(res.output) > 0 ? res.output : sprintf('nft delete table exited with code %d', res.rc)
		};
	}

	return { ok: true };
}

function sanitize_set_elements(set_name, raw_list) {
	if (set_name == 'lan_ifaces')
		return filter_ifname_list(raw_list);
	if (match(set_name, /_v4$/))
		return filter_ip_list(raw_list, 4);
	if (match(set_name, /_v6$/))
		return filter_ip_list(raw_list, 6);
	if (match(set_name, /_mac$/))
		return filter_mac_list(raw_list);
	if (match(set_name, /_ports$/))
		return parse_port_elements(raw_list);
	return to_list(raw_list, []);
}

function build_set_reload_script(sets_map) {
	let input = (type(sets_map) == 'object') ? { ...sets_map } : {};
	if (exists(input, 'v4') && !exists(input, 'bypass_v4'))
		input.bypass_v4 = input.v4;
	if (exists(input, 'v6') && !exists(input, 'bypass_v6'))
		input.bypass_v6 = input.v6;

	let target_names = [];
	for (let sname in RELOADABLE_SETS) {
		if (exists(input, sname))
			push(target_names, sname);
	}
	if (length(target_names) == 0) {
		target_names = [ 'bypass_v4', 'bypass_v6' ];
	}

	let lines = [];
	for (let sname in target_names) {
		push(lines, sprintf('flush set inet nimbus %s', sname));
		let elems = sanitize_set_elements(sname, input[sname]);
		if (length(elems) > 0) {
			let formatted = [];
			let quote = (sname == 'lan_ifaces');
			for (let el in elems)
				push(formatted, quote ? sprintf('"%s"', el) : ('' + el));
			push(lines, sprintf('add element inet nimbus %s { %s }', sname, join(', ', formatted)));
		}
	}

	return join('\n', lines) + '\n';
}

function reload_sets(sets_map, opts) {
	let options = opts || {};
	let script = build_set_reload_script(sets_map);

	let has_bypass_sets = (type(sets_map) == 'object') &&
		(exists(sets_map, 'bypass_v4') || exists(sets_map, 'bypass_v6') ||
		 exists(sets_map, 'v4') || exists(sets_map, 'v6'));

	let is_wan_only = (type(sets_map) == 'object') &&
		!has_bypass_sets &&
		(exists(sets_map, 'lan_ifaces') || exists(sets_map, 'lan_v4') || exists(sets_map, 'lan_v6') ||
		 exists(sets_map, 'wan_v4') || exists(sets_map, 'wan_v6'));

	let out_path = options.output_path ||
		(is_wan_only ? common.WAN_SETS_NFT_FILE : common.BYPASS_SETS_NFT_FILE);

	if (!common.atomic_write(out_path, script, 0600)) {
		return {
			ok: false,
			code: common.ERR_INTERNAL,
			error: sprintf('failed to write nftables set script to %s', out_path)
		};
	}

	if (options.dry_run === true)
		return { ok: true, script: script, output_path: out_path, loaded_counts: null };

	let nft_bin = get_nft_bin(options);
	let argv = options.check_only
		? [ nft_bin, '-c', '-f', out_path ]
		: [ nft_bin, '-f', out_path ];
	let res = run_nft_cmd(argv, options);
	if (res.rc != 0) {
		return {
			ok: false,
			code: common.ERR_INTERNAL,
			error: length(res.output) > 0 ? res.output : sprintf('nft set reload exited with code %d', res.rc),
			script: script,
			output_path: out_path
		};
	}

	let loaded_counts = null;
	if (has_bypass_sets && !options.check_only && type(options.runner) != 'function') {
		let cnt = get_bypass_set_counts(options);
		if (cnt.ok)
			loaded_counts = { bypass_v4: cnt.v4_count, bypass_v6: cnt.v6_count };
	}

	return { ok: true, script: script, output_path: out_path, loaded_counts: loaded_counts };
}

function reload_iface_sets(uci_cfg, opts) {
	let options = opts || {};
	let uci_data = uci_cfg || common.uci_get_all('nimbus', options.uci_confdir, options.uci_savedir);
	let net_ctx = resolve_network_context(uci_data, options);
	let sets_map = {
		lan_ifaces: net_ctx.lan_ifaces,
		lan_v4: net_ctx.lan_v4,
		lan_v6: net_ctx.lan_v6
	};
	if (net_ctx.topology == 'main') {
		sets_map.wan_v4 = net_ctx.wan_v4;
		sets_map.wan_v6 = net_ctx.wan_v6;
	}
	return reload_sets(sets_map, {
		...options,
		output_path: options.output_path || common.WAN_SETS_NFT_FILE
	});
}

function to_nonneg_int(v) {
	if (type(v) == 'int')
		return (v >= 0) ? v : 0;
	if (type(v) == 'string' && match(v, /^[0-9]+$/)) {
		let n = int(v, 10);
		return (!common.isnan(n) && n >= 0) ? n : 0;
	}
	return 0;
}

function parse_counters(raw_input) {
	let result = {
		ok: true,
		tcp_packets: 0,
		tcp_bytes: 0,
		udp_packets: 0,
		udp_bytes: 0,
		tun_packets: 0,
		tun_bytes: 0,
		lockdown_rejected_packets: 0,
		lockdown_rejected_bytes: 0,
		lockdown_dropped_packets: 0,
		lockdown_dropped_bytes: 0
	};

	let parsed = null;
	if (type(raw_input) == 'string') {
		if (length(trim(raw_input)) == 0)
			return result;
		try {
			parsed = json(raw_input);
		} catch (e) {
			return { ...result, ok: false, code: common.ERR_VALIDATE_FAILED, error: 'invalid nft JSON output' };
		}
	} else if (type(raw_input) == 'object') {
		parsed = raw_input;
	} else {
		return result;
	}

	let entries = parsed?.nftables;
	if (type(entries) != 'array')
		return result;

	let named_tcp_p = 0, named_tcp_b = 0;
	let named_udp_p = 0, named_udp_b = 0;
	let named_tun_p = 0, named_tun_b = 0;
	let named_lock_p = 0, named_lock_b = 0;

	let rule_tcp_p = 0, rule_tcp_b = 0;
	let rule_udp_p = 0, rule_udp_b = 0;
	let rule_lock_p = 0, rule_lock_b = 0;

	for (let entry in entries) {
		if (type(entry) != 'object')
			continue;

		if (type(entry.counter) == 'object') {
			let c = entry.counter;
			if (c.table != null && c.table != 'nimbus')
				continue;
			let pkts = to_nonneg_int(c.packets);
			let bytes = to_nonneg_int(c.bytes);
			let cname = c.name || '';

			if (cname == 'tcp_proxied' || cname == 'tcp') {
				named_tcp_p += pkts;
				named_tcp_b += bytes;
			} else if (cname == 'udp_proxied' || cname == 'udp') {
				named_udp_p += pkts;
				named_udp_b += bytes;
			} else if (cname == 'tun_proxied' || cname == 'tun') {
				named_tun_p += pkts;
				named_tun_b += bytes;
			} else if (cname == 'lockdown_dropped' || cname == 'lockdown_rejected' || cname == 'lockdown') {
				named_lock_p += pkts;
				named_lock_b += bytes;
			}
		}

		if (type(entry.rule) == 'object') {
			let r = entry.rule;
			if (r.table != null && r.table != 'nimbus')
				continue;
			let chain = r.chain || '';
			if (type(r.expr) != 'array')
				continue;

			for (let ex in r.expr) {
				if (type(ex) != 'object' || type(ex.counter) != 'object')
					continue;
				let pkts = to_nonneg_int(ex.counter.packets);
				let bytes = to_nonneg_int(ex.counter.bytes);

				if (chain == 'prerouting_tcp' || chain == 'prerouting_tcp_proxy' || chain == 'output_tcp') {
					rule_tcp_p += pkts;
					rule_tcp_b += bytes;
				} else if (chain == 'prerouting_udp' || chain == 'prerouting_udp_proxy') {
					rule_udp_p += pkts;
					rule_udp_b += bytes;
				} else if (chain == 'forward_lockdown' || chain == 'forward_lockdown_enforce') {
					rule_lock_p += pkts;
					rule_lock_b += bytes;
				}
			}
		}
	}

	result.tcp_packets = max(named_tcp_p, rule_tcp_p);
	result.tcp_bytes = max(named_tcp_b, rule_tcp_b);
	result.udp_packets = max(named_udp_p, rule_udp_p);
	result.udp_bytes = max(named_udp_b, rule_udp_b);
	result.tun_packets = named_tun_p;
	result.tun_bytes = named_tun_b;

	let lock_p = max(named_lock_p, rule_lock_p);
	let lock_b = max(named_lock_b, rule_lock_b);
	result.lockdown_rejected_packets = lock_p;
	result.lockdown_rejected_bytes = lock_b;
	result.lockdown_dropped_packets = lock_p;
	result.lockdown_dropped_bytes = lock_b;

	return result;
}

function get_counters(opts) {
	if (type(opts) == 'string' || (type(opts) == 'object' && exists(opts, 'nftables')))
		return parse_counters(opts);

	let options = opts || {};
	if (options.raw_json != null)
		return parse_counters(options.raw_json);

	let nft_bin = get_nft_bin(options);
	let res = run_nft_cmd([ nft_bin, '-j', 'list', 'counters', 'table', 'inet', 'nimbus' ], options);
	if (res.rc != 0) {
		let err_lc = lc(res.output || '');
		if (index(err_lc, 'no such file or directory') >= 0 || index(err_lc, 'does not exist') >= 0)
			return parse_counters(null);
		res = run_nft_cmd([ nft_bin, '-j', '-t', 'list', 'table', 'inet', 'nimbus' ], options);
		if (res.rc != 0)
			return parse_counters(null);
	} else if (length(res.output) == 0) {
		res = run_nft_cmd([ nft_bin, '-j', '-t', 'list', 'table', 'inet', 'nimbus' ], options);
		if (res.rc != 0)
			return parse_counters(null);
	}

	return parse_counters(res.output);
}

function check_fw4_lan_input(uci_cfg, opts) {
	let options = opts || {};
	let nimbus_uci = uci_cfg || common.uci_get_all('nimbus', options.uci_confdir, options.uci_savedir);
	let lan_names = to_list(nimbus_uci?.global?.lan_interfaces, [ 'lan' ]);
	let fw_uci = options.firewall_uci || common.uci_get_all('firewall', options.uci_confdir, options.uci_savedir);
	let warnings = [];

	if (type(fw_uci) != 'object')
		return warnings;

	let default_input = 'ACCEPT';
	let has_fw_config = false;
	let covered_lan = {};

	for (let k, sec in fw_uci) {
		if (type(sec) != 'object')
			continue;
		if (sec['.type'] == 'defaults') {
			has_fw_config = true;
			if (sec.input != null && length(trim('' + sec.input)) > 0)
				default_input = uc(trim('' + sec.input));
		}
	}

	for (let k, sec in fw_uci) {
		if (type(sec) != 'object' || sec['.type'] != 'zone')
			continue;

		has_fw_config = true;
		let zname = sec.name || k;
		let has_explicit_binding = (sec.network != null || sec.device != null || sec.subnet != null);
		let nets = to_list(sec.network, (!has_explicit_binding && type(sec.name) == 'string') ? [ sec.name ] : []);
		let devs = to_list(sec.device, []);
		let matched_lan = false;
		for (let ln in lan_names) {
			if (index(nets, ln) >= 0 || index(devs, ln) >= 0) {
				covered_lan[ln] = true;
				matched_lan = true;
			}
		}
		if (!matched_lan)
			continue;

		let policy = uc(trim('' + (sec.input || 'ACCEPT')));
		if (policy != 'ACCEPT') {
			push(warnings, sprintf(
				'fw4 zone "%s" has input policy "%s" (expected ACCEPT); TCP REDIRECT, UDP TPROXY, and DNS hijack traffic may be blocked',
				zname, policy
			));
		}
	}

	if (has_fw_config && default_input != 'ACCEPT') {
		for (let ln in lan_names) {
			if (!exists(covered_lan, ln)) {
				push(warnings, sprintf(
					'LAN interface "%s" is not assigned to any fw4 zone while defaults.input is "%s" (expected ACCEPT); TCP REDIRECT, UDP TPROXY, and DNS hijack traffic may be blocked',
					ln, default_input
				));
			}
		}
	}

	return warnings;
}

const build_rules_nft = generate_rules;

export {
	is_valid_ifname,
	classify_ip_or_cidr,
	resolve_network_context,
	parse_device_rules,
	parse_port_elements,
	generate_rules,
	build_rules_nft,
	build_emergency_lockdown_rules,
	apply_rules,
	apply_lockdown,
	apply_emergency_lockdown,
	replay_rules_file,
	delete_table,
	build_set_reload_script,
	reload_sets,
	reload_iface_sets,
	parse_set_elem_count,
	get_bypass_set_counts,
	parse_counters,
	get_counters,
	check_fw4_lan_input
};
