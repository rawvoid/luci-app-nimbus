#!/usr/bin/ucode
'use strict';

import * as fs from 'fs';
import * as common from 'common';
import * as nft from 'nft_manager';

let passed = 0;

function check(cond, msg) {
	if (!cond) {
		warn(sprintf('FAIL: %s\n', msg));
		exit(1);
	}
	passed++;
}

let nft_bin = getenv('NFT_BIN') || '/usr/sbin/nft';
let tmp_root = getenv('TMPDIR') || '/tmp';
let work_dir = sprintf('%s/nft_test_%d', tmp_root, time());
check(common.ensure_dir(work_dir, 0755), 'create work_dir');

function assert_rules_invariants(rules, mode, combo_desc) {
	check(index(rules, 'table inet nimbus\ndelete table inet nimbus\n') == 0,
		'idempotent header: ' + combo_desc);
	check(index(rules, 'elements = { }') < 0 && index(rules, 'elements = {}') < 0,
		'no empty elements = { }: ' + combo_desc);
	check(index(rules, 'fw4') < 0,
		'never touches fw4: ' + combo_desc);

	for (let sname in [
		'lan_ifaces', 'reserved_v4', 'reserved_v6', 'lan_v4', 'lan_v6',
		'wan_v4', 'wan_v6', 'fakeip_v4', 'fakeip_v6', 'bypass_v4', 'bypass_v6',
		'filter_tcp_ports', 'filter_udp_ports'
	]) {
		check(index(rules, 'set ' + sname + ' {') >= 0,
			sprintf('declares set %s: %s', sname, combo_desc));
	}
	check(index(rules, 'set lan_dev_') < 0,
		'omits legacy unordered lan_dev_* sets: ' + combo_desc);
	check(index(rules, '0x40') < 0,
		'does not pollute ct mark 0x40: ' + combo_desc);

	let lines = split(rules, '\n');
	for (let line in lines) {
		if (index(line, 'redirect to :') >= 0 && index(line, 'redirect to :53') < 0) {
			check(index(line, 'meta l4proto tcp') >= 0,
				'redirect rule contains meta l4proto tcp: ' + line);
		}
		if (index(line, 'tproxy ip to :') >= 0 || index(line, 'tproxy ip6 to :') >= 0) {
			check(index(line, 'meta l4proto udp') >= 0,
				'tproxy rule contains meta l4proto udp: ' + line);
		}
	}

	if (mode == 'lockdown') {
		check(index(rules, 'chain forward_lockdown {') >= 0,
			'lockdown has forward_lockdown chain: ' + combo_desc);
		check(index(rules, 'type filter hook forward priority filter - 1; policy accept;') >= 0,
			'lockdown hooks forward only: ' + combo_desc);
		check(index(rules, 'hook input') < 0 && index(rules, 'hook prerouting') < 0 && index(rules, 'hook output') < 0,
			'lockdown never hooks input/prerouting/output: ' + combo_desc);
		check(index(rules, 'meta l4proto icmpv6 icmpv6 type { 1, 2, 3, 4, 133, 134, 135, 136, 137 } return') >= 0,
			'lockdown preserves essential icmpv6 errors and NDP while blocking arbitrary echo leaks: ' + combo_desc);
		check(index(rules, 'counter name "lockdown_dropped" reject with icmpx type admin-prohibited') >= 0 &&
			index(rules, 'counter name "lockdown_dropped" counter') < 0,
			'lockdown rejects with deduplicated counter name "lockdown_dropped": ' + combo_desc);
	} else {
		check(index(rules, 'chain prerouting_tcp {') >= 0 && index(rules, 'chain prerouting_udp {') >= 0,
			'tproxy_redirect has prerouting_tcp and prerouting_udp: ' + combo_desc);
		check(index(rules, 'counter name "tcp_proxied" counter') < 0 &&
			index(rules, 'counter name "udp_proxied" counter') < 0,
			'proxy rules omit redundant anonymous counter alongside named counter: ' + combo_desc);
		check(index(rules, 'ct status dnat return') >= 0 && index(rules, 'fib daddr type local return') >= 0,
			'prerouting chains protect dnat and local destinations: ' + combo_desc);
		check(index(rules, 'ct mark & 0x30 == 0x10 return') >= 0 &&
			index(rules, 'ct mark & 0x30 == 0x20') >= 0 &&
			index(rules, 'ct mark set ct mark | ') < 0,
			'prerouting_udp has ct mark 0x10/0x20 fast path and clears 0x30 mask before setting: ' + combo_desc);
	}
}

// 1. Exhaustive matrix validation with real `nft -c -f`:
// {main, side} x {tproxy_redirect, lockdown} x {router_proxy=0,1} x
// {port_filter_mode=all,include,exclude,empty-include} x
// {lan_device_mode=default_proxy,default_bypass,all,proxy_listed,except_listed}
let topologies = [ 'main', 'side' ];
let modes = [ 'tproxy_redirect', 'lockdown' ];
let router_proxies = [ '0', '1' ];
let port_modes = [ 'all', 'include', 'exclude', 'empty-include' ];
let lan_modes = [ 'default_proxy', 'default_bypass', 'all', 'proxy_listed', 'except_listed' ];

let matrix_count = 0;
for (let topo in topologies) {
	for (let mode in modes) {
		for (let rp in router_proxies) {
			for (let pm in port_modes) {
				for (let lm in lan_modes) {
					matrix_count++;
					let actual_pm = (pm == 'empty-include') ? 'include' : pm;
					let tcp_ports = (pm == 'include' || pm == 'exclude') ? [ '80', '443', '8000-8999' ] : [];
					let udp_ports = (pm == 'include' || pm == 'exclude') ? [ '53', '443', '10000-10100' ] : [];

					let lan_devices = [
						{ enabled: '1', mac: 'AA:BB:CC:DD:EE:01', ip: '192.168.1.50', policy: 'bypass' },
						{ enabled: '1', mac: 'AA:BB:CC:DD:EE:02', ip: 'fd00::50', policy: 'proxy' },
						{ enabled: '1', ip: '192.168.1.60', policy: 'proxy' },
						{ enabled: '1', mac: 'AA:BB:CC:DD:EE:03', ip: '192.168.1.99', policy: 'block' }
					];

					let desc = sprintf('topo=%s mode=%s rp=%s pm=%s lm=%s', topo, mode, rp, pm, lm);
					let out_nft = sprintf('%s/matrix_%d.nft', work_dir, matrix_count);

					let res = nft.apply_rules({
						nft_bin: nft_bin,
						check_only: true,
						output_path: out_nft,
						topology: topo,
						mode: mode,
						router_proxy: rp,
						port_filter_mode: actual_pm,
						proxy_tcp_ports: tcp_ports,
						proxy_udp_ports: udp_ports,
						lan_proxy_mode: lm,
						lan_devices: lan_devices,
						lan_ifaces: [ 'br-lan' ],
						lan_v4: [ '192.168.1.0/24' ],
						lan_v6: [ 'fd00::/64' ],
						wan_v4: [ '203.0.113.10' ],
						wan_v6: [ '2001:db8:1::1', '2001:db8:2::/56' ],
						fakeip_v4: [ '198.18.0.0/15' ],
						fakeip_v6: [ 'fc00::/18' ],
						bypass_v4: [ '1.0.1.0/24', '1.0.2.0/23' ],
						bypass_v6: [ '2400:3200::/32' ]
					});

					check(res.ok === true, 'nft -c -f passed for ' + desc + (res.error ? (': ' + res.error) : ''));
					assert_rules_invariants(res.rules, mode, desc);
					check(index(res.rules, 'aa:bb:cc:dd:ee:03') < 0,
						'ignores unsupported device policy block: ' + desc);

					if (topo == 'side') {
						check(index(res.rules, '203.0.113.10') < 0 && index(res.rules, '2001:db8:1::1') < 0,
							'side topology omits wan_v4/wan_v6 elements: ' + desc);
					} else {
						check(index(res.rules, '203.0.113.10') >= 0 && index(res.rules, '2001:db8:1::1') >= 0,
							'main topology populates wan_v4/wan_v6 elements: ' + desc);
					}

					let is_default_bypass = (lm == 'default_bypass' || lm == 'proxy_listed');
					if (mode == 'tproxy_redirect') {
						check(index(res.rules, 'ether saddr aa:bb:cc:dd:ee:01 return') >= 0 &&
							index(res.rules, 'ether saddr aa:bb:cc:dd:ee:01 ct mark set ct mark & 0xffffffcf | 0x10 return') >= 0 &&
							index(res.rules, 'ether saddr aa:bb:cc:dd:ee:02 goto prerouting_tcp_proxy') >= 0 &&
							index(res.rules, 'ether saddr aa:bb:cc:dd:ee:02 goto prerouting_udp_proxy') >= 0,
							'device rules apply prior to default policy in tproxy_redirect: ' + desc);

						if (is_default_bypass) {
							check(index(res.rules, 'ip saddr 192.168.1.60 goto prerouting_tcp_proxy\n\t\treturn\n\t}') >= 0 &&
								index(res.rules, 'ip saddr 192.168.1.60 goto prerouting_udp_proxy\n\t\tct mark set ct mark & 0xffffffcf | 0x10 return\n\t}') >= 0,
								'default_bypass emits direct return fallbacks at TCP/UDP chain tails: ' + desc);
						} else {
							check(index(res.rules, 'ip saddr 192.168.1.60 goto prerouting_tcp_proxy\n\t\tgoto prerouting_tcp_proxy\n\t}') >= 0 &&
								index(res.rules, 'ip saddr 192.168.1.60 goto prerouting_udp_proxy\n\t\tgoto prerouting_udp_proxy\n\t}') >= 0,
								'default_proxy emits proxy goto fallbacks at TCP/UDP chain tails: ' + desc);
						}

						if (rp == '1') {
							check(index(res.rules, 'chain output_tcp {') >= 0 &&
								index(res.rules, 'chain output_udp {') >= 0 &&
								index(res.rules, 'iifname "lo" meta mark 0x1') >= 0,
								'router_proxy=1 generates output_tcp/output_udp and lo TPROXY rules: ' + desc);
						} else {
							check(index(res.rules, 'chain output_tcp {') < 0 &&
								index(res.rules, 'chain output_udp {') < 0 &&
								index(res.rules, 'iifname "lo"') < 0,
								'router_proxy=0 omits output chains and lo TPROXY rules: ' + desc);
						}

						if (pm == 'empty-include') {
							check(index(res.rules, 'tcp dport != @filter_tcp_ports') < 0 &&
								index(res.rules, 'udp dport != @filter_udp_ports') < 0 &&
								index(res.rules, 'ip daddr @fakeip_v4') < index(res.rules, '\t\treturn\n\t\tip daddr @reserved_v4') &&
								index(res.rules, 'ip6 daddr @fakeip_v6') < index(res.rules, '\t\tct mark set ct mark & 0xffffffcf | 0x10 return\n\t\tip daddr @reserved_v4'),
								'empty-include places Fake-IP priority before short-circuiting non-Fake-IP TCP and UDP: ' + desc);
						} else if (pm == 'include') {
							check(index(res.rules, 'ip6 daddr @fakeip_v6') < index(res.rules, 'tcp dport != @filter_tcp_ports return') &&
								index(res.rules, 'udp dport != @filter_udp_ports ct mark set ct mark & 0xffffffcf | 0x10 return') >= 0,
								'include mode places Fake-IP before @filter_tcp_ports and @filter_udp_ports: ' + desc);
						} else if (pm == 'exclude') {
							check(index(res.rules, 'ip6 daddr @fakeip_v6') < index(res.rules, 'tcp dport @filter_tcp_ports return') &&
								index(res.rules, 'udp dport @filter_udp_ports ct mark set ct mark & 0xffffffcf | 0x10 return') >= 0,
								'exclude mode places Fake-IP before @filter_tcp_ports and @filter_udp_ports: ' + desc);
						}
					} else {
						check(index(res.rules, 'ether saddr aa:bb:cc:dd:ee:01 return') >= 0 &&
							index(res.rules, 'ether saddr aa:bb:cc:dd:ee:02 goto forward_lockdown_enforce') >= 0,
							'lockdown preserves bypass and proxy device rules across all modes: ' + desc);

						if (is_default_bypass) {
							check(index(res.rules, 'ip saddr 192.168.1.60 goto forward_lockdown_enforce\n\t\treturn\n\t}') >= 0,
								'lockdown default_bypass emits return fallback at chain tail: ' + desc);
						} else {
							check(index(res.rules, 'ip saddr 192.168.1.60 goto forward_lockdown_enforce\n\t\tgoto forward_lockdown_enforce\n\t}') >= 0,
								'lockdown default_proxy emits enforce goto fallback at chain tail: ' + desc);
						}
					}
				}
			}
		}
	}
}
check(matrix_count == 160, 'tested all 160 primary matrix combinations');

// 2. Device rule precedence, first-match ordering, .index sorting, empty/bypass-only edge cases
let all_with_bypass = nft.apply_rules({
	nft_bin: nft_bin,
	check_only: true,
	output_path: work_dir + '/all_with_bypass.nft',
	mode: 'tproxy_redirect',
	lan_device_mode: 'all',
	lan_devices: [
		{ enabled: '1', mac: '78:2E:03:53:00:2F', ip: '10.11.1.115', policy: 'bypass' },
		{ enabled: '0', mac: 'AA:BB:CC:DD:EE:99', ip: '10.11.1.200', policy: 'proxy' }
	]
});
check(all_with_bypass.ok === true &&
	index(all_with_bypass.rules, 'ether saddr 78:2e:03:53:00:2f return') >= 0 &&
	index(all_with_bypass.rules, 'ip saddr 10.11.1.115 return') >= 0 &&
	index(all_with_bypass.rules, 'ether saddr 78:2e:03:53:00:2f ct mark set ct mark & 0xffffffcf | 0x10 return') >= 0 &&
	index(all_with_bypass.rules, 'ip saddr 10.11.1.115 ct mark set ct mark & 0xffffffcf | 0x10 return') >= 0 &&
	index(all_with_bypass.rules, 'prerouting_tcp_proxy') < 0 &&
	index(all_with_bypass.rules, 'aa:bb:cc:dd:ee:99') < 0,
	'default_proxy / legacy all applies enabled bypass rule, skips disabled rows, and avoids subchains');

let host_proxy_before_subnet_bypass = nft.apply_rules({
	nft_bin: nft_bin,
	check_only: true,
	output_path: work_dir + '/order_a.nft',
	mode: 'tproxy_redirect',
	lan_device_mode: 'default_proxy',
	lan_devices: [
		{ enabled: '1', ip: '10.11.1.50', policy: 'proxy' },
		{ enabled: '1', ip: '10.11.1.0/24', policy: 'bypass' }
	]
});
check(host_proxy_before_subnet_bypass.ok === true, 'host proxy before subnet bypass passes nft -c -f');
check(index(host_proxy_before_subnet_bypass.rules, 'ip saddr 10.11.1.50 goto prerouting_tcp_proxy') >= 0 &&
	index(host_proxy_before_subnet_bypass.rules, 'ip saddr 10.11.1.50 goto prerouting_tcp_proxy') <
	index(host_proxy_before_subnet_bypass.rules, 'ip saddr 10.11.1.0/24 return') &&
	index(host_proxy_before_subnet_bypass.rules, 'ip saddr 10.11.1.50 goto prerouting_udp_proxy') >= 0 &&
	index(host_proxy_before_subnet_bypass.rules, 'ip saddr 10.11.1.50 goto prerouting_udp_proxy') <
	index(host_proxy_before_subnet_bypass.rules, 'ip saddr 10.11.1.0/24 ct mark set ct mark & 0xffffffcf | 0x10 return'),
	'first-match order puts host proxy before subnet bypass in TCP and UDP');

let subnet_bypass_before_host_proxy = nft.apply_rules({
	nft_bin: nft_bin,
	check_only: true,
	output_path: work_dir + '/order_b.nft',
	mode: 'lockdown',
	uci: {
		global: { topology: 'main', lan_interfaces: [ 'lan' ] },
		proxy: { lan_device_mode: 'default_bypass' },
		z_subnet: { '.type': 'lan_device', '.index': 1, enabled: '1', ip: '10.11.1.50', policy: 'proxy' },
		a_subnet: { '.type': 'lan_device', '.index': 0, enabled: '1', ip: '10.11.1.0/24', policy: 'bypass' }
	}
});
check(subnet_bypass_before_host_proxy.ok === true, 'UCI .index ordered lockdown rules pass nft -c -f');
check(index(subnet_bypass_before_host_proxy.rules, 'ip saddr 10.11.1.0/24 return') >= 0 &&
	index(subnet_bypass_before_host_proxy.rules, 'ip saddr 10.11.1.0/24 return') <
	index(subnet_bypass_before_host_proxy.rules, 'ip saddr 10.11.1.50 goto forward_lockdown_enforce'),
	'UCI .index controls first-match order strictly regardless of object key order');

let empty_proxy_tproxy = nft.apply_rules({
	nft_bin: nft_bin,
	check_only: true,
	output_path: work_dir + '/empty_proxy_tproxy.nft',
	mode: 'tproxy_redirect',
	lan_proxy_mode: 'proxy_listed',
	lan_devices: [
		{ enabled: '1', mac: '78:2E:03:53:00:2F', policy: 'bypass' }
	]
});
check(empty_proxy_tproxy.ok === true &&
	index(empty_proxy_tproxy.rules, 'prerouting_tcp_proxy') < 0 &&
	index(empty_proxy_tproxy.rules, 'prerouting_udp_proxy') < 0 &&
	index(empty_proxy_tproxy.rules, 'ct mark & 0x30 == 0x20') < 0 &&
	index(empty_proxy_tproxy.rules, '78:2e:03:53:00:2f') < 0 &&
	index(empty_proxy_tproxy.rules, 'ip daddr @fakeip_v4') < 0 &&
	index(empty_proxy_tproxy.rules, '\t\tfib daddr type local return\n\t\treturn\n\t}') >= 0 &&
	index(empty_proxy_tproxy.rules, '\t\tct mark set ct mark & 0xffffffcf | 0x10 return\n\t}') >= 0,
	'default_bypass / proxy_listed without active proxy rules omits 0x20 fast-path, prunes dead tail, and short-circuits');

let empty_proxy_lockdown = nft.apply_rules({
	nft_bin: nft_bin,
	check_only: true,
	output_path: work_dir + '/empty_proxy_lockdown.nft',
	mode: 'lockdown',
	lan_device_mode: 'default_bypass',
	ipv4_enable: '0',
	ipv6_enable: '1',
	lan_devices: [
		{ enabled: '1', ip: '10.11.1.50', policy: 'proxy' }
	]
});
check(empty_proxy_lockdown.ok === true &&
	index(empty_proxy_lockdown.rules, 'forward_lockdown_enforce') < 0 &&
	index(empty_proxy_lockdown.rules, 'ip6 daddr @reserved_v6') < 0 &&
	index(empty_proxy_lockdown.rules, 'reject with icmpx') < 0 &&
	index(empty_proxy_lockdown.rules, 'counter lockdown_dropped {}') >= 0 &&
	index(empty_proxy_lockdown.rules, '\t\tmeta l4proto icmpv6 icmpv6 type { 1, 2, 3, 4, 133, 134, 135, 136, 137 } return\n\t\treturn\n\t}') >= 0,
	'default_bypass with IPv4-only proxy rule under ipv4_enable=0 prunes dead lockdown tail');

let explicit_override = nft.apply_rules({
	nft_bin: nft_bin,
	check_only: true,
	output_path: work_dir + '/explicit_override.nft',
	mode: 'tproxy_redirect',
	lan_device_mode: 'default_proxy',
	uci: {
		global: { topology: 'main', lan_interfaces: [ 'lan' ] },
		proxy: { lan_device_mode: 'default_proxy' },
		d0: { '.type': 'lan_device', enabled: '1', ip: '10.99.99.99', policy: 'bypass' }
	},
	lan_devices: []
});
check(explicit_override.ok === true &&
	index(explicit_override.rules, '10.99.99.99') < 0,
	'explicit options.lan_devices overrides uci_cfg lan_device sections');

let empty_pol_fallback = nft.apply_rules({
	nft_bin: nft_bin,
	check_only: true,
	output_path: work_dir + '/empty_policy_fallback.nft',
	mode: 'tproxy_redirect',
	lan_device_mode: 'default_proxy',
	lan_devices: [
		{ enabled: '1', ip: '10.11.1.88', policy: '' },
		{ enabled: '1', ip: '10.11.1.89' }
	]
});
check(empty_pol_fallback.ok === true &&
	index(empty_pol_fallback.rules, 'ip saddr 10.11.1.88 return') >= 0 &&
	index(empty_pol_fallback.rules, 'ip saddr 10.11.1.88 ct mark set ct mark & 0xffffffcf | 0x10 return') >= 0 &&
	index(empty_pol_fallback.rules, 'ip saddr 10.11.1.89 return') >= 0 &&
	index(empty_pol_fallback.rules, 'ip saddr 10.11.1.89 ct mark set ct mark & 0xffffffcf | 0x10 return') >= 0,
	'empty or omitted device policy defaults cleanly to bypass');

let partial_idx_rules = nft.parse_device_rules({
	c_sec: { '.type': 'lan_device', '.index': 5, enabled: '1', ip: '10.12.0.3', policy: 'bypass' },
	b_sec: { '.type': 'lan_device', enabled: '1', ip: '10.12.0.4', policy: 'proxy' },
	a_sec: { '.type': 'lan_device', '.index': 1, enabled: '1', ip: '10.12.0.1', policy: 'bypass' }
});
check(length(partial_idx_rules) == 3 &&
	partial_idx_rules[0].v4[0] == '10.12.0.1' &&
	partial_idx_rules[1].v4[0] == '10.12.0.3' &&
	partial_idx_rules[2].v4[0] == '10.12.0.4',
	'partial .index comparator maintains strict total order');

let uci_order_dir = work_dir + '/uci_order';
check(common.ensure_dir(uci_order_dir, 0755), 'create uci_order dir');
check(fs.writefile(uci_order_dir + '/nimbus',
	"config main 'global'\n\toption topology 'main'\n\tlist lan_interfaces 'lan'\n\n" +
	"config proxy 'proxy'\n\toption lan_device_mode 'default_proxy'\n\n" +
	"config lan_device\n\toption enabled '1'\n\toption ip '10.20.0.1'\n\toption policy 'proxy'\n\n" +
	"config lan_device\n\toption enabled '1'\n\toption ip '10.20.0.0/24'\n\toption policy 'bypass'\n\n" +
	"config lan_device\n\toption enabled '1'\n\toption ip '10.20.0.2'\n\toption policy 'proxy'\n"
) != null, 'write real UCI config fixture for libuci order test');
let real_uci_res = nft.apply_rules({
	nft_bin: nft_bin,
	check_only: true,
	output_path: work_dir + '/real_uci_order.nft',
	uci_confdir: uci_order_dir,
	uci_savedir: uci_order_dir + '/.uci',
	lan_ifaces: [ 'br-lan' ]
});
check(real_uci_res.ok === true, 'real libuci config passes nft -c -f');
let p1 = index(real_uci_res.rules, 'ip saddr 10.20.0.1 goto prerouting_tcp_proxy');
let p2 = index(real_uci_res.rules, 'ip saddr 10.20.0.0/24 return');
let p3 = index(real_uci_res.rules, 'ip saddr 10.20.0.2 goto prerouting_tcp_proxy');
check(p1 >= 0 && p2 > p1 && p3 > p2,
	'real libuci section order matches file top-to-bottom exactly');

let v4_only = nft.apply_rules({
	nft_bin: nft_bin,
	check_only: true,
	output_path: work_dir + '/v4_only.nft',
	ipv4_enable: '1',
	ipv6_enable: '0',
	router_proxy: '1',
	hijack_lan_dns: '1'
});
check(v4_only.ok === true &&
	index(v4_only.rules, 'chain prerouting_dns {') >= 0 &&
	index(v4_only.rules, 'tproxy ip6') < 0 &&
	index(v4_only.rules, 'meta nfproto ipv6') < 0,
	'ipv6_enable=0 + hijack_lan_dns=1 passes nft -c -f and omits IPv6 rules');

let dns_bypass_default_proxy = nft.apply_rules({
	nft_bin: nft_bin,
	check_only: true,
	output_path: work_dir + '/dns_bypass_default_proxy.nft',
	mode: 'tproxy_redirect',
	hijack_lan_dns: '1',
	lan_device_mode: 'default_proxy',
	lan_devices: [
		{ enabled: '1', mac: '78:2E:03:53:00:2F', ip: '10.11.1.115', policy: 'bypass' }
	]
});
check(dns_bypass_default_proxy.ok === true, 'hijack_lan_dns=1 default_proxy + bypass passes nft -c -f');
let d_proto = index(dns_bypass_default_proxy.rules, 'meta l4proto != { tcp, udp } return');
let d_port = index(dns_bypass_default_proxy.rules, 'th dport != 53 return');
let d_mark = index(dns_bypass_default_proxy.rules, 'meta mark 0xff return');
let d_mac = index(dns_bypass_default_proxy.rules, 'ether saddr 78:2e:03:53:00:2f return');
let d_ip = index(dns_bypass_default_proxy.rules, 'ip saddr 10.11.1.115 return');
let d_redir = index(dns_bypass_default_proxy.rules, 'meta l4proto { tcp, udp } th dport 53 counter redirect to :53');
check(index(dns_bypass_default_proxy.rules, 'prerouting_dns_hijack') < 0 &&
	d_proto >= 0 && d_port > d_proto && d_mark > d_port && d_mac > d_mark && d_ip > d_mac && d_redir > d_ip,
	'prerouting_dns checks protocol/port/outbound_mark before device bypass rules and omits hijack subchain');

let dns_mixed_default_proxy = nft.apply_rules({
	nft_bin: nft_bin,
	check_only: true,
	output_path: work_dir + '/dns_mixed_default_proxy.nft',
	mode: 'tproxy_redirect',
	hijack_lan_dns: '1',
	lan_device_mode: 'default_proxy',
	lan_devices: [
		{ enabled: '1', ip: '10.11.1.50', policy: 'proxy' },
		{ enabled: '1', ip: '10.11.1.0/24', policy: 'bypass' }
	]
});
check(dns_mixed_default_proxy.ok === true, 'hijack_lan_dns=1 mixed default_proxy passes nft -c -f');
check(index(dns_mixed_default_proxy.rules, 'chain prerouting_dns_hijack {') >= 0 &&
	index(dns_mixed_default_proxy.rules, 'ip saddr 10.11.1.50 goto prerouting_dns_hijack') >= 0 &&
	index(dns_mixed_default_proxy.rules, 'ip saddr 10.11.1.50 goto prerouting_dns_hijack') <
	index(dns_mixed_default_proxy.rules, 'ip saddr 10.11.1.0/24 return') &&
	index(dns_mixed_default_proxy.rules, 'ip saddr 10.11.1.0/24 return\n\t\tgoto prerouting_dns_hijack\n\t}') >= 0,
	'prerouting_dns respects ordered proxy-before-bypass rules and default_proxy fallback');

let dns_mixed_default_bypass = nft.apply_rules({
	nft_bin: nft_bin,
	check_only: true,
	output_path: work_dir + '/dns_mixed_default_bypass.nft',
	mode: 'tproxy_redirect',
	hijack_lan_dns: '1',
	lan_device_mode: 'default_bypass',
	lan_devices: [
		{ enabled: '1', ip: '10.11.1.50', policy: 'proxy' },
		{ enabled: '1', ip: '10.11.1.0/24', policy: 'bypass' }
	]
});
check(dns_mixed_default_bypass.ok === true &&
	index(dns_mixed_default_bypass.rules, 'ip saddr 10.11.1.0/24 return\n\t\treturn\n\t}') >= 0,
	'prerouting_dns respects default_bypass fallback after ordered rules');

let dns_short_circuit = nft.apply_rules({
	nft_bin: nft_bin,
	check_only: true,
	output_path: work_dir + '/dns_short_circuit.nft',
	mode: 'tproxy_redirect',
	hijack_lan_dns: '1',
	lan_device_mode: 'default_bypass',
	lan_devices: [
		{ enabled: '1', ip: '10.11.1.115', policy: 'bypass' }
	]
});
check(dns_short_circuit.ok === true &&
	index(dns_short_circuit.rules, 'prerouting_dns_hijack') < 0 &&
	index(dns_short_circuit.rules, 'redirect to :53') < 0 &&
	index(dns_short_circuit.rules, '\t\tfib daddr type local return\n\t\treturn\n\t}\n\n\tchain prerouting_tcp {') >= 0,
	'prerouting_dns short-circuits safely under default_bypass without active proxy rules');

let v6_only = nft.apply_rules({
	nft_bin: nft_bin,
	check_only: true,
	output_path: work_dir + '/v6_only.nft',
	ipv4_enable: '0',
	ipv6_enable: '1',
	router_proxy: '1',
	hijack_lan_dns: '1'
});
check(v6_only.ok === true &&
	index(v6_only.rules, 'tproxy ip to') < 0 &&
	index(v6_only.rules, 'meta nfproto ipv4') < 0 &&
	index(v6_only.rules, 'meta nfproto != ipv6 return') >= 0 &&
	index(v6_only.rules, 'tproxy ip6 to') >= 0,
	'ipv4_enable=0 passes nft -c -f, injects meta nfproto != ipv6 guard, and omits IPv4 rules');

// P0 regression tests: single-stack default_proxy lockdown, lan_ifaces validation/@alias deref, inbound UDP reply/DNAT & DHCPv4/v6 bypass, /0 rejection, emergency lockdown
let v4_only_lockdown = nft.apply_lockdown({
	nft_bin: nft_bin,
	check_only: true,
	output_path: work_dir + '/v4_only_lockdown.nft',
	ipv4_enable: '1',
	ipv6_enable: '0',
	lan_device_mode: 'default_proxy'
});
check(v4_only_lockdown.ok === true &&
	index(v4_only_lockdown.rules, 'meta nfproto != ipv4 return') >= 0 &&
	index(v4_only_lockdown.rules, 'meta l4proto icmpv6') < 0 &&
	index(v4_only_lockdown.rules, 'ct status dnat return') >= 0 &&
	index(v4_only_lockdown.rules, 'ct direction reply return') >= 0 &&
	index(v4_only_lockdown.rules, 'ip daddr @reserved_v4 return') >= 0 &&
	index(v4_only_lockdown.rules, 'ip6 daddr') < 0,
	'single-stack ipv6_enable=0 default_proxy lockdown guards unmanaged IPv6 from reject');

let v6_only_lockdown = nft.apply_lockdown({
	nft_bin: nft_bin,
	check_only: true,
	output_path: work_dir + '/v6_only_lockdown.nft',
	ipv4_enable: '0',
	ipv6_enable: '1',
	lan_device_mode: 'default_proxy'
});
check(v6_only_lockdown.ok === true &&
	index(v6_only_lockdown.rules, 'meta nfproto != ipv6 return') >= 0 &&
	index(v6_only_lockdown.rules, 'ip6 daddr @reserved_v6 return') >= 0 &&
	index(v6_only_lockdown.rules, 'ip daddr') < 0,
	'single-stack ipv4_enable=0 default_proxy lockdown guards unmanaged IPv4 from reject');

check(index(v4_only.rules, 'chain prerouting_dns {\n\t\ttype nat hook prerouting priority dstnat + 1; policy accept;\n\t\tiifname != @lan_ifaces return\n\t\tmeta nfproto != ipv4 return') >= 0 &&
	index(v4_only.rules, 'ct status dnat return\n\t\tct direction reply return') >= 0 &&
	index(v4_only.rules, 'meta nfproto ipv4 udp sport 68 udp dport 67 return') >= 0 &&
	index(v4_only.rules, 'udp sport 546') < 0 &&
	index(v6_only.rules, 'meta nfproto ipv6 udp sport 546 udp dport 547 return') >= 0 &&
	index(v6_only.rules, 'udp sport 68') < 0,
	'single-stack guards, ct dnat/reply bypass, and DHCPv4/v6 client port exclusions apply accurately');

// lan_ifaces injection / >15-char / @alias protection & ubus priority
let net_alias_dir = work_dir + '/net_alias_uci';
check(common.ensure_dir(net_alias_dir, 0755), 'create net_alias_dir');
check(fs.writefile(net_alias_dir + '/network',
	"config interface 'lan'\n\toption device 'br-lan'\n\n" +
	"config interface 'lan6'\n\toption device '@lan'\n\n" +
	"config interface 'iot'\n\toption device '@overlong_alias_interface_name'\n\n" +
	"config interface 'overlong_interface_section'\n\toption device 'this_device_name_is_way_over_15_chars'\n\n" +
	"config interface 'ubus_resolved'\n\toption device '@stale_alias_123456'\n"
) != null, 'write network UCI fixture with @alias and overlong device names');

let ctx_sanitized = nft.resolve_network_context({
	global: {
		topology: 'main',
		lan_interfaces: [
			'lan6',
			'iot',
			'overlong_interface_section',
			'ubus_resolved',
			'bad" }\nflush ruleset\n#',
			'..',
			'br-lan:0',
			'eth0.10'
		]
	}
}, {
	uci_confdir: net_alias_dir,
	uci_savedir: net_alias_dir + '/.uci',
	ubus_dump: {
		interface: [
			{ interface: 'ubus_resolved', l3_device: 'br-iot' }
		]
	}
});
check(index(ctx_sanitized.lan_ifaces, 'br-lan') >= 0 &&
	index(ctx_sanitized.lan_ifaces, 'br-iot') >= 0 &&
	index(ctx_sanitized.lan_ifaces, 'eth0.10') >= 0 &&
	length(ctx_sanitized.lan_ifaces) == 3,
	'resolve_network_context dereferences @lan -> br-lan, skips UCI when ubus resolves l3_device, and rejects injection/overlong/:label/.. names');

let inj_apply = nft.apply_rules({
	nft_bin: nft_bin,
	check_only: true,
	output_path: work_dir + '/inj_guard.nft',
	lan_ifaces: [ 'evil" }\ntable inet pwn {', '@too_long_interface_12345', '.' ]
});
check(inj_apply.ok === true &&
	index(inj_apply.rules, 'elements = { "br-lan" }') >= 0 &&
	index(inj_apply.rules, 'pwn') < 0,
	'malicious/invalid lan_ifaces safely falls back to br-lan and passes nft -c -f');

// /0 rejection and CIDR canonicalization
check(nft.classify_ip_or_cidr('0.0.0.0/0') == null &&
	nft.classify_ip_or_cidr('::/0') == null &&
	nft.classify_ip_or_cidr('1.2.3.4/0') == null &&
	nft.classify_ip_or_cidr('1.0.1.0/024')?.value == '1.0.1.0/24' &&
	nft.classify_ip_or_cidr('2001:0db8:0000:0000::1/064')?.value == '2001:db8::1/64',
	'classify_ip_or_cidr rejects /0 prefixes and canonicalizes leading zeros and IPv6 notation');

let emg_res = nft.apply_emergency_lockdown({
	nft_bin: nft_bin,
	check_only: true,
	output_path: work_dir + '/emergency_lockdown.nft'
});
check(emg_res.ok === true && emg_res.emergency === true &&
	index(emg_res.rules, 'chain forward_lockdown {') >= 0 &&
	index(emg_res.rules, 'reject with icmpx type admin-prohibited') >= 0,
	'static emergency lockdown ruleset passes real nft -c -f');

// 3. Live table load + atomic Set hot-reload (`reload_sets`) + live `get_counters`
let live_apply = nft.apply_rules({
	nft_bin: nft_bin,
	output_path: work_dir + '/live_rules.nft',
	mode: 'tproxy_redirect',
	bypass_v4: [ '1.0.1.0/24' ]
});
check(live_apply.ok === true, 'live nft -f apply_rules succeeds in container');

let reload_nonempty = nft.reload_sets({
	bypass_v4: [ '1.0.1.0/24', '1.0.2.0/24', '1.0.3.0/24', '8.8.8.0/24' ],
	bypass_v6: [ '2400:3200::/32' ]
}, {
	nft_bin: nft_bin,
	output_path: work_dir + '/bypass_sets.nft'
});
check(reload_nonempty.ok === true &&
	index(reload_nonempty.script, 'flush set inet nimbus bypass_v4\nadd element inet nimbus bypass_v4 { 1.0.1.0/24, 1.0.2.0/24, 1.0.3.0/24, 8.8.8.0/24 }\n') >= 0 &&
	index(reload_nonempty.script, 'flush set inet nimbus bypass_v6\nadd element inet nimbus bypass_v6 { 2400:3200::/32 }\n') >= 0 &&
	reload_nonempty.loaded_counts?.bypass_v4 == 2 &&
	reload_nonempty.loaded_counts?.bypass_v6 == 1,
	'reload_sets atomically reloads sets and reads auto-merged element count (4 CIDRs -> 2 intervals) via nft -j');

let reload_empty = nft.reload_sets({
	bypass_v4: [],
	bypass_v6: []
}, {
	nft_bin: nft_bin,
	output_path: work_dir + '/bypass_empty.nft'
});
check(reload_empty.ok === true &&
	reload_empty.script == 'flush set inet nimbus bypass_v4\nflush set inet nimbus bypass_v6\n' &&
	index(reload_empty.script, 'add element') < 0 &&
	reload_empty.loaded_counts?.bypass_v4 == 0 &&
	reload_empty.loaded_counts?.bypass_v6 == 0,
	'reload_sets omits add element when set arrays are empty and reports 0 loaded elements');

let iface_reload = nft.reload_iface_sets({
	global: {
		topology: 'main',
		lan_interfaces: [ 'lan' ],
		wan_interfaces: [ 'wan', 'wan6' ]
	}
}, {
	nft_bin: nft_bin,
	output_path: work_dir + '/wan_sets.nft',
	ubus_dump: {
		interface: [
			{
				interface: 'lan',
				l3_device: 'br-lan',
				'ipv4-address': [ { address: '192.168.10.1', mask: 24 } ],
				'ipv6-prefix-assignment': [ { address: 'fd10::', mask: 64 } ]
			},
			{
				interface: 'wan',
				l3_device: 'eth1',
				'ipv4-address': [ { address: '198.51.100.42', mask: 24 } ]
			},
			{
				interface: 'wan6',
				l3_device: 'eth1',
				'ipv6-address': [ { address: '2001:db8:99::2', mask: 64 } ],
				'ipv6-prefix': [ { address: '2001:db8:100::', mask: 56 } ]
			}
		]
	}
});
check(iface_reload.ok === true &&
	index(iface_reload.script, 'flush set inet nimbus lan_ifaces\nadd element inet nimbus lan_ifaces { "br-lan" }\n') >= 0 &&
	index(iface_reload.script, '192.168.10.1/24') >= 0 &&
	index(iface_reload.script, '198.51.100.42') >= 0 &&
	index(iface_reload.script, '2001:db8:99::2') >= 0 &&
	index(iface_reload.script, '2001:db8:100::/56') >= 0,
	'reload_iface_sets refreshes lan_ifaces alongside LAN/WAN IP sets atomically');

let live_ctrs = nft.get_counters({ nft_bin: nft_bin });
check(live_ctrs.ok === true &&
	live_ctrs.tcp_packets == 0 && live_ctrs.udp_packets == 0 && live_ctrs.lockdown_rejected_packets == 0,
	'live get_counters queries nft -j list counters table inet nimbus');

let live_apply_subchain = nft.apply_rules({
	nft_bin: nft_bin,
	output_path: work_dir + '/live_rules_subchain.nft',
	mode: 'tproxy_redirect',
	lan_device_mode: 'default_proxy',
	lan_devices: [
		{ enabled: '1', mac: 'AA:BB:CC:DD:EE:02', ip: '10.11.1.50', policy: 'proxy' },
		{ enabled: '1', ip: '10.11.1.0/24', policy: 'bypass' }
	]
});
check(live_apply_subchain.ok === true, 'live nft -f with ordered goto subchains succeeds in container');

let live_apply_lockdown_subchain = nft.apply_lockdown({
	nft_bin: nft_bin,
	output_path: work_dir + '/live_lockdown_subchain.nft',
	lan_device_mode: 'default_bypass',
	lan_devices: [
		{ enabled: '1', ip: '10.11.1.5', policy: 'bypass' },
		{ enabled: '1', ip: '10.11.1.0/24', policy: 'proxy' }
	]
});
check(live_apply_lockdown_subchain.ok === true, 'live nft -f lockdown with ordered goto subchain succeeds in container');

let live_apply_dns_subchain = nft.apply_rules({
	nft_bin: nft_bin,
	output_path: work_dir + '/live_dns_subchain.nft',
	mode: 'tproxy_redirect',
	hijack_lan_dns: '1',
	lan_device_mode: 'default_bypass',
	lan_devices: [
		{ enabled: '1', ip: '10.11.1.50', policy: 'proxy' },
		{ enabled: '1', ip: '10.11.1.0/24', policy: 'bypass' }
	]
});
check(live_apply_dns_subchain.ok === true, 'live nft -f hijack_lan_dns with ordered goto subchain succeeds in container');

check(nft.delete_table({ nft_bin: nft_bin }).ok === true, 'delete_table cleans up live table');
check(nft.delete_table({ nft_bin: nft_bin }).ok === true, 'delete_table is idempotent when table does not exist');
check(nft.delete_table({ nft_bin: '/nonexistent/nft-bin' }).ok === false,
	'delete_table surfaces real execution failure instead of swallowing it');

// 4. get_counters JSON parsing tests (both `nft -j list counters` and `nft -j list table` formats)
let sample_list_counters_json = sprintf('%J', {
	nftables: [
		{ metainfo: { version: '1.1.1', json_schema_version: 1 } },
		{ counter: { family: 'inet', table: 'nimbus', name: 'tcp_proxied', packets: 152410, bytes: 184291020 } },
		{ counter: { family: 'inet', table: 'nimbus', name: 'udp_proxied', packets: 48920, bytes: 32910440 } },
		{ counter: { family: 'inet', table: 'nimbus', name: 'lockdown_dropped', packets: 312, bytes: 24960 } }
	]
});
let parsed_named = nft.get_counters(sample_list_counters_json);
check(parsed_named.ok === true &&
	parsed_named.tcp_packets == 152410 && parsed_named.tcp_bytes == 184291020 &&
	parsed_named.udp_packets == 48920 && parsed_named.udp_bytes == 32910440 &&
	parsed_named.lockdown_rejected_packets == 312 && parsed_named.lockdown_dropped_packets == 312 &&
	parsed_named.lockdown_dropped_bytes == 24960,
	'get_counters parses nft -j list counters table inet nimbus JSON accurately');

let sample_list_table_json = sprintf('%J', {
	nftables: [
		{ metainfo: { version: '1.1.1', json_schema_version: 1 } },
		{
			rule: {
				family: 'inet',
				table: 'nimbus',
				chain: 'prerouting_tcp',
				expr: [ { counter: { packets: 100, bytes: 5000 } } ]
			}
		},
		{
			rule: {
				family: 'inet',
				table: 'nimbus',
				chain: 'prerouting_tcp_proxy',
				expr: [ { counter: { packets: 25, bytes: 1200 } } ]
			}
		},
		{
			rule: {
				family: 'inet',
				table: 'nimbus',
				chain: 'prerouting_udp_proxy',
				expr: [ { counter: { packets: 40, bytes: 8000 } } ]
			}
		},
		{
			rule: {
				family: 'inet',
				table: 'nimbus',
				chain: 'forward_lockdown_enforce',
				expr: [ { counter: { packets: 7, bytes: 420 } } ]
			}
		}
	]
});
let parsed_rules = nft.get_counters(sample_list_table_json);
check(parsed_rules.ok === true &&
	parsed_rules.tcp_packets == 125 && parsed_rules.tcp_bytes == 6200 &&
	parsed_rules.udp_packets == 40 && parsed_rules.udp_bytes == 8000 &&
	parsed_rules.lockdown_rejected_packets == 7 && parsed_rules.lockdown_dropped_packets == 7,
	'get_counters aggregates anonymous rule counters from nft -j list table inet nimbus');

// 5. check_fw4_lan_input diagnostic warning helper
let fw_ok = nft.check_fw4_lan_input(
	{ global: { lan_interfaces: [ 'lan' ] } },
	{ firewall_uci: { z_lan: { '.type': 'zone', name: 'lan', network: [ 'lan' ], input: 'ACCEPT' } } }
);
check(length(fw_ok) == 0, 'check_fw4_lan_input emits no warning when LAN zone input is ACCEPT');

let fw_warn = nft.check_fw4_lan_input(
	{ global: { lan_interfaces: [ 'lan' ] } },
	{ firewall_uci: { z_lan: { '.type': 'zone', name: 'lan', network: 'lan guest', input: 'REJECT' } } }
);
check(length(fw_warn) == 1 && index(fw_warn[0], 'REJECT') >= 0 &&
	index(fw_warn[0], 'TCP REDIRECT') >= 0 && index(fw_warn[0], 'UDP TPROXY') >= 0,
	'check_fw4_lan_input emits diagnostic warning covering TCP REDIRECT / UDP TPROXY / DNS hijack when LAN zone input is REJECT');

let fw_unassigned = nft.check_fw4_lan_input(
	{ global: { lan_interfaces: [ 'lan', 'iot_vlan' ] } },
	{
		firewall_uci: {
			def: { '.type': 'defaults', input: 'REJECT' },
			z_lan: { '.type': 'zone', name: 'lan', network: [ 'lan' ], input: 'ACCEPT' }
		}
	}
);
check(length(fw_unassigned) == 1 && index(fw_unassigned[0], 'iot_vlan') >= 0 &&
	index(fw_unassigned[0], 'not assigned to any fw4 zone') >= 0,
	'check_fw4_lan_input warns when a LAN interface is unassigned to any fw4 zone under defaults.input != ACCEPT');

// 6. P2 regression tests: WAN6 UCI ip6addr /128 stripping + ip6prefix + ubus priority, and get_counters short-circuit + -t
let wan_uci_dir = work_dir + '/wan_uci_test';
check(common.ensure_dir(wan_uci_dir, 0755), 'create wan_uci_dir');
check(fs.writefile(wan_uci_dir + '/network',
	"config interface 'lan'\n\toption device 'br-lan'\n\toption ipaddr '192.168.99.1/24'\n\n" +
	"config interface 'wan'\n\toption ipaddr '203.0.113.55/24'\n\n" +
	"config interface 'wan6'\n\toption ip6addr '2001:db8:dead::2/64'\n\toption ip6prefix '2001:db8:beef::/56'\n"
) != null, 'write static WAN/WAN6 network UCI fixture');

let ctx_uci_only = nft.resolve_network_context({
	global: { topology: 'main', lan_interfaces: [ 'lan' ], wan_interfaces: [ 'wan', 'wan6' ] }
}, {
	uci_confdir: wan_uci_dir,
	uci_savedir: wan_uci_dir + '/.uci',
	ubus_dump: { interface: [] }
});
check(index(ctx_uci_only.wan_v4, '203.0.113.55') >= 0 &&
	index(ctx_uci_only.wan_v6, '2001:db8:dead::2') >= 0 &&
	index(ctx_uci_only.wan_v6, '2001:db8:dead::2/64') < 0 &&
	index(ctx_uci_only.wan_v6, '2001:db8:beef::/56') >= 0,
	'UCI WAN6 fallback strips /64 link prefix to host /128 while preserving routed ip6prefix');

let ctx_ubus_wins = nft.resolve_network_context({
	global: { topology: 'main', lan_interfaces: [ 'lan' ], wan_interfaces: [ 'wan', 'wan6' ] }
}, {
	uci_confdir: wan_uci_dir,
	uci_savedir: wan_uci_dir + '/.uci',
	ubus_dump: {
		interface: [
			{ interface: 'lan', up: true, l3_device: 'br-lan', 'ipv4-address': [ { address: '10.0.0.1', mask: 24 } ] },
			{ interface: 'wan', up: true, l3_device: 'eth1', 'ipv4-address': [ { address: '198.51.100.9', mask: 24 } ] },
			{ interface: 'wan6', up: true, l3_device: 'eth1', 'ipv6-address': [ { address: '2001:db8:cafe::2', mask: 64 } ] }
		]
	}
});
check(index(ctx_ubus_wins.lan_v4, '10.0.0.1/24') >= 0 &&
	index(ctx_ubus_wins.lan_v4, '192.168.99.1/24') < 0 &&
	index(ctx_ubus_wins.wan_v4, '198.51.100.9') >= 0 &&
	index(ctx_ubus_wins.wan_v4, '203.0.113.55') < 0 &&
	index(ctx_ubus_wins.wan_v6, '2001:db8:cafe::2') >= 0 &&
	index(ctx_ubus_wins.wan_v6, '2001:db8:dead::2') < 0,
	'live ubus interface data takes precedence without merging stale static UCI addresses');

let ctrs_calls = [];
let ctrs_missing = nft.get_counters({
	runner: (argv) => {
		push(ctrs_calls, argv);
		return { rc: 1, output: 'Error: No such file or directory' };
	}
});
check(ctrs_missing.ok === true && length(ctrs_calls) == 1,
	'get_counters short-circuits without a second nft fork when table inet nimbus does not exist');

let ctrs_terse_calls = [];
let ctrs_terse = nft.get_counters({
	runner: (argv) => {
		push(ctrs_terse_calls, argv);
		if (length(ctrs_terse_calls) == 1)
			return { rc: 0, output: '' };
		return { rc: 0, output: sample_list_table_json };
	}
});
check(ctrs_terse.ok === true && ctrs_terse.tcp_packets == 125 &&
	length(ctrs_terse_calls) == 2 && index(ctrs_terse_calls[1], '-t') >= 0,
	'get_counters passes -t (--terse) when falling back to list table inet nimbus');

printf('test_nft_manager.uc: %d assertions passed\n', passed);
