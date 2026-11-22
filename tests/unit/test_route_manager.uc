#!/usr/bin/ucode
'use strict';

import * as fs from 'fs';
import * as common from 'common';
import * as route from 'route_manager';

let passed = 0;

function check(cond, msg) {
	if (!cond) {
		warn(sprintf('FAIL: %s\n', msg));
		exit(1);
	}
	passed++;
}

let tmp_root = getenv('TMPDIR') || '/tmp';
let work_dir = sprintf('%s/route_test_%d', tmp_root, time());
check(common.ensure_dir(work_dir, 0755), 'create work_dir');

let proc_sys = work_dir + '/proc_sys';
check(common.ensure_dir(proc_sys + '/net/core', 0755), 'create mock proc_sys/net/core');
check(common.ensure_dir(proc_sys + '/net/ipv4/conf/all', 0755), 'create mock proc_sys/net/ipv4/conf/all');
check(common.ensure_dir(proc_sys + '/net/ipv4/conf/br-lan', 0755), 'create mock proc_sys/net/ipv4/conf/br-lan');

function write_mock_proc(rel, val) {
	return common.atomic_write(proc_sys + '/' + rel, '' + val + '\n', 0644);
}

function read_mock_proc(rel) {
	let s = fs.readfile(proc_sys + '/' + rel);
	return (type(s) == 'string') ? trim(s) : null;
}

write_mock_proc('net/core/rmem_max', '212992');
write_mock_proc('net/core/wmem_max', '8388608');
write_mock_proc('net/ipv4/conf/all/rp_filter', '1');
write_mock_proc('net/ipv4/conf/all/send_redirects', '1');
write_mock_proc('net/ipv4/conf/br-lan/rp_filter', '2');
write_mock_proc('net/ipv4/conf/br-lan/send_redirects', '1');

let backup_path = work_dir + '/sysctl_backup.json';

// 1. Dual-stack command sequence & UDP buffer tuning
let recorded = [];
let res_dual = route.setup_routes({
	ip_bin: '/sbin/ip',
	proc_sys_root: proc_sys,
	sysctl_backup_path: backup_path,
	topology: 'main',
	ipv4_enable: '1',
	ipv6_enable: '1',
	proxy_mark: '0x1',
	route_table: '100',
	lan_ifaces: [ 'br-lan' ],
	runner: (argv) => {
		push(recorded, join(' ', argv));
		return 0;
	}
});

check(res_dual.ok === true, 'dual-stack setup_routes succeeds');
check(length(recorded) == 6, 'dual-stack setup_routes executes 6 ip commands');
check(recorded[0] == '/sbin/ip -4 rule del lookup 100', 'cmd 0 deletes stale ipv4 rule');
check(recorded[1] == '/sbin/ip -4 rule add fwmark 0x1 lookup 100 pref 1000', 'cmd 1 adds ipv4 fwmark rule');
check(recorded[2] == '/sbin/ip -4 route replace local 0.0.0.0/0 dev lo table 100', 'cmd 2 replaces ipv4 local default route');
check(recorded[3] == '/sbin/ip -6 rule del lookup 100', 'cmd 3 deletes stale ipv6 rule');
check(recorded[4] == '/sbin/ip -6 rule add fwmark 0x1 lookup 100 pref 1000', 'cmd 4 adds ipv6 fwmark rule');
check(recorded[5] == '/sbin/ip -6 route replace local ::/0 dev lo table 100', 'cmd 5 replaces ipv6 local default route');
check(read_mock_proc('net/core/rmem_max') == '4194304', 'rmem_max raised from 212992 to 4194304');
check(read_mock_proc('net/core/wmem_max') == '8388608', 'wmem_max >= 4194304 left untouched');
check(read_mock_proc('net/ipv4/conf/all/send_redirects') == '1' &&
	read_mock_proc('net/ipv4/conf/br-lan/rp_filter') == '2',
	'main topology does not alter side-router sysctls');

// 2. Single-stack IPv4-only and IPv6-only command sequences
let rec_v4 = [];
let res_v4 = route.setup_routes({
	ip_bin: '/sbin/ip',
	proc_sys_root: proc_sys,
	sysctl_backup_path: backup_path,
	ipv4_enable: '1',
	ipv6_enable: '0',
	proxy_mark: '0x20',
	route_table: '150',
	runner: (argv) => {
		push(rec_v4, join(' ', argv));
		return 0;
	}
});
check(res_v4.ok === true &&
	index(rec_v4, '/sbin/ip -4 rule add fwmark 0x20 lookup 150 pref 1000') >= 0 &&
	index(rec_v4, '/sbin/ip -6 rule del lookup 150') >= 0 &&
	index(rec_v4, '/sbin/ip -6 route flush table 150') >= 0 &&
	index(rec_v4, '/sbin/ip -6 rule add fwmark 0x20 lookup 150 pref 1000') < 0,
	'IPv4-only mode adds IPv4 rule/route and flushes IPv6 table');

// 3. Side-router sysctl tuning, idempotent backup across reloads, and teardown restoration
let res_side1 = route.setup_routes({
	ip_bin: '/sbin/ip',
	proc_sys_root: proc_sys,
	sysctl_backup_path: backup_path,
	topology: 'side',
	lan_ifaces: [ 'br-lan' ],
	runner: () => 0
});
check(res_side1.ok === true, 'side-router setup_routes succeeds');
check(read_mock_proc('net/ipv4/conf/all/rp_filter') == '0' &&
	read_mock_proc('net/ipv4/conf/all/send_redirects') == '0' &&
	read_mock_proc('net/ipv4/conf/br-lan/rp_filter') == '0' &&
	read_mock_proc('net/ipv4/conf/br-lan/send_redirects') == '0',
	'side-router sets rp_filter=0 and send_redirects=0 on all and br-lan');
check(fs.stat(backup_path) != null, 'side-router creates sysctl_backup.json');

// Second reload in side-router mode must NOT overwrite original backup values with '0'
let res_side2 = route.setup_routes({
	ip_bin: '/sbin/ip',
	proc_sys_root: proc_sys,
	sysctl_backup_path: backup_path,
	topology: 'side',
	lan_ifaces: [ 'br-lan' ],
	runner: () => 0
});
check(res_side2.ok === true, 'second side-router setup_routes reload succeeds');
let saved_bkp = common.read_json(backup_path);
check(saved_bkp['net.ipv4.conf.all.rp_filter'] == '1' &&
	saved_bkp['net.ipv4.conf.all.send_redirects'] == '1' &&
	saved_bkp['net.ipv4.conf.br-lan.rp_filter'] == '2' &&
	saved_bkp['net.ipv4.conf.br-lan.send_redirects'] == '1',
	'repeated side-router setup_routes preserves original pre-tuning sysctl snapshot');

let clean_cmds = [];
let res_clean = route.cleanup_routes({
	ip_bin: '/sbin/ip',
	proc_sys_root: proc_sys,
	sysctl_backup_path: backup_path,
	route_table: '100',
	runner: (argv) => {
		push(clean_cmds, join(' ', argv));
		return 0;
	}
});
check(res_clean.ok === true &&
	clean_cmds[0] == '/sbin/ip -4 rule del lookup 100' &&
	clean_cmds[1] == '/sbin/ip -4 route flush table 100' &&
	clean_cmds[2] == '/sbin/ip -6 rule del lookup 100' &&
	clean_cmds[3] == '/sbin/ip -6 route flush table 100',
	'cleanup_routes executes dual-stack rule del and route flush commands');
check(read_mock_proc('net/ipv4/conf/all/rp_filter') == '1' &&
	read_mock_proc('net/ipv4/conf/all/send_redirects') == '1' &&
	read_mock_proc('net/ipv4/conf/br-lan/rp_filter') == '2' &&
	read_mock_proc('net/ipv4/conf/br-lan/send_redirects') == '1' &&
	fs.stat(backup_path) == null,
	'cleanup_routes restores original sysctls and removes sysctl_backup.json');

// 4. Live kernel policy routing, self-healing (`ensure_routes`), and cleanup idempotency in container
let live_opts = {
	proc_sys_root: proc_sys,
	sysctl_backup_path: backup_path,
	proxy_mark: '0x1',
	route_table: '110',
	ipv4_enable: '1',
	ipv6_enable: '1'
};

check(route.cleanup_routes(live_opts).ok === true, 'initial live cleanup_routes succeeds');
let live_set = route.setup_routes(live_opts);
check(live_set.ok === true, 'live setup_routes adds IPv4 and IPv6 policy rules and routes');

let ens_ok = route.ensure_routes(live_opts);
check(ens_ok.ok === true && ens_ok.repaired === false,
	'ensure_routes detects healthy IPv4/IPv6 rules and routes without unnecessary repair');

// Simulate netifd flushing IPv4 rule and verify self-healing
system([ '/sbin/ip', '-4', 'rule', 'del', 'lookup', '110' ]);
let ens_repaired = route.ensure_routes(live_opts);
check(ens_repaired.ok === true && ens_repaired.repaired === true,
	'ensure_routes detects missing IPv4 rule and self-heals policy routing');

let ens_after = route.ensure_routes(live_opts);
check(ens_after.ok === true && ens_after.repaired === false,
	'policy routes are healthy after ensure_routes self-healing');

// Add an extra duplicate rule manually to verify cleanup_routes loop deletes all duplicates
system([ '/sbin/ip', '-4', 'rule', 'add', 'fwmark', '0x1', 'lookup', '110', 'pref', '1001' ]);
check(route.cleanup_routes(live_opts).ok === true, 'live cleanup_routes deletes all duplicate rules');
check(route.cleanup_routes(live_opts).ok === true, 'live cleanup_routes is idempotent when called again');

let ens_after_clean = route.ensure_routes({
	...live_opts,
	runner: (argv) => {
		if (index(argv, 'show') >= 0)
			return { rc: 0, output: '' };
		return 0;
	}
});
check(ens_after_clean.ok === true && ens_after_clean.repaired === true,
	'ensure_routes repairs when rule show output lacks lookup table');

printf('test_route_manager.uc: %d assertions passed\n', passed);
