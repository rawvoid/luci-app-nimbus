'use strict';

import * as fs from 'fs';
import * as common from 'common';
import * as nft from 'nft_manager';

const DEFAULT_IP_BIN = '/sbin/ip';
const SYSCTL_BACKUP_FILE = '/var/run/nimbus/sysctl_backup.json';
const UDP_BUF_MIN_BYTES = 4194304;
const CMD_TIMEOUT_MS = 5000;

let _rt_seq = 0;

function push_unique(arr, val) {
	if (val != null && val !== '' && index(arr, val) < 0)
		push(arr, val);
}

function parse_route_table(val) {
	if (type(val) == 'int')
		return (val >= 1 && val <= 252) ? val : common.DEFAULT_ROUTE_TABLE;
	if (type(val) == 'string' && match(trim(val), /^[0-9]+$/)) {
		let n = int(trim(val), 10);
		if (!common.isnan(n) && n >= 1 && n <= 252)
			return n;
	}
	return common.DEFAULT_ROUTE_TABLE;
}

function get_ip_bin(opts) {
	if (type(opts?.ip_bin) == 'string' && length(opts.ip_bin) > 0)
		return opts.ip_bin;
	if (fs.access('/usr/sbin/ip', 'x'))
		return '/usr/sbin/ip';
	if (fs.access('/sbin/ip', 'x'))
		return '/sbin/ip';
	if (fs.access('/bin/ip', 'x'))
		return '/bin/ip';
	return DEFAULT_IP_BIN;
}

function run_ip_cmd(argv, opts) {
	let options = opts || {};
	if (type(options.runner) == 'function') {
		let r = options.runner(argv);
		if (type(r) == 'int')
			return { rc: r, output: '' };
		if (type(r) == 'object' && exists(r, 'rc'))
			return { rc: r.rc, output: r.output || '' };
		return { rc: 0, output: '' };
	}

	let tmp_dir = getenv('TMPDIR') || '/tmp';
	common.ensure_dir(tmp_dir, 0755);
	_rt_seq++;
	let pid = fs.readlink('/proc/self') || '0';
	let out_path = sprintf('%s/nimbus-ip.%s.%d.tmp', tmp_dir, pid, _rt_seq);
	let fh = fs.open(out_path, 'wx', 0600);
	if (!fh)
		return { rc: -1, output: 'failed to create temporary output file' };
	fh.close();

	let sh_argv = [ '/bin/sh', '-c', 'out=$1; shift; exec "$@" >"$out" 2>&1', 'sh', out_path ];
	for (let a in argv)
		push(sh_argv, a);

	let rc = system(sh_argv, options.timeout_ms || CMD_TIMEOUT_MS);
	let output = fs.readfile(out_path) || '';
	fs.unlink(out_path);

	return { rc: rc, output: trim(output) };
}

function parse_route_params(uci_cfg, opts) {
	let options = opts || {};
	let uci_data = uci_cfg || options.uci || common.uci_get_all('nimbus', options.uci_confdir, options.uci_savedir);
	let g = uci_data?.global || {};
	let p = uci_data?.proxy || {};

	let proxy_mark_int = common.hex_u32_parse(
		options.proxy_mark ?? p.proxy_mark ?? common.DEFAULT_PROXY_MARK
	) ?? common.DEFAULT_PROXY_MARK;
	let proxy_mark = common.format_hex_u32(proxy_mark_int);

	let route_table_int = parse_route_table(options.route_table ?? p.route_table ?? common.DEFAULT_ROUTE_TABLE);
	let route_table = '' + route_table_int;
	let rule_prio = '' + (options.rule_prio ?? common.RULE_PRIO_PROXY);

	let ipv4_enable = ((options.ipv4_enable ?? g.ipv4_enable ?? '1') != '0' && options.ipv4_enable !== false);
	let ipv6_enable = ((options.ipv6_enable ?? g.ipv6_enable ?? '1') != '0' && options.ipv6_enable !== false);
	if (!ipv4_enable && !ipv6_enable)
		ipv4_enable = true;

	let topology = ((options.topology ?? g.topology ?? 'main') == 'side') ? 'side' : 'main';
	let net_ctx = nft.resolve_network_context(uci_data, options);

	return {
		proxy_mark: proxy_mark,
		route_table: route_table,
		rule_prio: rule_prio,
		ipv4_enable: ipv4_enable,
		ipv6_enable: ipv6_enable,
		topology: topology,
		lan_ifaces: net_ctx.lan_ifaces
	};
}

function read_proc_value(path) {
	let raw = fs.readfile(path);
	return (type(raw) == 'string') ? trim(raw) : null;
}

function write_proc_value(path, val) {
	let fh = fs.open(path, 'w');
	if (!fh)
		return false;
	let s = '' + val + '\n';
	let w = fh.write(s);
	fh.flush();
	fh.close();
	return (w != null && w == length(s));
}

function tune_udp_buffers(opts) {
	let options = opts || {};
	let proc_root = options.proc_sys_root || '/proc/sys';
	let tuned = [];

	for (let name in [ 'rmem_max', 'wmem_max' ]) {
		let p = sprintf('%s/net/core/%s', proc_root, name);
		let cur = read_proc_value(p);
		if (cur == null)
			continue;
		let n = int(cur, 10);
		if (!common.isnan(n) && n < UDP_BUF_MIN_BYTES) {
			if (write_proc_value(p, UDP_BUF_MIN_BYTES))
				push(tuned, name);
		}
	}

	return { ok: true, tuned: tuned };
}

function apply_side_sysctls(lan_ifaces, opts) {
	let options = opts || {};
	let proc_root = options.proc_sys_root || '/proc/sys';
	let backup_path = options.sysctl_backup_path || SYSCTL_BACKUP_FILE;

	let targets = [ 'all' ];
	if (type(lan_ifaces) == 'array') {
		for (let iface in lan_ifaces) {
			if (type(iface) == 'string' && match(iface, /^[A-Za-z0-9_.-]+$/))
				push_unique(targets, iface);
		}
	}

	let existing_backup = common.read_json(backup_path);
	let backup = (type(existing_backup) == 'object') ? existing_backup : {};
	let had_backup = (type(existing_backup) == 'object');
	let applied = {};

	for (let iface in targets) {
		for (let key in [ 'rp_filter', 'send_redirects' ]) {
			let proc_path = sprintf('%s/net/ipv4/conf/%s/%s', proc_root, iface, key);
			let sys_key = sprintf('net.ipv4.conf.%s.%s', iface, key);
			let cur = read_proc_value(proc_path);
			if (cur != null && !exists(backup, sys_key))
				backup[sys_key] = cur;

			if (write_proc_value(proc_path, '0'))
				applied[sys_key] = '0';
		}
	}

	if (!had_backup && length(keys(backup)) > 0)
		common.write_json_atomic(backup_path, backup, 0600);

	return {
		ok: true,
		targets: targets,
		applied: applied,
		backup_path: backup_path
	};
}

function restore_side_sysctls(opts) {
	let options = opts || {};
	let proc_root = options.proc_sys_root || '/proc/sys';
	let backup_path = options.sysctl_backup_path || SYSCTL_BACKUP_FILE;
	let backup = common.read_json(backup_path);

	if (type(backup) != 'object')
		return { ok: true, restored: false };

	let restored = {};
	for (let sys_key, orig_val in backup) {
		let m = match(sys_key, /^net\.ipv4\.conf\.([A-Za-z0-9_.-]+)\.(rp_filter|send_redirects)$/);
		if (!m)
			continue;
		let proc_path = sprintf('%s/net/ipv4/conf/%s/%s', proc_root, m[1], m[2]);
		if (write_proc_value(proc_path, orig_val))
			restored[sys_key] = '' + orig_val;
	}

	fs.unlink(backup_path);
	return { ok: true, restored: true, values: restored };
}

function delete_table_rules_loop(ip_bin, family_flag, route_table, opts) {
	let options = opts || {};
	let max_loops = options.max_del_loops || ((type(options.runner) == 'function') ? 1 : 16);
	let count = 0;

	while (count < max_loops) {
		let res = run_ip_cmd([ ip_bin, family_flag, 'rule', 'del', 'lookup', route_table ], options);
		count++;
		if (res.rc != 0)
			break;
	}

	return count;
}

function setup_routes(opts) {
	let options = opts || {};
	let params = parse_route_params(options.uci, options);
	let ip_bin = get_ip_bin(options);
	let commands = [];

	// Always clear disabled or pre-existing rules first for idempotency
	for (let fam in [ '-4', '-6' ]) {
		let enabled = (fam == '-4') ? params.ipv4_enable : params.ipv6_enable;
		let default_cidr = (fam == '-4') ? '0.0.0.0/0' : '::/0';

		delete_table_rules_loop(ip_bin, fam, params.route_table, options);
		push(commands, [ ip_bin, fam, 'rule', 'del', 'lookup', params.route_table ]);

		if (!enabled) {
			run_ip_cmd([ ip_bin, fam, 'route', 'flush', 'table', params.route_table ], options);
			push(commands, [ ip_bin, fam, 'route', 'flush', 'table', params.route_table ]);
			continue;
		}

		let rule_cmd = [
			ip_bin, fam, 'rule', 'add',
			'fwmark', params.proxy_mark,
			'lookup', params.route_table,
			'pref', params.rule_prio
		];
		let r1 = run_ip_cmd(rule_cmd, options);
		push(commands, rule_cmd);
		if (r1.rc != 0) {
			return {
				ok: false,
				code: common.ERR_INTERNAL,
				error: sprintf('failed to add %s policy rule: %s', fam, r1.output),
				commands: commands
			};
		}

		let route_cmd = [
			ip_bin, fam, 'route', 'replace',
			'local', default_cidr, 'dev', 'lo',
			'table', params.route_table
		];
		let r2 = run_ip_cmd(route_cmd, options);
		push(commands, route_cmd);
		if (r2.rc != 0) {
			return {
				ok: false,
				code: common.ERR_INTERNAL,
				error: sprintf('failed to replace %s local route: %s', fam, r2.output),
				commands: commands
			};
		}
	}

	tune_udp_buffers(options);

	let sysctl_res = null;
	if (params.topology == 'side')
		sysctl_res = apply_side_sysctls(params.lan_ifaces, options);
	else
		sysctl_res = restore_side_sysctls(options);

	return {
		ok: true,
		params: params,
		commands: commands,
		sysctl: sysctl_res
	};
}

function cleanup_routes(opts) {
	let options = opts || {};
	let params = parse_route_params(options.uci, options);
	let ip_bin = get_ip_bin(options);
	let commands = [];

	for (let fam in [ '-4', '-6' ]) {
		delete_table_rules_loop(ip_bin, fam, params.route_table, options);
		push(commands, [ ip_bin, fam, 'rule', 'del', 'lookup', params.route_table ]);

		let flush_cmd = [ ip_bin, fam, 'route', 'flush', 'table', params.route_table ];
		run_ip_cmd(flush_cmd, options);
		push(commands, flush_cmd);
	}

	let sysctl_res = restore_side_sysctls(options);

	return {
		ok: true,
		params: params,
		commands: commands,
		sysctl: sysctl_res
	};
}

function ensure_routes(opts) {
	let options = opts || {};
	let params = parse_route_params(options.uci, options);
	let ip_bin = get_ip_bin(options);
	let needs_repair = false;
	let lookup_re = regexp(sprintf('lookup[ \t]+%s([ \t\r\n]|$)', params.route_table));

	if (params.ipv4_enable) {
		let r_rule4 = run_ip_cmd([ ip_bin, '-4', 'rule', 'show' ], options);
		let r_rt4 = run_ip_cmd([ ip_bin, '-4', 'route', 'show', 'table', params.route_table ], options);
		if (r_rule4.rc != 0 || !match(r_rule4.output, lookup_re) ||
			r_rt4.rc != 0 || index(r_rt4.output, 'local') < 0) {
			needs_repair = true;
		}
	}

	if (!needs_repair && params.ipv6_enable) {
		let r_rule6 = run_ip_cmd([ ip_bin, '-6', 'rule', 'show' ], options);
		let r_rt6 = run_ip_cmd([ ip_bin, '-6', 'route', 'show', 'table', params.route_table ], options);
		if (r_rule6.rc != 0 || !match(r_rule6.output, lookup_re) ||
			r_rt6.rc != 0 || (length(r_rt6.output) > 0 && index(r_rt6.output, 'local') < 0)) {
			needs_repair = true;
		}
	}

	if (needs_repair) {
		let res = setup_routes(options);
		res.repaired = true;
		return res;
	}

	if (params.topology == 'side')
		apply_side_sysctls(params.lan_ifaces, options);

	return { ok: true, repaired: false, params: params };
}

const apply_routes = setup_routes;
const teardown_routes = cleanup_routes;

export {
	SYSCTL_BACKUP_FILE,
	parse_route_params,
	tune_udp_buffers,
	apply_side_sysctls,
	restore_side_sysctls,
	setup_routes,
	apply_routes,
	cleanup_routes,
	teardown_routes,
	ensure_routes
};
