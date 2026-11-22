'use strict';

import * as fs from 'fs';
import * as uci from 'uci';
import * as common from 'common';

const BACKUP_FIELDS = [
	'noresolv',
	'resolvfile',
	'server',
	'cachesize',
	'dnssec'
];

const DNSMASQ_INIT = '/etc/init.d/dnsmasq';
const DNSMASQ_TIMEOUT_MS = 5000;

function normalize_args(arg1, arg2) {
	if (arg2 != null)
		return { uci_cfg: arg1, opts: arg2 };

	if (type(arg1) == 'object') {
		if (exists(arg1, 'dns') || exists(arg1, 'global') || exists(arg1, 'proxy'))
			return { uci_cfg: arg1, opts: {} };
		return { uci_cfg: arg1.uci || null, opts: arg1 };
	}

	return { uci_cfg: null, opts: {} };
}

function to_server_list(val) {
	if (type(val) == 'array') {
		let out = [];
		for (let item in val) {
			if (item != null && length(trim('' + item)) > 0)
				push(out, trim('' + item));
		}
		return out;
	}

	if (type(val) == 'string' && length(trim(val)) > 0) {
		let out = [];
		for (let part in split(trim(val), /[ \t\r\n,]+/)) {
			if (length(part) > 0)
				push(out, part);
		}
		return out;
	}

	return [];
}

function parse_dns_port(val, fallback) {
	if (val == null || val === '')
		return fallback;

	if (type(val) == 'int')
		return (val >= 1 && val <= 65535) ? val : null;

	if (type(val) != 'string' || !match(trim(val), /^[0-9]+$/))
		return null;

	let n = int(trim(val), 10);
	return (!common.isnan(n) && n >= 1 && n <= 65535) ? n : null;
}

function open_dhcp_cursor(opts) {
	let options = opts || {};
	return (options.uci_confdir || options.uci_savedir)
		? uci.cursor(options.uci_confdir, options.uci_savedir)
		: uci.cursor();
}

function find_dnsmasq_section(cur) {
	if (!cur)
		return null;

	let sec_name = null;
	cur.foreach('dhcp', 'dnsmasq', (s) => {
		if (!sec_name && type(s?.['.name']) == 'string')
			sec_name = s['.name'];
	});
	return sec_name;
}

function reload_dnsmasq(opts) {
	let options = opts || {};
	if (options.skip_reload === true || options.dry_run === true)
		return { ok: true, reloaded: false };

	let argv = [ options.dnsmasq_init || DNSMASQ_INIT, 'reload' ];
	if (type(options.runner) == 'function') {
		let rc = options.runner(argv);
		let code = (type(rc) == 'object') ? (rc.rc ?? 0) : (rc ?? 0);
		return { ok: (code == 0), reloaded: true, rc: code };
	}

	if (!fs.access(argv[0], 'x'))
		return { ok: true, reloaded: false };

	let rc = system(argv, DNSMASQ_TIMEOUT_MS);
	return { ok: (rc == 0), reloaded: true, rc: rc };
}

function restore_field(cur, sec_name, field, val) {
	if (val == null)
		cur.delete('dhcp', sec_name, field);
	else
		cur.set('dhcp', sec_name, field, val);
}

function restore_dns(opts) {
	let options = opts || {};
	let backup_path = options.backup_path || common.DNS_BACKUP_FILE;

	if (!fs.stat(backup_path))
		return { ok: true, restored: false };

	let snap = common.read_json(backup_path);
	if (type(snap) != 'object') {
		return {
			ok: false,
			code: common.ERR_VALIDATE_FAILED,
			error: sprintf('invalid or corrupted DNS backup file: %s', backup_path)
		};
	}

	let cur = open_dhcp_cursor(options);
	let sec_name = find_dnsmasq_section(cur);
	if (!sec_name) {
		if (cur)
			cur.unload('dhcp');
		return {
			ok: false,
			code: common.ERR_NOT_FOUND,
			error: 'dhcp.@dnsmasq[0] section not found'
		};
	}

	for (let field in BACKUP_FIELDS)
		restore_field(cur, sec_name, field, snap[field]);

	if (!cur.commit('dhcp')) {
		cur.unload('dhcp');
		return {
			ok: false,
			code: common.ERR_INTERNAL,
			error: 'failed to commit restored dhcp configuration'
		};
	}
	cur.unload('dhcp');

	fs.unlink(backup_path);
	let rl = reload_dnsmasq(options);

	return {
		ok: true,
		restored: true,
		reloaded: rl.reloaded
	};
}

function apply_dns(arg1, arg2) {
	let norm = normalize_args(arg1, arg2);
	let options = norm.opts || {};
	let uci_cfg = norm.uci_cfg || common.uci_get_all('nimbus', options.uci_confdir, options.uci_savedir);
	let d = uci_cfg?.dns || {};

	let mode = trim('' + (options.mode ?? d.mode ?? 'none'));
	if (mode == '' || mode == 'none')
		return restore_dns(options);

	if (mode != 'singbox' && mode != 'custom' && mode != 'dnsmasq_upstream') {
		return {
			ok: false,
			code: common.ERR_INVALID_ARG,
			error: sprintf('unsupported dns.mode: %s', mode)
		};
	}

	let dns_port = parse_dns_port(
		options.effective_dns_port ?? options.singbox_dns_port ?? d.singbox_dns_port ?? d.listen_port,
		common.DEFAULT_DNS_PORT
	);
	if (dns_port == null) {
		return {
			ok: false,
			code: common.ERR_VALIDATE_FAILED,
			error: 'invalid singbox_dns_port'
		};
	}

	let custom_servers = to_server_list(options.custom_servers ?? d.custom_servers);
	if (mode == 'custom' && length(custom_servers) == 0) {
		return {
			ok: false,
			code: common.ERR_VALIDATE_FAILED,
			error: 'dns.custom_servers must contain at least one server when dns.mode is "custom"'
		};
	}

	let cur = open_dhcp_cursor(options);
	let sec_name = find_dnsmasq_section(cur);
	if (!sec_name) {
		if (cur)
			cur.unload('dhcp');
		return {
			ok: false,
			code: common.ERR_NOT_FOUND,
			error: 'dhcp.@dnsmasq[0] section not found'
		};
	}

	let backup_path = options.backup_path || common.DNS_BACKUP_FILE;
	let existing_snap = null;
	if (fs.stat(backup_path)) {
		existing_snap = common.read_json(backup_path);
	} else {
		let snap = {};
		for (let field in BACKUP_FIELDS)
			snap[field] = cur.get('dhcp', sec_name, field);

		if (!common.write_json_atomic(backup_path, snap, 0600)) {
			cur.unload('dhcp');
			return {
				ok: false,
				code: common.ERR_INTERNAL,
				error: sprintf('failed to write DNS backup to %s', backup_path)
			};
		}
		existing_snap = snap;
	}

	if (mode == 'singbox' || (mode == 'dnsmasq_upstream' && length(custom_servers) == 0)) {
		let upstream = sprintf('127.0.0.1#%d', dns_port);
		cur.set('dhcp', sec_name, 'noresolv', '1');
		cur.set('dhcp', sec_name, 'server', [ upstream ]);
		cur.set('dhcp', sec_name, 'cachesize', '0');
		cur.set('dhcp', sec_name, 'dnssec', '0');
	} else {
		cur.set('dhcp', sec_name, 'noresolv', '1');
		cur.set('dhcp', sec_name, 'server', custom_servers);
		if (type(existing_snap) == 'object') {
			restore_field(cur, sec_name, 'cachesize', existing_snap.cachesize);
			restore_field(cur, sec_name, 'dnssec', existing_snap.dnssec);
		}
	}

	if (!cur.commit('dhcp')) {
		cur.unload('dhcp');
		return {
			ok: false,
			code: common.ERR_INTERNAL,
			error: 'failed to commit dhcp configuration'
		};
	}
	cur.unload('dhcp');

	let rl = reload_dnsmasq(options);
	return {
		ok: true,
		mode: mode,
		reloaded: rl.reloaded
	};
}

const setup_dns = apply_dns;

export {
	BACKUP_FIELDS,
	apply_dns,
	setup_dns,
	restore_dns
};
