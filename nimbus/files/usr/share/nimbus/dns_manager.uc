'use strict';

import * as fs from 'fs';
import * as uci from 'uci';
import * as common from 'common';

const BACKUP_FIELDS = [
	'noresolv',
	'resolvfile',
	'server',
	'cachesize',
	'dnssec',
	'rebind_protection'
];

function build_rebind_table(cidrs) {
	let out = [];
	for (let item in cidrs) {
		let parts = split(item, '/');
		let b = iptoarr(parts[0]);
		let p = int(parts[1], 10);
		if (b && !common.isnan(p))
			push(out, { bytes: b, prefix: p });
	}
	return out;
}

const DNSMASQ_REBIND_V4 = build_rebind_table([
	'0.0.0.0/8',
	'10.0.0.0/8',
	'100.64.0.0/10',
	'127.0.0.0/8',
	'169.254.0.0/16',
	'172.16.0.0/12',
	'192.168.0.0/16'
]);

const DNSMASQ_REBIND_V6 = build_rebind_table([
	'::/128',
	'::1/128',
	'::ffff:0:0/96',
	'fc00::/7',
	'fe80::/10'
]);

function cidr_overlaps_table(raw_cidr, family, tbl) {
	if (type(raw_cidr) != 'string')
		return false;
	let parts = split(trim(raw_cidr), '/');
	let b = iptoarr(parts[0]);
	let expected_len = (family == 4) ? 4 : 16;
	if (!b || length(b) != expected_len)
		return false;
	let plen = (length(parts) == 2 && match(parts[1], /^[0-9]+$/))
		? int(parts[1], 10)
		: ((family == 4) ? 32 : 128);
	if (common.isnan(plen) || plen <= 0 || plen > ((family == 4) ? 32 : 128))
		return false;
	let masked = common.mask_cidr_bytes(b, plen);
	for (let entry in tbl) {
		let min_p = (plen < entry.prefix) ? plen : entry.prefix;
		if (common.cidr_bytes_match_prefix(masked, entry.bytes, min_p))
			return true;
	}
	return false;
}

function fakeip_needs_rebind_disable(fakeip) {
	if (type(fakeip) != 'object')
		return false;
	if (type(fakeip.ipv4) == 'array') {
		for (let c4 in fakeip.ipv4) {
			if (cidr_overlaps_table(c4, 4, DNSMASQ_REBIND_V4))
				return true;
		}
	}
	if (type(fakeip.ipv6) == 'array') {
		for (let c6 in fakeip.ipv6) {
			if (cidr_overlaps_table(c6, 6, DNSMASQ_REBIND_V6))
				return true;
		}
	}
	return false;
}

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

	for (let field in BACKUP_FIELDS) {
		if (exists(snap, field))
			restore_field(cur, sec_name, field, snap[field]);
	}

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
	if (!rl.ok) {
		return {
			ok: false,
			code: common.ERR_INTERNAL,
			error: sprintf('dnsmasq reload failed after restore (exit %d)', rl.rc ?? -1),
			restored: true,
			reloaded: false
		};
	}

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
		if (type(existing_snap) == 'object') {
			let snap_dirty = false;
			for (let field in BACKUP_FIELDS) {
				if (!exists(existing_snap, field)) {
					existing_snap[field] = cur.get('dhcp', sec_name, field);
					snap_dirty = true;
				}
			}
			if (snap_dirty)
				common.write_json_atomic(backup_path, existing_snap, 0600);
		}
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

	let disable_rebind = false;
	if (mode == 'singbox' || (mode == 'dnsmasq_upstream' && length(custom_servers) == 0)) {
		let upstream = sprintf('127.0.0.1#%d', dns_port);
		cur.set('dhcp', sec_name, 'noresolv', '1');
		cur.set('dhcp', sec_name, 'server', [ upstream ]);
		cur.set('dhcp', sec_name, 'cachesize', '0');
		cur.set('dhcp', sec_name, 'dnssec', '0');
		disable_rebind = fakeip_needs_rebind_disable(options.fakeip);
		if (disable_rebind)
			cur.set('dhcp', sec_name, 'rebind_protection', '0');
		else if (type(existing_snap) == 'object' && exists(existing_snap, 'rebind_protection'))
			restore_field(cur, sec_name, 'rebind_protection', existing_snap.rebind_protection);
	} else {
		cur.set('dhcp', sec_name, 'noresolv', '1');
		cur.set('dhcp', sec_name, 'server', custom_servers);
		if (type(existing_snap) == 'object') {
			restore_field(cur, sec_name, 'cachesize', existing_snap.cachesize);
			restore_field(cur, sec_name, 'dnssec', existing_snap.dnssec);
			if (exists(existing_snap, 'rebind_protection'))
				restore_field(cur, sec_name, 'rebind_protection', existing_snap.rebind_protection);
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
	if (!rl.ok) {
		return {
			ok: false,
			code: common.ERR_INTERNAL,
			error: sprintf('dnsmasq reload failed (exit %d)', rl.rc ?? -1),
			mode: mode,
			reloaded: false
		};
	}
	return {
		ok: true,
		mode: mode,
		rebind_disabled: disable_rebind,
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
