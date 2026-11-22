#!/usr/bin/ucode
'use strict';

import * as fs from 'fs';
import * as uci from 'uci';
import * as common from 'common';
import * as dns from 'dns_manager';

let passed = 0;

function check(cond, msg) {
	if (!cond) {
		warn(sprintf('FAIL: %s\n', msg));
		exit(1);
	}
	passed++;
}

let tmp_root = getenv('TMPDIR') || '/tmp';
let work_dir = sprintf('%s/dns_test_%d', tmp_root, time());
check(common.ensure_dir(work_dir, 0755), 'create work_dir');

let conf_dir = work_dir + '/etc_config';
let save_dir = work_dir + '/tmp_uci';
let backup_path = work_dir + '/dns_backup.json';
check(common.ensure_dir(conf_dir, 0755), 'create conf_dir');
check(common.ensure_dir(save_dir, 0755), 'create save_dir');

let initial_dhcp =
	"config dnsmasq\n" +
	"\toption domainneeded '1'\n" +
	"\toption localise_queries '1'\n" +
	"\toption resolvfile '/tmp/resolv.conf.d/resolv.conf.auto'\n" +
	"\toption cachesize '1000'\n" +
	"\tlist server '223.5.5.5'\n";

check(common.atomic_write(conf_dir + '/dhcp', initial_dhcp, 0644), 'seed dhcp config');

function get_dnsmasq_uci() {
	let cur = uci.cursor(conf_dir, save_dir);
	let sec = null;
	cur.foreach('dhcp', 'dnsmasq', (s) => {
		if (!sec)
			sec = s;
	});
	cur.unload('dhcp');
	return sec;
}

// 1. First takeover in mode='singbox' creates backup and modifies dhcp.@dnsmasq[0]
let reload_calls = [];
let res_sb = dns.apply_dns({
	dns: {
		mode: 'singbox',
		singbox_dns_port: '5353'
	}
}, {
	uci_confdir: conf_dir,
	uci_savedir: save_dir,
	backup_path: backup_path,
	effective_dns_port: 5353,
	runner: (argv) => {
		push(reload_calls, join(' ', argv));
		return 0;
	}
});

check(res_sb.ok === true && res_sb.mode == 'singbox' && res_sb.reloaded === true,
	'apply_dns in singbox mode succeeds and reloads dnsmasq');
check(length(reload_calls) == 1 && reload_calls[0] == '/etc/init.d/dnsmasq reload',
	'dnsmasq reload invoked with array argv');

let bkp_stat = fs.stat(backup_path);
check(bkp_stat != null && (bkp_stat.mode & 0777) == 0600,
	'dns_backup.json created with 0600 permissions');

let bkp1 = common.read_json(backup_path);
check(type(bkp1) == 'object' &&
	bkp1.noresolv === null &&
	bkp1.resolvfile == '/tmp/resolv.conf.d/resolv.conf.auto' &&
	bkp1.cachesize == '1000' &&
	bkp1.dnssec === null &&
	type(bkp1.server) == 'array' && length(bkp1.server) == 1 && bkp1.server[0] == '223.5.5.5',
	'dns_backup.json accurately captures original pre-takeover dhcp.@dnsmasq[0] fields');

let dm_sb = get_dnsmasq_uci();
check(dm_sb.noresolv == '1' &&
	dm_sb.cachesize == '0' &&
	dm_sb.dnssec == '0' &&
	type(dm_sb.server) == 'array' && length(dm_sb.server) == 1 && dm_sb.server[0] == '127.0.0.1#5353',
	'singbox mode sets noresolv=1, cachesize=0, dnssec=0, server=[127.0.0.1#5353]');

// 2. Second takeover / reload MUST NOT overwrite existing dns_backup.json
let res_sb2 = dns.apply_dns({
	dns: {
		mode: 'singbox',
		singbox_dns_port: '6053'
	}
}, {
	uci_confdir: conf_dir,
	uci_savedir: save_dir,
	backup_path: backup_path,
	effective_dns_port: 6053,
	runner: () => 0
});
check(res_sb2.ok === true, 'second apply_dns reload succeeds');

let bkp2 = common.read_json(backup_path);
check(bkp2.noresolv === null &&
	bkp2.cachesize == '1000' &&
	bkp2.server[0] == '223.5.5.5',
	'repeated apply_dns preserves original dns_backup.json without overwriting');

let dm_sb2 = get_dnsmasq_uci();
check(dm_sb2.server[0] == '127.0.0.1#6053', 'second reload updates server port to 127.0.0.1#6053');

// 3. Switch to mode='custom' / 'dnsmasq_upstream' preserves backup and restores original cachesize/dnssec
let res_custom = dns.apply_dns({
	dns: {
		mode: 'custom',
		custom_servers: [ '127.0.0.1#5335', '192.168.1.2#5353' ]
	}
}, {
	uci_confdir: conf_dir,
	uci_savedir: save_dir,
	backup_path: backup_path,
	runner: () => 0
});
check(res_custom.ok === true && res_custom.mode == 'custom', 'apply_dns in custom mode succeeds');

let dm_custom = get_dnsmasq_uci();
check(dm_custom.noresolv == '1' &&
	dm_custom.cachesize == '1000' &&
	dm_custom.dnssec == null &&
	type(dm_custom.server) == 'array' &&
	length(dm_custom.server) == 2 &&
	dm_custom.server[0] == '127.0.0.1#5335' &&
	dm_custom.server[1] == '192.168.1.2#5353',
	'custom mode sets custom_servers and restores original cachesize/dnssec from backup');

let res_upstream = dns.setup_dns({
	mode: 'dnsmasq_upstream',
	effective_dns_port: 5354,
	uci_confdir: conf_dir,
	uci_savedir: save_dir,
	backup_path: backup_path,
	runner: () => 0
});
check(res_upstream.ok === true && get_dnsmasq_uci().server[0] == '127.0.0.1#5354',
	'dnsmasq_upstream mode forwards to 127.0.0.1#<port>');

// 4. Lossless restore_dns restores original state and deletes dns_backup.json
let restore_calls = [];
let res_restore = dns.restore_dns({
	uci_confdir: conf_dir,
	uci_savedir: save_dir,
	backup_path: backup_path,
	runner: (argv) => {
		push(restore_calls, join(' ', argv));
		return 0;
	}
});
check(res_restore.ok === true && res_restore.restored === true,
	'restore_dns succeeds');
check(fs.stat(backup_path) == null, 'restore_dns deletes dns_backup.json');
check(length(restore_calls) == 1 && restore_calls[0] == '/etc/init.d/dnsmasq reload',
	'restore_dns reloads dnsmasq');

let dm_restored = get_dnsmasq_uci();
check(dm_restored.noresolv == null &&
	dm_restored.dnssec == null &&
	dm_restored.resolvfile == '/tmp/resolv.conf.d/resolv.conf.auto' &&
	dm_restored.cachesize == '1000' &&
	type(dm_restored.server) == 'array' && length(dm_restored.server) == 1 && dm_restored.server[0] == '223.5.5.5' &&
	dm_restored.domainneeded == '1',
	'restore_dns losslessly restores all dhcp.@dnsmasq[0] options and deletes temporary ones');

// 5. Idempotent restore_dns when backup does not exist
let res_noop = dns.restore_dns({
	uci_confdir: conf_dir,
	uci_savedir: save_dir,
	backup_path: backup_path,
	runner: () => 0
});
check(res_noop.ok === true && res_noop.restored === false,
	'restore_dns is a safe no-op when dns_backup.json does not exist');

// 6. Validation error when mode='custom' has empty custom_servers
let res_bad_custom = dns.apply_dns({
	dns: {
		mode: 'custom',
		custom_servers: []
	}
}, {
	uci_confdir: conf_dir,
	uci_savedir: save_dir,
	backup_path: backup_path,
	runner: () => 0
});
check(res_bad_custom.ok === false && res_bad_custom.code == common.ERR_VALIDATE_FAILED,
	'custom mode rejects empty custom_servers');

// 7. End-to-end integration with supervisor.uc (--prepare-start, --prepare-reload, --stop, and fail_open=1 Fail Handler)
let repo_root = getenv('NIMBUS_REPO_ROOT') || '/work';
let nimbus_lib = repo_root + '/nimbus/files/usr/share/nimbus';
let sup_script = nimbus_lib + '/supervisor.uc';
let singbox_bin = getenv('SINGBOX_BIN') || '/usr/local/bin/sing-box';
let fixture_profile = repo_root + '/tests/fixtures/v114_modern.json';
let run_dir = work_dir + '/run';
check(common.ensure_dir(run_dir, 0755), 'create run_dir for supervisor dns test');

let nimbus_uci_text =
	"config main 'global'\n" +
	"\toption enabled '1'\n" +
	"\toption topology 'main'\n" +
	"\toption proxy_mode 'tproxy_redirect'\n" +
	"\toption fail_open '1'\n" +
	"\toption ipv4_enable '1'\n" +
	"\toption ipv6_enable '1'\n\n" +
	"config proxy 'proxy'\n" +
	"\toption redirect_port '7891'\n" +
	"\toption tproxy_port '7892'\n" +
	"\toption outbound_mark '0xff'\n" +
	"\toption proxy_mark '0x1'\n" +
	"\toption route_table '100'\n\n" +
	"config dns 'dns'\n" +
	"\toption mode 'singbox'\n" +
	"\toption singbox_dns_port '5353'\n";
check(common.atomic_write(conf_dir + '/nimbus', nimbus_uci_text, 0644), 'write nimbus uci with dns.mode=singbox');

function run_sup(arg) {
	return system([
		'/bin/sh', '-c',
		'NIMBUS_UCI_CONFDIR="$1" NIMBUS_UCI_SAVEDIR="$2" NIMBUS_DNS_BACKUP_FILE="$3" ' +
		'NIMBUS_BIN_PATH="$4" NIMBUS_PROFILE_PATH="$5" NIMBUS_WORK_DIR="$6" ' +
		'NIMBUS_CONFIG_FILE="$6/config.json" NIMBUS_PID_FILE="$6/sing-box.pid" ' +
		'NIMBUS_STATE_FILE="$6/state.json" NIMBUS_LOCK_FILE="$6/nimbus.lock" ' +
		'NIMBUS_RULES_FILE="$6/rules.nft" NIMBUS_LOG_FILE="$6/nimbus.log" ' +
		'NIMBUS_CHECK_DIR="$6/check-dir" NIMBUS_NFT_CHECK_ONLY=1 NIMBUS_SKIP_ROUTES=1 ' +
		'exec /usr/bin/ucode -S -L "$7" "$8" "$9"',
		'sh', conf_dir, save_dir, backup_path, singbox_bin, fixture_profile, run_dir, nimbus_lib, sup_script, arg
	]);
}

check(run_sup('--prepare-start') == 0, 'supervisor --prepare-start with dns.mode=singbox succeeds');
check(fs.stat(backup_path) != null && get_dnsmasq_uci().server[0] == '127.0.0.1#5353',
	'supervisor --prepare-start takes over dnsmasq and writes dns_backup.json');

check(run_sup('--prepare-reload') == 0 || run_sup('--prepare-reload') == 10,
	'supervisor --prepare-reload succeeds');
check(common.read_json(backup_path).server[0] == '223.5.5.5',
	'supervisor --prepare-reload does not overwrite original dns_backup.json');

check(run_sup('--fail-handler') == 0, 'supervisor --fail-handler with fail_open=1 succeeds');
check(fs.stat(backup_path) == null && get_dnsmasq_uci().server[0] == '223.5.5.5',
	'supervisor --fail-handler (fail_open=1) restores dnsmasq from dns_backup.json');

check(run_sup('--prepare-start') == 0 && fs.stat(backup_path) != null,
	're-takeover on --prepare-start creates backup again');
check(run_sup('--stop') == 0, 'supervisor --stop succeeds');
check(fs.stat(backup_path) == null && get_dnsmasq_uci().server[0] == '223.5.5.5' &&
	get_dnsmasq_uci().cachesize == '1000',
	'supervisor --stop restores dnsmasq and deletes dns_backup.json');

printf('test_dns_manager.uc: %d assertions passed\n', passed);
