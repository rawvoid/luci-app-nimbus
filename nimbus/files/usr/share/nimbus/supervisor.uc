#!/usr/bin/ucode
'use strict';

import * as fs from 'fs';
import * as uloop from 'uloop';
import * as common from 'common';
import * as cb from 'config_builder';
import * as nft from 'nft_manager';
import * as route from 'route_manager';
import * as dns from 'dns_manager';
import * as lu from 'list_updater';
import * as pu from 'profile_updater';

const DEFAULT_MAX_RETRIES = 3;
const DEFAULT_RETRY_WINDOW_SEC = 60;
const DEFAULT_RETRY_BACKOFF_MS = 1000;
const DEFAULT_LOG_TIMER_MS = 30000;
const DEFAULT_KILL_GRACE_MS = 5000;
const DEFAULT_WAIT_EXIT_MS = 6000;
const LOCK_TIMEOUT_MS = 5000;
const LOCK_EXIT_CODE = 11;

function env_int(name, fallback) {
	let raw = getenv(name);
	if (type(raw) != 'string' || !match(trim(raw), /^[0-9]+$/))
		return fallback;
	let n = int(trim(raw), 10);
	return (!common.isnan(n) && n >= 0) ? n : fallback;
}

function get_runtime_paths() {
	let work_dir = getenv('NIMBUS_WORK_DIR') || common.RUN_DIR;
	let runtime_dir = getenv('NIMBUS_RUNTIME_DIR') || work_dir;
	return {
		uci_confdir: getenv('NIMBUS_UCI_CONFDIR') || null,
		uci_savedir: getenv('NIMBUS_UCI_SAVEDIR') || null,
		bin_path: getenv('NIMBUS_BIN_PATH') || null,
		profile_path: getenv('NIMBUS_PROFILE_PATH') || null,
		composers_dir: getenv('NIMBUS_COMPOSERS_DIR') || common.COMPOSERS_DIR,
		profiles_dir: getenv('NIMBUS_PROFILES_DIR') || common.PROFILES_DIR,
		config_file: getenv('NIMBUS_CONFIG_FILE') || common.CONFIG_FILE,
		work_dir: work_dir,
		runtime_dir: runtime_dir,
		core_stamp_file: getenv('NIMBUS_CORE_STAMP_FILE') || (runtime_dir + '/core.stamp'),
		pid_file: getenv('NIMBUS_PID_FILE') || common.PID_FILE,
		state_file: getenv('NIMBUS_STATE_FILE') || common.STATE_FILE,
		lock_file: getenv('NIMBUS_LOCK_FILE') || common.LOCK_FILE,
		rules_file: getenv('NIMBUS_RULES_FILE') || common.RULES_NFT_FILE,
		bypass_sets_file: getenv('NIMBUS_BYPASS_SETS_FILE') || (runtime_dir + '/bypass_sets.nft'),
		wan_sets_file: getenv('NIMBUS_WAN_SETS_FILE') || (runtime_dir + '/wan_sets.nft'),
		log_file: getenv('NIMBUS_LOG_FILE') || common.LOG_FILE,
		check_dir: getenv('NIMBUS_CHECK_DIR') || common.CHECK_DIR,
		dns_backup_file: getenv('NIMBUS_DNS_BACKUP_FILE') || common.DNS_BACKUP_FILE,
		local_lists_dir: getenv('NIMBUS_LOCAL_LISTS_DIR') || null,
		cache_lists_dir: getenv('NIMBUS_CACHE_LISTS_DIR') || null,
		crontab_file: getenv('NIMBUS_CRONTAB_FILE') || null,
		resolv_auto_path: getenv('NIMBUS_RESOLV_AUTO_PATH') || null,
		group_file: getenv('NIMBUS_GROUP_FILE') || null,
		init_script: getenv('NIMBUS_INIT_SCRIPT') || '/etc/init.d/nimbus',
		nft_bin: getenv('NFT_BIN') || null,
		nft_dry_run: (getenv('NIMBUS_NFT_DRY_RUN') == '1'),
		nft_check_only: (getenv('NIMBUS_NFT_CHECK_ONLY') == '1'),
		skip_routes: (getenv('NIMBUS_SKIP_ROUTES') == '1'),
		skip_hotplug_reload: (getenv('NIMBUS_SKIP_HOTPLUG_RELOAD') == '1' || getenv('NIMBUS_SKIP_ROUTES') == '1'),
		skip_dns_reload: (getenv('NIMBUS_SKIP_DNS_RELOAD') == '1' || getenv('NIMBUS_SKIP_ROUTES') == '1'),
		skip_cron_sync: (getenv('NIMBUS_SKIP_CRON_SYNC') == '1' || (getenv('NIMBUS_SKIP_CRON_SYNC') != '0' && !getenv('NIMBUS_CRONTAB_FILE') && getenv('NIMBUS_SKIP_ROUTES') == '1'))
	};
}

function compute_gomemlimit(uci_val) {
	if (type(uci_val) == 'string' && length(trim(uci_val)) > 0 && trim(uci_val) != 'auto')
		return trim(uci_val);

	let meminfo = fs.readfile('/proc/meminfo') || '';
	let m = match(meminfo, /MemTotal:[ \t]*([0-9]+)[ \t]*kB/);
	if (!m)
		return '128MiB';

	let kb = int(m[1], 10);
	if (common.isnan(kb) || kb <= 0)
		return '128MiB';

	let mib = int((kb * 4) / 10 / 1024);
	if (mib > 256)
		mib = 256;
	if (mib < 32)
		mib = 32;

	return sprintf('%dMiB', mib);
}

function is_pid_alive(pid_path) {
	let raw = fs.readfile(pid_path);
	if (type(raw) != 'string' || !match(trim(raw), /^[0-9]+$/))
		return false;
	let pid = trim(raw);
	return (fs.stat('/proc/' + pid) != null);
}

function unlink_own_pid(pid_path, expected_pid) {
	if (expected_pid == null) {
		fs.unlink(pid_path);
		return;
	}
	let raw = fs.readfile(pid_path);
	if (type(raw) == 'string' && trim(raw) == ('' + expected_pid))
		fs.unlink(pid_path);
}

function cmd_wait_exit(paths) {
	let max_ms = env_int('NIMBUS_WAIT_EXIT_MS', DEFAULT_WAIT_EXIT_MS);
	let waited = 0;
	while (waited < max_ms && is_pid_alive(paths.pid_file)) {
		sleep(50);
		waited += 50;
	}
	return 0;
}

function resolve_core_bin(paths, uci_cfg) {
	return paths.bin_path ||
		uci_cfg?.core?.bin_path ||
		uci_cfg?.core?.core_path ||
		common.DEFAULT_CORE_PATH;
}

function compute_core_stamp(core_bin, version_str, bin_sha256) {
	let ver = version_str || '';
	if (type(bin_sha256) == 'string' && length(bin_sha256) > 0)
		return sprintf('%s:%s:%s', core_bin, ver, bin_sha256);
	let st_bin = fs.stat(core_bin);
	return sprintf('%s:%s:%d:%d', core_bin, ver, st_bin?.size ?? 0, st_bin?.mtime ?? 0);
}

function maybe_apply_dns(uci_cfg, effective_dns_port, fakeip, paths) {
	return dns.apply_dns(uci_cfg, {
		effective_dns_port: effective_dns_port,
		fakeip: fakeip,
		uci_confdir: paths.uci_confdir,
		uci_savedir: paths.uci_savedir,
		backup_path: paths.dns_backup_file,
		skip_reload: paths.skip_dns_reload
	});
}

function maybe_restore_dns(paths) {
	return dns.restore_dns({
		uci_confdir: paths.uci_confdir,
		uci_savedir: paths.uci_savedir,
		backup_path: paths.dns_backup_file,
		skip_reload: paths.skip_dns_reload
	});
}

function build_state_payload(state_name, uci_cfg, ctx, config_hash, warnings, last_error, wl, old_state, paths) {
	let g = uci_cfg?.global || {};
	let d = uci_cfg?.dns || {};
	let c = uci_cfg?.core || {};
	let w = uci_cfg?.whitelist || {};
	let bctx = ctx || {};
	let prev = (type(old_state) == 'object') ? old_state : {};

	let out_mark = (type(bctx.effective_outbound_mark) == 'int')
		? common.format_hex_u32(bctx.effective_outbound_mark)
		: (uci_cfg?.proxy?.outbound_mark || '0xff');
	let active_target = common.resolve_active_target(uci_cfg, {
		composers_dir: paths?.composers_dir,
		profiles_dir: paths?.profiles_dir
	});
	let active_kind = active_target.ok ? active_target.kind : (bctx.active_kind ?? null);

	let payload = {
		state: state_name,
		emergency_lockdown: false,
		enabled: (g.enabled == '1'),
		topology: (g.topology == 'side') ? 'side' : 'main',
		proxy_mode: g.proxy_mode || 'tproxy_redirect',
		fail_open: (g.fail_open == '1'),
		active_profile: g.active_profile || '',
		active_kind: active_kind,
		active_name: active_target.ok ? active_target.name : '',
		composer: (active_kind == 'composer') ? (bctx.composer ?? prev?.composer ?? null) : null,
		config_hash: config_hash || null,
		core: {
			bin_path: bctx.core_bin || c.bin_path || c.core_path || common.DEFAULT_CORE_PATH,
			version: bctx.core_version || null,
			bin_sha256: bctx.bin_sha256 ?? null
		},
		effective: {
			outbound_mark: out_mark,
			proxy_local: exists(bctx, 'proxy_local')
				? (bctx.proxy_local === true)
				: common.is_proxy_local(uci_cfg),
			skgid: exists(bctx, 'effective_skgid') ? bctx.effective_skgid : (prev?.effective?.skgid ?? null),
			gomemlimit: exists(bctx, 'effective_gomemlimit') ? bctx.effective_gomemlimit : (prev?.effective?.gomemlimit ?? null),
			redirect_port: bctx.effective_redirect_port ?? null,
			tproxy_port: bctx.effective_tproxy_port ?? null,
			tun_iface: null,
			dns_mode: d.mode || 'none',
			dns_port: bctx.effective_dns_port ?? null,
			local_dns_source: bctx.local_dns_source ?? prev?.effective?.local_dns_source ?? 'none',
			local_dns_server: bctx.local_dns_server ?? prev?.effective?.local_dns_server ?? null,
			inbound_sources: bctx.inbound_sources || { redirect: null, tproxy: null, tun: null },
			fakeip: bctx.fakeip || { ipv4: [], ipv6: [] }
		},
		whitelist: {
			enabled: (w.enabled != '0'),
			v4_count: wl?.v4_count ?? prev?.whitelist?.v4_count ?? 0,
			v6_count: wl?.v6_count ?? prev?.whitelist?.v6_count ?? 0
		},
		apis: bctx.apis || {
			singbox_api: { detected: false },
			clash_api: { detected: false }
		},
		warnings: warnings || [],
		last_error: last_error || null,
		updated_at: time()
	};

	if (type(prev.list_meta) == 'object')
		payload.list_meta = prev.list_meta;
	if (type(prev.sub_meta) == 'object')
		payload.sub_meta = prev.sub_meta;

	return payload;
}

function execute_fail_handler(reason, paths, existing_lock) {
	let lock_fh = existing_lock || common.acquire_lock(LOCK_TIMEOUT_MS, paths.lock_file);
	fs.unlink(paths.pid_file);

	let uci_cfg = common.uci_get_all('nimbus', paths.uci_confdir, paths.uci_savedir);
	let w = uci_cfg?.whitelist || {};
	let old_state = common.read_state(paths.state_file) || {};
	let fail_open = (uci_cfg?.global?.fail_open == '1');
	let warnings = (type(old_state.warnings) == 'array') ? [ ...old_state.warnings ] : [];

	common.log_msg('error', sprintf('fail handler triggered (fail_open=%s): %s', fail_open ? '1' : '0', reason), paths.log_file);

	if (!fail_open) {
		let wl = lu.collect_active_lists(uci_cfg, {
			uci_confdir: paths.uci_confdir,
			uci_savedir: paths.uci_savedir,
			local_dir: paths.local_lists_dir,
			cache_dir: paths.cache_lists_dir
		});

		let lock_res = nft.apply_lockdown({
			uci: uci_cfg,
			uci_confdir: paths.uci_confdir,
			uci_savedir: paths.uci_savedir,
			fakeip_v4: old_state?.effective?.fakeip?.ipv4,
			fakeip_v6: old_state?.effective?.fakeip?.ipv6,
			bypass_v4: wl.v4,
			bypass_v6: wl.v6,
			output_path: paths.rules_file,
			nft_bin: paths.nft_bin,
			dry_run: paths.nft_dry_run,
			check_only: paths.nft_check_only
		});

		let lockdown_ok = (lock_res.ok === true);
		let used_emergency = false;
		let final_error = reason;
		if (lockdown_ok) {
			fs.unlink(paths.bypass_sets_file);
		} else {
			common.log_msg(
				'error',
				sprintf('primary lockdown rules failed (%s); falling back to static emergency lockdown', lock_res.error || 'unknown error'),
				paths.log_file
			);
			let emg_res = nft.apply_emergency_lockdown({
				output_path: paths.rules_file,
				nft_bin: paths.nft_bin,
				dry_run: paths.nft_dry_run,
				check_only: paths.nft_check_only
			});
			if (emg_res.ok === true) {
				lockdown_ok = true;
				used_emergency = true;
				fs.unlink(paths.bypass_sets_file);
				let emg_warn = sprintf(
					'primary lockdown rules failed (%s); emergency static fail-closed forward block is active',
					lock_res.error || 'nft error'
				);
				if (index(warnings, emg_warn) < 0)
					push(warnings, emg_warn);
			} else {
				final_error = sprintf(
					'%s (CRITICAL: failed to apply both primary and emergency lockdown rules: %s)',
					reason,
					emg_res.error || lock_res.error || 'nft error'
				);
				common.log_msg('error', final_error, paths.log_file);
			}
		}

		if (!paths.skip_routes) {
			route.cleanup_routes({
				uci: uci_cfg,
				uci_confdir: paths.uci_confdir,
				uci_savedir: paths.uci_savedir
			});
		}

		if (lockdown_ok && uci_cfg?.dns?.mode == 'singbox') {
			let dns_warn = 'LOCKDOWN active while dns.mode="singbox": router local DNS resolution is blocked to prevent DNS leaks; stop service to restore dnsmasq';
			if (index(warnings, dns_warn) < 0)
				push(warnings, dns_warn);
		}
		if (lockdown_ok && common.is_proxy_local(uci_cfg)) {
			let pl_warn = 'LOCKDOWN active while global.proxy_local="1": forward_lockdown blocks non-whitelist LAN forwarding only and does not filter router-local outbound traffic';
			if (index(warnings, pl_warn) < 0)
				push(warnings, pl_warn);
		}

		let lock_v4 = used_emergency
			? 0
			: (lock_res?.loaded_counts?.bypass_v4 ?? wl?.v4_count ?? old_state?.whitelist?.v4_count ?? 0);
		let lock_v6 = used_emergency
			? 0
			: (lock_res?.loaded_counts?.bypass_v6 ?? wl?.v6_count ?? old_state?.whitelist?.v6_count ?? 0);
		let active_target = common.resolve_active_target(uci_cfg, {
			composers_dir: paths.composers_dir,
			profiles_dir: paths.profiles_dir
		});
		let active_kind = active_target.ok ? active_target.kind : null;
		let next_state = {
			...old_state,
			state: lockdown_ok ? 'lockdown' : 'error',
			emergency_lockdown: (lockdown_ok && used_emergency),
			active_profile: uci_cfg?.global?.active_profile || '',
			active_kind: active_kind,
			active_name: active_target.ok ? active_target.name : '',
			composer: (active_kind == 'composer') ? (old_state?.composer ?? null) : null,
			fail_open: false,
			whitelist: {
				enabled: (w.enabled != '0'),
				v4_count: lock_v4,
				v6_count: lock_v6
			},
			warnings: warnings,
			last_error: final_error,
			updated_at: time()
		};
		common.write_state(next_state, paths.state_file);
	} else {
		fs.unlink(paths.bypass_sets_file);
		let del_res = nft.delete_table({
			nft_bin: paths.nft_bin,
			dry_run: paths.nft_dry_run
		});
		if (!del_res.ok) {
			let del_warn = sprintf('failed to delete table inet nimbus during fail-open recovery: %s', del_res.error || 'nft error');
			common.log_msg('error', del_warn, paths.log_file);
			if (index(warnings, del_warn) < 0)
				push(warnings, del_warn);
		}

		if (!paths.skip_routes) {
			route.cleanup_routes({
				uci: uci_cfg,
				uci_confdir: paths.uci_confdir,
				uci_savedir: paths.uci_savedir
			});
		}

		let dns_res = maybe_restore_dns(paths);
		if (type(dns_res) == 'object' && dns_res.ok === false) {
			let dns_err = sprintf('failed to restore dnsmasq during fail-open recovery: %s', dns_res.error || 'dns error');
			common.log_msg('error', dns_err, paths.log_file);
			if (index(warnings, dns_err) < 0)
				push(warnings, dns_err);
		}

		let active_target = common.resolve_active_target(uci_cfg, {
			composers_dir: paths.composers_dir,
			profiles_dir: paths.profiles_dir
		});
		let active_kind = active_target.ok ? active_target.kind : null;
		let next_state = {
			...old_state,
			state: 'error',
			emergency_lockdown: false,
			active_profile: uci_cfg?.global?.active_profile || '',
			active_kind: active_kind,
			active_name: active_target.ok ? active_target.name : '',
			composer: (active_kind == 'composer') ? (old_state?.composer ?? null) : null,
			fail_open: true,
			whitelist: {
				enabled: (w.enabled != '0'),
				v4_count: old_state?.whitelist?.v4_count ?? 0,
				v6_count: old_state?.whitelist?.v6_count ?? 0
			},
			warnings: warnings,
			last_error: reason,
			updated_at: time()
		};
		common.write_state(next_state, paths.state_file);
	}

	if (!existing_lock && lock_fh)
		common.release_lock(lock_fh);
}

function cmd_prepare_start(paths, is_reload) {
	let lock_ms = env_int('NIMBUS_LOCK_TIMEOUT_MS', LOCK_TIMEOUT_MS);
	let lock_fh = common.acquire_lock(lock_ms, paths.lock_file);
	if (!lock_fh) {
		common.log_msg('error', 'failed to acquire lock for service preparation', paths.log_file);
		return is_reload ? LOCK_EXIT_CODE : 1;
	}

	let uci_cfg = common.uci_get_all('nimbus', paths.uci_confdir, paths.uci_savedir);
	let old_state = common.read_state(paths.state_file) || {};
	let old_hash = old_state.config_hash || common.sha256_file(paths.config_file);
	let core_bin = resolve_core_bin(paths, uci_cfg);

	if (!is_reload) {
		common.write_state(build_state_payload('preparing', uci_cfg, {
			core_bin: core_bin,
			bin_sha256: old_state?.core?.bin_sha256 ?? null
		}, old_hash, [], null, null, old_state, paths), paths.state_file);
	}

	let bres = cb.build_config({
		uci: uci_cfg,
		uci_confdir: paths.uci_confdir,
		uci_savedir: paths.uci_savedir,
		bin_path: core_bin,
		profile_path: paths.profile_path,
		composers_dir: paths.composers_dir,
		profiles_dir: paths.profiles_dir,
		output_path: paths.config_file,
		check_dir: paths.check_dir,
		resolv_auto_path: paths.resolv_auto_path,
		ubus_dump: paths.ubus_dump,
		wan_dns_servers: paths.wan_dns_servers
	});

	if (!bres.ok) {
		execute_fail_handler(bres.error || 'configuration validation failed', paths, lock_fh);
		common.release_lock(lock_fh);
		return 1;
	}

	let ver_str = bres.context?.core_version || null;
	if (!ver_str) {
		let pver = cb.probe_core_version(core_bin);
		if (pver.ok)
			ver_str = pver.version;
	}
	let new_bin_sha = common.sha256_file(core_bin);
	let core_stamp = compute_core_stamp(core_bin, ver_str, new_bin_sha);

	let new_hash = common.sha256_file(paths.config_file);
	let proxy_local = common.is_proxy_local(uci_cfg);
	let effective_gomemlimit = compute_gomemlimit(uci_cfg?.global?.gomemlimit);
	let expected_skgid = common.resolve_group_gid(common.NIMBUS_GROUP, paths.group_file);
	let warnings = [ ...(bres.context?.warnings || []) ];
	if (proxy_local && expected_skgid == null) {
		let gid_warn = 'system group "nimbus" not found; router outbound proxy relies solely on SO_MARK anti-loop protection';
		if (index(warnings, gid_warn) < 0)
			push(warnings, gid_warn);
	}
	for (let fw_w in nft.check_fw4_lan_input(uci_cfg, { uci_confdir: paths.uci_confdir, uci_savedir: paths.uci_savedir })) {
		if (index(warnings, fw_w) < 0)
			push(warnings, fw_w);
	}

	let wl = lu.collect_active_lists(uci_cfg, {
		uci_confdir: paths.uci_confdir,
		uci_savedir: paths.uci_savedir,
		local_dir: paths.local_lists_dir,
		cache_dir: paths.cache_lists_dir
	});

	// Always set up policy routes BEFORE applying nftables rules so marked UDP has zero leak window
	if (!paths.skip_routes) {
		let rt_res = route.setup_routes({
			uci: uci_cfg,
			uci_confdir: paths.uci_confdir,
			uci_savedir: paths.uci_savedir
		});
		if (!rt_res.ok) {
			execute_fail_handler(rt_res.error || 'failed to apply policy routes', paths, lock_fh);
			common.release_lock(lock_fh);
			return 1;
		}
	}

	let nft_res = nft.apply_rules({
		uci: uci_cfg,
		uci_confdir: paths.uci_confdir,
		uci_savedir: paths.uci_savedir,
		context: bres.context,
		bypass_v4: wl.v4,
		bypass_v6: wl.v6,
		mode: 'tproxy_redirect',
		group_file: paths.group_file,
		output_path: paths.rules_file,
		nft_bin: paths.nft_bin,
		dry_run: paths.nft_dry_run,
		check_only: paths.nft_check_only
	});

	if (!nft_res.ok) {
		execute_fail_handler(nft_res.error || 'failed to apply nftables rules', paths, lock_fh);
		common.release_lock(lock_fh);
		return 1;
	}
	fs.unlink(paths.bypass_sets_file);

	let dns_res = maybe_apply_dns(uci_cfg, bres.context?.effective_dns_port, bres.context?.fakeip, paths);
	if (type(dns_res) == 'object' && dns_res.ok === false) {
		execute_fail_handler(dns_res.error || 'failed to apply dnsmasq takeover', paths, lock_fh);
		common.release_lock(lock_fh);
		return 1;
	}

	if (!paths.skip_cron_sync) {
		lu.sync_cron(uci_cfg, {
			uci_confdir: paths.uci_confdir,
			uci_savedir: paths.uci_savedir,
			crontab_file: paths.crontab_file,
			crontab_path: paths.crontab_file
		});
		pu.sync_cron(uci_cfg, {
			uci_confdir: paths.uci_confdir,
			uci_savedir: paths.uci_savedir,
			crontab_file: paths.crontab_file,
			crontab_path: paths.crontab_file
		});
	}

	common.atomic_write(paths.core_stamp_file, core_stamp + '\n', 0600);

	let state_ctx = {
		...(bres.context || {}),
		proxy_local: proxy_local,
		effective_skgid: expected_skgid,
		effective_gomemlimit: effective_gomemlimit,
		core_bin: core_bin,
		core_version: ver_str,
		bin_sha256: new_bin_sha
	};
	let wl_for_state = {
		...wl,
		v4_count: nft_res.loaded_counts?.bypass_v4 ?? wl.v4_count,
		v6_count: nft_res.loaded_counts?.bypass_v6 ?? wl.v6_count
	};
	let running_state = build_state_payload('running', uci_cfg, state_ctx, new_hash, warnings, null, wl_for_state, old_state, paths);
	common.write_state(running_state, paths.state_file);

	let old_bin_path = old_state?.core?.bin_path;
	let old_bin_sha = old_state?.core?.bin_sha256;
	let old_core_ver = old_state?.core?.version;
	let core_changed = (
		old_bin_path != core_bin ||
		(old_bin_sha != null && new_bin_sha != old_bin_sha) ||
		(old_bin_sha == null && old_core_ver != null && ver_str != null && old_core_ver != ver_str)
	);
	let old_mem = old_state?.effective?.gomemlimit;
	let mem_changed = (old_mem != null && old_mem != effective_gomemlimit);
	let live_gid = common.read_pid_gid(paths.pid_file);
	let gid_changed = (expected_skgid != null && live_gid != null && live_gid != expected_skgid);
	let skip_restart = (is_reload &&
		old_state.state == 'running' &&
		old_hash != null &&
		new_hash == old_hash &&
		!core_changed &&
		!mem_changed &&
		!gid_changed &&
		is_pid_alive(paths.pid_file));

	common.release_lock(lock_fh);
	return skip_restart ? 10 : 0;
}

function cmd_stop(paths) {
	let lock_fh = common.acquire_lock(LOCK_TIMEOUT_MS, paths.lock_file);
	let uci_cfg = common.uci_get_all('nimbus', paths.uci_confdir, paths.uci_savedir);
	let w = uci_cfg?.whitelist || {};
	let old_state = common.read_state(paths.state_file) || {};

	fs.unlink(paths.pid_file);
	fs.unlink(paths.bypass_sets_file);
	let del_res = nft.delete_table({
		nft_bin: paths.nft_bin,
		dry_run: paths.nft_dry_run
	});
	if (!del_res.ok)
		common.log_msg('error', sprintf('failed to delete table inet nimbus on stop: %s', del_res.error || 'nft error'), paths.log_file);

	if (!paths.skip_routes) {
		route.cleanup_routes({
			uci: uci_cfg,
			uci_confdir: paths.uci_confdir,
			uci_savedir: paths.uci_savedir
		});
	}

	let stop_warnings = [];
	let dns_res = maybe_restore_dns(paths);
	if (type(dns_res) == 'object' && dns_res.ok === false) {
		let dns_err = sprintf('failed to restore dnsmasq on stop: %s', dns_res.error || 'dns error');
		common.log_msg('error', dns_err, paths.log_file);
		push(stop_warnings, dns_err);
	}

	let active_target = common.resolve_active_target(uci_cfg, {
		composers_dir: paths.composers_dir,
		profiles_dir: paths.profiles_dir
	});
	let active_kind = active_target.ok ? active_target.kind : null;
	common.write_state({
		...old_state,
		state: 'stopped',
		emergency_lockdown: false,
		enabled: (uci_cfg?.global?.enabled == '1'),
		active_profile: uci_cfg?.global?.active_profile || '',
		active_kind: active_kind,
		active_name: active_target.ok ? active_target.name : '',
		composer: (active_kind == 'composer') ? (old_state?.composer ?? null) : null,
		whitelist: {
			enabled: (w.enabled != '0'),
			v4_count: old_state?.whitelist?.v4_count ?? 0,
			v6_count: old_state?.whitelist?.v6_count ?? 0
		},
		warnings: stop_warnings,
		last_error: null,
		updated_at: time()
	}, paths.state_file);

	if (lock_fh)
		common.release_lock(lock_fh);
	return 0;
}

function cmd_hotplug(paths) {
	let lock_fh = common.acquire_lock(LOCK_TIMEOUT_MS, paths.lock_file);
	if (!lock_fh)
		return 0;

	let st = common.read_state(paths.state_file);
	if (type(st) != 'object' || (st.state != 'running' && st.state != 'lockdown')) {
		common.release_lock(lock_fh);
		return 0;
	}

	let uci_cfg = common.uci_get_all('nimbus', paths.uci_confdir, paths.uci_savedir);
	if (st.emergency_lockdown === true) {
		if (!paths.nft_dry_run && !paths.nft_check_only && !nft.table_exists({ nft_bin: paths.nft_bin })) {
			let st_rules = fs.stat(paths.rules_file);
			let healed = false;
			if (st_rules && st_rules.type == 'file') {
				common.log_msg('warn', 'hotplug detected missing emergency lockdown table; replaying rules.nft', paths.log_file);
				healed = (nft.replay_rules_file(paths.rules_file, { nft_bin: paths.nft_bin }).ok === true);
			}
			if (!healed) {
				common.log_msg('warn', 'hotplug emergency rules.nft missing or replay failed; rebuilding static emergency lockdown', paths.log_file);
				nft.apply_emergency_lockdown({ output_path: paths.rules_file, nft_bin: paths.nft_bin });
			}
		}
		common.release_lock(lock_fh);
		return 0;
	}

	let iface_res = nft.reload_iface_sets(uci_cfg, {
		uci_confdir: paths.uci_confdir,
		uci_savedir: paths.uci_savedir,
		output_path: paths.wan_sets_file,
		nft_bin: paths.nft_bin,
		dry_run: paths.nft_dry_run,
		check_only: paths.nft_check_only
	});
	if (!iface_res.ok && !paths.nft_dry_run && !paths.nft_check_only) {
		let tbl_present = nft.table_exists({ nft_bin: paths.nft_bin });
		if (!tbl_present) {
			let st_rules = fs.stat(paths.rules_file);
			let healed = false;
			if (st_rules && st_rules.type == 'file') {
				common.log_msg('warn', 'hotplug detected missing table inet nimbus; replaying rules.nft to self-heal', paths.log_file);
				let heal_res = nft.replay_rules_file(paths.rules_file, { nft_bin: paths.nft_bin });
				if (heal_res.ok) {
					healed = true;
					let st_byp = fs.stat(paths.bypass_sets_file);
					if (st_byp && st_byp.type == 'file') {
						let byp_res = nft.replay_rules_file(paths.bypass_sets_file, { nft_bin: paths.nft_bin });
						if (!byp_res.ok)
							common.log_msg('warn', sprintf('hotplug bypass_sets.nft replay failed: %s', byp_res.error || 'nft error'), paths.log_file);
					}
					let retry_if = nft.reload_iface_sets(uci_cfg, {
						uci_confdir: paths.uci_confdir,
						uci_savedir: paths.uci_savedir,
						output_path: paths.wan_sets_file,
						nft_bin: paths.nft_bin
					});
					if (!retry_if.ok)
						common.log_msg('warn', sprintf('hotplug post-heal iface set reload failed: %s', retry_if.error || 'nft error'), paths.log_file);
				}
			}
			if (!healed) {
				execute_fail_handler('hotplug detected missing table inet nimbus and failed to replay rules.nft', paths, lock_fh);
				common.release_lock(lock_fh);
				return 0;
			}
		} else {
			common.log_msg('warn', sprintf('hotplug iface set reload failed while table exists: %s', iface_res.error || 'nft error'), paths.log_file);
		}
	}

	if (st.state == 'running' && !paths.skip_routes) {
		route.ensure_routes({
			uci: uci_cfg,
			uci_confdir: paths.uci_confdir,
			uci_savedir: paths.uci_savedir
		});
	}

	let need_dns_reload = false;
	let proxy_local_on = common.is_proxy_local(uci_cfg);
	if (st.state == 'running' &&
		(uci_cfg?.dns?.mode == 'singbox' || proxy_local_on) &&
		(uci_cfg?.dns?.local_dns_policy || 'auto') == 'auto' &&
		(st?.effective?.local_dns_source == 'wan' || st?.effective?.local_dns_source == 'fallback')) {
		let wan_res = cb.resolve_wan_upstream_dns(uci_cfg, {
			uci_confdir: paths.uci_confdir,
			uci_savedir: paths.uci_savedir,
			resolv_auto_path: paths.resolv_auto_path,
			ubus_dump: paths.ubus_dump,
			wan_dns_servers: paths.wan_dns_servers
		});
		if (wan_res.server && wan_res.server != st?.effective?.local_dns_server)
			need_dns_reload = true;
	}

	common.release_lock(lock_fh);

	if (need_dns_reload && !paths.skip_hotplug_reload && fs.access(paths.init_script, 'x'))
		system([ paths.init_script, 'reload' ], 15000);

	return 0;
}

function run_supervisor_daemon(paths) {
	let uci_cfg = common.uci_get_all('nimbus', paths.uci_confdir, paths.uci_savedir);
	let bin_path = resolve_core_bin(paths, uci_cfg);
	let gomemlimit = getenv('GOMEMLIMIT') || compute_gomemlimit(uci_cfg?.global?.gomemlimit);
	let gogc = getenv('GOGC') || '50';

	let max_retries = env_int('NIMBUS_MAX_RETRIES', DEFAULT_MAX_RETRIES);
	let retry_window_sec = env_int('NIMBUS_RETRY_WINDOW_SEC', DEFAULT_RETRY_WINDOW_SEC);
	let retry_backoff_ms = env_int('NIMBUS_RETRY_BACKOFF_MS', DEFAULT_RETRY_BACKOFF_MS);
	let log_timer_ms = env_int('NIMBUS_LOG_TIMER_MS', DEFAULT_LOG_TIMER_MS);
	let kill_grace_ms = env_int('NIMBUS_KILL_GRACE_MS', DEFAULT_KILL_GRACE_MS);

	let stopping = false;
	let child_proc = null;
	let child_pid = null;
	let retry_count = 0;
	let window_start = 0;
	let last_spawn_ts = 0;
	let retry_timer = null;
	let kill_timer = null;
	let log_timer = null;
	let use_uloop_signal = (type(uloop.signal) == 'function');
	let sig_term = null;
	let sig_int = null;

	function cleanup_timers() {
		if (retry_timer) {
			retry_timer.cancel();
			retry_timer = null;
		}
		if (kill_timer) {
			kill_timer.cancel();
			kill_timer = null;
		}
		if (log_timer) {
			log_timer.cancel();
			log_timer = null;
		}
	}

	function cleanup_signals() {
		if (use_uloop_signal) {
			if (sig_term) {
				sig_term.delete();
				sig_term = null;
			}
			if (sig_int) {
				sig_int.delete();
				sig_int = null;
			}
		} else if (type(signal) == 'function') {
			signal('SIGTERM', 'default');
			signal('SIGINT', 'default');
		}
	}

	function spawn_child() {
		if (stopping)
			return;

		last_spawn_ts = time();
		let child_env = {
			PATH: getenv('PATH') || '/usr/sbin:/usr/bin:/sbin:/bin',
			HOME: paths.work_dir,
			GOMEMLIMIT: gomemlimit,
			GOGC: gogc
		};

		child_proc = uloop.process(
			bin_path,
			[ 'run', '-c', paths.config_file, '-D', paths.work_dir ],
			child_env,
			(exit_code) => {
				let exited_pid = child_pid;
				child_proc = null;
				child_pid = null;
				unlink_own_pid(paths.pid_file, exited_pid);

				if (stopping) {
					cleanup_timers();
					uloop.end();
					return;
				}

				let now = time();
				if (window_start == 0 || (now - window_start) >= retry_window_sec ||
					(last_spawn_ts > 0 && (now - last_spawn_ts) >= retry_window_sec)) {
					window_start = now;
					retry_count = 0;
				}

				retry_count++;
				if (retry_count <= max_retries) {
					common.log_msg(
						'warn',
						sprintf('sing-box (pid=%s) exited with code %d; retry %d/%d in %dms',
							'' + exited_pid, exit_code, retry_count, max_retries, retry_backoff_ms),
						paths.log_file
					);
					retry_timer = uloop.timer(retry_backoff_ms, () => {
						retry_timer = null;
						spawn_child();
					});
					return;
				}

				cleanup_timers();
				let reason = sprintf(
					'sing-box crashed repeatedly (%d retries exhausted within %ds, last exit code %d)',
					max_retries, retry_window_sec, exit_code
				);
				execute_fail_handler(reason, paths, null);
				uloop.end();
			}
		);

		if (!child_proc) {
			cleanup_timers();
			execute_fail_handler(sprintf('failed to spawn sing-box binary: %s', bin_path), paths, null);
			uloop.end();
			return;
		}

		child_pid = child_proc.pid();
		common.atomic_write(paths.pid_file, sprintf('%d\n', child_pid), 0644);
	}

	function handle_stop_signal() {
		if (stopping)
			return;
		stopping = true;

		if (retry_timer) {
			retry_timer.cancel();
			retry_timer = null;
		}
		if (log_timer) {
			log_timer.cancel();
			log_timer = null;
		}

		if (child_proc && child_pid != null) {
			let stopping_pid = child_pid;
			system([ '/bin/kill', '-TERM', '' + stopping_pid ]);
			kill_timer = uloop.timer(kill_grace_ms, () => {
				if (child_pid != null)
					system([ '/bin/kill', '-KILL', '' + child_pid ]);
				unlink_own_pid(paths.pid_file, stopping_pid);
				cleanup_timers();
				uloop.end();
			});
			return;
		}

		unlink_own_pid(paths.pid_file, child_pid);
		cleanup_timers();
		uloop.end();
	}

	function schedule_log_truncation() {
		if (stopping)
			return;
		log_timer = uloop.timer(log_timer_ms, () => {
			common.truncate_log_hysteresis(paths.log_file, common.LOG_HIGH_BYTES, common.LOG_KEEP_BYTES);
			if (!stopping)
				schedule_log_truncation();
		});
	}

	try {
		common.ensure_dir(paths.work_dir, 0755);
		uloop.init();

		if (use_uloop_signal) {
			sig_term = uloop.signal('SIGTERM', handle_stop_signal);
			sig_int = uloop.signal('SIGINT', handle_stop_signal);
		} else if (type(signal) == 'function') {
			sig_term = signal('SIGTERM', handle_stop_signal);
			sig_int = signal('SIGINT', handle_stop_signal);
		} else {
			die('neither uloop.signal nor global signal() is available');
		}

		common.truncate_log_hysteresis(paths.log_file, common.LOG_HIGH_BYTES, common.LOG_KEEP_BYTES);
		schedule_log_truncation();
		spawn_child();

		uloop.run();
		cleanup_signals();
		cleanup_timers();
		return 0;
	} catch (err) {
		cleanup_signals();
		cleanup_timers();
		if (child_proc && child_pid != null)
			system([ '/bin/kill', '-TERM', '' + child_pid ]);
		if (!stopping) {
			let msg = err?.message || ('' + err) || 'unknown runtime error';
			execute_fail_handler(sprintf('supervisor unexpected error: %s', msg), paths, null);
			return 1;
		}
		fs.unlink(paths.pid_file);
		return 0;
	}
}

let paths = get_runtime_paths();
let cmd = ARGV[0] || '--daemon';

if (cmd == '--prepare-start')
	exit(cmd_prepare_start(paths, false));
else if (cmd == '--prepare-reload')
	exit(cmd_prepare_start(paths, true));
else if (cmd == '--stop')
	exit(cmd_stop(paths));
else if (cmd == '--wait-exit')
	exit(cmd_wait_exit(paths));
else if (cmd == '--hotplug')
	exit(cmd_hotplug(paths));
else if (cmd == '--fail-handler')
	exit((execute_fail_handler(ARGV[1] || 'service error', paths, null), 0));
else
	exit(run_supervisor_daemon(paths));
