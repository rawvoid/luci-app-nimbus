#!/usr/bin/ucode
'use strict';

import * as fs from 'fs';
import * as uloop from 'uloop';
import * as common from 'common';
import * as cb from 'config_builder';
import * as nft from 'nft_manager';
import * as route from 'route_manager';

const DEFAULT_MAX_RETRIES = 3;
const DEFAULT_RETRY_WINDOW_SEC = 60;
const DEFAULT_RETRY_BACKOFF_MS = 1000;
const DEFAULT_LOG_TIMER_MS = 30000;
const DEFAULT_KILL_GRACE_MS = 5000;
const LOCK_TIMEOUT_MS = 5000;

function env_int(name, fallback) {
	let raw = getenv(name);
	if (type(raw) != 'string' || !match(trim(raw), /^[0-9]+$/))
		return fallback;
	let n = int(trim(raw), 10);
	return (!common.isnan(n) && n >= 0) ? n : fallback;
}

function get_runtime_paths() {
	return {
		uci_confdir: getenv('NIMBUS_UCI_CONFDIR') || null,
		uci_savedir: getenv('NIMBUS_UCI_SAVEDIR') || null,
		bin_path: getenv('NIMBUS_BIN_PATH') || null,
		profile_path: getenv('NIMBUS_PROFILE_PATH') || null,
		config_file: getenv('NIMBUS_CONFIG_FILE') || common.CONFIG_FILE,
		work_dir: getenv('NIMBUS_WORK_DIR') || common.RUN_DIR,
		pid_file: getenv('NIMBUS_PID_FILE') || common.PID_FILE,
		state_file: getenv('NIMBUS_STATE_FILE') || common.STATE_FILE,
		lock_file: getenv('NIMBUS_LOCK_FILE') || common.LOCK_FILE,
		rules_file: getenv('NIMBUS_RULES_FILE') || common.RULES_NFT_FILE,
		log_file: getenv('NIMBUS_LOG_FILE') || common.LOG_FILE,
		check_dir: getenv('NIMBUS_CHECK_DIR') || common.CHECK_DIR,
		nft_dry_run: (getenv('NIMBUS_NFT_DRY_RUN') == '1'),
		nft_check_only: (getenv('NIMBUS_NFT_CHECK_ONLY') == '1'),
		skip_routes: (getenv('NIMBUS_SKIP_ROUTES') == '1')
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

function maybe_apply_dns(uci_cfg, effective_dns_port) {
	if (fs.stat('/usr/share/nimbus/dns_manager.uc') == null)
		return;
	let port_arg = (effective_dns_port != null) ? ('' + effective_dns_port) : 'null';
	system([
		'/usr/bin/ucode', '-S', '-L', '/usr/share/nimbus',
		'-e', sprintf('import * as d from "dns_manager"; if (type(d.apply_dns) == "function") d.apply_dns(null, { effective_dns_port: %s });', port_arg)
	], 5000);
}

function maybe_restore_dns() {
	if (fs.stat(common.DNS_BACKUP_FILE) == null || fs.stat('/usr/share/nimbus/dns_manager.uc') == null)
		return;
	system([
		'/usr/bin/ucode', '-S', '-L', '/usr/share/nimbus',
		'-e', 'import * as d from "dns_manager"; if (type(d.restore_dns) == "function") d.restore_dns();'
	], 5000);
}

function build_state_payload(state_name, uci_cfg, ctx, config_hash, warnings, last_error) {
	let g = uci_cfg?.global || {};
	let d = uci_cfg?.dns || {};
	let c = uci_cfg?.core || {};
	let w = uci_cfg?.whitelist || {};
	let bctx = ctx || {};

	let out_mark = (type(bctx.effective_outbound_mark) == 'int')
		? common.format_hex_u32(bctx.effective_outbound_mark)
		: (uci_cfg?.proxy?.outbound_mark || '0xff');

	return {
		state: state_name,
		enabled: (g.enabled == '1'),
		topology: (g.topology == 'side') ? 'side' : 'main',
		proxy_mode: g.proxy_mode || 'tproxy_redirect',
		fail_open: (g.fail_open == '1'),
		active_profile: g.active_profile || '',
		config_hash: config_hash || null,
		core: {
			bin_path: c.bin_path || '/etc/nimbus/bin/sing-box',
			version: bctx.core_version || null
		},
		effective: {
			outbound_mark: out_mark,
			redirect_port: bctx.effective_redirect_port ?? null,
			tproxy_port: bctx.effective_tproxy_port ?? null,
			tun_iface: null,
			dns_mode: d.mode || 'none',
			dns_port: bctx.effective_dns_port ?? null,
			inbound_sources: bctx.inbound_sources || { redirect: null, tproxy: null, tun: null },
			fakeip: bctx.fakeip || { ipv4: [], ipv6: [] }
		},
		whitelist: {
			enabled: (w.enabled != '0')
		},
		apis: bctx.apis || {
			singbox_api: { detected: false },
			clash_api: { detected: false }
		},
		warnings: warnings || [],
		last_error: last_error || null,
		updated_at: time()
	};
}

function execute_fail_handler(reason, paths, existing_lock) {
	let lock_fh = existing_lock || common.acquire_lock(LOCK_TIMEOUT_MS, paths.lock_file);
	fs.unlink(paths.pid_file);

	let uci_cfg = common.uci_get_all('nimbus', paths.uci_confdir, paths.uci_savedir);
	let old_state = common.read_state(paths.state_file) || {};
	let fail_open = (uci_cfg?.global?.fail_open == '1');
	let warnings = (type(old_state.warnings) == 'array') ? [ ...old_state.warnings ] : [];

	common.log_msg('error', sprintf('fail handler triggered (fail_open=%s): %s', fail_open ? '1' : '0', reason), paths.log_file);

	if (!fail_open) {
		nft.apply_lockdown({
			uci: uci_cfg,
			uci_confdir: paths.uci_confdir,
			uci_savedir: paths.uci_savedir,
			output_path: paths.rules_file,
			dry_run: paths.nft_dry_run,
			check_only: paths.nft_check_only
		});

		if (!paths.skip_routes) {
			route.cleanup_routes({
				uci: uci_cfg,
				uci_confdir: paths.uci_confdir,
				uci_savedir: paths.uci_savedir
			});
		}

		if (uci_cfg?.dns?.mode == 'singbox') {
			let dns_warn = 'LOCKDOWN active while dns.mode="singbox": router local DNS resolution is blocked to prevent DNS leaks; stop service to restore dnsmasq';
			if (index(warnings, dns_warn) < 0)
				push(warnings, dns_warn);
		}

		let next_state = {
			...old_state,
			state: 'lockdown',
			fail_open: false,
			warnings: warnings,
			last_error: reason,
			updated_at: time()
		};
		common.write_state(next_state, paths.state_file);
	} else {
		nft.delete_table({
			dry_run: paths.nft_dry_run
		});

		if (!paths.skip_routes) {
			route.cleanup_routes({
				uci: uci_cfg,
				uci_confdir: paths.uci_confdir,
				uci_savedir: paths.uci_savedir
			});
		}

		maybe_restore_dns();

		let next_state = {
			...old_state,
			state: 'error',
			fail_open: true,
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
	let lock_fh = common.acquire_lock(LOCK_TIMEOUT_MS, paths.lock_file);
	if (!lock_fh) {
		common.log_msg('error', 'failed to acquire lock for service preparation', paths.log_file);
		return 1;
	}

	let uci_cfg = common.uci_get_all('nimbus', paths.uci_confdir, paths.uci_savedir);
	let old_state = common.read_state(paths.state_file) || {};
	let old_hash = old_state.config_hash || common.sha256_file(paths.config_file);

	if (!is_reload) {
		common.write_state(build_state_payload('preparing', uci_cfg, null, old_hash, [], null), paths.state_file);
	}

	let bin_path = paths.bin_path || uci_cfg?.core?.bin_path || '/etc/nimbus/bin/sing-box';
	let bres = cb.build_config({
		uci: uci_cfg,
		uci_confdir: paths.uci_confdir,
		uci_savedir: paths.uci_savedir,
		bin_path: bin_path,
		profile_path: paths.profile_path,
		output_path: paths.config_file,
		check_dir: paths.check_dir
	});

	if (!bres.ok) {
		execute_fail_handler(bres.error || 'configuration validation failed', paths, lock_fh);
		common.release_lock(lock_fh);
		return 1;
	}

	let new_hash = common.sha256_file(paths.config_file);
	let warnings = [ ...(bres.context?.warnings || []) ];
	for (let fw_w in nft.check_fw4_lan_input(uci_cfg, { uci_confdir: paths.uci_confdir, uci_savedir: paths.uci_savedir })) {
		if (index(warnings, fw_w) < 0)
			push(warnings, fw_w);
	}

	let nft_res = nft.apply_rules({
		uci: uci_cfg,
		uci_confdir: paths.uci_confdir,
		uci_savedir: paths.uci_savedir,
		context: bres.context,
		mode: 'tproxy_redirect',
		output_path: paths.rules_file,
		dry_run: paths.nft_dry_run,
		check_only: paths.nft_check_only
	});

	if (!nft_res.ok) {
		execute_fail_handler(nft_res.error || 'failed to apply nftables rules', paths, lock_fh);
		common.release_lock(lock_fh);
		return 1;
	}

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

	maybe_apply_dns(uci_cfg, bres.context?.effective_dns_port);

	let running_state = build_state_payload('running', uci_cfg, bres.context, new_hash, warnings, null);
	common.write_state(running_state, paths.state_file);

	let skip_restart = (is_reload &&
		old_state.state == 'running' &&
		old_hash != null &&
		new_hash == old_hash &&
		is_pid_alive(paths.pid_file));

	common.release_lock(lock_fh);
	return skip_restart ? 10 : 0;
}

function cmd_stop(paths) {
	let lock_fh = common.acquire_lock(LOCK_TIMEOUT_MS, paths.lock_file);
	let uci_cfg = common.uci_get_all('nimbus', paths.uci_confdir, paths.uci_savedir);
	let old_state = common.read_state(paths.state_file) || {};

	fs.unlink(paths.pid_file);
	nft.delete_table({ dry_run: paths.nft_dry_run });

	if (!paths.skip_routes) {
		route.cleanup_routes({
			uci: uci_cfg,
			uci_confdir: paths.uci_confdir,
			uci_savedir: paths.uci_savedir
		});
	}

	maybe_restore_dns();

	common.write_state({
		...old_state,
		state: 'stopped',
		enabled: (uci_cfg?.global?.enabled == '1'),
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
	nft.reload_iface_sets(uci_cfg, {
		uci_confdir: paths.uci_confdir,
		uci_savedir: paths.uci_savedir,
		dry_run: paths.nft_dry_run,
		check_only: paths.nft_check_only
	});

	if (st.state == 'running' && !paths.skip_routes) {
		route.ensure_routes({
			uci: uci_cfg,
			uci_confdir: paths.uci_confdir,
			uci_savedir: paths.uci_savedir
		});
	}

	common.release_lock(lock_fh);
	return 0;
}

function run_supervisor_daemon(paths) {
	let uci_cfg = common.uci_get_all('nimbus', paths.uci_confdir, paths.uci_savedir);
	let bin_path = paths.bin_path || uci_cfg?.core?.bin_path || '/etc/nimbus/bin/sing-box';
	let gomemlimit = getenv('GOMEMLIMIT') || compute_gomemlimit(uci_cfg?.global?.gomemlimit);
	let gogc = getenv('GOGC') || '50';

	let max_retries = env_int('NIMBUS_MAX_RETRIES', DEFAULT_MAX_RETRIES);
	let retry_window_sec = env_int('NIMBUS_RETRY_WINDOW_SEC', DEFAULT_RETRY_WINDOW_SEC);
	let retry_backoff_ms = env_int('NIMBUS_RETRY_BACKOFF_MS', DEFAULT_RETRY_BACKOFF_MS);
	let log_timer_ms = env_int('NIMBUS_LOG_TIMER_MS', DEFAULT_LOG_TIMER_MS);
	let kill_grace_ms = env_int('NIMBUS_KILL_GRACE_MS', DEFAULT_KILL_GRACE_MS);

	common.ensure_dir(paths.work_dir, 0755);

	uloop.init();

	let stopping = false;
	let child_proc = null;
	let child_pid = null;
	let retry_count = 0;
	let window_start = 0;
	let last_spawn_ts = 0;
	let retry_timer = null;
	let kill_timer = null;
	let log_timer = null;

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
				fs.unlink(paths.pid_file);

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
			system([ '/bin/kill', '-TERM', '' + child_pid ]);
			kill_timer = uloop.timer(kill_grace_ms, () => {
				if (child_pid != null)
					system([ '/bin/kill', '-KILL', '' + child_pid ]);
				fs.unlink(paths.pid_file);
				cleanup_timers();
				uloop.end();
			});
			return;
		}

		fs.unlink(paths.pid_file);
		cleanup_timers();
		uloop.end();
	}

	let sig_term = uloop.signal('SIGTERM', handle_stop_signal);
	let sig_int = uloop.signal('SIGINT', handle_stop_signal);

	function schedule_log_truncation() {
		if (stopping)
			return;
		log_timer = uloop.timer(log_timer_ms, () => {
			common.truncate_log_hysteresis(paths.log_file, common.LOG_HIGH_BYTES, common.LOG_KEEP_BYTES);
			if (!stopping)
				schedule_log_truncation();
		});
	}

	common.truncate_log_hysteresis(paths.log_file, common.LOG_HIGH_BYTES, common.LOG_KEEP_BYTES);
	schedule_log_truncation();
	spawn_child();

	uloop.run();

	if (sig_term)
		sig_term.delete();
	if (sig_int)
		sig_int.delete();
	cleanup_timers();
	return 0;
}

let paths = get_runtime_paths();
let cmd = ARGV[0] || '--daemon';

if (cmd == '--prepare-start')
	exit(cmd_prepare_start(paths, false));
else if (cmd == '--prepare-reload')
	exit(cmd_prepare_start(paths, true));
else if (cmd == '--stop')
	exit(cmd_stop(paths));
else if (cmd == '--hotplug')
	exit(cmd_hotplug(paths));
else if (cmd == '--fail-handler')
	exit((execute_fail_handler(ARGV[1] || 'service error', paths, null), 0));
else
	exit(run_supervisor_daemon(paths));
