'use strict';

import * as fs from 'fs';
import * as uci from 'uci';
import * as ubus from 'ubus';
import * as uloop from 'uloop';
import * as common from 'nimbus.common';
import * as cb from 'nimbus.config_builder';
import * as nft from 'nimbus.nft_manager';
import * as lu from 'nimbus.list_updater';
import * as pu from 'nimbus.profile_updater';
import * as cm from 'nimbus.core_manager';

const LOG_READ_DEFAULT_LINES = 200;
const LOG_READ_MAX_LINES = 2000;
const CORE_STALE_SEC = 120;

const WORKER_DISPATCH =
	"'use strict';\n" +
	"import * as fs from 'fs';\n" +
	"import * as common from 'common';\n" +
	"import * as cb from 'config_builder';\n" +
	"import * as nft from 'nft_manager';\n" +
	"import * as lu from 'list_updater';\n" +
	"import * as pu from 'profile_updater';\n" +
	"import * as cm from 'core_manager';\n" +
	"let op = ARGV[0], args_p = ARGV[1], out_p = ARGV[2];\n" +
	"let a = common.read_json(args_p) || {};\n" +
	"let res = null;\n" +
	"if (op == 'status_probe') {\n" +
	"\tlet cnt = a.need_nft ? nft.get_counters(a.nft_opts || {}) : null;\n" +
	"\tlet ver = a.need_ver ? cb.probe_core_version(a.bin_path) : null;\n" +
	"\tres = { ok: true, counters: cnt, core_version: (ver && ver.ok) ? ver.version : null };\n" +
	"} else if (op == 'profile_check') {\n" +
	"\tlet raw = fs.readfile(a.raw_path);\n" +
	"\tif (raw == null) res = { ok: false, code: common.ERR_INTERNAL, error: 'failed to read staged profile' };\n" +
	"\telse res = cb.build_config({ ...(a.opts || {}), raw_config: raw, validate_only: true });\n" +
	"} else if (op == 'profile_update') {\n" +
	"\tres = pu.update_profiles(a.section_id, a.opts);\n" +
	"} else if (op == 'list_update') {\n" +
	"\tres = lu.update_lists(a.section_id, a.opts);\n" +
	"} else if (op == 'reload_whitelist') {\n" +
	"\tres = lu.reload_whitelist_sets(null, a.opts);\n" +
	"} else if (op == 'core_info') {\n" +
	"\tres = cm.get_core_info(null, a.opts);\n" +
	"} else if (op == 'core_check_update') {\n" +
	"\tres = cm.check_update(null, a.opts);\n" +
	"} else if (op == 'core_install') {\n" +
	"\tres = cm.install_core(a.opts);\n" +
	"} else {\n" +
	"\tres = { ok: false, code: common.ERR_INTERNAL, error: 'unknown worker op' };\n" +
	"}\n" +
	"if (out_p && length(out_p) > 0)\n" +
	"\tcommon.write_json_atomic(out_p, res, 0600);\n";

let shared_ubus = null;
let in_flight_write = false;
let core_task_running = false;
let active_jobs = {};
let job_seq = 0;

function get_cfg() {
	let ov = (type(global?.__nimbus_rpc_cfg) == 'object') ? global.__nimbus_rpc_cfg : {};
	let uci_confdir = ov.uci_confdir ?? getenv('NIMBUS_UCI_CONFDIR') ?? null;
	let uci_savedir = ov.uci_savedir ?? getenv('NIMBUS_UCI_SAVEDIR') ??
		(uci_confdir ? (uci_confdir + '/.uci') : null);
	let repo_root = getenv('NIMBUS_REPO_ROOT');
	let default_lib = repo_root ? (repo_root + '/nimbus/files/usr/share/nimbus') : '/usr/share/nimbus';

	return {
		uci_confdir: uci_confdir,
		uci_savedir: uci_savedir,
		state_file: ov.state_file ?? getenv('NIMBUS_STATE_FILE') ?? common.STATE_FILE,
		config_file: ov.config_file ?? getenv('NIMBUS_CONFIG_FILE') ?? common.CONFIG_FILE,
		pid_file: ov.pid_file ?? getenv('NIMBUS_PID_FILE') ?? common.PID_FILE,
		lock_file: ov.lock_file ?? getenv('NIMBUS_LOCK_FILE') ?? common.LOCK_FILE,
		log_file: ov.log_file ?? getenv('NIMBUS_LOG_FILE') ?? common.LOG_FILE,
		profiles_dir: ov.profiles_dir ?? getenv('NIMBUS_PROFILES_DIR') ?? common.PROFILES_DIR,
		local_lists_dir: ov.local_lists_dir ?? getenv('NIMBUS_LOCAL_LISTS_DIR') ?? common.LOCAL_LISTS_DIR,
		cache_lists_dir: ov.cache_lists_dir ?? getenv('NIMBUS_CACHE_LISTS_DIR') ?? common.CACHE_LISTS_DIR,
		core_task_file: ov.core_task_file ?? getenv('NIMBUS_CORE_TASK_FILE') ?? common.CORE_TASK_FILE,
		upload_profile_path: ov.upload_profile_path ?? getenv('NIMBUS_UPLOAD_PROFILE_PATH') ?? common.UPLOAD_PROFILE_PATH,
		upload_list_path: ov.upload_list_path ?? getenv('NIMBUS_UPLOAD_LIST_PATH') ?? common.UPLOAD_LIST_PATH,
		upload_bin_path: ov.upload_bin_path ?? getenv('NIMBUS_UPLOAD_BIN_PATH') ?? common.UPLOAD_BIN_PATH,
		crontab_file: ov.crontab_file ?? getenv('NIMBUS_CRONTAB_FILE') ?? common.CRONTABS_ROOT,
		check_dir: ov.check_dir ?? getenv('NIMBUS_CHECK_DIR') ?? common.CHECK_DIR,
		core_work_dir: ov.core_work_dir ?? getenv('NIMBUS_CORE_WORK_DIR') ?? '/tmp/nimbus-core-dl',
		init_script: ov.init_script ?? getenv('NIMBUS_INIT_SCRIPT') ?? '/etc/init.d/nimbus',
		cron_init: ov.cron_init ?? getenv('NIMBUS_CRON_INIT') ?? '/etc/init.d/cron',
		nft_bin: ov.nft_bin ?? getenv('NFT_BIN') ?? '/usr/sbin/nft',
		ucode_bin: ov.ucode_bin ?? getenv('NIMBUS_UCODE_BIN') ?? '/usr/bin/ucode',
		lib_dir: ov.lib_dir ?? getenv('NIMBUS_LIB_DIR') ?? default_lib,
		ubus_socket: ov.ubus_socket ?? getenv('UBUS_SOCKET') ?? null,
		bin_path: ov.bin_path ?? getenv('NIMBUS_BIN_PATH') ?? null,
		curl_bin: ov.curl_bin ?? getenv('NIMBUS_CURL_BIN') ?? null,
		openwrt_arch: ov.openwrt_arch ?? getenv('NIMBUS_OPENWRT_ARCH') ?? null,
		openwrt_release_path: ov.openwrt_release_path ?? getenv('NIMBUS_OPENWRT_RELEASE') ?? null,
		release_json: ov.release_json ?? null,
		tmp_free_bytes: ov.tmp_free_bytes ?? null,
		target_free_bytes: ov.target_free_bytes ?? null,
		tmp_free_kb: ov.tmp_free_kb ?? null,
		target_free_kb: ov.target_free_kb ?? null,
		same_fs: ov.same_fs ?? null,
		nft_dry_run: (ov.nft_dry_run != null) ? (ov.nft_dry_run === true) : (getenv('NIMBUS_NFT_DRY_RUN') == '1'),
		nft_check_only: (ov.nft_check_only != null) ? (ov.nft_check_only === true) : (getenv('NIMBUS_NFT_CHECK_ONLY') == '1'),
		skip_nft: (ov.skip_nft === true || getenv('NIMBUS_SKIP_NFT') == '1'),
		skip_core_probe: (ov.skip_core_probe === true),
		skip_cron_reload: (ov.skip_cron_reload === true || getenv('NIMBUS_SKIP_CRON_RELOAD') == '1'),
		skip_reload: (ov.skip_reload === true || getenv('NIMBUS_SKIP_RELOAD') == '1'),
		disable_ubus: (ov.disable_ubus === true),
		mock_counters: ov.mock_counters ?? null,
		mock_service_list: ov.mock_service_list ?? null,
		mock_core_info: ov.mock_core_info ?? null,
		mock_core_check: ov.mock_core_check ?? null
	};
}

function fail(code, error, extra) {
	return {
		ok: false,
		code: code || common.ERR_INTERNAL,
		error: error || 'unexpected error',
		...(extra || {})
	};
}

function to_bool(val, fallback) {
	if (val === true || val === '1' || val === 1)
		return true;
	if (val === false || val === '0' || val === 0)
		return false;
	return fallback;
}

function to_uci_bool(val, fallback) {
	return to_bool(val, fallback) ? '1' : '0';
}

function is_valid_section_id(id) {
	return (type(id) == 'string' && match(id, /^[A-Za-z0-9_]+$/) != null);
}

function is_http_url(url) {
	return (type(url) == 'string' && match(trim(url), /^https?:\/\/[^ \t\r\n]+$/) != null);
}

function parse_int_range(val, min_v, max_v) {
	let n = null;
	if (type(val) == 'int') {
		n = val;
	} else if (type(val) == 'string' && match(trim(val), /^[0-9]+$/)) {
		n = int(trim(val), 10);
		if (common.isnan(n))
			n = null;
	}
	if (n == null || n < min_v || n > max_v)
		return null;
	return n;
}

function make_unique_section_id(uci_cfg, preferred, prefix) {
	let base = lc(replace(trim('' + (preferred || '')), /\.[^.]+$/, ''));
	base = replace(base, /[^a-z0-9_]+/g, '_');
	base = replace(base, /^_+|_+$/g, '');
	if (length(base) == 0)
		base = prefix;
	if (!match(base, /^[a-z_]/))
		base = prefix + '_' + base;

	let cand = base;
	let seq = 2;
	while (exists(uci_cfg, cand)) {
		cand = sprintf('%s_%d', base, seq);
		seq++;
	}
	return cand;
}

function open_uci(cfg) {
	if (cfg.uci_confdir) {
		common.ensure_dir(cfg.uci_confdir, 0755);
		let nimbus_file = cfg.uci_confdir + '/nimbus';
		if (!fs.stat(nimbus_file))
			common.atomic_write(nimbus_file, '', 0644);
	}
	if (cfg.uci_savedir)
		common.ensure_dir(cfg.uci_savedir, 0755);
	return (cfg.uci_confdir || cfg.uci_savedir)
		? uci.cursor(cfg.uci_confdir, cfg.uci_savedir)
		: uci.cursor();
}

function read_uci(cfg) {
	return common.uci_get_all('nimbus', cfg.uci_confdir, cfg.uci_savedir);
}

function build_worker_opts(cfg) {
	let opts = {
		state_file: cfg.state_file,
		lock_file: cfg.lock_file,
		config_file: cfg.config_file,
		profiles_dir: cfg.profiles_dir,
		local_dir: cfg.local_lists_dir,
		cache_dir: cfg.cache_lists_dir,
		task_file: cfg.core_task_file,
		check_dir: cfg.check_dir,
		work_dir: cfg.core_work_dir,
		init_script: cfg.init_script,
		nft_bin: cfg.nft_bin,
		nft_dry_run: cfg.nft_dry_run,
		nft_check_only: cfg.nft_check_only
	};
	if (cfg.uci_confdir)
		opts.uci_confdir = cfg.uci_confdir;
	if (cfg.uci_savedir)
		opts.uci_savedir = cfg.uci_savedir;
	if (cfg.bin_path) {
		opts.bin_path = cfg.bin_path;
		opts.core_path = cfg.bin_path;
	}
	if (cfg.upload_bin_path)
		opts.upload_path = cfg.upload_bin_path;
	if (cfg.curl_bin)
		opts.curl_bin = cfg.curl_bin;
	if (cfg.openwrt_arch)
		opts.openwrt_arch = cfg.openwrt_arch;
	if (cfg.openwrt_release_path)
		opts.openwrt_release_path = cfg.openwrt_release_path;
	if (cfg.release_json != null)
		opts.release_json = cfg.release_json;
	if (cfg.tmp_free_bytes != null)
		opts.tmp_free_bytes = cfg.tmp_free_bytes;
	if (cfg.target_free_bytes != null)
		opts.target_free_bytes = cfg.target_free_bytes;
	if (cfg.tmp_free_kb != null)
		opts.tmp_free_kb = cfg.tmp_free_kb;
	if (cfg.target_free_kb != null)
		opts.target_free_kb = cfg.target_free_kb;
	if (cfg.same_fs != null)
		opts.same_fs = cfg.same_fs;
	if (cfg.skip_reload)
		opts.skip_reload = true;
	return opts;
}

function build_child_env(cfg) {
	let env = {
		PATH: getenv('PATH') || '/usr/sbin:/usr/bin:/sbin:/bin',
		TMPDIR: getenv('TMPDIR') || '/tmp'
	};
	if (cfg.uci_confdir)
		env.NIMBUS_UCI_CONFDIR = cfg.uci_confdir;
	if (cfg.uci_savedir)
		env.NIMBUS_UCI_SAVEDIR = cfg.uci_savedir;
	if (cfg.state_file)
		env.NIMBUS_STATE_FILE = cfg.state_file;
	if (cfg.lock_file)
		env.NIMBUS_LOCK_FILE = cfg.lock_file;
	if (cfg.config_file)
		env.NIMBUS_CONFIG_FILE = cfg.config_file;
	if (cfg.pid_file)
		env.NIMBUS_PID_FILE = cfg.pid_file;
	if (cfg.log_file)
		env.NIMBUS_LOG_FILE = cfg.log_file;
	if (cfg.bin_path)
		env.NIMBUS_BIN_PATH = cfg.bin_path;
	if (cfg.check_dir)
		env.NIMBUS_CHECK_DIR = cfg.check_dir;
	if (cfg.local_lists_dir)
		env.NIMBUS_LOCAL_LISTS_DIR = cfg.local_lists_dir;
	if (cfg.cache_lists_dir)
		env.NIMBUS_CACHE_LISTS_DIR = cfg.cache_lists_dir;
	if (cfg.crontab_file)
		env.NIMBUS_CRONTAB_FILE = cfg.crontab_file;
	return env;
}

function get_ubus_conn(cfg) {
	if (cfg.disable_ubus)
		return null;
	if (!shared_ubus) {
		try {
			shared_ubus = cfg.ubus_socket ? ubus.connect(cfg.ubus_socket) : ubus.connect();
		} catch (e) {
			shared_ubus = null;
		}
	}
	return shared_ubus;
}

function run_detached(cmd, argv, env, on_exit) {
	let jid = ++job_seq;
	let job = { proc: null };
	active_jobs[jid] = job;
	job.proc = uloop.process(cmd, argv, env, (rc) => {
		delete active_jobs[jid];
		if (type(on_exit) == 'function')
			on_exit(rc);
	});
	if (!job.proc) {
		delete active_jobs[jid];
		return false;
	}
	return true;
}

function run_async(req, cfg, cmd, argv, on_done) {
	let jid = ++job_seq;
	let job = { proc: null, defer: null };
	active_jobs[jid] = job;

	job.proc = uloop.process(cmd, argv, build_child_env(cfg), (rc) => {
		delete active_jobs[jid];
		let reply_obj = on_done(rc);
		req.reply(reply_obj);
	});

	if (!job.proc) {
		delete active_jobs[jid];
		return { started: false, deferred: null, reply: on_done(-1) };
	}

	let conn = get_ubus_conn(cfg);
	if (conn) {
		job.defer = conn.defer('luci.nimbus', 'core_task_status', {}, () => {
			job.defer = null;
		});
		if (!job.defer) {
			try {
				shared_ubus.disconnect();
			} catch (e) {
			}
			shared_ubus = null;
			conn = get_ubus_conn(cfg);
			if (conn) {
				job.defer = conn.defer('luci.nimbus', 'core_task_status', {}, () => {
					job.defer = null;
				});
			}
		}
	}

	return { started: true, deferred: job.defer, reply: null };
}

function create_tmp_json_path(prefix) {
	let tmp_dir = getenv('TMPDIR') || '/tmp';
	common.ensure_dir(tmp_dir, 0755);
	job_seq++;
	let pid = fs.readlink('/proc/self') || '0';
	return sprintf('%s/%s.%s.%d.json', tmp_dir, prefix, pid, job_seq);
}

function run_ucode_worker(req, cfg, op, worker_args, on_result) {
	let args_path = create_tmp_json_path('nimbus-rpc-args');
	let out_path = create_tmp_json_path('nimbus-rpc-out');

	if (!common.write_json_atomic(args_path, worker_args || {}, 0600)) {
		fs.unlink(args_path);
		return { started: false, deferred: null, reply: on_result(fail(common.ERR_INTERNAL, 'failed to stage worker arguments'), -1) };
	}

	return run_async(req, cfg, cfg.ucode_bin,
		[ '-S', '-L', cfg.lib_dir, '-e', WORKER_DISPATCH, op, args_path, out_path ],
		(rc) => {
			let res = common.read_json(out_path);
			fs.unlink(args_path);
			fs.unlink(out_path);
			return on_result(res, rc);
		}
	);
}

function with_write_lock(cfg, fn) {
	if (in_flight_write)
		return fail(common.ERR_LOCKED, 'another write operation is already in progress');

	let lock_fh = common.acquire_lock(0, cfg.lock_file);
	if (!lock_fh)
		return fail(common.ERR_LOCKED, 'nimbus lock is busy');

	let released = false;
	function release_once() {
		if (!released) {
			released = true;
			common.release_lock(lock_fh);
		}
	}

	let res = fn(release_once);
	if (type(res) == 'object' && exists(res, '__async_result')) {
		let ar = res.__async_result;
		if (!ar.started) {
			release_once();
			return ar.reply;
		}
		return ar.deferred;
	}

	release_once();
	return res;
}

function sync_cron_nonblocking(kind, uci_cfg, cfg) {
	let cpath = cfg.crontab_file || common.CRONTABS_ROOT;
	let is_root = (cpath == common.CRONTABS_ROOT);
	let tag = (kind == 'profile') ? pu.CRON_TAG : lu.CRON_TAG;
	let alt_tag = (kind == 'profile') ? 'nimbus-sub-sync' : 'nimbus-list-sync';

	let want = false;
	let line = null;
	if (kind == 'profile') {
		want = pu.has_auto_update_subscriptions(uci_cfg);
		if (want) {
			let cmd = "/usr/bin/ucode -S -L /usr/share/nimbus -e 'import * as p from \"profile_updater\"; p.run_scheduled_updates();'";
			line = sprintf('%s %s', pu.CRON_EXPR, cmd);
		}
	} else {
		let w = uci_cfg?.whitelist || {};
		let wl_on = (w.enabled != '0' && w.enabled !== false);
		let auto_on = (w.auto_update == '1' || w.auto_update === true);
		want = (wl_on && auto_on);
		if (want) {
			let expr = trim('' + (w.update_cron || '30 4 * * *'));
			let cmd = "/usr/bin/ucode -S -L /usr/share/nimbus -e 'import * as l from \"list_updater\"; l.update_lists();'";
			line = sprintf('%s %s', expr, cmd);
		}
	}

	if (!is_root) {
		return (kind == 'profile')
			? pu.sync_cron(uci_cfg, { crontab_path: cpath })
			: lu.sync_cron(uci_cfg, { crontab_path: cpath });
	}

	// Update /etc/crontabs/root without blocking system(); reload cron via uloop.process
	let old_raw = fs.readfile(cpath);
	let markers = [ '# ' + tag, '# ' + alt_tag ];
	if (old_raw == null && !want)
		return { ok: true, changed: false };

	let kept = [];
	if (type(old_raw) == 'string' && length(old_raw) > 0) {
		let lines = split(old_raw, '\n');
		if (length(lines) > 0 && lines[length(lines) - 1] == '')
			pop(lines);
		for (let l in lines) {
			let drop = false;
			for (let m in markers) {
				if (index(l, m) >= 0) {
					drop = true;
					break;
				}
			}
			if (!drop)
				push(kept, l);
		}
	}
	if (want && line)
		push(kept, line + ' # ' + tag);

	let new_raw = length(kept) ? (join('\n', kept) + '\n') : '';
	if (old_raw != null && new_raw == old_raw)
		return { ok: true, changed: false };

	if (!common.atomic_write(cpath, new_raw, 0600))
		return { ok: false, changed: false };

	if (!cfg.skip_cron_reload && fs.access(cfg.cron_init, 'x'))
		run_detached(cfg.cron_init, [ 'reload' ], build_child_env(cfg), null);

	return { ok: true, changed: true };
}

function read_text_or_upload(args, upload_path) {
	let from_upload = (args?.from_upload === true);
	if (from_upload) {
		let lst = fs.lstat(upload_path);
		if (!lst)
			return { ok: false, code: common.ERR_NOT_FOUND, error: sprintf('uploaded file not found: %s', upload_path) };
		if (lst.type != 'file')
			return { ok: false, code: common.ERR_INVALID_ARG, error: 'uploaded path must be a regular file (symlinks rejected)' };
		let raw = fs.readfile(upload_path);
		if (type(raw) != 'string')
			return { ok: false, code: common.ERR_INTERNAL, error: 'failed to read uploaded file' };
		return { ok: true, content: raw, from_upload: true };
	}

	if (type(args?.content) != 'string')
		return { ok: false, code: common.ERR_INVALID_ARG, error: 'content must be a string' };

	if (length(args.content) > common.MAX_DIRECT_TEXT_BYTES) {
		return {
			ok: false,
			code: common.ERR_INVALID_ARG,
			error: sprintf('content exceeds %d bytes direct transfer limit', common.MAX_DIRECT_TEXT_BYTES)
		};
	}

	return { ok: true, content: args.content, from_upload: false };
}

function cleanup_upload(is_upload, upload_path) {
	if (!is_upload)
		return;
	let lst = fs.lstat(upload_path);
	if (lst && lst.type == 'file')
		fs.unlink(upload_path);
}

function normalize_state_name(raw) {
	if (raw == 'preparing' || raw == 'running' || raw == 'lockdown' || raw == 'stopped')
		return raw;
	return 'stopped';
}

function read_process_status(pid_file) {
	let raw = fs.readfile(pid_file);
	if (type(raw) != 'string' || !match(trim(raw), /^[0-9]+$/))
		return { running: false, pid: null, uptime: 0, rss_kb: 0 };

	let pid_str = trim(raw);
	let pid_num = int(pid_str, 10);
	let proc_st = fs.stat('/proc/' + pid_str);
	if (!proc_st || common.isnan(pid_num) || pid_num <= 0)
		return { running: false, pid: null, uptime: 0, rss_kb: 0 };

	let uptime = (type(proc_st.mtime) == 'int' && time() >= proc_st.mtime) ? (time() - proc_st.mtime) : 0;
	let rss_kb = 0;
	let pstat = fs.readfile('/proc/' + pid_str + '/status');
	if (type(pstat) == 'string') {
		let m = match(pstat, /VmRSS:[ \t]*([0-9]+)[ \t]*kB/);
		if (m) {
			let v = int(m[1], 10);
			if (!common.isnan(v) && v >= 0)
				rss_kb = v;
		}
	}

	return {
		running: true,
		pid: pid_num,
		uptime: uptime,
		rss_kb: rss_kb
	};
}

function sanitize_apis(raw_apis) {
	let sb_in = (type(raw_apis?.singbox_api) == 'object') ? raw_apis.singbox_api : {};
	let ca_in = (type(raw_apis?.clash_api) == 'object') ? raw_apis.clash_api : {};
	let sb_det = (sb_in.detected === true);
	let ca_det = (ca_in.detected === true);

	return {
		singbox_api: {
			detected: sb_det,
			scheme: sb_det ? (sb_in.scheme || 'http') : null,
			listen: sb_det ? (sb_in.listen ?? null) : null,
			port: sb_det ? (sb_in.port ?? null) : null,
			has_secret: sb_det ? (sb_in.has_secret === true) : false,
			dashboard_enabled: sb_det ? (sb_in.dashboard_enabled === true) : false,
			dashboard_path: sb_det ? (sb_in.dashboard_path ?? null) : null,
			loopback_only: sb_det ? (sb_in.loopback_only === true) : false,
			no_secret: sb_det ? (sb_in.no_secret === true) : false
		},
		clash_api: {
			detected: ca_det,
			listen: ca_det ? (ca_in.listen ?? null) : null,
			port: ca_det ? (ca_in.port ?? null) : null,
			has_secret: ca_det ? (ca_in.has_secret === true) : false,
			external_ui: ca_det ? (ca_in.external_ui === true) : false,
			loopback_only: ca_det ? (ca_in.loopback_only === true) : false,
			no_secret: ca_det ? (ca_in.no_secret === true) : false
		}
	};
}

function build_status_payload(uci_cfg, st, proc_info, bin_path, core_installed, core_ver, cnt) {
	let g = uci_cfg?.global || {};
	let p = uci_cfg?.proxy || {};
	let d = uci_cfg?.dns || {};
	let w = uci_cfg?.whitelist || {};
	let eff = (type(st?.effective) == 'object') ? st.effective : {};

	let out_mark = eff.outbound_mark;
	if (type(out_mark) == 'int')
		out_mark = common.format_hex_u32(out_mark);
	if (type(out_mark) != 'string' || length(out_mark) == 0)
		out_mark = p.outbound_mark || '0xff';

	return {
		ok: true,
		state: normalize_state_name(st?.state),
		enabled: (g.enabled == '1'),
		topology: (g.topology == 'side') ? 'side' : 'main',
		proxy_mode: g.proxy_mode || 'tproxy_redirect',
		fail_open: (g.fail_open == '1'),
		active_profile: g.active_profile || '',
		process: proc_info,
		core: {
			installed: core_installed,
			bin_path: bin_path,
			version: core_installed ? (core_ver ?? null) : null
		},
		effective: {
			outbound_mark: out_mark,
			redirect_port: eff.redirect_port ?? null,
			tproxy_port: eff.tproxy_port ?? null,
			tun_iface: null,
			dns_mode: eff.dns_mode || d.mode || 'none',
			dns_port: eff.dns_port ?? null,
			inbound_sources: (type(eff.inbound_sources) == 'object')
				? eff.inbound_sources
				: { redirect: null, tproxy: null, tun: null },
			fakeip: (type(eff.fakeip) == 'object')
				? { ipv4: eff.fakeip.ipv4 || [], ipv6: eff.fakeip.ipv6 || [] }
				: { ipv4: [], ipv6: [] }
		},
		whitelist: {
			enabled: (w.enabled != '0'),
			v4_count: st?.whitelist?.v4_count ?? 0,
			v6_count: st?.whitelist?.v6_count ?? 0
		},
		counters: {
			tcp_packets: cnt?.tcp_packets ?? 0,
			tcp_bytes: cnt?.tcp_bytes ?? 0,
			udp_packets: cnt?.udp_packets ?? 0,
			udp_bytes: cnt?.udp_bytes ?? 0,
			tun_packets: 0,
			tun_bytes: 0,
			lockdown_rejected_packets: cnt?.lockdown_rejected_packets ?? 0
		},
		apis: sanitize_apis(st?.apis),
		last_error: st?.last_error ?? null,
		warnings: (type(st?.warnings) == 'array') ? st.warnings : []
	};
}

function dispatch_async_read(req, cfg, op, worker_args, on_result) {
	let ar = run_ucode_worker(req, cfg, op, worker_args, on_result);
	return ar.started ? ar.deferred : ar.reply;
}

function read_validated_file(filename, validator, base_dir, kind_label) {
	if (!validator(filename))
		return fail(common.ERR_INVALID_ARG, sprintf('invalid %s filename: %s', kind_label, '' + filename));

	let fpath = base_dir + '/' + filename;
	let st = fs.lstat(fpath);
	if (!st)
		return fail(common.ERR_NOT_FOUND, sprintf('%s file not found: %s', kind_label, filename));
	if (st.type != 'file')
		return fail(common.ERR_INVALID_ARG, sprintf('%s path must be a regular file', kind_label));

	let content = fs.readfile(fpath);
	if (type(content) != 'string')
		return fail(common.ERR_INTERNAL, sprintf('failed to read %s file', kind_label));

	return {
		ok: true,
		filename: filename,
		content: content,
		size_bytes: st.size,
		mtime: st.mtime
	};
}

function reload_whitelist_async_or_sync(req, cfg, release_once, build_reply) {
	let st = common.read_state(cfg.state_file) || {};
	let active_svc = (st.state == 'running' || st.state == 'lockdown');

	if (!active_svc) {
		let uci_cfg = read_uci(cfg);
		let res = lu.reload_whitelist_sets(uci_cfg, {
			...build_worker_opts(cfg),
			skip_lock: true
		});
		release_once();
		return build_reply(res);
	}

	in_flight_write = true;
	let ar = run_ucode_worker(req, cfg, 'reload_whitelist',
		{ opts: { ...build_worker_opts(cfg), skip_lock: true } },
		(res) => {
			in_flight_write = false;
			release_once();
			if (!res || res.ok === false)
				return fail(res?.code || common.ERR_INTERNAL, res?.error || 'failed to reload whitelist nftables sets');
			return build_reply(res);
		}
	);
	return { __async_result: ar };
}

function dispatch_updater_rpc(req, cfg, kind) {
	let is_prof = (kind == 'profile');
	let sec_type = is_prof ? 'profile' : 'list_source';
	let section_id = (type(req.args?.section_id) == 'string') ? trim(req.args.section_id) : '';

	if (length(section_id) > 0) {
		if (!is_valid_section_id(section_id))
			return fail(common.ERR_INVALID_ARG, sprintf('invalid section_id: %s', section_id));
		let uci_cfg = read_uci(cfg);
		let sec = uci_cfg?.[section_id];
		if (type(sec) != 'object' || sec['.type'] != sec_type)
			return fail(common.ERR_NOT_FOUND, sprintf('%s "%s" not found', sec_type, section_id));
		if (is_prof && (sec.type || 'local') != 'subscription')
			return fail(common.ERR_INVALID_ARG, sprintf('profile "%s" is not a subscription profile', section_id));
		if (!is_prof && (sec.type || 'url') != 'url')
			return fail(common.ERR_INVALID_ARG, sprintf('list_source "%s" is not a remote url source', section_id));
	}

	let op = is_prof ? 'profile_update' : 'list_update';
	let fb_code = is_prof ? common.ERR_VALIDATE_FAILED : common.ERR_NETWORK;
	let fb_msg = is_prof ? 'subscription update failed' : 'whitelist update failed';

	return with_write_lock(cfg, (release_once) => {
		in_flight_write = true;
		release_once();

		let ar = run_ucode_worker(req, cfg, op, {
			section_id: (length(section_id) > 0) ? section_id : null,
			opts: build_worker_opts(cfg)
		}, (res) => {
			in_flight_write = false;
			if (!res)
				return fail(common.ERR_INTERNAL, sprintf('%s worker failed', op));
			if (res.ok === false && !res.code) {
				let err_info = first_result_error(res.results, fb_code, fb_msg);
				return { ...res, ...err_info };
			}
			return res;
		});
		return { __async_result: ar };
	});
}

function find_profile_by_filename(uci_cfg, filename, skip_id) {
	for (let k, sec in (uci_cfg || {})) {
		if (type(sec) != 'object' || sec['.type'] != 'profile')
			continue;
		let id = sec['.name'] || k;
		if (skip_id && id == skip_id)
			continue;
		if (sec.filename == filename)
			return { id: id, section: sec };
	}
	return null;
}

function find_list_by_filename(uci_cfg, filename, skip_id) {
	for (let k, sec in (uci_cfg || {})) {
		if (type(sec) != 'object' || sec['.type'] != 'list_source')
			continue;
		let id = sec['.name'] || k;
		if (skip_id && id == skip_id)
			continue;
		if (sec.filename == filename)
			return { id: id, section: sec };
	}
	return null;
}

function first_result_error(results, fallback_code, fallback_msg) {
	if (type(results) == 'array') {
		for (let r in results) {
			if (type(r) == 'object' && r.status == 'failed' && type(r.error) == 'string')
				return { code: fallback_code, error: r.error };
		}
	}
	return { code: fallback_code, error: fallback_msg };
}

function is_core_task_active(cfg) {
	if (core_task_running)
		return true;
	let t = common.read_json(cfg.core_task_file);
	if (type(t) != 'object')
		return false;
	let active_states = [ 'checking_space', 'downloading', 'verifying', 'installing', 'reloading' ];
	if (index(active_states, t.state) < 0)
		return false;
	let age = (type(t.updated_at) == 'int') ? (time() - t.updated_at) : 0;
	return (age >= 0 && age < CORE_STALE_SEC);
}

const methods = {
	status: {
		args: {},
		call: function(req) {
			let cfg = get_cfg();
			let uci_cfg = read_uci(cfg);
			let st = common.read_state(cfg.state_file) || {};
			let proc_info = read_process_status(cfg.pid_file);

			let conn = get_ubus_conn(cfg);
			if (conn && !cfg.mock_service_list) {
				try {
					conn.call('service', 'list', { name: 'nimbus' });
				} catch (e) {
				}
			}

			let bin_path = cfg.bin_path || uci_cfg?.core?.bin_path || common.DEFAULT_CORE_PATH;
			let st_bin = fs.stat(bin_path);
			let core_installed = (st_bin != null && st_bin.type == 'file' && fs.access(bin_path, 'x'));
			let core_ver = core_installed ? (st?.core?.version ?? null) : null;

			let st_name = normalize_state_name(st?.state);
			let need_nft = (st_name == 'running' || st_name == 'lockdown') && !cfg.skip_nft && !cfg.mock_counters;
			let need_ver = core_installed && (core_ver == null) && !cfg.skip_core_probe;

			if (!need_nft && !need_ver) {
				let cnt = cfg.mock_counters || {};
				return build_status_payload(uci_cfg, st, proc_info, bin_path, core_installed, core_ver, cnt);
			}

			return dispatch_async_read(req, cfg, 'status_probe', {
				need_nft: need_nft,
				need_ver: need_ver,
				bin_path: bin_path,
				nft_opts: { nft_bin: cfg.nft_bin }
			}, (probe_res) => {
				let cnt = cfg.mock_counters || probe_res?.counters || {};
				let ver = core_ver ?? probe_res?.core_version ?? null;
				return build_status_payload(uci_cfg, st, proc_info, bin_path, core_installed, ver, cnt);
			});
		}
	},

	api_secret: {
		args: {},
		call: function(req) {
			let cfg = get_cfg();
			return with_write_lock(cfg, () => {
				let runtime_cfg = common.read_json(cfg.config_file);
				if (type(runtime_cfg) != 'object') {
					return {
						ok: true,
						singbox_api_secret: null,
						clash_api_secret: null
					};
				}
				let secrets = cb.extract_api_secrets(runtime_cfg);
				return {
					ok: true,
					singbox_api_secret: secrets.singbox_api_secret ?? null,
					clash_api_secret: secrets.clash_api_secret ?? null
				};
			});
		}
	},

	service_action: {
		args: { action: '' },
		call: function(req) {
			let cfg = get_cfg();
			let action = req.args?.action;
			if (type(action) != 'string' || index([ 'start', 'stop', 'restart', 'reload' ], action) < 0)
				return fail(common.ERR_INVALID_ARG, 'action must be one of start, stop, restart, reload');

			return with_write_lock(cfg, (release_once) => {
				in_flight_write = true;
				release_once();

				let ar = run_async(req, cfg, cfg.init_script, [ action ], (rc) => {
					in_flight_write = false;
					let st = common.read_state(cfg.state_file) || {};
					let next_state = normalize_state_name(st.state);

					if (rc != 0 || (action != 'stop' && (next_state == 'lockdown' || st.state == 'error'))) {
						return fail(
							common.ERR_VALIDATE_FAILED,
							st.last_error || sprintf('service %s failed (exit %d)', action, rc),
							{ state: next_state }
						);
					}
					return { ok: true, state: next_state };
				});
				return { __async_result: ar };
			});
		}
	},

	log_read: {
		args: { lines: 0 },
		call: function(req) {
			let cfg = get_cfg();
			let want_lines = LOG_READ_DEFAULT_LINES;
			if (exists(req.args, 'lines') && req.args.lines != null) {
				want_lines = parse_int_range(req.args.lines, 1, LOG_READ_MAX_LINES);
				if (want_lines == null)
					return fail(common.ERR_INVALID_ARG, sprintf('lines must be between 1 and %d', LOG_READ_MAX_LINES));
			}

			let st = fs.lstat(cfg.log_file);
			if (!st) {
				return {
					ok: true,
					content: '',
					size_bytes: 0,
					truncated: false
				};
			}
			if (st.type != 'file')
				return fail(common.ERR_INVALID_ARG, 'log path is not a regular file');

			let raw = fs.readfile(cfg.log_file);
			if (type(raw) != 'string')
				return fail(common.ERR_INTERNAL, 'failed to read log file');

			if (length(raw) == 0) {
				return {
					ok: true,
					content: '',
					size_bytes: st.size,
					truncated: false
				};
			}

			let parts = split(raw, '\n');
			let has_trailing_nl = (length(parts) > 0 && parts[length(parts) - 1] == '');
			if (has_trailing_nl)
				pop(parts);

			let truncated = (length(parts) > want_lines);
			let start_idx = truncated ? (length(parts) - want_lines) : 0;
			let kept = slice(parts, start_idx);
			let content = join('\n', kept) + (has_trailing_nl && length(kept) > 0 ? '\n' : '');

			return {
				ok: true,
				content: content,
				size_bytes: st.size,
				truncated: truncated
			};
		}
	},

	log_clear: {
		args: {},
		call: function(req) {
			let cfg = get_cfg();
			return with_write_lock(cfg, () => {
				let st = fs.lstat(cfg.log_file);
				if (!st)
					return { ok: true };
				if (st.type != 'file')
					return fail(common.ERR_INVALID_ARG, 'log path is not a regular file');

				let fh = fs.open(cfg.log_file, 'r+');
				if (!fh)
					return fail(common.ERR_INTERNAL, 'failed to open log file for truncation');
				let ok_trunc = fh.truncate(0);
				fh.close();
				if (!ok_trunc)
					return fail(common.ERR_INTERNAL, 'failed to truncate log file');
				return { ok: true };
			});
		}
	},

	profile_list: {
		args: {},
		call: function(req) {
			let cfg = get_cfg();
			return pu.list_profiles(null, {
				uci_confdir: cfg.uci_confdir,
				uci_savedir: cfg.uci_savedir,
				profiles_dir: cfg.profiles_dir
			});
		}
	},

	profile_read: {
		args: { filename: '' },
		call: function(req) {
			let cfg = get_cfg();
			return read_validated_file(req.args?.filename, common.is_valid_profile_filename, cfg.profiles_dir, 'profile');
		}
	},

	profile_save: {
		args: { filename: '', content: '', from_upload: false, validate: true },
		call: function(req) {
			let cfg = get_cfg();
			let filename = req.args?.filename;
			if (!common.is_valid_profile_filename(filename))
				return fail(common.ERR_INVALID_ARG, sprintf('invalid profile filename: %s', '' + filename));

			let want_validate = (req.args?.validate !== false);

			return with_write_lock(cfg, (release_once) => {
				let input = read_text_or_upload(req.args, cfg.upload_profile_path);
				if (!input.ok)
					return input;

				let parsed = null;
				try {
					parsed = json(input.content);
				} catch (e) {
					parsed = null;
				}
				if (type(parsed) != 'object') {
					cleanup_upload(input.from_upload, cfg.upload_profile_path);
					return fail(common.ERR_VALIDATE_FAILED, 'profile content must be a valid JSON object');
				}

				let uci_cfg = read_uci(cfg);
				let bin_path = cfg.bin_path || uci_cfg?.core?.bin_path || common.DEFAULT_CORE_PATH;
				let bin_ok = (fs.stat(bin_path)?.type == 'file' && fs.access(bin_path, 'x'));

				function finish_save(checked_flag) {
					let target = cfg.profiles_dir + '/' + filename;
					if (!common.atomic_write(target, input.content, 0644)) {
						cleanup_upload(input.from_upload, cfg.upload_profile_path);
						return fail(common.ERR_INTERNAL, sprintf('failed to write profile: %s', filename));
					}
					cleanup_upload(input.from_upload, cfg.upload_profile_path);

					let st_file = fs.stat(target);
					let st_run = common.read_state(cfg.state_file);
					let active_id = uci_cfg?.global?.active_profile || '';
					let active_sec = (length(active_id) > 0) ? uci_cfg?.[active_id] : null;
					let reload_required = (type(active_sec) == 'object' &&
						active_sec['.type'] == 'profile' &&
						active_sec.filename == filename &&
						st_run?.state == 'running');

					return {
						ok: true,
						filename: filename,
						size_bytes: st_file ? st_file.size : length(input.content),
						mtime: st_file ? st_file.mtime : time(),
						checked: checked_flag,
						reload_required: reload_required
					};
				}

				if (!want_validate || !bin_ok)
					return finish_save(false);

				let raw_stage = create_tmp_json_path('nimbus-prof-raw');
				if (!common.atomic_write(raw_stage, input.content, 0600)) {
					cleanup_upload(input.from_upload, cfg.upload_profile_path);
					return fail(common.ERR_INTERNAL, 'failed to stage profile for validation');
				}

				in_flight_write = true;
				let ar = run_ucode_worker(req, cfg, 'profile_check', {
					raw_path: raw_stage,
					opts: {
						...build_worker_opts(cfg),
						bin_path: bin_path
					}
				}, (chk_res) => {
					fs.unlink(raw_stage);
					let reply;
					if (!chk_res || chk_res.ok !== true) {
						cleanup_upload(input.from_upload, cfg.upload_profile_path);
						reply = fail(chk_res?.code || common.ERR_VALIDATE_FAILED, chk_res?.error || 'sing-box check failed');
					} else {
						reply = finish_save(true);
					}
					in_flight_write = false;
					release_once();
					return reply;
				});
				return { __async_result: ar };
			});
		}
	},

	profile_meta_save: {
		args: {
			section_id: '',
			name: '',
			type: '',
			filename: '',
			url: '',
			user_agent: '',
			via_proxy: false,
			auto_update: false,
			update_interval_hours: 0
		},
		call: function(req) {
			let cfg = get_cfg();
			let a = req.args || {};
			let name = trim('' + (a.name || ''));
			if (length(name) == 0)
				return fail(common.ERR_INVALID_ARG, 'profile name is required');

			let ptype = trim('' + (a.type || 'local'));
			if (ptype != 'local' && ptype != 'subscription')
				return fail(common.ERR_INVALID_ARG, 'profile type must be local or subscription');

			let filename = a.filename;
			if (!common.is_valid_profile_filename(filename))
				return fail(common.ERR_INVALID_ARG, sprintf('invalid profile filename: %s', '' + filename));

			let url = trim('' + (a.url || ''));
			if (ptype == 'subscription' && !is_http_url(url))
				return fail(common.ERR_INVALID_ARG, 'subscription profile requires a valid http(s) URL');

			let interval_hours = 24;
			if (exists(a, 'update_interval_hours') && a.update_interval_hours != null) {
				interval_hours = parse_int_range(a.update_interval_hours, 1, 720);
				if (interval_hours == null)
					return fail(common.ERR_INVALID_ARG, 'update_interval_hours must be between 1 and 720');
			}

			let req_id = (type(a.section_id) == 'string') ? trim(a.section_id) : '';
			if (length(req_id) > 0 && !is_valid_section_id(req_id))
				return fail(common.ERR_INVALID_ARG, sprintf('invalid section_id: %s', req_id));

			return with_write_lock(cfg, () => {
				let uci_cfg = read_uci(cfg);
				let target_id = req_id;
				if (length(target_id) > 0) {
					let existing = uci_cfg?.[target_id];
					if (type(existing) != 'object' || existing['.type'] != 'profile')
						return fail(common.ERR_NOT_FOUND, sprintf('profile section "%s" not found', target_id));
				} else {
					target_id = make_unique_section_id(uci_cfg, filename || name, 'profile');
				}

				let dup = find_profile_by_filename(uci_cfg, filename, target_id);
				if (dup)
					return fail(common.ERR_CONFLICT, sprintf('filename "%s" is already used by profile "%s"', filename, dup.id));

				let ua = trim('' + (a.user_agent || ''));
				if (length(ua) == 0)
					ua = 'sing-box/nimbus';

				let cur = open_uci(cfg);
				if (!cur)
					return fail(common.ERR_INTERNAL, 'failed to open UCI cursor');

				cur.set('nimbus', target_id, 'profile');
				cur.set('nimbus', target_id, 'name', name);
				cur.set('nimbus', target_id, 'type', ptype);
				cur.set('nimbus', target_id, 'filename', filename);
				cur.set('nimbus', target_id, 'url', (ptype == 'subscription') ? url : '');
				cur.set('nimbus', target_id, 'user_agent', ua);
				cur.set('nimbus', target_id, 'via_proxy', to_uci_bool(a.via_proxy, false));
				cur.set('nimbus', target_id, 'auto_update', to_uci_bool(a.auto_update, false));
				cur.set('nimbus', target_id, 'update_interval_hours', '' + interval_hours);

				let committed = cur.commit('nimbus');
				cur.unload('nimbus');
				if (!committed)
					return fail(common.ERR_INTERNAL, 'failed to commit profile metadata');

				sync_cron_nonblocking('profile', read_uci(cfg), cfg);
				return { ok: true, section_id: target_id };
			});
		}
	},

	profile_activate: {
		args: { section_id: '', reload: false },
		call: function(req) {
			let cfg = get_cfg();
			let section_id = req.args?.section_id;
			if (!is_valid_section_id(section_id))
				return fail(common.ERR_INVALID_ARG, sprintf('invalid section_id: %s', '' + section_id));

			let want_reload = (req.args?.reload === true);

			return with_write_lock(cfg, (release_once) => {
				let uci_cfg = read_uci(cfg);
				let sec = uci_cfg?.[section_id];
				if (type(sec) != 'object' || sec['.type'] != 'profile')
					return fail(common.ERR_NOT_FOUND, sprintf('profile section "%s" not found', section_id));

				let cur = open_uci(cfg);
				if (!cur)
					return fail(common.ERR_INTERNAL, 'failed to open UCI cursor');

				if (type(uci_cfg?.global) != 'object')
					cur.set('nimbus', 'global', 'main');
				cur.set('nimbus', 'global', 'active_profile', section_id);
				let committed = cur.commit('nimbus');
				cur.unload('nimbus');
				if (!committed)
					return fail(common.ERR_INTERNAL, 'failed to commit active_profile');

				let st = common.read_state(cfg.state_file) || {};
				let active_svc = (st.state == 'running' || st.state == 'lockdown');
				if (!want_reload || !active_svc) {
					return {
						ok: true,
						active_profile: section_id,
						reloaded: false
					};
				}

				in_flight_write = true;
				release_once();

				let ar = run_async(req, cfg, cfg.init_script, [ 'reload' ], (rc) => {
					in_flight_write = false;
					let st_after = common.read_state(cfg.state_file) || {};
					let next_state = normalize_state_name(st_after.state);
					if (rc != 0 || next_state == 'lockdown' || st_after.state == 'error') {
						return fail(
							common.ERR_VALIDATE_FAILED,
							st_after.last_error || sprintf('service reload failed (exit %d)', rc),
							{ active_profile: section_id, reloaded: false, state: next_state }
						);
					}
					return {
						ok: true,
						active_profile: section_id,
						reloaded: true
					};
				});
				return { __async_result: ar };
			});
		}
	},

	profile_delete: {
		args: { section_id: '' },
		call: function(req) {
			let cfg = get_cfg();
			let section_id = req.args?.section_id;
			if (!is_valid_section_id(section_id))
				return fail(common.ERR_INVALID_ARG, sprintf('invalid section_id: %s', '' + section_id));

			return with_write_lock(cfg, () => {
				let uci_cfg = read_uci(cfg);
				let sec = uci_cfg?.[section_id];
				if (type(sec) != 'object' || sec['.type'] != 'profile')
					return fail(common.ERR_NOT_FOUND, sprintf('profile section "%s" not found', section_id));

				if (uci_cfg?.global?.active_profile == section_id)
					return fail(common.ERR_CONFLICT, sprintf('cannot delete active profile "%s"', section_id));

				let cur = open_uci(cfg);
				if (!cur)
					return fail(common.ERR_INTERNAL, 'failed to open UCI cursor');

				cur.delete('nimbus', section_id);
				let committed = cur.commit('nimbus');
				cur.unload('nimbus');
				if (!committed)
					return fail(common.ERR_INTERNAL, 'failed to delete profile section');

				let fname = sec.filename;
				if (common.is_valid_profile_filename(fname) && !find_profile_by_filename(read_uci(cfg), fname, null))
					fs.unlink(cfg.profiles_dir + '/' + fname);

				sync_cron_nonblocking('profile', read_uci(cfg), cfg);
				return { ok: true, section_id: section_id };
			});
		}
	},

	profile_update: {
		args: { section_id: '' },
		call: function(req) {
			return dispatch_updater_rpc(req, get_cfg(), 'profile');
		}
	},

	list_status: {
		args: {},
		call: function(req) {
			let cfg = get_cfg();
			return lu.get_list_status(null, {
				uci_confdir: cfg.uci_confdir,
				uci_savedir: cfg.uci_savedir,
				local_dir: cfg.local_lists_dir,
				cache_dir: cfg.cache_lists_dir
			});
		}
	},

	whitelist_config_save: {
		args: { enabled: false, auto_update: false, update_cron: '' },
		call: function(req) {
			let cfg = get_cfg();
			let a = req.args || {};

			return with_write_lock(cfg, (release_once) => {
				let uci_cfg = read_uci(cfg);
				let cur_w = uci_cfg?.whitelist || {};
				let enabled_str = to_uci_bool(exists(a, 'enabled') && a.enabled != null ? a.enabled : cur_w.enabled, true);
				let auto_str = to_uci_bool(exists(a, 'auto_update') && a.auto_update != null ? a.auto_update : cur_w.auto_update, true);
				let cron_expr = trim('' + ((exists(a, 'update_cron') && a.update_cron != null && length(trim('' + a.update_cron)) > 0)
					? a.update_cron
					: (cur_w.update_cron || '30 4 * * *')));

				if (!lu.is_valid_cron_expr(cron_expr))
					return fail(common.ERR_INVALID_ARG, sprintf('invalid 5-field cron expression: %s', cron_expr));

				let cur = open_uci(cfg);
				if (!cur)
					return fail(common.ERR_INTERNAL, 'failed to open UCI cursor');

				cur.set('nimbus', 'whitelist', 'whitelist');
				cur.set('nimbus', 'whitelist', 'enabled', enabled_str);
				cur.set('nimbus', 'whitelist', 'auto_update', auto_str);
				cur.set('nimbus', 'whitelist', 'update_cron', cron_expr);
				let committed = cur.commit('nimbus');
				cur.unload('nimbus');
				if (!committed)
					return fail(common.ERR_INTERNAL, 'failed to commit whitelist config');

				sync_cron_nonblocking('whitelist', read_uci(cfg), cfg);

				return reload_whitelist_async_or_sync(req, cfg, release_once, (rl) => {
					return { ok: true, hot_reloaded: (rl?.hot_reloaded === true) };
				});
			});
		}
	},

	list_source_save: {
		args: {
			section_id: '',
			name: '',
			type: '',
			enabled: false,
			family: '',
			filename: '',
			url: '',
			via_proxy: false
		},
		call: function(req) {
			let cfg = get_cfg();
			let a = req.args || {};
			let name = trim('' + (a.name || ''));
			if (length(name) == 0)
				return fail(common.ERR_INVALID_ARG, 'list_source name is required');

			let ltype = trim('' + (a.type || 'local'));
			if (ltype != 'local' && ltype != 'url')
				return fail(common.ERR_INVALID_ARG, 'list_source type must be local or url');

			let family = trim('' + (a.family || 'auto'));
			if (family != 'auto' && family != 'ipv4' && family != 'ipv6')
				return fail(common.ERR_INVALID_ARG, 'list_source family must be auto, ipv4, or ipv6');

			let filename = a.filename || '';
			let url = trim('' + (a.url || ''));
			if (ltype == 'local') {
				if (!common.is_valid_list_filename(filename))
					return fail(common.ERR_INVALID_ARG, sprintf('invalid list filename: %s', '' + filename));
			} else {
				if (!is_http_url(url))
					return fail(common.ERR_INVALID_ARG, 'url list_source requires a valid http(s) URL');
			}

			let req_id = (type(a.section_id) == 'string') ? trim(a.section_id) : '';
			if (length(req_id) > 0 && !is_valid_section_id(req_id))
				return fail(common.ERR_INVALID_ARG, sprintf('invalid section_id: %s', req_id));

			return with_write_lock(cfg, (release_once) => {
				let uci_cfg = read_uci(cfg);
				let target_id = req_id;
				if (length(target_id) > 0) {
					let existing = uci_cfg?.[target_id];
					if (type(existing) != 'object' || existing['.type'] != 'list_source')
						return fail(common.ERR_NOT_FOUND, sprintf('list_source section "%s" not found', target_id));
				} else {
					target_id = make_unique_section_id(uci_cfg, filename || name, 'list');
				}

				if (ltype == 'local') {
					let dup = find_list_by_filename(uci_cfg, filename, target_id);
					if (dup)
						return fail(common.ERR_CONFLICT, sprintf('filename "%s" is already used by list_source "%s"', filename, dup.id));
				}

				let cur = open_uci(cfg);
				if (!cur)
					return fail(common.ERR_INTERNAL, 'failed to open UCI cursor');

				cur.set('nimbus', target_id, 'list_source');
				cur.set('nimbus', target_id, 'name', name);
				cur.set('nimbus', target_id, 'type', ltype);
				cur.set('nimbus', target_id, 'enabled', to_uci_bool(a.enabled, true));
				cur.set('nimbus', target_id, 'family', family);
				if (ltype == 'local') {
					cur.set('nimbus', target_id, 'filename', filename);
					cur.set('nimbus', target_id, 'url', '');
					cur.set('nimbus', target_id, 'via_proxy', '0');
				} else {
					cur.set('nimbus', target_id, 'filename', '');
					cur.set('nimbus', target_id, 'url', url);
					cur.set('nimbus', target_id, 'via_proxy', to_uci_bool(a.via_proxy, false));
				}

				let committed = cur.commit('nimbus');
				cur.unload('nimbus');
				if (!committed)
					return fail(common.ERR_INTERNAL, 'failed to commit list_source metadata');

				if (ltype == 'local') {
					let local_path = cfg.local_lists_dir + '/' + filename;
					if (!fs.stat(local_path))
						common.atomic_write(local_path, '', 0644);
				}

				return reload_whitelist_async_or_sync(req, cfg, release_once, (rl) => {
					return {
						ok: true,
						section_id: target_id,
						hot_reloaded: (rl?.hot_reloaded === true)
					};
				});
			});
		}
	},

	list_read: {
		args: { filename: '' },
		call: function(req) {
			let cfg = get_cfg();
			return read_validated_file(req.args?.filename, common.is_valid_list_filename, cfg.local_lists_dir, 'list');
		}
	},

	list_save: {
		args: { filename: '', content: '', from_upload: false },
		call: function(req) {
			let cfg = get_cfg();
			let filename = req.args?.filename;
			if (!common.is_valid_list_filename(filename))
				return fail(common.ERR_INVALID_ARG, sprintf('invalid list filename: %s', '' + filename));

			return with_write_lock(cfg, (release_once) => {
				let input = read_text_or_upload(req.args, cfg.upload_list_path);
				if (!input.ok)
					return input;

				let uci_cfg = read_uci(cfg);
				let match_src = find_list_by_filename(uci_cfg, filename, null);
				let family = match_src?.section?.family || 'auto';

				let parsed = lu.parse_list_content(input.content, family, {
					strict: true,
					allow_domains: false
				});
				if (!parsed.ok) {
					cleanup_upload(input.from_upload, cfg.upload_list_path);
					return fail(common.ERR_VALIDATE_FAILED, 'invalid entries found', {
						invalid_lines: parsed.invalid_lines
					});
				}

				let target_path = cfg.local_lists_dir + '/' + filename;
				if (!common.atomic_write(target_path, input.content, 0644)) {
					cleanup_upload(input.from_upload, cfg.upload_list_path);
					return fail(common.ERR_INTERNAL, sprintf('failed to write local list: %s', filename));
				}
				cleanup_upload(input.from_upload, cfg.upload_list_path);

				return reload_whitelist_async_or_sync(req, cfg, release_once, (rl) => {
					return {
						ok: true,
						filename: filename,
						v4_count: parsed.v4_count,
						v6_count: parsed.v6_count,
						hot_reloaded: (rl?.hot_reloaded === true)
					};
				});
			});
		}
	},

	list_delete: {
		args: { section_id: '' },
		call: function(req) {
			let cfg = get_cfg();
			let section_id = req.args?.section_id;
			if (!is_valid_section_id(section_id))
				return fail(common.ERR_INVALID_ARG, sprintf('invalid section_id: %s', '' + section_id));

			return with_write_lock(cfg, (release_once) => {
				let uci_cfg = read_uci(cfg);
				let sec = uci_cfg?.[section_id];
				if (type(sec) != 'object' || sec['.type'] != 'list_source')
					return fail(common.ERR_NOT_FOUND, sprintf('list_source section "%s" not found', section_id));

				let cur = open_uci(cfg);
				if (!cur)
					return fail(common.ERR_INTERNAL, 'failed to open UCI cursor');

				cur.delete('nimbus', section_id);
				let committed = cur.commit('nimbus');
				cur.unload('nimbus');
				if (!committed)
					return fail(common.ERR_INTERNAL, 'failed to delete list_source section');

				if ((sec.type || 'url') == 'local') {
					if (common.is_valid_list_filename(sec.filename) && !find_list_by_filename(read_uci(cfg), sec.filename, null))
						fs.unlink(cfg.local_lists_dir + '/' + sec.filename);
				} else {
					fs.unlink(cfg.cache_lists_dir + '/' + section_id + '.txt');
				}

				return reload_whitelist_async_or_sync(req, cfg, release_once, (rl) => {
					return {
						ok: true,
						section_id: section_id,
						hot_reloaded: (rl?.hot_reloaded === true)
					};
				});
			});
		}
	},

	list_update: {
		args: { section_id: '' },
		call: function(req) {
			return dispatch_updater_rpc(req, get_cfg(), 'list');
		}
	},

	core_info: {
		args: {},
		call: function(req) {
			let cfg = get_cfg();
			if (type(cfg.mock_core_info) == 'function')
				return cfg.mock_core_info(cfg);

			return dispatch_async_read(req, cfg, 'core_info', {
				opts: build_worker_opts(cfg)
			}, (res) => {
				return res || fail(common.ERR_INTERNAL, 'failed to collect core info');
			});
		}
	},

	core_check_update: {
		args: {},
		call: function(req) {
			let cfg = get_cfg();
			if (type(cfg.mock_core_check) == 'function')
				return cfg.mock_core_check(cfg);

			return dispatch_async_read(req, cfg, 'core_check_update', {
				opts: build_worker_opts(cfg)
			}, (res) => {
				return res || fail(common.ERR_NETWORK, 'failed to check core updates');
			});
		}
	},

	core_install: {
		args: { source: '', download_url: '', digest: '' },
		call: function(req) {
			let cfg = get_cfg();
			let a = req.args || {};
			let source = trim('' + (a.source || 'github'));
			if (source != 'github' && source != 'upload')
				return fail(common.ERR_INVALID_ARG, sprintf('unsupported core installation source "%s"', source));

			let dl_url = trim('' + (a.download_url || ''));
			if (length(dl_url) > 0 && !is_http_url(dl_url))
				return fail(common.ERR_INVALID_ARG, 'invalid download_url');

			let digest = trim('' + (a.digest || ''));
			if (length(digest) > 0 && !match(digest, /^(sha256:)?[0-9a-fA-F]{64}$/i))
				return fail(common.ERR_INVALID_ARG, 'invalid sha256 digest format');

			if (source == 'upload') {
				let candidates = [ cfg.upload_bin_path ];
				if (cfg.upload_bin_path == common.UPLOAD_BIN_PATH)
					push(candidates, cm.LEGACY_UPLOAD_PATH);
				let found_file = false;
				for (let up in candidates) {
					let lst = fs.lstat(up);
					if (!lst)
						continue;
					if (lst.type != 'file')
						return fail(common.ERR_INVALID_ARG, 'uploaded core path must be a regular file (symlinks rejected)');
					found_file = true;
					break;
				}
				if (!found_file)
					return fail(common.ERR_NOT_FOUND, 'uploaded core file not found');
			}

			if (is_core_task_active(cfg))
				return fail(common.ERR_LOCKED, 'a core installation task is already in progress');

			return with_write_lock(cfg, () => {
				let opts = {
					...build_worker_opts(cfg),
					source: source
				};
				if (length(dl_url) > 0)
					opts.download_url = dl_url;
				if (length(digest) > 0)
					opts.digest = digest;

				let args_path = create_tmp_json_path('nimbus-core-args');
				if (!common.write_json_atomic(args_path, { opts: opts }, 0600)) {
					fs.unlink(args_path);
					return fail(common.ERR_INTERNAL, 'failed to stage core install arguments');
				}

				common.write_json_atomic(cfg.core_task_file, {
					ok: true,
					state: 'checking_space',
					progress: 5,
					message: 'Starting core installation',
					installed_version: null,
					error: null,
					updated_at: time()
				}, 0600);

				core_task_running = true;
				let spawned = run_detached(
					cfg.ucode_bin,
					[ '-S', '-L', cfg.lib_dir, '-e', WORKER_DISPATCH, 'core_install', args_path, '' ],
					build_child_env(cfg),
					() => {
						core_task_running = false;
						fs.unlink(args_path);
					}
				);

				if (!spawned) {
					core_task_running = false;
					fs.unlink(args_path);
					common.write_json_atomic(cfg.core_task_file, {
						ok: false,
						state: 'failed',
						progress: 0,
						message: 'failed to spawn core installer',
						installed_version: null,
						error: 'failed to spawn core installer',
						updated_at: time()
					}, 0600);
					return fail(common.ERR_INTERNAL, 'failed to start core installation worker');
				}

				return { ok: true, started: true };
			});
		}
	},

	core_task_status: {
		args: {},
		call: function(req) {
			let cfg = get_cfg();
			return cm.get_task_status({ task_file: cfg.core_task_file });
		}
	}
};

return { 'luci.nimbus': methods };
