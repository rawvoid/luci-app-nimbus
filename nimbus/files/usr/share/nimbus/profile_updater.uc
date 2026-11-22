'use strict';

import * as fs from 'fs';
import * as common from 'common';
import * as cb from 'config_builder';

const CRON_TAG = 'nimbus-profile';
const CRON_EXPR = '0 * * * *';
const CRON_CMD = '/usr/bin/ucode -S -L /usr/share/nimbus -e \'import * as p from "profile_updater"; p.run_scheduled_updates();\'';
const DEFAULT_USER_AGENT = 'sing-box/nimbus';
const DEFAULT_INTERVAL_HOURS = 24;
const CURL_CONNECT_TIMEOUT = '15';
const CURL_MAX_TIME = '60';

function parse_interval_hours(val) {
	if (type(val) == 'int')
		return (val >= 1 && val <= 720) ? val : DEFAULT_INTERVAL_HOURS;
	if (type(val) == 'string' && match(trim(val), /^[0-9]+$/)) {
		let n = int(trim(val), 10);
		if (!common.isnan(n) && n >= 1 && n <= 720)
			return n;
	}
	return DEFAULT_INTERVAL_HOURS;
}

function get_profile_sections(uci_cfg) {
	let out = [];
	if (type(uci_cfg) != 'object')
		return out;

	for (let k, sec in uci_cfg) {
		if (type(sec) != 'object' || sec['.type'] != 'profile')
			continue;
		push(out, {
			id: sec['.name'] || k,
			section: sec
		});
	}
	return out;
}

function list_profiles(uci_cfg, opts) {
	let options = opts || {};
	let uci_data = uci_cfg || common.uci_get_all('nimbus', options.uci_confdir, options.uci_savedir);
	let profiles_dir = options.profiles_dir || common.PROFILES_DIR;
	let active_id = uci_data?.global?.active_profile || '';
	let out = [];

	for (let item in get_profile_sections(uci_data)) {
		let id = item.id;
		let sec = item.section;
		let fname = sec.filename || '';
		let valid_name = common.is_valid_profile_filename(fname);
		let fpath = valid_name ? (profiles_dir + '/' + fname) : null;
		let st = fpath ? fs.stat(fpath) : null;
		let exists_file = (st != null && st.type == 'file');

		push(out, {
			id: id,
			name: sec.name || id,
			type: sec.type || 'local',
			filename: fname,
			url: sec.url || '',
			user_agent: sec.user_agent || DEFAULT_USER_AGENT,
			via_proxy: (sec.via_proxy == '1' || sec.via_proxy === true),
			auto_update: (sec.auto_update == '1' || sec.auto_update === true),
			update_interval_hours: parse_interval_hours(sec.update_interval_hours),
			exists: exists_file,
			size_bytes: exists_file ? st.size : 0,
			mtime: exists_file ? st.mtime : null,
			active: (id == active_id)
		});
	}

	return {
		ok: true,
		active_profile: active_id,
		profiles: out
	};
}

function detect_local_proxy_url(opts) {
	let options = opts || {};
	if (type(options.proxy_url) == 'string' && length(options.proxy_url) > 0)
		return options.proxy_url;

	let cfg = common.read_json(options.config_file || common.CONFIG_FILE);
	if (type(cfg?.inbounds) != 'array')
		return null;

	for (let inb in cfg.inbounds) {
		if (type(inb) != 'object')
			continue;
		let p = inb.listen_port;
		if (type(p) != 'int' || p < 1 || p > 65535)
			continue;
		if (inb.type == 'mixed' || inb.type == 'http')
			return sprintf('http://127.0.0.1:%d', p);
		if (inb.type == 'socks')
			return sprintf('socks5h://127.0.0.1:%d', p);
	}
	return null;
}

function download_subscription_to_tmp(url, tmp_path, sec, opts) {
	let options = opts || {};
	if (type(options.fetcher) == 'function')
		return options.fetcher(url, tmp_path, sec);

	let ua = trim('' + (sec?.user_agent || DEFAULT_USER_AGENT));
	if (length(ua) == 0)
		ua = DEFAULT_USER_AGENT;

	let argv = [
		options.curl_bin || 'curl',
		'-fsSL',
		'--connect-timeout', '' + (options.connect_timeout || CURL_CONNECT_TIMEOUT),
		'--max-time', '' + (options.max_time || CURL_MAX_TIME),
		'-A', ua,
		'-o', tmp_path
	];

	if (sec?.via_proxy == '1' || sec?.via_proxy === true) {
		let proxy_url = detect_local_proxy_url(options);
		if (proxy_url) {
			push(argv, '--proxy');
			push(argv, proxy_url);
		}
	}

	push(argv, url);

	if (type(options.runner) == 'function') {
		let r = options.runner(argv);
		let code = (type(r) == 'object') ? (r.rc ?? 0) : (r ?? 0);
		return { ok: (code == 0), rc: code, argv: argv };
	}

	let rc = system(argv, 65000);
	return { ok: (rc == 0), rc: rc, argv: argv };
}

function trigger_service_reload(opts) {
	let options = opts || {};
	if (options.skip_reload === true)
		return true;

	if (type(options.on_reload) == 'function') {
		let r = options.on_reload();
		return (r !== false);
	}

	let argv = [ options.init_script || '/etc/init.d/nimbus', 'reload' ];
	if (type(options.reload_runner) == 'function') {
		let rc = options.reload_runner(argv);
		let code = (type(rc) == 'object') ? (rc.rc ?? 0) : (rc ?? 0);
		return (code == 0);
	}

	if (!fs.access(argv[0], 'x'))
		return true;

	return (system(argv, 15000) == 0);
}

function update_profiles(section_id, opts) {
	let options = opts || {};
	if (type(section_id) == 'object' && opts == null) {
		options = section_id;
		section_id = options.section_id || null;
	}

	let uci_data = options.uci || common.uci_get_all('nimbus', options.uci_confdir, options.uci_savedir);
	let profiles_dir = options.profiles_dir || common.PROFILES_DIR;
	let bin_path = options.bin_path || uci_data?.core?.bin_path || '/etc/nimbus/bin/sing-box';
	let check_dir = options.check_dir || common.CHECK_DIR;
	let active_profile = uci_data?.global?.active_profile || '';
	let sections = get_profile_sections(uci_data);
	let targets = [];

	if (type(section_id) == 'string' && length(trim(section_id)) > 0) {
		let want_id = trim(section_id);
		for (let item in sections) {
			if (item.id == want_id) {
				if ((item.section.type || 'local') != 'subscription') {
					return {
						ok: false,
						code: common.ERR_INVALID_ARG,
						error: sprintf('profile "%s" is not a subscription profile', want_id)
					};
				}
				push(targets, item);
				break;
			}
		}
		if (length(targets) == 0) {
			return {
				ok: false,
				code: common.ERR_NOT_FOUND,
				error: sprintf('profile "%s" not found', want_id)
			};
		}
	} else {
		let now = options.now ?? time();
		for (let item in sections) {
			let sec = item.section;
			if ((sec.type || 'local') != 'subscription')
				continue;

			if (options.due_only === true) {
				if (sec.auto_update != '1' && sec.auto_update !== true)
					continue;
				let fname = sec.filename || '';
				let fpath = common.is_valid_profile_filename(fname) ? (profiles_dir + '/' + fname) : null;
				let st = fpath ? fs.stat(fpath) : null;
				let interval_sec = parse_interval_hours(sec.update_interval_hours) * 3600;
				if (st != null && st.type == 'file' && (now - st.mtime) < interval_sec)
					continue;
			}

			push(targets, item);
		}
	}

	let tmp_dir = options.tmp_dir || getenv('TMPDIR') || '/tmp';
	common.ensure_dir(tmp_dir, 0755);
	common.ensure_dir(profiles_dir, 0755);

	let state_path = options.state_file || common.STATE_FILE;
	let st = common.read_state(state_path) || {};
	if (type(st.sub_meta) != 'object')
		st.sub_meta = {};

	let results = [];
	let active_changed = false;
	let all_ok = true;

	for (let item in targets) {
		let id = item.id;
		let sec = item.section;
		let fname = sec.filename || '';
		let url = trim('' + (sec.url || ''));

		if (!common.is_valid_profile_filename(fname)) {
			all_ok = false;
			let err = sprintf('invalid profile filename: %s', '' + fname);
			st.sub_meta[id] = {
				...(st.sub_meta[id] || {}),
				status: 'failed',
				error: err,
				updated_at: time()
			};
			push(results, {
				id: id,
				status: 'failed',
				changed: false,
				size_bytes: 0,
				mtime: null,
				error: err
			});
			continue;
		}

		if (!match(url, /^https?:\/\/.+/)) {
			all_ok = false;
			let err = 'invalid or empty subscription URL';
			st.sub_meta[id] = {
				...(st.sub_meta[id] || {}),
				status: 'failed',
				error: err,
				updated_at: time()
			};
			push(results, {
				id: id,
				status: 'failed',
				changed: false,
				size_bytes: 0,
				mtime: null,
				error: err
			});
			continue;
		}

		let tmp_path = sprintf('%s/nimbus-sub-%s.%d.tmp', tmp_dir, id, time());
		fs.unlink(tmp_path);

		let dl = download_subscription_to_tmp(url, tmp_path, sec, options);
		let raw = fs.readfile(tmp_path);

		if (!dl.ok || type(raw) != 'string' || length(trim(raw)) == 0) {
			fs.unlink(tmp_path);
			all_ok = false;
			let err = !dl.ok ? sprintf('subscription download failed (rc=%d)', dl.rc ?? -1) : 'downloaded subscription is empty';
			st.sub_meta[id] = {
				...(st.sub_meta[id] || {}),
				status: 'failed',
				error: err,
				updated_at: time()
			};
			push(results, {
				id: id,
				status: 'failed',
				changed: false,
				size_bytes: 0,
				mtime: null,
				error: err
			});
			continue;
		}

		let parsed_json = null;
		try {
			parsed_json = json(raw);
		} catch (e) {
			parsed_json = null;
		}

		if (type(parsed_json) != 'object') {
			fs.unlink(tmp_path);
			all_ok = false;
			let err = 'downloaded subscription is not a valid JSON object';
			st.sub_meta[id] = {
				...(st.sub_meta[id] || {}),
				status: 'failed',
				error: err,
				updated_at: time()
			};
			push(results, {
				id: id,
				status: 'failed',
				changed: false,
				size_bytes: 0,
				mtime: null,
				error: err
			});
			continue;
		}

		let bres = cb.build_config({
			uci: uci_data,
			uci_confdir: options.uci_confdir,
			uci_savedir: options.uci_savedir,
			raw_config: parsed_json,
			bin_path: bin_path,
			check_dir: check_dir,
			validate_only: true,
			skip_check: (options.skip_check === true)
		});

		if (!bres.ok) {
			fs.unlink(tmp_path);
			all_ok = false;
			let err = bres.error || 'sing-box check validation failed';
			st.sub_meta[id] = {
				...(st.sub_meta[id] || {}),
				status: 'failed',
				error: err,
				updated_at: time()
			};
			push(results, {
				id: id,
				status: 'failed',
				changed: false,
				size_bytes: 0,
				mtime: null,
				error: err
			});
			continue;
		}

		let new_hash = common.sha256_file(tmp_path);
		fs.unlink(tmp_path);

		let target_path = profiles_dir + '/' + fname;
		let old_hash = common.sha256_file(target_path);
		let changed = (old_hash == null || new_hash != old_hash);

		if (changed) {
			if (!common.atomic_write(target_path, raw, 0644)) {
				all_ok = false;
				let err = sprintf('failed to write profile file: %s', target_path);
				push(results, {
					id: id,
					status: 'failed',
					changed: false,
					size_bytes: 0,
					mtime: null,
					error: err
				});
				continue;
			}
			if (id == active_profile)
				active_changed = true;
		}

		let st_file = fs.stat(target_path);
		let status_str = changed ? 'updated' : 'unchanged';
		let size_b = st_file ? st_file.size : length(raw);
		let mtime_v = st_file ? st_file.mtime : time();

		st.sub_meta[id] = {
			sha256: new_hash,
			status: status_str,
			changed: changed,
			size_bytes: size_b,
			mtime: mtime_v,
			updated_at: time(),
			error: null
		};

		push(results, {
			id: id,
			status: status_str,
			changed: changed,
			sha256: new_hash,
			size_bytes: size_b,
			mtime: mtime_v,
			error: null
		});
	}

	common.write_state(st, state_path);

	let is_running = (options.service_running === true) || (st.state == 'running');
	let reloaded = false;
	if (active_changed && is_running) {
		reloaded = trigger_service_reload(options);
	}

	return {
		ok: all_ok,
		reloaded: reloaded,
		results: results
	};
}

function run_scheduled_updates(opts) {
	return update_profiles(null, { ...(opts || {}), due_only: true });
}

function has_auto_update_subscriptions(uci_cfg) {
	for (let item in get_profile_sections(uci_cfg)) {
		let sec = item.section;
		if ((sec.type || 'local') == 'subscription' &&
			(sec.auto_update == '1' || sec.auto_update === true)) {
			return true;
		}
	}
	return false;
}

function sync_cron(uci_cfg, opts) {
	let options = opts || {};
	if (type(uci_cfg) == 'object' && opts == null &&
		!exists(uci_cfg, 'global') && !exists(uci_cfg, 'proxy')) {
		options = uci_cfg;
		uci_cfg = options.uci || null;
	}

	let uci_data = uci_cfg || common.uci_get_all('nimbus', options.uci_confdir, options.uci_savedir);
	let want_cron = (options.enabled != null)
		? (options.enabled == '1' || options.enabled === true)
		: has_auto_update_subscriptions(uci_data);

	let tag = options.cron_tag || CRON_TAG;
	let crontab_path = options.crontab_path || common.CRONTABS_ROOT;
	let expr = options.cron_expr || CRON_EXPR;
	let cmd = options.cron_cmd || CRON_CMD;
	let line = want_cron ? sprintf('%s %s', expr, cmd) : null;

	return common.cron_sync_tag(tag, line, crontab_path);
}

const update_profile = update_profiles;

export {
	CRON_TAG,
	CRON_EXPR,
	list_profiles,
	update_profiles,
	update_profile,
	run_scheduled_updates,
	has_auto_update_subscriptions,
	sync_cron
};
