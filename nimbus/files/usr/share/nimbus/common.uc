'use strict';

import * as fs from 'fs';
import * as uci from 'uci';

const RUN_DIR = '/var/run/nimbus';
const STATE_FILE = '/var/run/nimbus/state.json';
const CONFIG_FILE = '/var/run/nimbus/config.json';
const CONFIG_TMP_FILE = '/var/run/nimbus/config.json.tmp';
const PID_FILE = '/var/run/nimbus/sing-box.pid';
const LOCK_FILE = '/var/run/nimbus/nimbus.lock';
const CORE_STAMP_FILE = '/var/run/nimbus/core.stamp';
const RULES_NFT_FILE = '/var/run/nimbus/rules.nft';
const BYPASS_SETS_NFT_FILE = '/var/run/nimbus/bypass_sets.nft';
const WAN_SETS_NFT_FILE = '/var/run/nimbus/wan_sets.nft';
const ROUTE_STATE_FILE = '/var/run/nimbus/route_state.json';
const CORE_TASK_FILE = '/var/run/nimbus/core_task.json';
const LOG_FILE = '/var/log/nimbus.log';

const ETC_DIR = '/etc/nimbus';
const COMPOSERS_DIR = '/etc/nimbus/composers';
const PROFILES_DIR = '/etc/nimbus/profiles';
const LISTS_DIR = '/etc/nimbus/lists';
const LOCAL_LISTS_DIR = '/etc/nimbus/lists/local';
const CACHE_LISTS_DIR = '/etc/nimbus/lists/cache';
const BIN_DIR = '/etc/nimbus/bin';
const DEFAULT_CORE_PATH = '/etc/nimbus/bin/sing-box';
const DNS_BACKUP_FILE = '/etc/nimbus/dns_backup.json';
const CRONTABS_ROOT = '/etc/crontabs/root';

const CHECK_DIR = '/tmp/nimbus-check-dir';
const UPLOAD_PROFILE_PATH = '/tmp/nimbus-upload.json';
const UPLOAD_LIST_PATH = '/tmp/nimbus-upload.txt';
const UPLOAD_BIN_PATH = '/tmp/nimbus-upload.bin';

const MAX_DIRECT_TEXT_BYTES = 262144;
const LOG_HIGH_BYTES = 524288;
const LOG_KEEP_BYTES = 262144;

const TABLE_NAME = 'inet nimbus';
const NIMBUS_GROUP = 'nimbus';
const GROUP_FILE = '/etc/group';
const WHITELIST_MIN_PREFIX_V4 = 8;
const WHITELIST_MIN_PREFIX_V6 = 16;
const CT_BYPASS_BIT = 0x10;
const CT_PROXY_BIT = 0x20;
const CT_MARK_MASK = 0x30;
const RULE_PRIO_PROXY = 1000;

const DEFAULT_REDIRECT_PORT = 7891;
const DEFAULT_TPROXY_PORT = 7892;
const DEFAULT_DNS_PORT = 5353;
const DEFAULT_OUTBOUND_MARK = 0xff;
const DEFAULT_PROXY_MARK = 0x1;
const DEFAULT_ROUTE_TABLE = 100;

const TAG_REDIRECT_IN = 'nimbus-redirect-in';
const TAG_TPROXY_IN = 'nimbus-tproxy-in';
const TAG_DNS_IN = 'nimbus-dns-in';

const ERR_INVALID_ARG = 'E_INVALID_ARG';
const ERR_NOT_FOUND = 'E_NOT_FOUND';
const ERR_CONFLICT = 'E_CONFLICT';
const ERR_VALIDATE_FAILED = 'E_VALIDATE_FAILED';
const ERR_LOCKED = 'E_LOCKED';
const ERR_NETWORK = 'E_NETWORK';
const ERR_DISK_SPACE = 'E_DISK_SPACE';
const ERR_INTERNAL = 'E_INTERNAL';

const RESERVED_V4 = [
	'0.0.0.0/8',
	'10.0.0.0/8',
	'100.64.0.0/10',
	'127.0.0.0/8',
	'169.254.0.0/16',
	'172.16.0.0/12',
	'192.0.0.0/24',
	'192.0.2.0/24',
	'192.88.99.0/24',
	'192.168.0.0/16',
	'198.51.100.0/24',
	'203.0.113.0/24',
	'224.0.0.0/4',
	'240.0.0.0/4'
];

const RESERVED_V6 = [
	'::/128',
	'::1/128',
	'::ffff:0:0/96',
	'64:ff9b::/96',
	'100::/64',
	'2001::/32',
	'2001:db8::/32',
	'fc00::/7',
	'fe80::/10',
	'ff00::/8'
];

let _tmp_seq = 0;

function isnan(v) {
	return (v != v);
}

function get_pid() {
	let p = fs.readlink('/proc/self');
	return (type(p) == 'string' && length(p) > 0) ? p : '0';
}

function next_tmp_path(prefix) {
	_tmp_seq++;
	return sprintf('%s.tmp.%s.%d', prefix, get_pid(), _tmp_seq);
}

function ensure_dir(path, mode) {
	if (type(path) != 'string' || length(path) == 0)
		return false;

	let dir_mode = (mode != null) ? mode : 0755;
	let st = fs.stat(path);
	if (st)
		return st.type == 'directory';

	let parent = fs.dirname(path);
	if (parent && parent != path && parent != '.' && parent != '/') {
		if (!ensure_dir(parent, dir_mode))
			return false;
	}

	if (fs.mkdir(path, dir_mode)) {
		fs.chmod(path, dir_mode);
		return true;
	}

	let st2 = fs.stat(path);
	return (st2 != null && st2.type == 'directory');
}

function atomic_write(path, content, mode) {
	if (type(path) != 'string' || length(path) == 0 || type(content) != 'string')
		return false;

	let file_mode = (mode != null) ? mode : 0644;
	let parent = fs.dirname(path);
	if (parent && parent != '.' && parent != '/' && !ensure_dir(parent, 0755))
		return false;

	let tmp_path = next_tmp_path(path);
	let fh = fs.open(tmp_path, 'wx', 0600);
	if (!fh)
		return false;

	let written = fh.write(content);
	if (written == null || written != length(content)) {
		fh.close();
		fs.unlink(tmp_path);
		return false;
	}

	if (fh.flush() === false) {
		fh.close();
		fs.unlink(tmp_path);
		return false;
	}

	if (!fh.close()) {
		fs.unlink(tmp_path);
		return false;
	}

	if (!fs.chmod(tmp_path, file_mode)) {
		fs.unlink(tmp_path);
		return false;
	}

	if (!fs.rename(tmp_path, path)) {
		fs.unlink(tmp_path);
		return false;
	}

	return true;
}

function read_json(path) {
	if (type(path) != 'string' || length(path) == 0)
		return null;

	let raw = fs.readfile(path);
	if (raw == null)
		return null;

	try {
		return json(raw);
	} catch (e) {
		return null;
	}
}

function write_json_atomic(path, obj, mode) {
	let text = sprintf('%.2J\n', obj);
	return atomic_write(path, text, mode);
}

function elapsed_ms(t0, t1) {
	return ((t1[0] - t0[0]) * 1000) + int((t1[1] - t0[1]) / 1000000);
}

function acquire_lock(blocking_timeout_ms, lock_path) {
	let lpath = lock_path || LOCK_FILE;
	let parent = fs.dirname(lpath);
	if (parent && parent != '.' && parent != '/' && !ensure_dir(parent, 0755))
		return null;

	let fh = fs.open(lpath, 'a+', 0600);
	if (!fh)
		return null;

	if (fh.lock('xn'))
		return fh;

	let timeout_ms = (blocking_timeout_ms != null) ? blocking_timeout_ms : 0;
	if (timeout_ms <= 0) {
		fh.close();
		return null;
	}

	let start_ts = clock(true);
	while (true) {
		let spent = elapsed_ms(start_ts, clock(true));
		let rem = timeout_ms - spent;
		if (rem <= 0)
			break;

		sleep(rem < 25 ? rem : 25);
		if (fh.lock('xn'))
			return fh;
	}

	fh.close();
	return null;
}

function release_lock(fh) {
	if (!fh)
		return;

	fh.lock('u');
	fh.close();
}

function resolve_lock_path(opts) {
	let options = opts || {};
	return options.lock_file ||
		(options.state_file ? fs.dirname(options.state_file) + '/nimbus.lock' : LOCK_FILE);
}

function merge_meta_updates(existing_meta, updates) {
	let merged = (type(existing_meta) == 'object') ? { ...existing_meta } : {};
	for (let id, upd in (updates || {})) {
		if (upd._merge) {
			let prev = (type(merged[id]) == 'object') ? merged[id] : {};
			merged[id] = {
				...prev,
				status: upd.status,
				error: upd.error,
				updated_at: upd.updated_at
			};
		} else {
			merged[id] = upd;
		}
	}
	return merged;
}

function strip_secrets_recursive(val) {
	if (type(val) == 'array') {
		let arr = [];
		for (let item in val)
			push(arr, strip_secrets_recursive(item));
		return arr;
	}

	if (type(val) == 'object') {
		let copy = {};
		for (let k, v in val) {
			if (k == 'secret' || k == 'singbox_api_secret' || k == 'clash_api_secret')
				continue;
			copy[k] = strip_secrets_recursive(v);
		}
		return copy;
	}

	return val;
}

function read_state(state_path) {
	return read_json(state_path || STATE_FILE);
}

function write_state(state_obj, state_path) {
	if (type(state_obj) != 'object')
		return false;

	return write_json_atomic(state_path || STATE_FILE, strip_secrets_recursive(state_obj), 0600);
}

function uci_get_all(package_name, confdir, savedir) {
	let pkg = package_name || 'nimbus';
	let cur = (confdir || savedir) ? uci.cursor(confdir, savedir) : uci.cursor();
	if (!cur)
		return {};

	let data = cur.get_all(pkg);
	cur.unload(pkg);
	return (type(data) == 'object') ? data : {};
}

function find_sha256_bin() {
	if (fs.access('/usr/bin/sha256sum', 'x'))
		return '/usr/bin/sha256sum';
	if (fs.access('/bin/sha256sum', 'x'))
		return '/bin/sha256sum';
	return null;
}

function create_secure_tmp_file(prefix) {
	let tmp_dir = getenv('TMPDIR') || '/tmp';
	ensure_dir(tmp_dir, 0755);
	let path = next_tmp_path(sprintf('%s/%s', tmp_dir, prefix));
	let fh = fs.open(path, 'wx', 0600);
	if (!fh)
		return null;
	return { path: path, fh: fh };
}

function sha256_file(path) {
	if (type(path) != 'string' || length(path) == 0)
		return null;

	let st = fs.stat(path);
	if (!st || st.type != 'file')
		return null;

	let sha_bin = find_sha256_bin();
	if (!sha_bin)
		return null;

	let tmp_out = create_secure_tmp_file('nimbus-sha256-out');
	if (!tmp_out)
		return null;
	tmp_out.fh.close();

	let rc = system(['/bin/sh', '-c', 'exec "$1" -- "$2" > "$3"', 'sh', sha_bin, path, tmp_out.path]);
	let out = fs.readfile(tmp_out.path);
	fs.unlink(tmp_out.path);

	if (rc != 0 || type(out) != 'string')
		return null;

	let m = match(out, /^([0-9a-fA-F]{64})\s/);
	return m ? lc(m[1]) : null;
}

function sha256_str(str) {
	if (type(str) != 'string')
		return null;

	let tmp_in = create_secure_tmp_file('nimbus-sha256-in');
	if (!tmp_in)
		return null;

	let w = tmp_in.fh.write(str);
	if (w == null || w != length(str) || tmp_in.fh.flush() === false || tmp_in.fh.close() === false) {
		tmp_in.fh.close();
		fs.unlink(tmp_in.path);
		return null;
	}

	let digest = sha256_file(tmp_in.path);
	fs.unlink(tmp_in.path);
	return digest;
}

function cron_sync_tag(tag, line_or_null, crontab_path) {
	if (type(tag) != 'string' || length(trim(tag)) == 0 || index(tag, '\n') >= 0 || index(tag, '\r') >= 0)
		return { ok: false, changed: false, error: 'invalid cron tag' };

	let clean_tag = replace(trim(tag), /^#+\s*/, '');
	if (length(clean_tag) == 0)
		return { ok: false, changed: false, error: 'empty cron tag' };

	let marker = '# ' + clean_tag;
	let escaped_marker = replace(marker, /([][().*+?^${}|\\])/g, '\\$1');
	let marker_re = regexp('(^|\\s)' + escaped_marker + '(\\s|$)');

	let cpath = crontab_path || CRONTABS_ROOT;
	let old_raw = fs.readfile(cpath);
	let want_add = (type(line_or_null) == 'string' && length(trim(line_or_null)) > 0);

	if (old_raw == null && !want_add)
		return { ok: true, changed: false };

	let kept = [];
	if (type(old_raw) == 'string' && length(old_raw) > 0) {
		let lines = split(old_raw, '\n');
		if (length(lines) > 0 && lines[length(lines) - 1] == '')
			pop(lines);

		for (let line in lines) {
			if (!match(line, marker_re))
				push(kept, line);
		}
	}

	if (want_add) {
		let newline = trim(line_or_null);
		if (index(newline, '\n') >= 0 || index(newline, '\r') >= 0)
			return { ok: false, changed: false, error: 'invalid cron line' };
		if (!match(newline, marker_re))
			newline = newline + ' ' + marker;
		push(kept, newline);
	}

	let new_raw = length(kept) ? (join('\n', kept) + '\n') : '';
	if (old_raw != null && new_raw == old_raw)
		return { ok: true, changed: false };

	if (!atomic_write(cpath, new_raw, 0600))
		return { ok: false, changed: false, error: 'failed to write crontab' };

	let changed = true;
	if (changed === true && cpath == CRONTABS_ROOT && fs.access('/etc/init.d/cron', 'x'))
		system([ '/etc/init.d/cron', 'reload' ], 5000);

	return { ok: true, changed: changed };
}

function truncate_log_hysteresis(log_path, high_bytes, keep_bytes) {
	let path = log_path || LOG_FILE;
	let high = (high_bytes != null) ? high_bytes : LOG_HIGH_BYTES;
	let keep = (keep_bytes != null) ? keep_bytes : LOG_KEEP_BYTES;

	if (keep <= 0 || high < keep)
		return { ok: false, truncated: false, error: 'invalid hysteresis thresholds' };

	let st = fs.lstat(path);
	if (!st)
		return { ok: true, truncated: false, size: 0 };

	if (st.type != 'file')
		return { ok: false, truncated: false, error: 'log path is not a regular file' };

	if (st.size <= high)
		return { ok: true, truncated: false, size: st.size };

	let fh = fs.open(path, 'r+');
	if (!fh)
		return { ok: false, truncated: false, error: fs.error() || 'failed to open log file' };

	if (!fh.seek(0, 2)) {
		let err = fs.error() || 'seek end failed';
		fh.close();
		return { ok: false, truncated: false, error: err };
	}

	let total = fh.tell();
	if (total == null || total <= high) {
		fh.close();
		return { ok: true, truncated: false, size: total || 0 };
	}

	let to_read = min(keep, total);
	if (!fh.seek(-to_read, 2)) {
		let err = fs.error() || 'seek tail failed';
		fh.close();
		return { ok: false, truncated: false, error: err };
	}

	let tail = fh.read(to_read);
	if (type(tail) != 'string') {
		let err = fs.error() || 'read tail failed';
		fh.close();
		return { ok: false, truncated: false, error: err };
	}

	let nl = index(tail, '\n');
	if (nl >= 0 && nl + 1 < length(tail))
		tail = substr(tail, nl + 1);

	if (!fh.seek(0, 0)) {
		let err = fs.error() || 'seek start failed';
		fh.close();
		return { ok: false, truncated: false, error: err };
	}

	let written = fh.write(tail);
	if (written == null || written != length(tail)) {
		let err = fs.error() || 'write tail failed';
		fh.close();
		return { ok: false, truncated: false, error: err };
	}

	fh.flush();
	if (!fh.truncate(length(tail))) {
		let err = fs.error() || 'truncate failed';
		fh.close();
		return { ok: false, truncated: false, error: err };
	}

	fh.close();
	return {
		ok: true,
		truncated: true,
		old_size: total,
		new_size: length(tail)
	};
}

function is_valid_profile_filename(name) {
	if (type(name) != 'string')
		return false;
	if (!match(name, /^[A-Za-z0-9._-]+\.json$/))
		return false;
	if (index(name, '..') >= 0 || name == '.json')
		return false;
	return true;
}

function is_valid_list_filename(name) {
	if (type(name) != 'string')
		return false;
	if (!match(name, /^[A-Za-z0-9._-]+\.txt$/))
		return false;
	if (index(name, '..') >= 0 || name == '.txt')
		return false;
	return true;
}

function resolve_active_target(uci_cfg, opts) {
	let options = opts || {};
	let active = uci_cfg?.global?.active_profile;
	if (type(active) != 'string' || length(trim(active)) == 0)
		return { ok: false, code: ERR_NOT_FOUND, error: 'global.active_profile is not configured' };

	let id = trim(active);
	let sec = uci_cfg?.[id];
	if (type(sec) != 'object')
		return { ok: false, code: ERR_NOT_FOUND, error: sprintf('active configuration "%s" not found', id) };

	let stype = sec['.type'];
	if (stype == 'composer') {
		if (!is_valid_profile_filename(sec.filename))
			return { ok: false, code: ERR_INVALID_ARG, error: sprintf('invalid composer filename: %s', '' + sec.filename) };
		return {
			ok: true,
			kind: 'composer',
			id: id,
			name: sec.name || id,
			section: sec,
			path: (options.composers_dir || COMPOSERS_DIR) + '/' + sec.filename
		};
	}

	if (stype == 'profile') {
		if (sec.as_config != '1' && sec.as_config !== true)
			return { ok: false, code: ERR_VALIDATE_FAILED, error: sprintf('profile "%s" is not enabled as a standalone configuration (as_config=0)', id) };
		if (!is_valid_profile_filename(sec.filename))
			return { ok: false, code: ERR_INVALID_ARG, error: sprintf('invalid profile filename: %s', '' + sec.filename) };
		return {
			ok: true,
			kind: 'profile',
			id: id,
			name: sec.name || id,
			section: sec,
			path: (options.profiles_dir || PROFILES_DIR) + '/' + sec.filename
		};
	}

	return { ok: false, code: ERR_NOT_FOUND, error: sprintf('active configuration "%s" has unsupported type "%s"', id, '' + stype) };
}

function hex_u32_parse(val) {
	if (type(val) == 'int')
		return (val >= 1 && val <= 0xffffffff) ? val : null;

	if (type(val) != 'string')
		return null;

	let s = trim(val);
	if (!match(s, /^(0[xX])?[0-9a-fA-F]+$/))
		return null;

	let n = int(s, 16);
	if (isnan(n) || n < 1 || n > 0xffffffff)
		return null;

	return n;
}

function format_hex_u32(n) {
	if (type(n) != 'int' || n < 0 || n > 0xffffffff)
		return null;

	return sprintf('0x%x', n);
}

function is_proxy_local(uci_cfg) {
	let g = uci_cfg?.global || {};
	let raw = g.proxy_local ?? g.router_proxy ?? '0';
	return (raw == '1' || raw === 1 || raw === true);
}

function mask_cidr_bytes(bytes, prefix) {
	let out = [ ...bytes ];
	let full_bytes = int(prefix / 8);
	let rem_bits = prefix % 8;
	if (full_bytes < length(out)) {
		if (rem_bits > 0) {
			let mask = (0xff << (8 - rem_bits)) & 0xff;
			out[full_bytes] = out[full_bytes] & mask;
			for (let i = full_bytes + 1; i < length(out); i++)
				out[i] = 0;
		} else {
			for (let i = full_bytes; i < length(out); i++)
				out[i] = 0;
		}
	}
	return out;
}

function cidr_bytes_match_prefix(ip_bytes, net_bytes, prefix_len) {
	let full_bytes = int(prefix_len / 8);
	let rem_bits = prefix_len % 8;

	for (let i = 0; i < full_bytes; i++) {
		if (ip_bytes[i] != net_bytes[i])
			return false;
	}

	if (rem_bits > 0) {
		let mask = (0xff << (8 - rem_bits)) & 0xff;
		if ((ip_bytes[full_bytes] & mask) != (net_bytes[full_bytes] & mask))
			return false;
	}

	return true;
}

function resolve_group_gid(group_name, group_file) {
	let gname = (type(group_name) == 'string' && length(trim(group_name)) > 0)
		? trim(group_name)
		: NIMBUS_GROUP;
	let gpath = group_file || getenv('NIMBUS_GROUP_FILE') || GROUP_FILE;
	let raw = fs.readfile(gpath);
	if (type(raw) != 'string' || length(raw) == 0)
		return null;

	for (let line in split(raw, '\n')) {
		let s = trim(line);
		if (length(s) == 0 || substr(s, 0, 1) == '#')
			continue;
		let parts = split(s, ':');
		if (length(parts) >= 3 && parts[0] == gname) {
			if (!match(parts[2], /^[0-9]+$/))
				return null;
			let gid = int(parts[2], 10);
			if (!isnan(gid) && gid > 0 && gid <= 4294967294)
				return gid;
			return null;
		}
	}
	return null;
}

function read_pid_gid(pid_path) {
	let raw_pid = fs.readfile(pid_path);
	if (type(raw_pid) != 'string' || !match(trim(raw_pid), /^[0-9]+$/))
		return null;

	let status = fs.readfile('/proc/' + trim(raw_pid) + '/status');
	if (type(status) != 'string')
		return null;

	for (let line in split(status, '\n')) {
		let m = match(line, /^Gid:[ \t]+([0-9]+)[ \t]+([0-9]+)/);
		if (m) {
			let egid = int(m[2], 10);
			if (!isnan(egid) && egid >= 0)
				return egid;
			return null;
		}
	}
	return null;
}

function log_msg(level, msg, log_path) {
	let path = log_path || LOG_FILE;
	let parent = fs.dirname(path);
	if (parent && parent != '.' && parent != '/' && !ensure_dir(parent, 0755))
		return false;

	let tm = localtime();
	let ts = sprintf('%04d-%02d-%02d %02d:%02d:%02d',
		tm.year, tm.mon, tm.mday, tm.hour, tm.min, tm.sec);
	let lvl = level || 'info';
	let line = sprintf('[%s] [nimbus] [%s] %s\n', ts, lvl, '' + msg);

	let fh = fs.open(path, 'a', 0644);
	if (!fh)
		return false;

	let w = fh.write(line);
	fh.flush();
	fh.close();
	return (w != null && w == length(line));
}

export {
	RUN_DIR,
	STATE_FILE,
	CONFIG_FILE,
	CONFIG_TMP_FILE,
	PID_FILE,
	LOCK_FILE,
	CORE_STAMP_FILE,
	RULES_NFT_FILE,
	BYPASS_SETS_NFT_FILE,
	WAN_SETS_NFT_FILE,
	ROUTE_STATE_FILE,
	CORE_TASK_FILE,
	LOG_FILE,
	ETC_DIR,
	COMPOSERS_DIR,
	PROFILES_DIR,
	LISTS_DIR,
	LOCAL_LISTS_DIR,
	CACHE_LISTS_DIR,
	BIN_DIR,
	DEFAULT_CORE_PATH,
	DNS_BACKUP_FILE,
	CRONTABS_ROOT,
	CHECK_DIR,
	UPLOAD_PROFILE_PATH,
	UPLOAD_LIST_PATH,
	UPLOAD_BIN_PATH,
	MAX_DIRECT_TEXT_BYTES,
	LOG_HIGH_BYTES,
	LOG_KEEP_BYTES,
	TABLE_NAME,
	NIMBUS_GROUP,
	GROUP_FILE,
	WHITELIST_MIN_PREFIX_V4,
	WHITELIST_MIN_PREFIX_V6,
	CT_BYPASS_BIT,
	CT_PROXY_BIT,
	CT_MARK_MASK,
	RULE_PRIO_PROXY,
	DEFAULT_REDIRECT_PORT,
	DEFAULT_TPROXY_PORT,
	DEFAULT_DNS_PORT,
	DEFAULT_OUTBOUND_MARK,
	DEFAULT_PROXY_MARK,
	DEFAULT_ROUTE_TABLE,
	TAG_REDIRECT_IN,
	TAG_TPROXY_IN,
	TAG_DNS_IN,
	ERR_INVALID_ARG,
	ERR_NOT_FOUND,
	ERR_CONFLICT,
	ERR_VALIDATE_FAILED,
	ERR_LOCKED,
	ERR_NETWORK,
	ERR_DISK_SPACE,
	ERR_INTERNAL,
	RESERVED_V4,
	RESERVED_V6,
	isnan,
	next_tmp_path,
	ensure_dir,
	atomic_write,
	read_json,
	write_json_atomic,
	acquire_lock,
	release_lock,
	resolve_lock_path,
	merge_meta_updates,
	read_state,
	write_state,
	uci_get_all,
	sha256_file,
	sha256_str,
	cron_sync_tag,
	truncate_log_hysteresis,
	is_valid_profile_filename,
	is_valid_list_filename,
	resolve_active_target,
	hex_u32_parse,
	format_hex_u32,
	is_proxy_local,
	mask_cidr_bytes,
	cidr_bytes_match_prefix,
	resolve_group_gid,
	read_pid_gid,
	log_msg
};
