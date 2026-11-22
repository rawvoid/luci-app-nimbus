'use strict';

import * as fs from 'fs';
import * as common from 'common';
import * as nft from 'nft_manager';

const CRON_TAG = 'nimbus-whitelist';
const CRON_CMD = '/usr/bin/ucode -S -L /usr/share/nimbus -e \'import * as l from "list_updater"; l.update_lists();\'';
const DEFAULT_CRON_EXPR = '30 4 * * *';
const CURL_CONNECT_TIMEOUT = '10';
const CURL_MAX_TIME = '30';

function push_unique(arr, seen, val) {
	if (!exists(seen, val)) {
		seen[val] = true;
		push(arr, val);
	}
}

function bytes_match_prefix(ip_bytes, net_bytes, prefix_len) {
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

function build_reserved_table(cidr_list) {
	let out = [];
	for (let item in cidr_list) {
		let parts = split(item, '/');
		let b = iptoarr(parts[0]);
		let p = int(parts[1], 10);
		if (b && !common.isnan(p))
			push(out, { bytes: b, prefix: p, cidr: item });
	}
	return out;
}

const RESERVED_V4_TABLE = build_reserved_table([
	...common.RESERVED_V4,
	'198.18.0.0/15'
]);

const RESERVED_V6_TABLE = build_reserved_table(common.RESERVED_V6);

function is_reserved_ip(ip_bytes, family) {
	let tbl = (family == 4) ? RESERVED_V4_TABLE : RESERVED_V6_TABLE;
	for (let entry in tbl) {
		if (bytes_match_prefix(ip_bytes, entry.bytes, entry.prefix))
			return true;
	}
	return false;
}

function is_valid_port_str(s) {
	if (type(s) != 'string' || !match(s, /^[0-9]+$/))
		return false;
	let p = int(s, 10);
	return (!common.isnan(p) && p >= 1 && p <= 65535);
}

function is_valid_domain_name(s) {
	if (type(s) != 'string' || length(s) == 0 || length(s) > 253)
		return false;

	if (index(s, '.') < 0)
		return false;

	let labels = split(s, '.');
	if (length(labels) < 2)
		return false;

	for (let lbl in labels) {
		if (length(lbl) < 1 || length(lbl) > 63)
			return false;
		if (!match(lbl, /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$/))
			return false;
	}

	let tld = labels[length(labels) - 1];
	return (match(tld, /^[a-zA-Z]{2,63}$/) != null);
}

function strip_line_comment(line) {
	let out = line;

	let hash_idx = index(out, '#');
	if (hash_idx >= 0)
		out = substr(out, 0, hash_idx);

	let semi_idx = index(out, ';');
	if (semi_idx >= 0)
		out = substr(out, 0, semi_idx);

	let m_slash = match(out, /^(.*?)([ \t]|^)\/\/.*$/);
	if (m_slash)
		out = m_slash[1];

	return trim(out);
}

function strip_endpoint_port(token) {
	if (substr(token, 0, 1) == '[') {
		let m6 = match(token, /^\[([^\]]+)\](:([0-9]+))?$/);
		if (!m6)
			return { ok: false, reason: 'invalid bracketed IPv6 endpoint' };
		if (m6[3] != null && !is_valid_port_str(m6[3]))
			return { ok: false, reason: 'invalid port number' };
		return { ok: true, value: m6[1], had_port: (m6[3] != null) };
	}

	if (index(token, '/') < 0) {
		let m4 = match(token, /^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):([0-9]+)$/);
		if (m4) {
			if (!is_valid_port_str(m4[2]))
				return { ok: false, reason: 'invalid port number' };
			return { ok: true, value: m4[1], had_port: true };
		}

		let md = match(token, /^([a-zA-Z0-9*._-]+):([0-9]+)$/);
		if (md && index(md[1], '.') >= 0) {
			if (!is_valid_port_str(md[2]))
				return { ok: false, reason: 'invalid port number' };
			return { ok: true, value: md[1], had_port: true };
		}
	}

	return { ok: true, value: token, had_port: false };
}

function parse_list_content(content, family, opts) {
	let options = opts || {};
	let fam_mode = lc(trim('' + (family || options.family || 'auto')));
	let strict = (options.strict !== false);
	let allow_reserved = (options.allow_reserved === true);
	let allow_domains = (options.allow_domains !== false);

	let v4 = [];
	let v6 = [];
	let domains = [];
	let seen_v4 = {};
	let seen_v6 = {};
	let seen_dom = {};
	let invalid_lines = [];
	let is_html = false;

	if (type(content) != 'string') {
		return {
			ok: false,
			code: common.ERR_INVALID_ARG,
			error: 'list content must be a string',
			is_html: false,
			v4: v4,
			v6: v6,
			v4_entries: v4,
			v6_entries: v6,
			domains: domains,
			v4_count: 0,
			v6_count: 0,
			domain_count: 0,
			invalid_lines: [],
			invalid_count: 0,
			cleaned_text: ''
		};
	}

	let lines = split(content, '\n');
	for (let i = 0; i < length(lines); i++) {
		let line_no = i + 1;
		let raw_line = replace(lines[i], /\r+$/, '');
		let trimmed_raw = trim(raw_line);
		if (length(trimmed_raw) == 0)
			continue;

		if (match(lc(trimmed_raw), /<\s*(!doctype|html|head|body|script)\b/)) {
			is_html = true;
			push(invalid_lines, {
				line: line_no,
				text: trimmed_raw,
				reason: 'HTML content detected'
			});
			continue;
		}

		let token = strip_line_comment(trimmed_raw);
		if (length(token) == 0)
			continue;

		if (match(token, /[ \t]/)) {
			push(invalid_lines, {
				line: line_no,
				text: token,
				reason: 'unexpected whitespace in entry'
			});
			continue;
		}

		let ep = strip_endpoint_port(token);
		if (!ep.ok) {
			push(invalid_lines, {
				line: line_no,
				text: token,
				reason: ep.reason
			});
			continue;
		}
		let clean_tok = ep.value;

		let looks_like_ip = (index(clean_tok, '/') >= 0) ||
			(index(clean_tok, ':') >= 0) ||
			(match(clean_tok, /^[0-9.]+$/) != null);

		if (looks_like_ip) {
			let parts = split(clean_tok, '/');
			if (length(parts) > 2 || length(parts[0]) == 0) {
				push(invalid_lines, {
					line: line_no,
					text: token,
					reason: 'invalid IP/CIDR syntax'
				});
				continue;
			}

			let ip_bytes = iptoarr(parts[0]);
			if (!ip_bytes) {
				push(invalid_lines, {
					line: line_no,
					text: token,
					reason: 'invalid IPv4/CIDR'
				});
				continue;
			}

			let entry_fam = (length(ip_bytes) == 4) ? 4 : ((length(ip_bytes) == 16) ? 6 : 0);
			if (entry_fam == 0) {
				push(invalid_lines, {
					line: line_no,
					text: token,
					reason: 'unsupported IP family'
				});
				continue;
			}

			let prefix = (entry_fam == 4) ? 32 : 128;
			let has_prefix = (length(parts) == 2);
			if (has_prefix) {
				if (!match(parts[1], /^[0-9]+$/)) {
					push(invalid_lines, {
						line: line_no,
						text: token,
						reason: 'invalid CIDR prefix length'
					});
					continue;
				}
				prefix = int(parts[1], 10);
				let max_p = (entry_fam == 4) ? 32 : 128;
				if (common.isnan(prefix) || prefix < 0 || prefix > max_p) {
					push(invalid_lines, {
						line: line_no,
						text: token,
						reason: 'CIDR prefix out of range'
					});
					continue;
				}
				if (prefix == 0) {
					push(invalid_lines, {
						line: line_no,
						text: token,
						reason: 'default route /0 is not allowed'
					});
					continue;
				}
			}

			if (!allow_reserved && is_reserved_ip(ip_bytes, entry_fam)) {
				push(invalid_lines, {
					line: line_no,
					text: token,
					reason: 'loopback, private, or reserved IP range is not allowed'
				});
				continue;
			}

			if (fam_mode == 'ipv4' && entry_fam != 4) {
				if (options.ignore_other_family !== true) {
					push(invalid_lines, {
						line: line_no,
						text: token,
						reason: 'IPv6 entry not allowed in ipv4 list'
					});
				}
				continue;
			}

			if (fam_mode == 'ipv6' && entry_fam != 6) {
				if (options.ignore_other_family !== true) {
					push(invalid_lines, {
						line: line_no,
						text: token,
						reason: 'IPv4 entry not allowed in ipv6 list'
					});
				}
				continue;
			}

			let norm_entry = has_prefix
				? sprintf('%s/%d', lc(parts[0]), prefix)
				: lc(parts[0]);

			if (entry_fam == 4)
				push_unique(v4, seen_v4, norm_entry);
			else
				push_unique(v6, seen_v6, norm_entry);
			continue;
		}

		// Domain candidate
		let dom_candidate = replace(clean_tok, /^(domain:|full:|\*\.|\.)/, '');
		if (allow_domains && fam_mode != 'ipv4' && fam_mode != 'ipv6' && is_valid_domain_name(dom_candidate)) {
			push_unique(domains, seen_dom, lc(dom_candidate));
			continue;
		}

		push(invalid_lines, {
			line: line_no,
			text: token,
			reason: 'invalid IPv4/IPv6/CIDR entry'
		});
	}

	let capped_invalid = [];
	for (let i = 0; i < length(invalid_lines) && i < 10; i++)
		push(capped_invalid, invalid_lines[i]);

	let cleaned_all = [ ...v4, ...v6, ...domains ];
	let cleaned_text = (length(cleaned_all) > 0) ? (join('\n', cleaned_all) + '\n') : '';

	let ok = strict
		? (!is_html && length(invalid_lines) == 0)
		: (!is_html && (length(cleaned_all) > 0 || length(invalid_lines) == 0));

	let err_msg = null;
	if (!ok) {
		if (is_html)
			err_msg = 'HTML content is not a valid whitelist';
		else if (length( capped_invalid ) > 0)
			err_msg = sprintf('line %d: %s (%s)', capped_invalid[0].line, capped_invalid[0].reason, capped_invalid[0].text);
		else
			err_msg = 'invalid entries found';
	}

	return {
		ok: ok,
		code: ok ? null : common.ERR_VALIDATE_FAILED,
		error: err_msg,
		is_html: is_html,
		v4: v4,
		v6: v6,
		v4_entries: v4,
		v6_entries: v6,
		domains: domains,
		v4_count: length(v4),
		v6_count: length(v6),
		domain_count: length(domains),
		invalid_lines: capped_invalid,
		all_invalid_lines: invalid_lines,
		invalid_count: length(invalid_lines),
		cleaned_text: cleaned_text
	};
}

function clean_list_content(content, family, opts) {
	return parse_list_content(content, family, { ...(opts || {}), strict: false });
}

function resolve_source_path(sec_id, sec, opts) {
	let options = opts || {};
	let stype = sec?.type || 'url';

	if (stype == 'local') {
		let fname = sec?.filename || '';
		if (!common.is_valid_list_filename(fname))
			return null;
		let local_dir = options.local_dir || common.LOCAL_LISTS_DIR;
		return local_dir + '/' + fname;
	}

	let cache_dir = options.cache_dir || options.lists_dir || common.CACHE_LISTS_DIR;
	let primary = sprintf('%s/%s.txt', cache_dir, sec_id);
	if (fs.stat(primary) != null || options.cache_dir != null || options.lists_dir != null)
		return primary;

	let alt = sprintf('%s/%s.txt', common.LISTS_DIR, sec_id);
	if (fs.stat(alt) != null)
		return alt;

	return primary;
}

function get_list_sections(uci_cfg) {
	let out = [];
	if (type(uci_cfg) != 'object')
		return out;

	for (let k, sec in uci_cfg) {
		if (type(sec) != 'object' || sec['.type'] != 'list_source')
			continue;
		push(out, {
			id: sec['.name'] || k,
			section: sec
		});
	}
	return out;
}

function collect_active_lists(uci_cfg, opts) {
	let options = opts || {};
	let uci_data = uci_cfg || common.uci_get_all('nimbus', options.uci_confdir, options.uci_savedir);
	let wl_enabled = (uci_data?.whitelist?.enabled != '0' && uci_data?.whitelist?.enabled !== false);

	let v4 = [];
	let v6 = [];
	let seen_v4 = {};
	let seen_v6 = {};
	let sources = [];

	for (let item in get_list_sections(uci_data)) {
		let id = item.id;
		let sec = item.section;
		let enabled = (sec.enabled != '0' && sec.enabled !== false);
		let family = sec.family || 'auto';
		let path = resolve_source_path(id, sec, options);
		let st = path ? fs.stat(path) : null;
		let exists_file = (st != null && st.type == 'file');
		let src_v4 = 0;
		let src_v6 = 0;

		if (exists_file) {
			let raw = fs.readfile(path) || '';
			let parsed = parse_list_content(raw, family, { strict: false });
			src_v4 = parsed.v4_count;
			src_v6 = parsed.v6_count;

			if (wl_enabled && enabled) {
				for (let e4 in parsed.v4)
					push_unique(v4, seen_v4, e4);
				for (let e6 in parsed.v6)
					push_unique(v6, seen_v6, e6);
			}
		}

		let src_info = {
			id: id,
			name: sec.name || id,
			type: sec.type || 'url',
			enabled: enabled,
			family: family,
			exists: exists_file,
			size_bytes: exists_file ? st.size : 0,
			mtime: exists_file ? st.mtime : null,
			v4_count: src_v4,
			v6_count: src_v6
		};
		if (src_info.type == 'local')
			src_info.filename = sec.filename || '';
		else {
			src_info.url = sec.url || '';
			src_info.via_proxy = (sec.via_proxy == '1' || sec.via_proxy === true);
		}
		push(sources, src_info);
	}

	return {
		whitelist_enabled: wl_enabled,
		v4: v4,
		v6: v6,
		v4_count: length(v4),
		v6_count: length(v6),
		sources: sources
	};
}

function get_list_status(uci_cfg, opts) {
	let options = opts || {};
	let uci_data = uci_cfg || common.uci_get_all('nimbus', options.uci_confdir, options.uci_savedir);
	let w = uci_data?.whitelist || {};
	let active = collect_active_lists(uci_data, options);

	return {
		ok: true,
		whitelist: {
			enabled: (w.enabled != '0' && w.enabled !== false),
			auto_update: (w.auto_update != '0' && w.auto_update !== false),
			update_cron: w.update_cron || DEFAULT_CRON_EXPR
		},
		nft_loaded: {
			v4_count: active.v4_count,
			v6_count: active.v6_count
		},
		sources: active.sources
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

function download_url_to_tmp(url, tmp_path, sec, opts, cache_path) {
	let options = opts || {};
	if (type(options.fetcher) == 'function')
		return options.fetcher(url, tmp_path, sec, cache_path);

	let argv = [
		options.curl_bin || 'curl',
		'-fsSL',
		'--connect-timeout', '' + (options.connect_timeout || CURL_CONNECT_TIMEOUT),
		'--max-time', '' + (options.max_time || CURL_MAX_TIME),
		'-o', tmp_path
	];

	if (cache_path && fs.stat(cache_path) != null) {
		push(argv, '-z');
		push(argv, cache_path);
	}

	if ((sec?.via_proxy == '1' || sec?.via_proxy === true)) {
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

function reload_whitelist_sets(uci_cfg, opts) {
	let options = opts || {};
	let uci_data = uci_cfg || common.uci_get_all('nimbus', options.uci_confdir, options.uci_savedir);
	let active = collect_active_lists(uci_data, options);
	let state_path = options.state_file || common.STATE_FILE;
	let st = common.read_state(state_path) || {};

	let service_active = (options.force_reload === true) ||
		(st.state == 'running' || st.state == 'lockdown');

	let hot_reloaded = false;
	if (service_active) {
		let nres = nft.reload_sets({
			bypass_v4: active.v4,
			bypass_v6: active.v6
		}, {
			output_path: options.bypass_nft_path || common.BYPASS_SETS_NFT_FILE,
			dry_run: options.nft_dry_run,
			check_only: options.nft_check_only,
			runner: options.nft_runner
		});
		hot_reloaded = (nres.ok === true);
	}

	if (type(st) == 'object' && (fs.stat(state_path) != null || options.state_file != null)) {
		st.whitelist = {
			enabled: active.whitelist_enabled,
			v4_count: active.v4_count,
			v6_count: active.v6_count
		};
		common.write_state(st, state_path);
	}

	return {
		ok: true,
		hot_reloaded: hot_reloaded,
		nft_loaded: {
			v4_count: active.v4_count,
			v6_count: active.v6_count
		}
	};
}

function save_local_list(filename, content, opts) {
	let options = opts || {};
	if (!common.is_valid_list_filename(filename)) {
		return {
			ok: false,
			code: common.ERR_INVALID_ARG,
			error: sprintf('invalid list filename: %s', '' + filename)
		};
	}

	let parsed = parse_list_content(content, options.family || 'auto', {
		strict: (options.strict !== false),
		allow_domains: (options.allow_domains === true)
	});
	if (!parsed.ok) {
		return {
			ok: false,
			code: common.ERR_VALIDATE_FAILED,
			error: 'invalid entries found',
			invalid_lines: parsed.invalid_lines
		};
	}

	let local_dir = options.local_dir || common.LOCAL_LISTS_DIR;
	let target_path = local_dir + '/' + filename;
	if (!common.atomic_write(target_path, content, 0644)) {
		return {
			ok: false,
			code: common.ERR_INTERNAL,
			error: sprintf('failed to write local list: %s', target_path)
		};
	}

	let rl = reload_whitelist_sets(options.uci, options);
	return {
		ok: true,
		filename: filename,
		v4_count: parsed.v4_count,
		v6_count: parsed.v6_count,
		hot_reloaded: rl.hot_reloaded
	};
}

function update_lists(section_id, opts) {
	let options = opts || {};
	if (type(section_id) == 'object' && opts == null) {
		options = section_id;
		section_id = options.section_id || null;
	}

	let uci_data = options.uci || common.uci_get_all('nimbus', options.uci_confdir, options.uci_savedir);
	let sections = get_list_sections(uci_data);
	let targets = [];

	if (type(section_id) == 'string' && length(trim(section_id)) > 0) {
		let want_id = trim(section_id);
		for (let item in sections) {
			if (item.id == want_id) {
				if ((item.section.type || 'url') != 'url') {
					return {
						ok: false,
						code: common.ERR_INVALID_ARG,
						error: sprintf('list_source "%s" is not a remote url source', want_id)
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
				error: sprintf('list_source "%s" not found', want_id)
			};
		}
	} else {
		for (let item in sections) {
			let sec = item.section;
			if ((sec.type || 'url') == 'url' && sec.enabled != '0' && sec.enabled !== false)
				push(targets, item);
		}
	}

	let tmp_dir = options.tmp_dir || getenv('TMPDIR') || '/tmp';
	common.ensure_dir(tmp_dir, 0755);

	let state_path = options.state_file || common.STATE_FILE;
	let st = common.read_state(state_path) || {};
	if (type(st.list_meta) != 'object')
		st.list_meta = {};

	let results = [];
	let any_changed = false;
	let all_ok = true;

	for (let item in targets) {
		let id = item.id;
		let sec = item.section;
		let url = trim('' + (sec.url || ''));

		if (!match(url, /^https?:\/\/.+/)) {
			all_ok = false;
			let err = 'invalid or empty URL';
			st.list_meta[id] = {
				...(st.list_meta[id] || {}),
				status: 'failed',
				error: err,
				updated_at: time()
			};
			push(results, {
				id: id,
				status: 'failed',
				changed: false,
				v4_count: 0,
				v6_count: 0,
				error: err
			});
			continue;
		}

		let target_path = resolve_source_path(id, sec, options);
		let tmp_path = sprintf('%s/nimbus-list-%s.%d.tmp', tmp_dir, id, time());
		fs.unlink(tmp_path);

		let dl = download_url_to_tmp(url, tmp_path, sec, options, target_path);
		if (dl.ok && fs.stat(tmp_path) == null && target_path && fs.stat(target_path) != null) {
			let cached_raw = fs.readfile(target_path) || '';
			let cached_parsed = parse_list_content(cached_raw, sec.family || 'auto', {
				strict: false,
				ignore_other_family: (options.ignore_other_family === true)
			});
			let cached_hash = common.sha256_file(target_path);
			let st_cached = fs.stat(target_path);
			st.list_meta[id] = {
				sha256: cached_hash,
				status: 'unchanged',
				changed: false,
				v4_count: cached_parsed.v4_count,
				v6_count: cached_parsed.v6_count,
				size_bytes: st_cached ? st_cached.size : length(cached_raw),
				mtime: st_cached ? st_cached.mtime : time(),
				updated_at: time(),
				error: null
			};
			push(results, {
				id: id,
				status: 'unchanged',
				changed: false,
				sha256: cached_hash,
				v4_count: cached_parsed.v4_count,
				v6_count: cached_parsed.v6_count,
				error: null
			});
			continue;
		}

		let raw = fs.readfile(tmp_path);

		if (!dl.ok || type(raw) != 'string' || length(trim(raw)) == 0) {
			fs.unlink(tmp_path);
			all_ok = false;
			let err = !dl.ok ? sprintf('download failed (rc=%d)', dl.rc ?? -1) : 'downloaded file is empty';
			st.list_meta[id] = {
				...(st.list_meta[id] || {}),
				status: 'failed',
				error: err,
				updated_at: time()
			};
			push(results, {
				id: id,
				status: 'failed',
				changed: false,
				v4_count: 0,
				v6_count: 0,
				error: err
			});
			continue;
		}

		let parsed = parse_list_content(raw, sec.family || 'auto', {
			strict: (options.strict !== false),
			ignore_other_family: (options.ignore_other_family === true)
		});

		let total_valid = parsed.v4_count + parsed.v6_count + parsed.domain_count;
		if (!parsed.ok || total_valid == 0) {
			fs.unlink(tmp_path);
			all_ok = false;
			let err = parsed.error || 'downloaded list contains no valid entries';
			st.list_meta[id] = {
				...(st.list_meta[id] || {}),
				status: 'failed',
				error: err,
				updated_at: time()
			};
			push(results, {
				id: id,
				status: 'failed',
				changed: false,
				v4_count: 0,
				v6_count: 0,
				error: err
			});
			continue;
		}

		let payload = (options.write_cleaned === true) ? parsed.cleaned_text : raw;
		let new_hash = (options.write_cleaned === true)
			? common.sha256_str(payload)
			: common.sha256_file(tmp_path);
		fs.unlink(tmp_path);

		let old_hash = common.sha256_file(target_path);
		let changed = (old_hash == null || new_hash != old_hash);

		if (changed) {
			if (!common.atomic_write(target_path, payload, 0644)) {
				all_ok = false;
				let err = sprintf('failed to write cache file: %s', target_path);
				push(results, {
					id: id,
					status: 'failed',
					changed: false,
					v4_count: 0,
					v6_count: 0,
					error: err
				});
				continue;
			}
			any_changed = true;
		}

		let st_file = fs.stat(target_path);
		let status_str = changed ? 'updated' : 'unchanged';
		st.list_meta[id] = {
			sha256: new_hash,
			status: status_str,
			changed: changed,
			v4_count: parsed.v4_count,
			v6_count: parsed.v6_count,
			size_bytes: st_file ? st_file.size : length(payload),
			mtime: st_file ? st_file.mtime : time(),
			updated_at: time(),
			error: null
		};

		push(results, {
			id: id,
			status: status_str,
			changed: changed,
			sha256: new_hash,
			v4_count: parsed.v4_count,
			v6_count: parsed.v6_count,
			error: null
		});
	}

	let active = collect_active_lists(uci_data, options);
	st.whitelist = {
		enabled: active.whitelist_enabled,
		v4_count: active.v4_count,
		v6_count: active.v6_count
	};
	common.write_state(st, state_path);

	let service_active = (options.force_reload === true) ||
		(st.state == 'running' || st.state == 'lockdown');
	let hot_reloaded = false;

	if (service_active && (any_changed || options.force_reload === true)) {
		let nres = nft.reload_sets({
			bypass_v4: active.v4,
			bypass_v6: active.v6
		}, {
			output_path: options.bypass_nft_path || common.BYPASS_SETS_NFT_FILE,
			dry_run: options.nft_dry_run,
			check_only: options.nft_check_only,
			runner: options.nft_runner
		});
		hot_reloaded = (nres.ok === true);
	}

	return {
		ok: all_ok || (length(results) > 0 && type(section_id) != 'string'),
		all_succeeded: all_ok,
		hot_reloaded: hot_reloaded,
		nft_loaded: {
			v4_count: active.v4_count,
			v6_count: active.v6_count
		},
		results: results
	};
}

function is_valid_cron_expr(expr) {
	if (type(expr) != 'string')
		return false;
	let s = trim(expr);
	if (index(s, '\n') >= 0 || index(s, '\r') >= 0)
		return false;
	let fields = split(s, /[ \t]+/);
	if (length(fields) != 5)
		return false;
	for (let f in fields) {
		if (!match(f, /^[0-9*,\/-]+$/))
			return false;
	}
	return true;
}

function sync_cron(uci_cfg, opts) {
	let options = opts || {};
	if (type(uci_cfg) == 'object' && opts == null &&
		!exists(uci_cfg, 'whitelist') && !exists(uci_cfg, 'global')) {
		options = uci_cfg;
		uci_cfg = options.uci || null;
	}

	let uci_data = uci_cfg || common.uci_get_all('nimbus', options.uci_confdir, options.uci_savedir);
	let w = uci_data?.whitelist || {};

	let enabled = (options.enabled ?? w.enabled ?? '1');
	let auto_update = (options.auto_update ?? w.auto_update ?? '1');
	let cron_expr = trim('' + (options.update_cron ?? w.update_cron ?? DEFAULT_CRON_EXPR));

	let is_on = (enabled != '0' && enabled !== false) &&
		(auto_update == '1' || auto_update === true);

	if (is_on && !is_valid_cron_expr(cron_expr)) {
		return {
			ok: false,
			code: common.ERR_INVALID_ARG,
			error: sprintf('invalid 5-field cron expression: %s', cron_expr)
		};
	}

	let tag = options.cron_tag || CRON_TAG;
	let alt_tag = (tag == 'nimbus-list-sync') ? 'nimbus-whitelist' : 'nimbus-list-sync';
	let crontab_path = options.crontab_path || options.crontab_file || common.CRONTABS_ROOT;
	let cmd = options.cron_cmd || CRON_CMD;
	let line = is_on ? sprintf('%s %s', cron_expr, cmd) : null;

	let alt_res = (alt_tag != tag)
		? common.cron_sync_tag(alt_tag, null, crontab_path)
		: { ok: true, changed: false };
	let main_res = common.cron_sync_tag(tag, line, crontab_path);
	return {
		ok: (alt_res.ok !== false && main_res.ok === true),
		changed: (alt_res.changed === true || main_res.changed === true),
		...(main_res.error ? { error: main_res.error } : {})
	};
}

const update_list = update_lists;

export {
	CRON_TAG,
	parse_list_content,
	clean_list_content,
	collect_active_lists,
	get_list_status,
	save_local_list,
	reload_whitelist_sets,
	update_lists,
	update_list,
	is_valid_cron_expr,
	sync_cron
};
