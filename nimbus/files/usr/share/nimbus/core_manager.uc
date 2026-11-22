'use strict';

import * as fs from 'fs';
import * as common from 'common';
import * as cb from 'config_builder';

const DEFAULT_BIN_PATH = '/etc/nimbus/bin/sing-box';
const DEFAULT_REPO = 'SagerNet/sing-box';
const DEFAULT_WORK_DIR = '/tmp/nimbus-core-dl';
const LEGACY_UPLOAD_PATH = '/tmp/nimbus-core-upload.tar.gz';

const MIN_TMP_SPACE_BYTES = 55 * 1024 * 1024;
const MIN_TARGET_SPACE_BYTES = 40 * 1024 * 1024;

let _cm_seq = 0;

function remove_tree(path) {
	if (type(path) != 'string' || length(path) == 0 || path == '/')
		return true;

	let st = fs.lstat(path);
	if (!st)
		return true;

	if (st.type != 'directory')
		return fs.unlink(path);

	let entries = fs.lsdir(path);
	if (entries) {
		for (let entry in entries) {
			if (entry == '.' || entry == '..')
				continue;
			remove_tree(path + '/' + entry);
		}
	}

	return fs.rmdir(path);
}

function run_cmd_capture(argv, timeout_ms) {
	let tmp_dir = getenv('TMPDIR') || '/tmp';
	common.ensure_dir(tmp_dir, 0755);
	_cm_seq++;
	let pid = fs.readlink('/proc/self') || '0';
	let out_path = sprintf('%s/nimbus-core-cmd.%s.%d.tmp', tmp_dir, pid, _cm_seq);
	let fh = fs.open(out_path, 'wx', 0600);
	if (!fh)
		return { rc: -1, output: 'failed to create temporary output file' };
	fh.close();

	let sh_argv = [ '/bin/sh', '-c', 'out=$1; shift; exec "$@" >"$out" 2>&1', 'sh', out_path ];
	for (let a in argv)
		push(sh_argv, a);

	let rc = system(sh_argv, timeout_ms || 15000);
	let output = fs.readfile(out_path) || '';
	fs.unlink(out_path);

	return { rc: rc, output: trim(output) };
}

function resolve_bin_path(uci_cfg, opts) {
	let options = opts || {};
	return options.bin_path ||
		options.core_path ||
		uci_cfg?.core?.bin_path ||
		uci_cfg?.core?.core_path ||
		DEFAULT_BIN_PATH;
}

function read_openwrt_arch(opts) {
	let options = opts || {};
	if (type(options.openwrt_arch) == 'string' && length(trim(options.openwrt_arch)) > 0)
		return trim(options.openwrt_arch);
	if (type(options.arch) == 'string' && length(trim(options.arch)) > 0)
		return trim(options.arch);

	let rel_path = options.openwrt_release_path || '/etc/openwrt_release';
	let rel_raw = fs.readfile(rel_path);
	if (type(rel_raw) == 'string') {
		let m = match(rel_raw, /DISTRIB_ARCH=['"]?([^'"\r\n]+)['"]?/);
		if (m && length(trim(m[1])) > 0)
			return trim(m[1]);
	}

	if (type(options.uname_m) == 'string' && length(trim(options.uname_m)) > 0)
		return trim(options.uname_m);

	let ures = run_cmd_capture([ '/bin/uname', '-m' ], 5000);
	if (ures.rc == 0 && length(ures.output) > 0)
		return ures.output;

	return 'unknown';
}

function map_arch_to_target(openwrt_arch) {
	let a = lc(trim('' + openwrt_arch));

	if (a == 'x86_64' || a == 'amd64')
		return 'amd64';
	if (match(a, /^i[3456]86(_|$)/) || a == 'x86' || a == '386')
		return '386';
	if (match(a, /^(aarch64|arm64)(_|$)/))
		return 'arm64';
	if (match(a, /^arm_cortex-a(5|7|8|9|15)/) || match(a, /^armv7/))
		return 'armv7';
	if (match(a, /^arm_(arm1176|mpcore)/) || match(a, /^armv6/))
		return 'armv6';
	if (match(a, /^arm_(arm926|xscale|fa526)/) || match(a, /^armv5/) || match(a, /^arm_/))
		return 'armv5';
	if (match(a, /^mips64el(_|$)/) || match(a, /^mips64le(_|$)/))
		return 'mips64le';
	if (match(a, /^mips64(_|$)/))
		return 'mips64';
	if (match(a, /^mipsel(_|$)/) || match(a, /^mipsle(_|$)/))
		return 'mipsle-softfloat';
	if (match(a, /^mips(_|$)/))
		return 'mips-softfloat';
	if (match(a, /^riscv64(_|$)/))
		return 'riscv64';
	if (match(a, /^(loongarch64|loong64)(_|$)/))
		return 'loong64';

	return null;
}

function detect_arch(opts) {
	let options = opts || {};
	let openwrt_arch = read_openwrt_arch(options);
	let target = map_arch_to_target(openwrt_arch);

	if (!target) {
		return {
			ok: false,
			code: common.ERR_VALIDATE_FAILED,
			error: sprintf('unsupported OpenWrt architecture: %s', openwrt_arch),
			openwrt_arch: openwrt_arch,
			target: null
		};
	}

	let is_arm32 = (target == 'armv7' || target == 'armv6' || target == 'armv5');
	let abi = 'musl';
	let preferred_suffix = sprintf('linux-%s-musl.tar.gz', target);
	let fallback_suffix = sprintf('linux-%s.tar.gz', target);
	let candidates = [ preferred_suffix, fallback_suffix ];

	if (is_arm32) {
		let is_hf = null;
		if (options.has_armhf != null) {
			is_hf = (options.has_armhf === true);
		} else if (options.abi != null || options.float_abi != null) {
			let raw_abi = lc(trim('' + (options.abi || options.float_abi)));
			is_hf = (index(raw_abi, 'hf') >= 0 || raw_abi == 'hard');
		} else {
			let lib_dir = options.lib_dir || '/lib';
			if (fs.stat(lib_dir + '/ld-musl-armhf.so.1') != null)
				is_hf = true;
			else if (fs.stat(lib_dir + '/ld-musl-arm.so.1') != null)
				is_hf = false;
			else
				is_hf = (target == 'armv7' && index(lc(openwrt_arch), 'soft') < 0);
		}

		if (is_hf) {
			abi = 'musleabihf';
			preferred_suffix = sprintf('linux-%s-musl.tar.gz', target);
			fallback_suffix = sprintf('linux-%s.tar.gz', target);
			candidates = [
				sprintf('linux-%s-musl.tar.gz', target),
				sprintf('linux-%s-musleabihf.tar.gz', target),
				sprintf('linux-%s.tar.gz', target)
			];
		} else {
			abi = 'musleabi';
			preferred_suffix = sprintf('linux-%s.tar.gz', target);
			fallback_suffix = sprintf('linux-%s.tar.gz', target);
			candidates = [
				sprintf('linux-%s.tar.gz', target),
				sprintf('linux-%s-musleabi.tar.gz', target),
				sprintf('linux-%s-musl.tar.gz', target)
			];
		}
	}

	return {
		ok: true,
		openwrt_arch: openwrt_arch,
		target: target,
		libc: 'musl',
		abi: abi,
		preferred_suffix: preferred_suffix,
		fallback_suffix: fallback_suffix,
		candidates: candidates
	};
}

function parse_sha256sums(sums_text, asset_name) {
	if (type(sums_text) != 'string' || length(trim(sums_text)) == 0)
		return null;

	let lines = split(sums_text, '\n');
	for (let raw in lines) {
		let line = trim(replace(raw, /\r+$/, ''));
		if (length(line) == 0)
			continue;

		let m = match(line, /^([0-9a-fA-F]{64})[ \t]+\*?(.+)$/);
		if (m) {
			let fname = trim(m[2]);
			if (asset_name == null || fname == asset_name || fs.basename(fname) == asset_name)
				return lc(m[1]);
			continue;
		}

		if (asset_name == null || length(lines) <= 2) {
			let m_single = match(line, /^([0-9a-fA-F]{64})$/);
			if (m_single)
				return lc(m_single[1]);
		}
	}

	return null;
}

function apply_mirror_prefix(url, mirror_prefix) {
	if (type(url) != 'string' || length(url) == 0)
		return url;
	if (type(mirror_prefix) != 'string' || !match(trim(mirror_prefix), /^https?:\/\//))
		return url;

	let prefix = replace(trim(mirror_prefix), /\/+$/, '');
	if (substr(url, 0, length(prefix) + 1) == (prefix + '/'))
		return url;

	return prefix + '/' + url;
}

function parse_release_info(release_input, arch_info, opts) {
	let options = opts || {};
	let channel = options.channel || 'stable';
	let mirror_prefix = options.mirror_prefix || '';

	let arch = arch_info || detect_arch(options);
	if (!arch || arch.ok === false)
		return arch || { ok: false, code: common.ERR_VALIDATE_FAILED, error: 'failed to detect architecture' };

	let rel_data = release_input;
	if (type(release_input) == 'string') {
		try {
			rel_data = json(release_input);
		} catch (e) {
			return {
				ok: false,
				code: common.ERR_VALIDATE_FAILED,
				error: 'invalid GitHub Release JSON'
			};
		}
	}

	let rel = null;
	if (type(rel_data) == 'array') {
		for (let item in rel_data) {
			if (type(item) != 'object' || item.draft === true)
				continue;
			if (channel == 'stable' && item.prerelease === true)
				continue;
			rel = item;
			break;
		}
		if (!rel) {
			for (let item in rel_data) {
				if (type(item) == 'object' && item.draft !== true) {
					rel = item;
					break;
				}
			}
		}
	} else if (type(rel_data) == 'object') {
		rel = rel_data;
	}

	if (type(rel) != 'object' || type(rel.assets) != 'array') {
		return {
			ok: false,
			code: common.ERR_NOT_FOUND,
			error: 'no valid GitHub release found'
		};
	}

	let tag_name = trim('' + (rel.tag_name || rel.name || ''));
	let latest_version = replace(tag_name, /^[vV]/, '');
	if (length(latest_version) == 0) {
		return {
			ok: false,
			code: common.ERR_VALIDATE_FAILED,
			error: 'release is missing tag_name'
		};
	}

	let matched_asset = null;
	for (let cand in arch.candidates) {
		let suffix = '-' + cand;
		for (let a in rel.assets) {
			if (type(a) != 'object' || type(a.name) != 'string')
				continue;
			if (substr(a.name, -length(suffix)) == suffix || a.name == cand) {
				matched_asset = a;
				break;
			}
		}
		if (matched_asset)
			break;
	}

	if (!matched_asset) {
		return {
			ok: false,
			code: common.ERR_NOT_FOUND,
			error: sprintf('no matching sing-box asset found for architecture %s (%s)',
				arch.openwrt_arch, arch.preferred_suffix)
		};
	}

	let checksum_asset = null;
	for (let a in rel.assets) {
		if (type(a) != 'object' || type(a.name) != 'string')
			continue;
		let lname = lc(a.name);
		if (lname == 'sha256sums' || lname == 'checksums.txt' || lname == 'sha256sum.txt' ||
			a.name == (matched_asset.name + '.sha256')) {
			checksum_asset = a;
			break;
		}
	}

	let digest = null;
	if (type(matched_asset.digest) == 'string' && match(matched_asset.digest, /^sha256:[0-9a-fA-F]{64}$/i)) {
		digest = lc(matched_asset.digest);
	} else if (type(options.sha256sums_text) == 'string') {
		let h = parse_sha256sums(options.sha256sums_text, matched_asset.name);
		if (h)
			digest = 'sha256:' + h;
	} else if (type(rel.body) == 'string') {
		let h = parse_sha256sums(rel.body, matched_asset.name);
		if (h)
			digest = 'sha256:' + h;
	}

	let dl_url = apply_mirror_prefix(matched_asset.browser_download_url || '', mirror_prefix);
	let sums_url = checksum_asset
		? apply_mirror_prefix(checksum_asset.browser_download_url || '', mirror_prefix)
		: null;

	return {
		ok: true,
		tag_name: tag_name,
		latest_version: latest_version,
		prerelease: (rel.prerelease === true),
		published_at: rel.published_at || null,
		release_url: rel.html_url || null,
		asset: {
			name: matched_asset.name,
			size_bytes: (type(matched_asset.size) == 'int') ? matched_asset.size : 0,
			download_url: dl_url,
			digest: digest
		},
		checksum_asset: checksum_asset ? {
			name: checksum_asset.name,
			download_url: sums_url
		} : null
	};
}

function find_existing_dir(path) {
	let cur = path || '/tmp';
	while (type(cur) == 'string' && length(cur) > 0 && cur != '.' && cur != '/') {
		let st = fs.stat(cur);
		if (st && st.type == 'directory')
			return cur;
		let parent = fs.dirname(cur);
		if (!parent || parent == cur)
			break;
		cur = parent;
	}
	return '/';
}

function query_df_kb(dir_path) {
	let target = find_existing_dir(dir_path);
	let res = run_cmd_capture([ '/bin/df', '-Pk', target ], 5000);
	if (res.rc != 0 || length(res.output) == 0)
		return { free_kb: 0, dev: target };

	let lines = split(res.output, '\n');
	if (length(lines) < 2)
		return { free_kb: 0, dev: target };

	let last = trim(lines[length(lines) - 1]);
	let cols = split(last, /[ \t]+/);
	if (length(cols) < 4 || !match(cols[3], /^[0-9]+$/))
		return { free_kb: 0, dev: target };

	let kb = int(cols[3], 10);
	return {
		free_kb: (!common.isnan(kb) && kb >= 0) ? kb : 0,
		dev: cols[0] || target,
		mount: cols[length(cols) - 1] || target
	};
}

function get_disk_info(bin_path, opts) {
	let options = opts || {};
	let tmp_dir = options.tmp_dir || getenv('TMPDIR') || '/tmp';
	let target_dir = fs.dirname(bin_path || DEFAULT_BIN_PATH);

	let tmp_df = (options.tmp_free_kb != null)
		? { free_kb: options.tmp_free_kb, dev: 'mock_tmp' }
		: ((options.tmp_free_bytes != null)
			? { free_kb: int(options.tmp_free_bytes / 1024), dev: 'mock_tmp' }
			: query_df_kb(tmp_dir));

	let target_df = (options.target_free_kb != null)
		? { free_kb: options.target_free_kb, dev: 'mock_target' }
		: ((options.target_free_bytes != null)
			? { free_kb: int(options.target_free_bytes / 1024), dev: 'mock_target' }
			: query_df_kb(target_dir));

	let tmp_bytes = options.tmp_free_bytes ?? (tmp_df.free_kb * 1024);
	let target_bytes = options.target_free_bytes ?? (target_df.free_kb * 1024);
	let same_fs = (options.same_fs != null)
		? (options.same_fs === true)
		: (tmp_df.dev != null && tmp_df.dev == target_df.dev);

	return {
		tmp_free_kb: int(tmp_bytes / 1024),
		target_free_kb: int(target_bytes / 1024),
		tmp_free_bytes: tmp_bytes,
		target_free_bytes: target_bytes,
		same_fs: same_fs
	};
}

function check_pre_download_space(asset_size, bin_path, opts) {
	let options = opts || {};
	if (options.skip_space_check === true)
		return { ok: true };

	let disk = get_disk_info(bin_path, options);
	let size = (type(asset_size) == 'int' && asset_size > 0) ? asset_size : (12 * 1024 * 1024);
	let min_tmp = options.min_tmp_bytes ?? MIN_TMP_SPACE_BYTES;
	let min_target = options.min_target_bytes ?? MIN_TARGET_SPACE_BYTES;

	let tmp_req = max(int(size * 3.5), min_tmp);
	let target_req = max(int(size * 3.0), min_target);

	if (disk.same_fs) {
		let combined_req = tmp_req + target_req;
		if (disk.tmp_free_bytes < combined_req) {
			return {
				ok: false,
				code: common.ERR_DISK_SPACE,
				error: sprintf('insufficient shared disk space: need %d KB, available %d KB',
					int(combined_req / 1024), disk.tmp_free_kb)
			};
		}
		return { ok: true, disk: disk };
	}

	if (disk.tmp_free_bytes < tmp_req) {
		return {
			ok: false,
			code: common.ERR_DISK_SPACE,
			error: sprintf('insufficient /tmp disk space: need %d KB, available %d KB',
				int(tmp_req / 1024), disk.tmp_free_kb)
		};
	}

	if (disk.target_free_bytes < target_req) {
		return {
			ok: false,
			code: common.ERR_DISK_SPACE,
			error: sprintf('insufficient target directory disk space: need %d KB, available %d KB',
				int(target_req / 1024), disk.target_free_kb)
		};
	}

	return { ok: true, disk: disk };
}

function check_post_extract_space(bin_size, bin_path, opts) {
	let options = opts || {};
	if (options.skip_space_check === true)
		return { ok: true };

	let disk = get_disk_info(bin_path, options);
	let needed = int((bin_size > 0 ? bin_size : 1) * 1.2);
	if (disk.target_free_bytes < needed) {
		return {
			ok: false,
			code: common.ERR_DISK_SPACE,
			error: sprintf('insufficient target space after extraction: need %d KB, available %d KB',
				int(needed / 1024), disk.target_free_kb)
		};
	}

	return { ok: true, disk: disk };
}

function get_core_info(uci_cfg, opts) {
	let options = opts || {};
	if (type(uci_cfg) == 'object' && opts == null &&
		!exists(uci_cfg, 'core') && !exists(uci_cfg, 'global')) {
		options = uci_cfg;
		uci_cfg = options.uci || null;
	}

	let uci_data = uci_cfg || common.uci_get_all('nimbus', options.uci_confdir, options.uci_savedir);
	let bin_path = resolve_bin_path(uci_data, options);
	let arch = detect_arch(options);
	let disk = get_disk_info(bin_path, options);

	let st = fs.stat(bin_path);
	let exists_bin = (st != null && st.type == 'file');
	let is_exec = (exists_bin && fs.access(bin_path, 'x'));
	let ver_res = is_exec ? cb.probe_core_version(bin_path) : { ok: false };

	return {
		ok: true,
		arch: {
			openwrt_arch: arch.openwrt_arch,
			target: arch.target,
			libc: arch.libc || 'musl',
			abi: arch.abi || 'musl',
			preferred_suffix: arch.preferred_suffix
		},
		installed: {
			exists: exists_bin,
			executable: is_exec,
			bin_path: bin_path,
			version: ver_res.ok ? ver_res.version : null,
			size_bytes: exists_bin ? st.size : 0,
			mtime: exists_bin ? st.mtime : null
		},
		disk: {
			tmp_free_kb: disk.tmp_free_kb,
			target_free_kb: disk.target_free_kb
		}
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

function curl_download(url, out_path, via_proxy, opts) {
	let options = opts || {};
	if (type(options.fetcher) == 'function')
		return options.fetcher(url, out_path);

	let argv = [
		options.curl_bin || 'curl',
		'-fsSL',
		'--connect-timeout', '' + (options.connect_timeout || '15'),
		'--max-time', '' + (options.max_time || '180'),
		'-o', out_path
	];

	if (via_proxy) {
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

	let rc = system(argv, 185000);
	return { ok: (rc == 0), rc: rc, argv: argv };
}

function check_update(uci_cfg, opts) {
	let options = opts || {};
	if (type(uci_cfg) == 'object' && opts == null &&
		!exists(uci_cfg, 'core') && !exists(uci_cfg, 'global')) {
		options = uci_cfg;
		uci_cfg = options.uci || null;
	}

	let uci_data = uci_cfg || common.uci_get_all('nimbus', options.uci_confdir, options.uci_savedir);
	let c = uci_data?.core || {};
	let repo = trim('' + (options.repo ?? c.repo ?? DEFAULT_REPO));
	if (!match(repo, /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/)) {
		return {
			ok: false,
			code: common.ERR_INVALID_ARG,
			error: sprintf('invalid GitHub repository format: %s', repo)
		};
	}

	let channel = (options.channel ?? c.channel ?? 'stable') == 'prerelease' ? 'prerelease' : 'stable';
	let mirror_prefix = options.mirror_prefix ?? c.mirror_prefix ?? '';
	let via_proxy = (options.download_via_proxy ?? c.download_via_proxy) == '1' ||
		options.download_via_proxy === true;

	let arch = detect_arch(options);
	if (!arch.ok)
		return arch;

	let release_raw = options.release_json ?? null;
	if (release_raw == null) {
		let api_url = (channel == 'prerelease')
			? sprintf('https://api.github.com/repos/%s/releases?per_page=10', repo)
			: sprintf('https://api.github.com/repos/%s/releases/latest', repo);

		let tmp_dir = options.tmp_dir || getenv('TMPDIR') || '/tmp';
		common.ensure_dir(tmp_dir, 0755);
		_cm_seq++;
		let tmp_api = sprintf('%s/nimbus-gh-release.%d.json', tmp_dir, _cm_seq);
		let dl = curl_download(api_url, tmp_api, via_proxy, options);
		release_raw = fs.readfile(tmp_api);
		fs.unlink(tmp_api);

		if (!dl.ok || release_raw == null || length(trim(release_raw)) == 0) {
			return {
				ok: false,
				code: common.ERR_NETWORK,
				error: 'failed to fetch GitHub release information'
			};
		}
	}

	let parsed = parse_release_info(release_raw, arch, {
		...options,
		channel: channel,
		mirror_prefix: mirror_prefix
	});
	if (!parsed.ok)
		return parsed;

	let bin_path = resolve_bin_path(uci_data, options);
	let cur_ver = cb.probe_core_version(bin_path);
	let installed_version = cur_ver.ok ? cur_ver.version : null;

	return {
		ok: true,
		latest_version: parsed.latest_version,
		installed_version: installed_version,
		prerelease: parsed.prerelease,
		published_at: parsed.published_at,
		release_url: parsed.release_url,
		asset: parsed.asset,
		checksum_asset: parsed.checksum_asset,
		update_available: (installed_version == null || installed_version != parsed.latest_version)
	};
}

function write_task_state(state, progress, message, installed_version, error, opts) {
	let options = opts || {};
	let task_file = options.task_file || common.CORE_TASK_FILE;
	let payload = {
		ok: (state != 'failed'),
		state: state,
		progress: progress,
		message: message,
		installed_version: installed_version || null,
		error: error || null,
		updated_at: time()
	};
	common.write_json_atomic(task_file, payload, 0600);
	return payload;
}

function get_task_status(opts) {
	let options = opts || {};
	let task_file = options.task_file || common.CORE_TASK_FILE;
	let data = common.read_json(task_file);
	if (type(data) != 'object') {
		return {
			ok: true,
			state: 'idle',
			progress: 0,
			message: null,
			installed_version: null,
			error: null,
			updated_at: null
		};
	}
	return {
		ok: true,
		state: data.state || 'idle',
		progress: (type(data.progress) == 'int') ? data.progress : 0,
		message: data.message ?? null,
		installed_version: data.installed_version ?? null,
		error: data.error ?? null,
		updated_at: data.updated_at ?? null
	};
}

function find_singbox_in_dir(dir_path) {
	let entries = fs.lsdir(dir_path);
	if (!entries)
		return null;

	for (let entry in entries) {
		if (entry == '.' || entry == '..')
			continue;
		let full = dir_path + '/' + entry;
		let st = fs.lstat(full);
		if (!st)
			continue;
		if (st.type == 'file' && entry == 'sing-box')
			return full;
		if (st.type == 'directory') {
			let sub = find_singbox_in_dir(full);
			if (sub)
				return sub;
		}
	}
	return null;
}

function is_gzip_file(path) {
	let fh = fs.open(path, 'r');
	if (!fh)
		return false;
	let head = fh.read(2);
	fh.close();
	return (type(head) == 'string' && length(head) == 2 &&
		ord(head, 0) == 0x1f && ord(head, 1) == 0x8b);
}

function extract_or_stage_binary(src_path, extract_dir) {
	common.ensure_dir(extract_dir, 0700);

	if (is_gzip_file(src_path)) {
		let rc = system([ '/bin/tar', '-xzf', src_path, '-C', extract_dir ], 60000);
		if (rc != 0) {
			return {
				ok: false,
				code: common.ERR_VALIDATE_FAILED,
				error: 'failed to extract sing-box tar.gz archive'
			};
		}
		let found = find_singbox_in_dir(extract_dir);
		if (!found) {
			return {
				ok: false,
				code: common.ERR_VALIDATE_FAILED,
				error: 'sing-box binary not found inside extracted archive'
			};
		}
		return { ok: true, bin_path: found };
	}

	let staged = extract_dir + '/sing-box';
	let rc = system([ '/bin/cp', '-f', src_path, staged ], 15000);
	if (rc != 0 || !fs.stat(staged)) {
		return {
			ok: false,
			code: common.ERR_INTERNAL,
			error: 'failed to stage uploaded sing-box binary'
		};
	}
	return { ok: true, bin_path: staged };
}

function atomic_replace_binary(src_bin, target_bin) {
	let target_dir = fs.dirname(target_bin);
	if (!common.ensure_dir(target_dir, 0755)) {
		return {
			ok: false,
			code: common.ERR_INTERNAL,
			error: sprintf('failed to create target directory: %s', target_dir)
		};
	}

	_cm_seq++;
	let pid = fs.readlink('/proc/self') || '0';
	let tmp_target = sprintf('%s.new.%s.%d', target_bin, pid, _cm_seq);
	fs.unlink(tmp_target);

	let rc = system([ '/bin/cp', '-f', src_bin, tmp_target ], 30000);
	if (rc != 0 || !fs.chmod(tmp_target, 0755)) {
		fs.unlink(tmp_target);
		return {
			ok: false,
			code: common.ERR_INTERNAL,
			error: sprintf('failed to stage new binary at %s', tmp_target)
		};
	}

	if (!fs.rename(tmp_target, target_bin)) {
		fs.unlink(tmp_target);
		return {
			ok: false,
			code: common.ERR_INTERNAL,
			error: sprintf('failed to atomically replace %s', target_bin)
		};
	}

	return { ok: true };
}

function install_core(opts) {
	let options = opts || {};
	let uci_data = options.uci || common.uci_get_all('nimbus', options.uci_confdir, options.uci_savedir);
	let source = trim('' + (options.source || 'github'));
	let bin_path = resolve_bin_path(uci_data, options);
	let work_dir = options.work_dir || DEFAULT_WORK_DIR;

	if (source != 'github' && source != 'upload') {
		return {
			ok: false,
			code: common.ERR_INVALID_ARG,
			error: sprintf('unsupported core installation source "%s" in v1.0', source)
		};
	}

	remove_tree(work_dir);
	if (!common.ensure_dir(work_dir, 0700)) {
		return {
			ok: false,
			code: common.ERR_INTERNAL,
			error: sprintf('failed to create work directory: %s', work_dir)
		};
	}

	let upload_candidates = [];
	if (type(options.upload_path) == 'string' && length(options.upload_path) > 0)
		push(upload_candidates, options.upload_path);
	push(upload_candidates, common.UPLOAD_BIN_PATH);
	push(upload_candidates, LEGACY_UPLOAD_PATH);

	function cleanup_all() {
		remove_tree(work_dir);
		if (source == 'upload') {
			for (let up in upload_candidates)
				fs.unlink(up);
		}
	}

	function fail_install(code, err_msg) {
		cleanup_all();
		write_task_state('failed', 0, err_msg, null, err_msg, options);
		return {
			ok: false,
			code: code,
			error: err_msg
		};
	}

	let candidate_archive_or_bin = null;

	if (source == 'github') {
		write_task_state('checking_space', 10, 'Checking release and available disk space', null, null, options);

		let dl_url = trim('' + (options.download_url || ''));
		let asset_name = options.asset_name || 'sing-box.tar.gz';
		let asset_size = (type(options.asset_size) == 'int') ? options.asset_size : 0;
		let expected_sha256 = null;
		let sums_url = options.checksum_url || null;

		if (type(options.expected_sha256) == 'string' && match(options.expected_sha256, /^[0-9a-fA-F]{64}$/)) {
			expected_sha256 = lc(options.expected_sha256);
		} else if (type(options.digest) == 'string' && match(options.digest, /^(sha256:)?[0-9a-fA-F]{64}$/i)) {
			expected_sha256 = lc(replace(options.digest, /^sha256:/i, ''));
		}

		if (length(dl_url) == 0) {
			let upd = check_update(uci_data, options);
			if (!upd.ok)
				return fail_install(upd.code || common.ERR_NETWORK, upd.error || 'failed to query GitHub release');

			dl_url = upd.asset.download_url;
			asset_name = upd.asset.name;
			asset_size = upd.asset.size_bytes;
			if (!expected_sha256 && type(upd.asset.digest) == 'string')
				expected_sha256 = lc(replace(upd.asset.digest, /^sha256:/i, ''));
			if (!sums_url && upd.checksum_asset)
				sums_url = upd.checksum_asset.download_url;
		}

		if (!match(dl_url, /^https?:\/\/.+/))
			return fail_install(common.ERR_INVALID_ARG, 'invalid asset download_url');

		let sp1 = check_pre_download_space(asset_size, bin_path, options);
		if (!sp1.ok)
			return fail_install(sp1.code, sp1.error);

		write_task_state('downloading', 40, sprintf('Downloading %s', asset_name), null, null, options);
		let via_proxy = (options.download_via_proxy ?? uci_data?.core?.download_via_proxy) == '1' ||
			options.download_via_proxy === true;

		let archive_path = work_dir + '/' + fs.basename(asset_name);
		let dl_res = curl_download(dl_url, archive_path, via_proxy, options);
		if (!dl_res.ok || !fs.stat(archive_path))
			return fail_install(common.ERR_NETWORK, sprintf('failed to download %s', asset_name));

		write_task_state('verifying', 65, 'Verifying archive SHA256 checksum', null, null, options);

		if (!expected_sha256 && type(options.sha256sums_text) == 'string')
			expected_sha256 = parse_sha256sums(options.sha256sums_text, asset_name);

		if (!expected_sha256 && type(sums_url) == 'string' && length(sums_url) > 0) {
			let sums_path = work_dir + '/SHA256SUMS';
			let sdl = curl_download(sums_url, sums_path, via_proxy, options);
			if (sdl.ok) {
				let sums_txt = fs.readfile(sums_path);
				expected_sha256 = parse_sha256sums(sums_txt, asset_name);
			}
		}

		if (options.require_checksum === true && !expected_sha256)
			return fail_install(common.ERR_VALIDATE_FAILED, 'missing SHA256 checksum for release asset');

		if (expected_sha256) {
			let actual_sha256 = common.sha256_file(archive_path);
			if (!actual_sha256 || actual_sha256 != expected_sha256) {
				return fail_install(
					common.ERR_VALIDATE_FAILED,
					sprintf('SHA256 mismatch for %s: expected %s, got %s',
						asset_name, expected_sha256, '' + actual_sha256)
				);
			}
		}

		candidate_archive_or_bin = archive_path;
	} else {
		// source == 'upload'
		write_task_state('checking_space', 10, 'Validating uploaded core package', null, null, options);

		let found_upload = null;
		for (let up in upload_candidates) {
			let lst = fs.lstat(up);
			if (lst) {
				if (lst.type != 'file')
					return fail_install(common.ERR_INVALID_ARG, 'uploaded core path must be a regular file (symlinks rejected)');
				found_upload = up;
				break;
			}
		}

		if (!found_upload)
			return fail_install(common.ERR_NOT_FOUND, 'uploaded core file not found in /tmp');

		let up_stat = fs.stat(found_upload);
		if (!up_stat || up_stat.size <= 0)
			return fail_install(common.ERR_VALIDATE_FAILED, 'uploaded core file is empty');

		candidate_archive_or_bin = found_upload;
	}

	write_task_state('verifying', 75, 'Extracting and verifying sing-box binary', null, null, options);
	let extract_dir = work_dir + '/extract';
	let ext = extract_or_stage_binary(candidate_archive_or_bin, extract_dir);
	if (!ext.ok)
		return fail_install(ext.code, ext.error);

	let tmp_bin = ext.bin_path;
	let bin_st = fs.stat(tmp_bin);
	if (!bin_st || bin_st.size <= 0)
		return fail_install(common.ERR_VALIDATE_FAILED, 'extracted sing-box binary is empty');

	let sp2 = check_post_extract_space(bin_st.size, bin_path, options);
	if (!sp2.ok)
		return fail_install(sp2.code, sp2.error);

	if (!fs.chmod(tmp_bin, 0755))
		return fail_install(common.ERR_INTERNAL, 'failed to chmod 0755 extracted sing-box binary');

	let ver = cb.probe_core_version(tmp_bin);
	if (!ver.ok)
		return fail_install(common.ERR_VALIDATE_FAILED, ver.error || 'extracted sing-box binary failed version check');

	write_task_state('installing', 85, sprintf('Installing sing-box %s to %s', ver.version, bin_path), null, null, options);
	let rep = atomic_replace_binary(tmp_bin, bin_path);
	if (!rep.ok)
		return fail_install(rep.code, rep.error);

	cleanup_all();

	let state_path = options.state_file || common.STATE_FILE;
	let st = common.read_state(state_path) || {};
	let was_running = (options.service_running === true) || (st.state == 'running');
	let reloaded = false;

	if (was_running && options.skip_reload !== true) {
		write_task_state('reloading', 95, 'Reloading nimbus service', ver.version, null, options);
		if (type(options.on_reload) == 'function') {
			reloaded = (options.on_reload() !== false);
		} else if (fs.access('/etc/init.d/nimbus', 'x')) {
			reloaded = (system([ '/etc/init.d/nimbus', 'reload' ], 15000) == 0);
		}
	}

	if (type(st) == 'object' && (fs.stat(state_path) != null || options.state_file != null)) {
		st.core = {
			bin_path: bin_path,
			version: ver.version
		};
		common.write_state(st, state_path);
	}

	write_task_state('done', 100, sprintf('Installed sing-box %s', ver.version), ver.version, null, options);

	return {
		ok: true,
		source: source,
		bin_path: bin_path,
		installed_version: ver.version,
		reloaded: reloaded
	};
}

export {
	DEFAULT_BIN_PATH,
	DEFAULT_REPO,
	LEGACY_UPLOAD_PATH,
	detect_arch,
	map_arch_to_target,
	parse_sha256sums,
	parse_release_info,
	get_disk_info,
	check_pre_download_space,
	check_post_extract_space,
	get_core_info,
	check_update,
	get_task_status,
	install_core
};
