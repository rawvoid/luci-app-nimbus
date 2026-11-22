#!/usr/bin/ucode
'use strict';

import * as fs from 'fs';
import * as common from 'common';
import * as cm from 'core_manager';

let passed = 0;

function check(cond, msg) {
	if (!cond) {
		warn(sprintf('FAIL: %s\n', msg));
		exit(1);
	}
	passed++;
}

let repo_root = getenv('NIMBUS_REPO_ROOT') || '/work';
let rel_fixture_raw = fs.readfile(repo_root + '/tests/fixtures/github_release.json');
check(type(rel_fixture_raw) == 'string' && length(rel_fixture_raw) > 0, 'read tests/fixtures/github_release.json');

let tmp_root = getenv('TMPDIR') || '/tmp';
let work_dir = sprintf('%s/core_test_%d', tmp_root, time());
check(common.ensure_dir(work_dir, 0755), 'create work_dir');

// 1. OpenWrt architecture mapping (including ARMv7 musleabihf vs musleabi detection via /lib/ld-musl-*.so.1)
let lib_hf = work_dir + '/lib_hf';
let lib_sf = work_dir + '/lib_sf';
check(common.ensure_dir(lib_hf, 0755) && common.ensure_dir(lib_sf, 0755), 'create mock lib dirs');
check(common.atomic_write(lib_hf + '/ld-musl-armhf.so.1', '', 0755), 'create mock ld-musl-armhf.so.1');
check(common.atomic_write(lib_sf + '/ld-musl-arm.so.1', '', 0755), 'create mock ld-musl-arm.so.1');

let arch_cases = [
	{ arch: 'x86_64', target: 'amd64', suffix: 'linux-amd64-musl.tar.gz' },
	{ arch: 'i386_pentium4', target: '386', suffix: 'linux-386-musl.tar.gz' },
	{ arch: 'aarch64_cortex-a53', target: 'arm64', suffix: 'linux-arm64-musl.tar.gz' },
	{ arch: 'arm_cortex-a7_neon-vfpv4', lib_dir: lib_hf, target: 'armv7', abi: 'musleabihf', suffix: 'linux-armv7-musl.tar.gz' },
	{ arch: 'arm_cortex-a7', lib_dir: lib_sf, target: 'armv7', abi: 'musleabi', suffix: 'linux-armv7.tar.gz' },
	{ arch: 'arm_arm1176jzf-s_vfp', lib_dir: lib_hf, target: 'armv6', abi: 'musleabihf', suffix: 'linux-armv6-musl.tar.gz' },
	{ arch: 'arm_arm926ej-s', lib_dir: lib_sf, target: 'armv5', abi: 'musleabi', suffix: 'linux-armv5.tar.gz' },
	{ arch: 'mipsel_24kc', target: 'mipsle-softfloat', suffix: 'linux-mipsle-softfloat-musl.tar.gz' },
	{ arch: 'mips_24kc', target: 'mips-softfloat', suffix: 'linux-mips-softfloat-musl.tar.gz' },
	{ arch: 'mips64el_octeon', target: 'mips64le', suffix: 'linux-mips64le-musl.tar.gz' },
	{ arch: 'mips64_octeon', target: 'mips64', suffix: 'linux-mips64-musl.tar.gz' },
	{ arch: 'riscv64_riscv64', target: 'riscv64', suffix: 'linux-riscv64-musl.tar.gz' },
	{ arch: 'loongarch64_generic', target: 'loong64', suffix: 'linux-loong64-musl.tar.gz' }
];

for (let tc in arch_cases) {
	let det = cm.detect_arch({
		openwrt_arch: tc.arch,
		lib_dir: tc.lib_dir
	});
	check(det.ok === true && det.target == tc.target && det.preferred_suffix == tc.suffix,
		sprintf('detect_arch maps %s -> target=%s suffix=%s', tc.arch, tc.target, tc.suffix));
	if (tc.abi) {
		check(det.abi == tc.abi, sprintf('detect_arch detects ABI %s for %s', tc.abi, tc.arch));
	}
}

// Also test reading DISTRIB_ARCH from mock /etc/openwrt_release file
let mock_rel_file = work_dir + '/openwrt_release';
check(common.atomic_write(mock_rel_file, "DISTRIB_ID='OpenWrt'\nDISTRIB_ARCH='aarch64_generic'\n", 0644),
	'write mock openwrt_release');
let det_from_file = cm.detect_arch({ openwrt_release_path: mock_rel_file });
check(det_from_file.ok === true && det_from_file.target == 'arm64' &&
	det_from_file.preferred_suffix == 'linux-arm64-musl.tar.gz',
	'detect_arch parses DISTRIB_ARCH from openwrt_release file');

// 2. GitHub Release JSON parsing, ARMv7 hf vs softfloat asset selection, mirror_prefix, and Sha256Sums parsing
let rel_arm64 = cm.parse_release_info(rel_fixture_raw, det_from_file, {
	mirror_prefix: 'https://mirror.example.com/'
});
check(rel_arm64.ok === true &&
	rel_arm64.latest_version == '1.14.4' &&
	rel_arm64.asset.name == 'sing-box-1.14.4-linux-arm64-musl.tar.gz' &&
	rel_arm64.asset.digest == 'sha256:b95e25f921dc5e17a4cf13327243d1177642c7e35425bf5372862c477c359f56' &&
	index(rel_arm64.asset.download_url, 'https://mirror.example.com/https://github.com/') == 0 &&
	rel_arm64.checksum_asset.name == 'Sha256Sums',
	'parse_release_info selects arm64-musl asset, digest, Sha256Sums, and prepends mirror_prefix');

let rel_armv7_hf = cm.parse_release_info(rel_fixture_raw, cm.detect_arch({ openwrt_arch: 'arm_cortex-a7', lib_dir: lib_hf }));
check(rel_armv7_hf.ok === true && rel_armv7_hf.asset.name == 'sing-box-1.14.4-linux-armv7-musl.tar.gz',
	'ARMv7 hard-float (musleabihf) selects linux-armv7-musl.tar.gz');

let rel_armv7_sf = cm.parse_release_info(rel_fixture_raw, cm.detect_arch({ openwrt_arch: 'arm_cortex-a7', lib_dir: lib_sf }));
check(rel_armv7_sf.ok === true && rel_armv7_sf.asset.name == 'sing-box-1.14.4-linux-armv7.tar.gz',
	'ARMv7 soft-float (musleabi) selects pure Go static linux-armv7.tar.gz');

// 3. Two-stage disk space checks (pre-download & post-extract)
let sp_fail_tmp = cm.check_pre_download_space(12 * 1024 * 1024, '/etc/nimbus/bin/sing-box', {
	tmp_free_bytes: 20 * 1024 * 1024,
	target_free_bytes: 100 * 1024 * 1024,
	same_fs: false
});
check(sp_fail_tmp.ok === false && sp_fail_tmp.code == common.ERR_DISK_SPACE,
	'pre-download space check fails with E_DISK_SPACE when /tmp has < 55MB');

let sp_fail_target = cm.check_pre_download_space(12 * 1024 * 1024, '/etc/nimbus/bin/sing-box', {
	tmp_free_bytes: 100 * 1024 * 1024,
	target_free_bytes: 25 * 1024 * 1024,
	same_fs: false
});
check(sp_fail_target.ok === false && sp_fail_target.code == common.ERR_DISK_SPACE,
	'pre-download space check fails with E_DISK_SPACE when target dir has < 40MB');

let sp_fail_post = cm.check_post_extract_space(25 * 1024 * 1024, '/etc/nimbus/bin/sing-box', {
	target_free_bytes: 26 * 1024 * 1024
});
check(sp_fail_post.ok === false && sp_fail_post.code == common.ERR_DISK_SPACE,
	'post-extract space check fails with E_DISK_SPACE when target free < bin_size * 1.2');

// 4. Package a real .tar.gz archive with an executable sing-box binary and test github + upload installations
let pkg_build_dir = work_dir + '/pkg_build/sing-box-1.14.4-linux-arm64-musl';
check(common.ensure_dir(pkg_build_dir, 0755), 'create pkg_build_dir');
let mock_sb_script =
	'#!/bin/sh\n' +
	'if [ "$1" = "version" ]; then\n' +
	'\tprintf "sing-box version 1.14.4\\n"\n' +
	'\texit 0\n' +
	'fi\n' +
	'exit 0\n';
check(common.atomic_write(pkg_build_dir + '/sing-box', mock_sb_script, 0755), 'create executable sing-box in pkg_build_dir');

let built_tgz = work_dir + '/sing-box-1.14.4-linux-arm64-musl.tar.gz';
check(system([ '/bin/tar', '-czf', built_tgz, '-C', work_dir + '/pkg_build', 'sing-box-1.14.4-linux-arm64-musl' ]) == 0,
	'build test sing-box tar.gz archive');
let built_sha256 = common.sha256_file(built_tgz);
check(type(built_sha256) == 'string' && length(built_sha256) == 64, 'compute SHA256 of test tar.gz');

let sha256sums_content = sprintf(
	'0000000000000000000000000000000000000000000000000000000000000000  other-file.tar.gz\n' +
	'%s  sing-box-1.14.4-linux-arm64-musl.tar.gz\n',
	built_sha256
);
check(cm.parse_sha256sums(sha256sums_content, 'sing-box-1.14.4-linux-arm64-musl.tar.gz') == built_sha256,
	'parse_sha256sums extracts matching 64-char SHA256 from Sha256Sums content');

let target_bin = work_dir + '/etc_nimbus_bin/sing-box';
let task_file = work_dir + '/core_task.json';
let state_file = work_dir + '/state.json';
let dl_work_dir = work_dir + '/core_dl';
check(common.write_state({ state: 'running', warnings: [], last_error: null }, state_file), 'seed running state');

// 4a. Test SHA256 mismatch aborts installation without creating target_bin
let bad_sha_res = cm.install_core({
	source: 'github',
	core_path: target_bin,
	work_dir: dl_work_dir,
	task_file: task_file,
	state_file: state_file,
	download_url: 'https://github.com/SagerNet/sing-box/releases/download/v1.14.4/sing-box-1.14.4-linux-arm64-musl.tar.gz',
	asset_name: 'sing-box-1.14.4-linux-arm64-musl.tar.gz',
	digest: 'sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
	tmp_free_bytes: 200 * 1024 * 1024,
	target_free_bytes: 200 * 1024 * 1024,
	fetcher: (url, out_path) => {
		system([ '/bin/cp', '-f', built_tgz, out_path ]);
		return { ok: true, rc: 0 };
	}
});
check(bad_sha_res.ok === false && bad_sha_res.code == common.ERR_VALIDATE_FAILED,
	'install_core aborts on SHA256 checksum mismatch');
check(fs.stat(target_bin) == null && fs.stat(dl_work_dir) == null,
	'target_bin is not written and work_dir is cleaned up on SHA256 mismatch');
check(cm.get_task_status({ task_file: task_file }).state == 'failed',
	'core_task.json records state=failed on SHA256 mismatch');

// 4b. Test GitHub installation verified against Sha256Sums
let reloaded = false;
let gh_ok_res = cm.install_core({
	source: 'github',
	core_path: target_bin,
	work_dir: dl_work_dir,
	task_file: task_file,
	state_file: state_file,
	openwrt_arch: 'aarch64_cortex-a53',
	release_json: replace(rel_fixture_raw, 'b95e25f921dc5e17a4cf13327243d1177642c7e35425bf5372862c477c359f56', built_sha256),
	sha256sums_text: sha256sums_content,
	tmp_free_bytes: 200 * 1024 * 1024,
	target_free_bytes: 200 * 1024 * 1024,
	on_reload: () => {
		reloaded = true;
		return true;
	},
	fetcher: (url, out_path) => {
		system([ '/bin/cp', '-f', built_tgz, out_path ]);
		return { ok: true, rc: 0 };
	}
});
check(gh_ok_res.ok === true && gh_ok_res.installed_version == '1.14.4' && reloaded === true,
	'install_core (source=github) verifies SHA256, extracts binary, checks version, atomically installs, and reloads');
let st_installed = fs.stat(target_bin);
check(st_installed != null && (st_installed.mode & 0777) == 0755 && fs.stat(dl_work_dir) == null,
	'installed sing-box binary has 0755 permissions and work_dir is cleaned up');
let t_status = cm.get_task_status({ task_file: task_file });
check(t_status.state == 'done' && t_status.progress == 100 && t_status.installed_version == '1.14.4',
	'core_task.json records state=done, progress=100, installed_version=1.14.4');

// 5. Test "upload" installation from /tmp/nimbus-core-upload.tar.gz and cleanup on both failure and success
let upload_tgz = cm.LEGACY_UPLOAD_PATH;
check(system([ '/bin/cp', '-f', built_tgz, upload_tgz ]) == 0 && fs.stat(upload_tgz) != null,
	'stage /tmp/nimbus-core-upload.tar.gz');

let target_bin_upload = work_dir + '/etc_nimbus_bin/sing-box-uploaded';
let up_ok = cm.install_core({
	source: 'upload',
	core_path: target_bin_upload,
	work_dir: dl_work_dir,
	task_file: task_file,
	state_file: state_file,
	skip_reload: true,
	tmp_free_bytes: 200 * 1024 * 1024,
	target_free_bytes: 200 * 1024 * 1024
});
check(up_ok.ok === true && up_ok.installed_version == '1.14.4' && fs.stat(target_bin_upload) != null,
	'install_core (source=upload) extracts /tmp/nimbus-core-upload.tar.gz and installs binary');
check(fs.stat(upload_tgz) == null && fs.stat(dl_work_dir) == null,
	'install_core (source=upload) cleans up /tmp/nimbus-core-upload.tar.gz and temp dir');

// Test broken upload cleanup
check(common.atomic_write(upload_tgz, '#!/bin/sh\nexit 1\n', 0755), 'stage broken uploaded binary');
let up_fail = cm.install_core({
	source: 'upload',
	core_path: target_bin_upload,
	work_dir: dl_work_dir,
	task_file: task_file,
	state_file: state_file,
	skip_reload: true,
	tmp_free_bytes: 200 * 1024 * 1024,
	target_free_bytes: 200 * 1024 * 1024
});
check(up_fail.ok === false && up_fail.code == common.ERR_VALIDATE_FAILED,
	'install_core (source=upload) rejects binary that fails version verification');
check(fs.stat(upload_tgz) == null && fs.stat(dl_work_dir) == null,
	'install_core (source=upload) cleans up /tmp/nimbus-core-upload.tar.gz even when verification fails');

// 6. Verify unsupported source is rejected in v1.0
let bad_src = cm.install_core({ source: 'custom_url' });
check(bad_src.ok === false && bad_src.code == common.ERR_INVALID_ARG,
	'v1.0 install_core only accepts "github" and "upload" sources');

// 7. Verify get_core_info
let info = cm.get_core_info(null, {
	openwrt_arch: 'x86_64',
	bin_path: target_bin,
	tmp_free_kb: 120000,
	target_free_kb: 80000
});
check(info.ok === true &&
	info.arch.target == 'amd64' &&
	info.installed.exists === true &&
	info.installed.executable === true &&
	info.installed.version == '1.14.4' &&
	info.disk.tmp_free_kb == 120000,
	'get_core_info returns architecture, installed binary version, and disk free space');

printf('test_core_manager.uc: %d assertions passed\n', passed);
