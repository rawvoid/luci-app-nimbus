'use strict';
'require view';
'require form';
'require uci';
'require dom';
'require poll';
'require nimbus.api as nimbusApi';

var ACTIVE_STATES = [
	'queued',
	'checking_space',
	'downloading',
	'verifying',
	'extracting',
	'installing',
	'reloading'
];

function isTaskActive(state) {
	return ACTIVE_STATES.indexOf(state) >= 0;
}

function makeBadge(text, bg, fg) {
	return E('span', {
		'class': 'label',
		'style': 'display:inline-block;padding:2px 8px;border-radius:3px;font-size:85%;font-weight:600;background:%s;color:%s;'.format(bg, fg)
	}, text);
}

function formatTaskState(state) {
	var labels = {
		'idle': _('Idle'),
		'queued': _('Queued'),
		'checking_space': _('Checking Disk Space'),
		'downloading': _('Downloading'),
		'verifying': _('Verifying'),
		'extracting': _('Extracting'),
		'installing': _('Installing Binary'),
		'reloading': _('Reloading Service'),
		'done': _('Completed'),
		'failed': _('Failed'),
		'error': _('Failed')
	};
	return labels[state] || state || _('Unknown');
}

function renderKeyValueRows(rows) {
	return E('table', { 'class': 'table' }, rows.map(function(row) {
		return E('tr', { 'class': 'tr' }, [
			E('td', { 'class': 'td left', 'style': 'width:34%;font-weight:600;' }, row[0]),
			E('td', { 'class': 'td left' }, row[1])
		]);
	}));
}

return view.extend({
	load: function() {
		return Promise.all([
			nimbusApi.coreInfo(),
			nimbusApi.coreTaskStatus().catch(function() { return { ok: true, state: 'idle', progress: 0 }; }),
			uci.load('nimbus')
		]);
	},

	render: function(data) {
		var self = this;
		var info = data[0] || {};
		var task = data[1] || { state: 'idle', progress: 0 };
		var updateInfo = null;
		var checkingUpdate = false;
		var taskPollFn = null;
		var taskPollInFlight = false;

		var statusBox = E('div', { 'class': 'cbi-section' });
		var actionsBox = E('div', { 'class': 'cbi-section' });
		var progressBox = E('div', { 'style': 'margin-top:12px;' });
		var releaseBox = E('div', { 'style': 'margin-top:12px;' });

		function stopTaskPolling() {
			if (taskPollFn) {
				poll.remove(taskPollFn);
				taskPollFn = null;
			}
		}

		function refreshInfo() {
			return nimbusApi.coreInfo().then(function(res) {
				if (res && res.ok !== false) {
					info = res;
					renderStatus();
				}
			}).catch(function() {});
		}

		function startTaskPolling() {
			if (taskPollFn)
				return;

			taskPollFn = function() {
				if (taskPollInFlight)
					return Promise.resolve();
				taskPollInFlight = true;

				return nimbusApi.coreTaskStatus().then(function(st) {
					taskPollInFlight = false;
					if (!st || st.ok === false)
						return;
					task = st;
					renderProgress();
					if (!isTaskActive(st.state)) {
						stopTaskPolling();
						renderActions();
						refreshInfo();
						if (st.state === 'done') {
							nimbusApi.notifySuccess(_('sing-box core %s installed successfully.').format(
								st.installed_version || ''
							));
						} else if (st.state === 'failed' || st.state === 'error') {
							nimbusApi.notifyError(st.error || _('Core installation failed.'));
						}
					}
				}, function() {
					taskPollInFlight = false;
				});
			};

			poll.add(taskPollFn, 1);
		}

		function triggerInstall(source, downloadUrl, digest) {
			nimbusApi.coreInstall(source, downloadUrl, digest).then(function(res) {
				if (!res || res.ok === false) {
					nimbusApi.notifyError(res);
					return;
				}
				task = {
					ok: true,
					state: 'checking_space',
					progress: 5,
					message: _('Starting core installation...'),
					error: null
				};
				renderActions();
				renderProgress();
				startTaskPolling();
			}).catch(function(err) {
				nimbusApi.notifyError(err);
			});
		}

		function handleCheckUpdate() {
			if (checkingUpdate)
				return;
			checkingUpdate = true;
			renderActions();

			nimbusApi.coreCheckUpdate().then(function(res) {
				checkingUpdate = false;
				if (!res || res.ok === false) {
					nimbusApi.notifyError(res);
					renderActions();
					return;
				}
				updateInfo = res;
				renderActions();
				renderRelease();
			}).catch(function(err) {
				checkingUpdate = false;
				nimbusApi.notifyError(err);
				renderActions();
			});
		}

		function handleUploadCore(btn) {
			nimbusApi.uploadCoreFile(btn).then(function() {
				triggerInstall('upload', '', '');
			}).catch(function(err) {
				if (!nimbusApi.isUploadCancelled(err))
					nimbusApi.notifyError(err);
			});
		}

		function renderStatus() {
			var arch = info.arch || {};
			var inst = info.installed || {};
			var disk = info.disk || {};

			var instBadge = inst.exists
				? (inst.executable
					? makeBadge(_('Installed: v%s').format(inst.version || _('unknown')), '#e6f4ea', '#137333')
					: makeBadge(_('Not Executable'), '#fce8e6', '#c5221f'))
				: makeBadge(_('Not Installed'), '#fef7e0', '#b06000');

			dom.content(statusBox, [
				E('h3', {}, _('Core Status & Architecture')),
				renderKeyValueRows([
					[ _('Installation Status'), instBadge ],
					[ _('Binary Path'), E('code', {}, inst.bin_path || '/etc/nimbus/bin/sing-box') ],
					[ _('Binary Size'), inst.exists ? nimbusApi.formatBytes(inst.size_bytes || 0) : '-' ],
					[ _('Last Modified'), inst.exists ? nimbusApi.formatTimestamp(inst.mtime) : '-' ],
					[ _('OpenWrt Architecture'), arch.openwrt_arch || '-' ],
					[ _('sing-box Target / ABI'), '%s (%s)'.format(arch.target || '-', arch.abi || arch.libc || 'musl') ],
					[ _('Preferred Release Asset'), E('code', {}, arch.preferred_suffix || '-') ],
					[ _('Free Space (/tmp)'), nimbusApi.formatBytes((disk.tmp_free_kb || 0) * 1024) ],
					[ _('Free Space (Target Dir)'), nimbusApi.formatBytes((disk.target_free_kb || 0) * 1024) ]
				])
			]);
		}

		function renderProgress() {
			var state = task.state || 'idle';
			if (state === 'idle') {
				dom.content(progressBox, []);
				return;
			}

			var pct = Math.max(0, Math.min(100, parseInt(task.progress || 0, 10) || 0));
			var isErr = (state === 'failed' || state === 'error');
			var barColor = isErr ? '#d93025' : (state === 'done' ? '#1e8e3e' : '#1a73e8');

			var nodes = [
				E('div', { 'class': isErr ? 'alert-message error' : 'alert-message notice' }, [
					E('div', { 'style': 'display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;' }, [
						E('strong', {}, '%s (%d%%)'.format(formatTaskState(state), pct)),
						E('span', { 'style': 'font-size:90%;' }, task.message || '')
					]),
					E('div', {
						'class': 'cbi-progressbar',
						'title': '%d%%'.format(pct),
						'style': 'width:100%;height:14px;background:#e0e0e0;border-radius:3px;overflow:hidden;'
					}, [
						E('div', {
							'style': 'width:%d%%;height:100%;background:%s;transition:width 0.25s ease;'.format(pct, barColor)
						})
					]),
					isErr && task.error ? E('div', { 'style': 'margin-top:6px;' }, task.error) : ''
				])
			];
			dom.content(progressBox, nodes);
		}

		function renderRelease() {
			if (!updateInfo) {
				dom.content(releaseBox, []);
				return;
			}

			var asset = updateInfo.asset || {};
			var badge = updateInfo.update_available
				? makeBadge(_('Update Available'), '#e8f0fe', '#1967d2')
				: makeBadge(_('Up to Date'), '#e6f4ea', '#137333');

			var rows = [
				[ _('Latest Release'), E('div', { 'style': 'display:flex;align-items:center;gap:8px;flex-wrap:wrap;' }, [
					E('strong', {}, 'v' + (updateInfo.latest_version || '-')),
					updateInfo.prerelease ? makeBadge(_('Prerelease'), '#fef7e0', '#b06000') : '',
					badge
				]) ],
				[ _('Published At'), updateInfo.published_at || '-' ],
				[ _('Matched Asset'), E('code', {}, asset.name || '-') ],
				[ _('Asset Size'), asset.size_bytes ? nimbusApi.formatBytes(asset.size_bytes) : '-' ],
				[ _('SHA256 Digest'), asset.digest ? E('code', { 'style': 'word-break:break-all;' }, asset.digest) : _('Not provided in release metadata') ]
			];
			if (updateInfo.release_url) {
				rows.push([
					_('Release Notes'),
					E('a', { 'href': updateInfo.release_url, 'target': '_blank', 'rel': 'noopener noreferrer' }, updateInfo.release_url)
				]);
			}

			dom.content(releaseBox, [
				renderKeyValueRows(rows),
				E('div', { 'style': 'margin-top:8px;' }, [
					E('button', {
						'type': 'button',
						'class': 'btn cbi-button cbi-button-apply',
						'disabled': isTaskActive(task.state) ? 'disabled' : null,
						'click': function() {
							triggerInstall('github', asset.download_url || '', asset.digest || '');
						}
					}, _('Install v%s from GitHub').format(updateInfo.latest_version || ''))
				])
			]);
		}

		function renderActions() {
			var active = isTaskActive(task.state);
			dom.content(actionsBox, [
				E('h3', {}, _('Install & Upgrade sing-box Core')),
				E('p', { 'class': 'cbi-section-descr' },
					_('Download verified musl releases from GitHub or upload a local .tar.gz archive or sing-box binary.')),
				E('div', { 'style': 'display:flex;gap:8px;flex-wrap:wrap;align-items:center;' }, [
					E('button', {
						'type': 'button',
						'class': 'btn cbi-button cbi-button-action',
						'disabled': (active || checkingUpdate) ? 'disabled' : null,
						'click': handleCheckUpdate
					}, checkingUpdate ? _('Checking...') : _('Check for Updates')),
					E('button', {
						'type': 'button',
						'class': 'btn cbi-button cbi-button-apply',
						'disabled': active ? 'disabled' : null,
						'click': function() { triggerInstall('github', '', ''); }
					}, _('Install Latest from GitHub')),
					E('button', {
						'type': 'button',
						'class': 'btn cbi-button cbi-button-neutral',
						'disabled': active ? 'disabled' : null,
						'click': function(ev) { handleUploadCore(ev.currentTarget); }
					}, _('Upload Package (.tar.gz / Binary)'))
				]),
				progressBox,
				releaseBox
			]);
		}

		var m = new form.Map('nimbus');
		var sCore = m.section(form.NamedSection, 'core', 'core', _('Core Download & Path Settings'));
		sCore.anonymous = true;
		sCore.addremove = false;

		var o;
		o = sCore.option(form.Value, 'bin_path', _('Binary Path'),
			_('Absolute path where the sing-box binary is stored (may point to external storage or /tmp).'));
		o.default = '/etc/nimbus/bin/sing-box';
		o.rmempty = false;
		o.validate = function(section_id, value) {
			var v = String(value || '').trim();
			if (!v || v.charAt(0) !== '/')
				return _('Binary path must be an absolute path starting with "/".');
			return true;
		};

		o = sCore.option(form.Value, 'repo', _('GitHub Repository'));
		o.default = 'SagerNet/sing-box';
		o.rmempty = false;
		o.validate = function(section_id, value) {
			if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(String(value || '').trim()))
				return _('Repository must match owner/repo format (e.g. SagerNet/sing-box).');
			return true;
		};

		o = sCore.option(form.ListValue, 'channel', _('Release Channel'));
		o.value('stable', _('Stable'));
		o.value('prerelease', _('Prerelease'));
		o.default = 'stable';

		o = sCore.option(form.Value, 'mirror_prefix', _('GitHub Mirror Prefix'),
			_('Optional http(s):// prefix prepended to GitHub asset download URLs.'));
		o.rmempty = true;
		o.validate = function(section_id, value) {
			var v = String(value || '').trim();
			if (v && !/^https?:\/\/.+/.test(v))
				return _('Mirror prefix must be empty or start with http:// or https://.');
			return true;
		};

		o = sCore.option(form.Flag, 'download_via_proxy', _('Download via Proxy'),
			_('Route GitHub API queries and asset downloads through an active local proxy inbound when available.'));
		o.default = '0';
		o.rmempty = false;

		self._coreMap = m;
		self._refreshInfo = refreshInfo;

		renderStatus();
		renderActions();
		renderProgress();
		if (isTaskActive(task.state))
			startTaskPolling();

		return m.render().then(function(formEl) {
			return E('div', { 'class': 'cbi-map' }, [
				E('h2', {}, _('Nimbus Core')),
				statusBox,
				actionsBox,
				formEl
			]);
		});
	},

	handleSave: function() {
		return this._coreMap ? this._coreMap.save() : Promise.resolve();
	},

	handleSaveApply: function(ev, mode) {
		var self = this;
		return this.super('handleSaveApply', [ ev, mode ]).then(function() {
			if (self._refreshInfo)
				return self._refreshInfo();
		});
	},

	handleReset: function() {
		return this._coreMap ? this._coreMap.reset() : Promise.resolve();
	}
});
