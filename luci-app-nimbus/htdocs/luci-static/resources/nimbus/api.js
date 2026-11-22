'use strict';
'require baseclass';
'require rpc';
'require ui';

var MAX_DIRECT_TEXT_BYTES = 262144;
var UPLOAD_PROFILE_PATH = '/tmp/nimbus-upload.json';
var UPLOAD_LIST_PATH = '/tmp/nimbus-upload.txt';
var UPLOAD_BIN_PATH = '/tmp/nimbus-upload.bin';

var callStatus = rpc.declare({
	object: 'luci.nimbus',
	method: 'status'
});

var callApiSecret = rpc.declare({
	object: 'luci.nimbus',
	method: 'api_secret'
});

var callServiceAction = rpc.declare({
	object: 'luci.nimbus',
	method: 'service_action',
	params: [ 'action' ]
});

var callLogRead = rpc.declare({
	object: 'luci.nimbus',
	method: 'log_read',
	params: [ 'lines' ]
});

var callLogClear = rpc.declare({
	object: 'luci.nimbus',
	method: 'log_clear'
});

var callProfileList = rpc.declare({
	object: 'luci.nimbus',
	method: 'profile_list'
});

var callProfileRead = rpc.declare({
	object: 'luci.nimbus',
	method: 'profile_read',
	params: [ 'filename' ]
});

var callProfileSave = rpc.declare({
	object: 'luci.nimbus',
	method: 'profile_save',
	params: [ 'filename', 'content', 'from_upload', 'validate' ]
});

var callProfileMetaSave = rpc.declare({
	object: 'luci.nimbus',
	method: 'profile_meta_save',
	params: [
		'section_id',
		'name',
		'type',
		'filename',
		'url',
		'user_agent',
		'via_proxy',
		'auto_update',
		'update_interval_hours'
	]
});

var callProfileActivate = rpc.declare({
	object: 'luci.nimbus',
	method: 'profile_activate',
	params: [ 'section_id', 'reload' ]
});

var callProfileDelete = rpc.declare({
	object: 'luci.nimbus',
	method: 'profile_delete',
	params: [ 'section_id' ]
});

var callProfileUpdate = rpc.declare({
	object: 'luci.nimbus',
	method: 'profile_update',
	params: [ 'section_id' ]
});

var callListStatus = rpc.declare({
	object: 'luci.nimbus',
	method: 'list_status'
});

var callWhitelistConfigSave = rpc.declare({
	object: 'luci.nimbus',
	method: 'whitelist_config_save',
	params: [ 'enabled', 'auto_update', 'update_cron' ]
});

var callListSourceSave = rpc.declare({
	object: 'luci.nimbus',
	method: 'list_source_save',
	params: [
		'section_id',
		'name',
		'type',
		'enabled',
		'family',
		'filename',
		'url',
		'via_proxy'
	]
});

var callListRead = rpc.declare({
	object: 'luci.nimbus',
	method: 'list_read',
	params: [ 'filename' ]
});

var callListSave = rpc.declare({
	object: 'luci.nimbus',
	method: 'list_save',
	params: [ 'filename', 'content', 'from_upload' ]
});

var callListDelete = rpc.declare({
	object: 'luci.nimbus',
	method: 'list_delete',
	params: [ 'section_id' ]
});

var callListUpdate = rpc.declare({
	object: 'luci.nimbus',
	method: 'list_update',
	params: [ 'section_id' ]
});

var callCoreInfo = rpc.declare({
	object: 'luci.nimbus',
	method: 'core_info'
});

var callCoreCheckUpdate = rpc.declare({
	object: 'luci.nimbus',
	method: 'core_check_update'
});

var callCoreInstall = rpc.declare({
	object: 'luci.nimbus',
	method: 'core_install',
	params: [ 'source', 'download_url', 'digest' ]
});

var callCoreTaskStatus = rpc.declare({
	object: 'luci.nimbus',
	method: 'core_task_status'
});

var callNetworkInterfaceDump = rpc.declare({
	object: 'network.interface',
	method: 'dump',
	expect: { 'interface': [] }
});

var callGetHostHints = rpc.declare({
	object: 'luci-rpc',
	method: 'getHostHints',
	expect: { '': {} }
});

var NimbusApi = baseclass.extend({
	MAX_DIRECT_TEXT_BYTES: MAX_DIRECT_TEXT_BYTES,
	UPLOAD_PROFILE_PATH: UPLOAD_PROFILE_PATH,
	UPLOAD_LIST_PATH: UPLOAD_LIST_PATH,
	UPLOAD_BIN_PATH: UPLOAD_BIN_PATH,

	status: function() {
		return callStatus();
	},

	apiSecret: function() {
		return callApiSecret();
	},

	serviceAction: function(action) {
		return callServiceAction(action);
	},

	logRead: function(lines) {
		return callLogRead(lines != null ? lines : 200);
	},

	logClear: function() {
		return callLogClear();
	},

	profileList: function() {
		return callProfileList();
	},

	profileRead: function(filename) {
		return callProfileRead(filename);
	},

	profileSave: function(opts) {
		var o = opts || {};
		var fromUpload = o.from_upload === true;
		var validate = o.validate !== false;
		return callProfileSave(
			o.filename || '',
			fromUpload ? '' : (o.content != null ? String(o.content) : ''),
			fromUpload,
			validate
		);
	},

	profileMetaSave: function(meta) {
		var m = meta || {};
		var isSub = m.type === 'subscription';
		var interval;
		if (isSub && m.update_interval_hours != null && m.update_interval_hours !== '')
			interval = parseInt(m.update_interval_hours, 10);

		return callProfileMetaSave(
			m.section_id || '',
			m.name || '',
			m.type || 'local',
			m.filename || '',
			isSub ? (m.url || '') : '',
			m.user_agent || 'sing-box/nimbus',
			m.via_proxy === true,
			isSub ? (m.auto_update === true) : false,
			interval
		);
	},

	profileActivate: function(sectionId, reload) {
		return callProfileActivate(sectionId, reload === true);
	},

	profileDelete: function(sectionId) {
		return callProfileDelete(sectionId);
	},

	profileUpdate: function(sectionId) {
		return callProfileUpdate(sectionId || '');
	},

	listStatus: function() {
		return callListStatus();
	},

	whitelistConfigSave: function(enabled, autoUpdate, updateCron) {
		return callWhitelistConfigSave(
			enabled === true,
			autoUpdate === true,
			updateCron || '30 4 * * *'
		);
	},

	listSourceSave: function(src) {
		var s = src || {};
		var isLocal = (s.type || 'local') === 'local';
		return callListSourceSave(
			s.section_id || '',
			s.name || '',
			isLocal ? 'local' : 'url',
			s.enabled !== false,
			s.family || 'auto',
			isLocal ? (s.filename || '') : '',
			isLocal ? '' : (s.url || ''),
			isLocal ? false : (s.via_proxy === true)
		);
	},

	listRead: function(filename) {
		return callListRead(filename);
	},

	listSave: function(opts) {
		var o = opts || {};
		var fromUpload = o.from_upload === true;
		return callListSave(
			o.filename || '',
			fromUpload ? '' : (o.content != null ? String(o.content) : ''),
			fromUpload
		);
	},

	listDelete: function(sectionId) {
		return callListDelete(sectionId);
	},

	listUpdate: function(sectionId) {
		return callListUpdate(sectionId || '');
	},

	coreInfo: function() {
		return callCoreInfo();
	},

	coreCheckUpdate: function() {
		return callCoreCheckUpdate();
	},

	coreInstall: function(source, downloadUrl, digest) {
		return callCoreInstall(source || 'github', downloadUrl || '', digest || '');
	},

	coreTaskStatus: function() {
		return callCoreTaskStatus();
	},

	getNetworkInterfaces: function() {
		return callNetworkInterfaceDump();
	},

	getHostHints: function() {
		return callGetHostHints();
	},

	uploadProfileFile: function(btn) {
		return ui.uploadFile(UPLOAD_PROFILE_PATH, btn);
	},

	uploadListFile: function(btn) {
		return ui.uploadFile(UPLOAD_LIST_PATH, btn);
	},

	uploadCoreFile: function(btn) {
		return ui.uploadFile(UPLOAD_BIN_PATH, btn);
	},

	isUploadCancelled: function(err) {
		var msg = err ? String(err.message || err) : '';
		return /cancel|abort/i.test(msg);
	},

	utf8ByteLength: function(str) {
		var text = str != null ? String(str) : '';
		if (typeof TextEncoder !== 'undefined')
			return new TextEncoder().encode(text).length;
		return unescape(encodeURIComponent(text)).length;
	},

	formatBytes: function(bytes) {
		var val = Number(bytes || 0);
		if (!isFinite(val) || val < 0)
			return '0 B';
		if (val < 1024)
			return '%d B'.format(val);
		var units = [ 'KiB', 'MiB', 'GiB', 'TiB' ];
		var idx = -1;
		while (val >= 1024 && idx < units.length - 1) {
			val = val / 1024;
			idx++;
		}
		return '%.2f %s'.format(val, units[idx]);
	},

	formatUptime: function(seconds) {
		var s = parseInt(seconds, 10);
		if (isNaN(s) || s < 0)
			return '0s';
		var d = Math.floor(s / 86400);
		var h = Math.floor((s % 86400) / 3600);
		var m = Math.floor((s % 3600) / 60);
		var sec = s % 60;
		var parts = [];
		if (d > 0) parts.push('%dd'.format(d));
		if (h > 0 || d > 0) parts.push('%dh'.format(h));
		if (m > 0 || h > 0 || d > 0) parts.push('%dm'.format(m));
		parts.push('%ds'.format(sec));
		return parts.join(' ');
	},

	formatTimestamp: function(ts) {
		if (!ts)
			return '-';
		var d = new Date(Number(ts) * 1000);
		if (isNaN(d.getTime()))
			return '-';
		return d.toLocaleString();
	},

	formatErrorCode: function(code) {
		var map = {
			'E_INVALID_ARG': _('Invalid argument'),
			'E_NOT_FOUND': _('Resource not found'),
			'E_CONFLICT': _('Resource conflict'),
			'E_VALIDATE_FAILED': _('Validation failed'),
			'E_LOCKED': _('Another operation is in progress'),
			'E_NETWORK': _('Network request failed'),
			'E_DISK_SPACE': _('Insufficient disk space'),
			'E_INTERNAL': _('Internal error')
		};
		return map[code] || code || _('Error');
	},

	formatError: function(errOrRes) {
		if (!errOrRes)
			return _('Unknown error');
		if (typeof errOrRes === 'string')
			return errOrRes;
		var detail = errOrRes.error || errOrRes.message || '';
		if (errOrRes.code) {
			var label = this.formatErrorCode(errOrRes.code);
			return detail ? '%s: %s'.format(label, detail) : label;
		}
		return detail || _('Operation failed');
	},

	notifyError: function(errOrRes) {
		ui.addNotification(null, E('p', this.formatError(errOrRes)), 'danger');
	},

	notifySuccess: function(msg) {
		ui.addNotification(null, E('p', msg), 'info');
	},

	confirmAction: function(title, message) {
		return new Promise(function(resolve) {
			ui.showModal(title, [
				E('p', message),
				E('div', { 'class': 'right' }, [
					E('button', {
						'class': 'btn cbi-button',
						'click': function() {
							ui.hideModal();
							resolve(false);
						}
					}, _('Cancel')),
					' ',
					E('button', {
						'class': 'btn cbi-button cbi-button-negative',
						'click': function() {
							ui.hideModal();
							resolve(true);
						}
					}, _('Confirm'))
				])
			]);
		});
	},

	buildApiUrl: function(apiInfo, pathSuffix) {
		if (!apiInfo || !apiInfo.detected || !apiInfo.port)
			return null;
		var scheme = apiInfo.scheme || 'http';
		var rawListen = String(apiInfo.listen || '').trim();
		var host = window.location.hostname || '127.0.0.1';
		if (rawListen && rawListen !== '0.0.0.0' && rawListen !== '::' && rawListen !== '*')
			host = rawListen;
		if (host.indexOf(':') >= 0 && host.charAt(0) !== '[')
			host = '[' + host + ']';
		return '%s://%s:%d%s'.format(scheme, host, apiInfo.port, pathSuffix || '/');
	},

	copyToClipboard: function(text) {
		var val = text != null ? String(text) : '';
		if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function')
			return navigator.clipboard.writeText(val);

		return new Promise(function(resolve, reject) {
			var ta = document.createElement('textarea');
			ta.value = val;
			ta.setAttribute('readonly', '');
			ta.style.position = 'fixed';
			ta.style.left = '-9999px';
			document.body.appendChild(ta);
			ta.select();
			try {
				var ok = document.execCommand('copy');
				document.body.removeChild(ta);
				if (ok)
					resolve();
				else
					reject(new Error('Copy command failed'));
			} catch (e) {
				document.body.removeChild(ta);
				reject(e);
			}
		});
	}
});

return new NimbusApi();
