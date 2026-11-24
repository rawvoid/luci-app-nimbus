'use strict';
'require view';
'require dom';
'require poll';
'require nimbus.api as nimbusApi';

return view.extend({
	handleSave: null,
	handleSaveApply: null,
	handleReset: null,

	load: function() {
		return nimbusApi.logRead(200);
	},

	render: function(initialData) {
		var logData = initialData || { ok: true, content: '', size_bytes: 0, truncated: false };
		var lineCount = 200;
		var paused = false;
		var autoScroll = true;
		var inFlight = false;

		var metaLabel = E('small', { 'style': 'opacity:0.75;' });
		var logPre = E('textarea', {
			'class': 'cbi-input-textarea',
			'readonly': 'readonly',
			'rows': '24',
			'wrap': 'off',
			'spellcheck': 'false',
			'style': 'width:100%;font-family:monospace;resize:vertical;'
		});

		var linesSelect = E('select', { 'class': 'cbi-input-select', 'style': 'width:auto;' }, [
			E('option', { 'value': '100' }, _('Last 100 lines')),
			E('option', { 'value': '200', 'selected': 'selected' }, _('Last 200 lines')),
			E('option', { 'value': '500' }, _('Last 500 lines')),
			E('option', { 'value': '1000' }, _('Last 1000 lines')),
			E('option', { 'value': '2000' }, _('Last 2000 lines'))
		]);

		var pauseBtn = E('button', { 'type': 'button', 'class': 'btn cbi-button cbi-button-neutral' }, _('Pause'));
		var scrollCb = E('input', { 'type': 'checkbox', 'checked': 'checked' });

		function renderLogContent(res) {
			logData = res || { ok: true, content: '', size_bytes: 0, truncated: false };
			var text = logData.content || '';
			logPre.value = text || _('(Log file is empty)');
			if (autoScroll)
				logPre.scrollTop = logPre.scrollHeight;

			var meta = _('File size: %s').format(nimbusApi.formatBytes(logData.size_bytes || 0));
			if (logData.truncated)
				meta += ' · ' + _('Showing trailing %d lines').format(lineCount);
			dom.content(metaLabel, meta);
		}

		function refreshLog() {
			if (inFlight)
				return Promise.resolve();
			inFlight = true;
			return nimbusApi.logRead(lineCount).then(function(res) {
				inFlight = false;
				if (!res || res.ok === false) {
					nimbusApi.notifyError(res);
					return;
				}
				renderLogContent(res);
			}, function(err) {
				inFlight = false;
				nimbusApi.notifyError(err);
			});
		}

		linesSelect.addEventListener('change', function() {
			var n = parseInt(linesSelect.value, 10);
			if (!isNaN(n) && n >= 1 && n <= 2000)
				lineCount = n;
			refreshLog();
		});

		pauseBtn.addEventListener('click', function() {
			paused = !paused;
			dom.content(pauseBtn, paused ? _('Resume') : _('Pause'));
		});

		scrollCb.addEventListener('change', function() {
			autoScroll = scrollCb.checked;
			if (autoScroll)
				logPre.scrollTop = logPre.scrollHeight;
		});

		var refreshBtn = E('button', {
			'type': 'button',
			'class': 'btn cbi-button cbi-button-action',
			'click': refreshLog
		}, _('Refresh'));

		var clearBtn = E('button', {
			'type': 'button',
			'class': 'btn cbi-button cbi-button-negative',
			'click': function() {
				nimbusApi.confirmAction(
					_('Clear Logs'),
					_('Truncate /var/log/nimbus.log to 0 bytes?')
				).then(function(yes) {
					if (!yes)
						return;
					return nimbusApi.logClear().then(function(res) {
						if (!res || res.ok === false)
							nimbusApi.notifyError(res);
						else
							nimbusApi.notifySuccess(_('Log file cleared.'));
						return refreshLog();
					});
				}).catch(function(err) {
					nimbusApi.notifyError(err);
				});
			}
		}, _('Clear Logs'));

		renderLogContent(logData);

		poll.add(function() {
			if (paused || inFlight)
				return Promise.resolve();
			inFlight = true;
			return nimbusApi.logRead(lineCount).then(function(res) {
				inFlight = false;
				if (res && res.ok !== false)
					renderLogContent(res);
			}, function() {
				inFlight = false;
			});
		}, 3);

		return E('div', { 'class': 'cbi-map' }, [
			E('h2', {}, _('Nimbus Logs')),
			E('div', { 'class': 'cbi-map-descr' },
				_('Live viewer for /var/log/nimbus.log in tmpfs (automatically rotated above 512 KiB).')),
			E('div', { 'class': 'cbi-section' }, [
				E('div', { 'style': 'display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;margin-bottom:10px;' }, [
					E('div', { 'style': 'display:flex;align-items:center;gap:8px;flex-wrap:wrap;' }, [
						linesSelect,
						pauseBtn,
						refreshBtn,
						clearBtn,
						E('label', { 'style': 'display:flex;align-items:center;gap:5px;margin:0 0 0 6px;font-weight:normal;' }, [
							scrollCb,
							E('span', {}, _('Auto-scroll'))
						])
					]),
					metaLabel
				]),
				logPre
			])
		]);
	}
});
