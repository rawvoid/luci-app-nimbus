'use strict';
'require view';
'require dom';
'require ui';
'require nimbus.api as nimbusApi';

function isValidListFilename(name) {
	if (typeof name !== 'string' || !/^[A-Za-z0-9._-]+\.txt$/.test(name))
		return false;
	return (name.indexOf('..') < 0 && name !== '.txt');
}

function isHttpUrl(url) {
	return (typeof url === 'string' && /^https?:\/\/[^\s]+$/.test(url.trim()));
}

function isValidCronExpr(expr) {
	if (typeof expr !== 'string')
		return false;
	var parts = expr.trim().split(/\s+/);
	return parts.length === 5;
}

function makeBadge(text, bg, fg) {
	return E('span', {
		'class': 'label',
		'style': 'display:inline-block;padding:2px 7px;border-radius:3px;font-size:85%;font-weight:600;background:%s;color:%s;'.format(bg, fg)
	}, text);
}

function stripComment(line) {
	var s = line.replace(/\r+$/, '');
	var h = s.indexOf('#');
	if (h >= 0) s = s.slice(0, h);
	var sc = s.indexOf(';');
	if (sc >= 0) s = s.slice(0, sc);
	var sl = s.match(/^(.*?)(?:[ \t]|^)\/\/.*$/);
	if (sl) s = sl[1];
	return s.trim();
}

function isIpv4OrCidr(token) {
	var parts = token.split('/');
	if (parts.length > 2)
		return false;
	var octets = parts[0].split('.');
	if (octets.length !== 4)
		return false;
	for (var i = 0; i < 4; i++) {
		if (!/^[0-9]{1,3}$/.test(octets[i]))
			return false;
		var n = parseInt(octets[i], 10);
		if (n < 0 || n > 255)
			return false;
	}
	if (parts.length === 2) {
		if (!/^[0-9]{1,2}$/.test(parts[1]))
			return false;
		var p = parseInt(parts[1], 10);
		if (p < 1 || p > 32)
			return false;
	}
	return true;
}

function isIpv6OrCidr(token) {
	var parts = token.split('/');
	if (parts.length > 2 || parts[0].indexOf(':') < 0)
		return false;
	if (!/^[0-9a-fA-F:]+$/.test(parts[0]))
		return false;
	if (parts.length === 2) {
		if (!/^[0-9]{1,3}$/.test(parts[1]))
			return false;
		var p = parseInt(parts[1], 10);
		if (p < 1 || p > 128)
			return false;
	}
	return true;
}

function previewCleanList(rawText, family) {
	var v4 = [], v6 = [], ignored = 0, invalid = [];
	var seen = {};
	var lines = String(rawText || '').split('\n');
	for (var i = 0; i < lines.length; i++) {
		var raw = lines[i].replace(/\r+$/, '').trim();
		if (!raw) {
			ignored++;
			continue;
		}
		var tok = stripComment(raw);
		if (!tok) {
			ignored++;
			continue;
		}
		var lower = tok.toLowerCase();
		if (isIpv4OrCidr(lower) && family !== 'ipv6') {
			if (!seen[lower]) {
				seen[lower] = true;
				v4.push(lower);
			}
		} else if (isIpv6OrCidr(lower) && family !== 'ipv4') {
			if (!seen[lower]) {
				seen[lower] = true;
				v6.push(lower);
			}
		} else {
			invalid.push({ line: i + 1, text: tok });
		}
	}
	return {
		v4: v4,
		v6: v6,
		ignored: ignored,
		invalid: invalid,
		cleaned: v4.concat(v6).join('\n')
	};
}

function renderInvalidLinesBox(res) {
	var items = (res && Array.isArray(res.invalid_lines)) ? res.invalid_lines : [];
	if (items.length === 0)
		return E('div', { 'class': 'alert-message error' }, nimbusApi.formatError(res));

	return E('div', { 'class': 'alert-message error' }, [
		E('strong', {}, nimbusApi.formatError(res)),
		E('ul', { 'style': 'margin:6px 0 0 18px;' }, items.map(function(item) {
			return E('li', {}, _('Line %d: "%s" — %s').format(item.line || 0, item.text || '', item.reason || _('invalid entry')));
		}))
	]);
}

return view.extend({
	handleSave: null,
	handleSaveApply: null,
	handleReset: null,

	load: function() {
		return nimbusApi.listStatus();
	},

	render: function(initialData) {
		var statusData = initialData || {
			whitelist: { enabled: true, auto_update: true, update_cron: '30 4 * * *' },
			nft_loaded: { v4_count: 0, v6_count: 0 },
			sources: []
		};
		var policyBox = E('div', { 'class': 'cbi-section' });
		var sourcesBox = E('div', { 'class': 'cbi-section' });
		var busy = false;

		function refreshStatus() {
			return nimbusApi.listStatus().then(function(res) {
				if (!res || res.ok === false) {
					nimbusApi.notifyError(res);
					return;
				}
				statusData = res;
				renderAll();
			}).catch(function(err) {
				nimbusApi.notifyError(err);
			});
		}

		function showInvalidUploadModal(filename, res) {
			ui.showModal(_('Validation Failed: %s').format(filename), [
				renderInvalidLinesBox(res),
				E('div', { 'class': 'right' }, [
					E('button', { 'type': 'button', 'class': 'btn cbi-button', 'click': ui.hideModal }, _('Close'))
				])
			]);
		}

		function handleUploadList(src, btn, onDone) {
			nimbusApi.uploadListFile(btn).then(function() {
				return nimbusApi.listSave({
					filename: src.filename,
					from_upload: true
				});
			}).then(function(res) {
				if (!res || res.ok === false) {
					if (res && Array.isArray(res.invalid_lines) && res.invalid_lines.length > 0)
						showInvalidUploadModal(src.filename, res);
					else
						nimbusApi.notifyError(res);
					return;
				}
				nimbusApi.notifySuccess(res.hot_reloaded
					? _('Saved "%s" (%d IPv4, %d IPv6) and atomically hot-reloaded nftables.').format(src.filename, res.v4_count || 0, res.v6_count || 0)
					: _('Saved "%s" (%d IPv4, %d IPv6).').format(src.filename, res.v4_count || 0, res.v6_count || 0));
				return refreshStatus().then(function() {
					if (onDone)
						onDone(res);
				});
			}).catch(function(err) {
				if (!nimbusApi.isUploadCancelled(err))
					nimbusApi.notifyError(err);
			});
		}

		function openLocalEditor(src) {
			nimbusApi.listRead(src.filename).then(function(res) {
				var content = '';
				if (res && res.ok)
					content = res.content || '';
				else if (res && res.code !== 'E_NOT_FOUND') {
					nimbusApi.notifyError(res);
					return;
				}

				var errBox = E('div', { 'style': 'display:none;' });
				var textarea = E('textarea', {
					'class': 'cbi-input-textarea',
					'rows': '16',
					'spellcheck': 'false',
					'placeholder': '# 1.1.8.0/24\n# 2400:3200::/32',
					'style': 'width:100%;font-family:monospace;font-size:12px;resize:vertical;'
				}, content);
				var sizeLabel = E('span', { 'style': 'font-size:90%;color:#666;' });
				var saveBtn = E('button', { 'type': 'button', 'class': 'btn cbi-button cbi-button-save' }, _('Save & Hot-Reload'));

				function updateByteCount() {
					var len = nimbusApi.utf8ByteLength(textarea.value);
					var over = len > nimbusApi.MAX_DIRECT_TEXT_BYTES;
					sizeLabel.style.color = over ? '#c5221f' : '#666';
					dom.content(sizeLabel, _('%s / %s direct limit').format(
						nimbusApi.formatBytes(len),
						nimbusApi.formatBytes(nimbusApi.MAX_DIRECT_TEXT_BYTES)
					));
				}

				textarea.addEventListener('input', updateByteCount);
				updateByteCount();

				saveBtn.addEventListener('click', function() {
					errBox.style.display = 'none';
					var raw = textarea.value;
					if (nimbusApi.utf8ByteLength(raw) > nimbusApi.MAX_DIRECT_TEXT_BYTES) {
						errBox.style.display = 'block';
						dom.content(errBox, E('div', { 'class': 'alert-message error' },
							_('Content exceeds the 256 KiB inline transfer limit. Use "Upload .txt File" instead.')));
						return;
					}

					saveBtn.disabled = true;
					nimbusApi.listSave({
						filename: src.filename,
						content: raw,
						from_upload: false
					}).then(function(sres) {
						saveBtn.disabled = false;
						if (!sres || sres.ok === false) {
							errBox.style.display = 'block';
							dom.content(errBox, renderInvalidLinesBox(sres));
							return;
						}
						ui.hideModal();
						nimbusApi.notifySuccess(sres.hot_reloaded
							? _('Saved "%s" (%d IPv4, %d IPv6) and atomically hot-reloaded nftables.').format(src.filename, sres.v4_count || 0, sres.v6_count || 0)
							: _('Saved "%s" (%d IPv4, %d IPv6).').format(src.filename, sres.v4_count || 0, sres.v6_count || 0));
						return refreshStatus();
					}).catch(function(err) {
						saveBtn.disabled = false;
						errBox.style.display = 'block';
						dom.content(errBox, E('div', { 'class': 'alert-message error' }, nimbusApi.formatError(err)));
					});
				});

				ui.showModal(_('Edit Whitelist: %s').format(src.filename), [
					E('p', { 'class': 'cbi-section-descr' },
						_('Enter one IPv4, IPv6, or CIDR range per line. Comments beginning with "#", ";", or "//" are supported.')),
					errBox,
					textarea,
					E('div', { 'style': 'margin:6px 0 12px;' }, sizeLabel),
					E('div', { 'style': 'display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px;' }, [
						E('button', {
							'type': 'button',
							'class': 'btn cbi-button cbi-button-action',
							'click': function(ev) {
								handleUploadList(src, ev.currentTarget, function() {
									ui.hideModal();
								});
							}
						}, _('Upload .txt File')),
						E('div', { 'style': 'display:flex;gap:8px;' }, [
							E('button', { 'type': 'button', 'class': 'btn cbi-button', 'click': ui.hideModal }, _('Cancel')),
							saveBtn
						])
					])
				]);
			}).catch(function(err) {
				nimbusApi.notifyError(err);
			});
		}

		function openCleanedPreview(src) {
			nimbusApi.listRead(src.filename).then(function(res) {
				if (!res || res.ok === false) {
					nimbusApi.notifyError(res);
					return;
				}
				var parsed = previewCleanList(res.content || '', src.family || 'auto');
				var body = [
					E('div', { 'style': 'display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px;' }, [
						makeBadge(_('IPv4: %d').format(parsed.v4.length), '#e6f4ea', '#137333'),
						makeBadge(_('IPv6: %d').format(parsed.v6.length), '#e8f0fe', '#1967d2'),
						makeBadge(_('Ignored / Comments: %d').format(parsed.ignored), '#f1f3f4', '#5f6368'),
						parsed.invalid.length > 0 ? makeBadge(_('Invalid: %d').format(parsed.invalid.length), '#fce8e6', '#c5221f') : ''
					])
				];

				if (parsed.invalid.length > 0) {
					body.push(E('div', { 'class': 'alert-message warning' }, [
						E('strong', {}, _('Unrecognized Lines (not loaded into nftables):')),
						E('ul', { 'style': 'margin:4px 0 0 18px;' }, parsed.invalid.slice(0, 10).map(function(it) {
							return E('li', {}, _('Line %d: %s').format(it.line, it.text));
						}))
					]));
				}

				body.push(E('textarea', {
					'class': 'cbi-input-textarea',
					'rows': '14',
					'readonly': 'readonly',
					'style': 'width:100%;font-family:monospace;font-size:12px;'
				}, parsed.cleaned || _('(empty)')));

				body.push(E('div', { 'class': 'right', 'style': 'margin-top:10px;display:flex;justify-content:flex-end;gap:8px;' }, [
					parsed.cleaned ? E('button', {
						'type': 'button',
						'class': 'btn cbi-button cbi-button-action',
						'click': function() {
							nimbusApi.copyToClipboard(parsed.cleaned).then(function() {
								nimbusApi.notifySuccess(_('Cleaned whitelist entries copied to clipboard.'));
							}, function() {
								nimbusApi.notifyError(_('Failed to copy to clipboard.'));
							});
						}
					}, _('Copy Cleaned')) : '',
					E('button', { 'type': 'button', 'class': 'btn cbi-button', 'click': ui.hideModal }, _('Close'))
				]));

				ui.showModal(_('Cleaned Preview: %s').format(src.filename), body);
			}).catch(function(err) {
				nimbusApi.notifyError(err);
			});
		}

		function openSourceModal(existing) {
			var isEdit = Boolean(existing && existing.id);
			var s = existing || {};
			var errBox = E('div', { 'style': 'display:none;' });

			var nameInput = E('input', {
				'type': 'text',
				'class': 'cbi-input-text',
				'value': s.name || '',
				'placeholder': _('e.g. Custom Direct')
			});
			var typeSelect = E('select', { 'class': 'cbi-input-select' }, [
				E('option', { 'value': 'local', 'selected': (s.type || 'local') === 'local' ? 'selected' : null }, _('Local File')),
				E('option', { 'value': 'url', 'selected': s.type === 'url' ? 'selected' : null }, _('Remote URL'))
			]);
			var familySelect = E('select', { 'class': 'cbi-input-select' }, [
				E('option', { 'value': 'auto', 'selected': (s.family || 'auto') === 'auto' ? 'selected' : null }, _('Auto (IPv4 + IPv6)')),
				E('option', { 'value': 'ipv4', 'selected': s.family === 'ipv4' ? 'selected' : null }, _('IPv4 Only')),
				E('option', { 'value': 'ipv6', 'selected': s.family === 'ipv6' ? 'selected' : null }, _('IPv6 Only'))
			]);
			var enabledCb = E('input', {
				'type': 'checkbox',
				'checked': (s.enabled !== false) ? 'checked' : null
			});
			var fileInput = E('input', {
				'type': 'text',
				'class': 'cbi-input-text',
				'value': s.filename || '',
				'placeholder': 'custom_list.txt'
			});
			var urlInput = E('input', {
				'type': 'text',
				'class': 'cbi-input-text',
				'value': s.url || '',
				'placeholder': 'https://example.com/list.txt'
			});
			var viaProxyCb = E('input', {
				'type': 'checkbox',
				'checked': s.via_proxy ? 'checked' : null
			});

			var localRow = E('div', { 'class': 'cbi-value' }, [
				E('label', { 'class': 'cbi-value-title' }, _('Filename')),
				E('div', { 'class': 'cbi-value-field' }, [
					fileInput,
					E('div', { 'class': 'cbi-value-description' }, _('Stored under /etc/nimbus/lists/local/, e.g. custom_direct.txt.'))
				])
			]);
			var urlBox = E('div', {}, [
				E('div', { 'class': 'cbi-value' }, [
					E('label', { 'class': 'cbi-value-title' }, _('Source URL')),
					E('div', { 'class': 'cbi-value-field' }, urlInput)
				]),
				E('div', { 'class': 'cbi-value' }, [
					E('label', { 'class': 'cbi-value-title' }, _('Fetch via Proxy')),
					E('div', { 'class': 'cbi-value-field' }, viaProxyCb)
				])
			]);

			function syncTypeVisibility() {
				var isLocal = (typeSelect.value === 'local');
				localRow.style.display = isLocal ? '' : 'none';
				urlBox.style.display = isLocal ? 'none' : 'block';
			}
			typeSelect.addEventListener('change', syncTypeVisibility);
			syncTypeVisibility();

			function showFormErr(msg) {
				errBox.style.display = 'block';
				dom.content(errBox, E('div', { 'class': 'alert-message error' }, msg));
			}

			var saveBtn = E('button', { 'type': 'button', 'class': 'btn cbi-button cbi-button-save' }, _('Save'));
			saveBtn.addEventListener('click', function() {
				errBox.style.display = 'none';
				var name = nameInput.value.trim();
				var ltype = typeSelect.value;
				var fname = fileInput.value.trim();
				var url = urlInput.value.trim();

				if (!name) {
					showFormErr(_('Source name is required.'));
					return;
				}
				if (ltype === 'local' && !isValidListFilename(fname)) {
					showFormErr(_('Filename must match ^[A-Za-z0-9._-]+\\.txt$ (no path separators or "..").'));
					return;
				}
				if (ltype === 'url' && !isHttpUrl(url)) {
					showFormErr(_('Remote source requires a valid http:// or https:// URL.'));
					return;
				}

				saveBtn.disabled = true;
				nimbusApi.listSourceSave({
					section_id: isEdit ? s.id : '',
					name: name,
					type: ltype,
					enabled: enabledCb.checked,
					family: familySelect.value,
					filename: ltype === 'local' ? fname : '',
					url: ltype === 'url' ? url : '',
					via_proxy: ltype === 'url' ? viaProxyCb.checked : false
				}).then(function(res) {
					saveBtn.disabled = false;
					if (!res || res.ok === false) {
						showFormErr(nimbusApi.formatError(res));
						return;
					}
					ui.hideModal();
					nimbusApi.notifySuccess(res.hot_reloaded
						? _('Whitelist source saved and atomically hot-reloaded nftables.')
						: _('Whitelist source saved.'));
					return refreshStatus();
				}).catch(function(err) {
					saveBtn.disabled = false;
					showFormErr(nimbusApi.formatError(err));
				});
			});

			ui.showModal(isEdit ? _('Edit Whitelist Source: %s').format(s.name || s.id) : _('Add Whitelist Source'), [
				errBox,
				E('div', { 'class': 'cbi-value' }, [
					E('label', { 'class': 'cbi-value-title' }, _('Name')),
					E('div', { 'class': 'cbi-value-field' }, nameInput)
				]),
				E('div', { 'class': 'cbi-value' }, [
					E('label', { 'class': 'cbi-value-title' }, _('Type')),
					E('div', { 'class': 'cbi-value-field' }, typeSelect)
				]),
				E('div', { 'class': 'cbi-value' }, [
					E('label', { 'class': 'cbi-value-title' }, _('Address Family')),
					E('div', { 'class': 'cbi-value-field' }, familySelect)
				]),
				E('div', { 'class': 'cbi-value' }, [
					E('label', { 'class': 'cbi-value-title' }, _('Enabled')),
					E('div', { 'class': 'cbi-value-field' }, enabledCb)
				]),
				localRow,
				urlBox,
				E('div', { 'class': 'right' }, [
					E('button', { 'type': 'button', 'class': 'btn cbi-button', 'click': ui.hideModal }, _('Cancel')),
					' ',
					saveBtn
				])
			]);
		}

		function runListUpdate(sectionId) {
			if (busy)
				return;
			busy = true;
			renderAll();

			nimbusApi.listUpdate(sectionId || '').then(function(res) {
				busy = false;
				var results = (res && Array.isArray(res.results)) ? res.results : [];
				var updated = 0, unchanged = 0, errs = [];
				results.forEach(function(r) {
					if (r.status === 'updated') updated++;
					else if (r.status === 'unchanged') unchanged++;
					else errs.push('%s: %s'.format(r.id, r.error || _('failed')));
				});
				if (!res || res.ok === false) {
					nimbusApi.notifyError(errs.length ? errs.join('; ') : res);
				} else {
					nimbusApi.notifySuccess(res.hot_reloaded
						? _('Remote lists updated: %d updated, %d unchanged, nftables atomically hot-reloaded.').format(updated, unchanged)
						: _('Remote lists updated: %d updated, %d unchanged.').format(updated, unchanged));
				}
				return refreshStatus();
			}).catch(function(err) {
				busy = false;
				nimbusApi.notifyError(err);
				return refreshStatus();
			});
		}

		function deleteSource(src) {
			nimbusApi.confirmAction(
				_('Delete Whitelist Source'),
				_('Delete whitelist source "%s" and its associated file/cache?').format(src.name || src.id)
			).then(function(yes) {
				if (!yes)
					return;
				return nimbusApi.listDelete(src.id).then(function(res) {
					if (!res || res.ok === false)
						nimbusApi.notifyError(res);
					else
						nimbusApi.notifySuccess(res.hot_reloaded
							? _('Whitelist source deleted and nftables hot-reloaded.')
							: _('Whitelist source deleted.'));
					return refreshStatus();
				});
			}).catch(function(err) {
				nimbusApi.notifyError(err);
			});
		}

		function renderPolicy() {
			var wl = statusData.whitelist || {};
			var loaded = statusData.nft_loaded || {};

			var enabledCb = E('input', { 'type': 'checkbox', 'checked': wl.enabled !== false ? 'checked' : null });
			var autoCb = E('input', { 'type': 'checkbox', 'checked': wl.auto_update !== false ? 'checked' : null });
			var cronInput = E('input', {
				'type': 'text',
				'class': 'cbi-input-text',
				'value': wl.update_cron || '30 4 * * *',
				'placeholder': '30 4 * * *'
			});

			var savePolicyBtn = E('button', {
				'type': 'button',
				'class': 'btn cbi-button cbi-button-save',
				'click': function() {
					var cronExpr = cronInput.value.trim();
					if (!isValidCronExpr(cronExpr)) {
						nimbusApi.notifyError(_('Cron expression must have 5 space-separated fields (e.g. "30 4 * * *").'));
						return;
					}
					savePolicyBtn.disabled = true;
					nimbusApi.whitelistConfigSave(enabledCb.checked, autoCb.checked, cronExpr).then(function(res) {
						savePolicyBtn.disabled = false;
						if (!res || res.ok === false) {
							nimbusApi.notifyError(res);
							return;
						}
						nimbusApi.notifySuccess(res.hot_reloaded
							? _('Whitelist policy saved and atomically hot-reloaded nftables.')
							: _('Whitelist policy saved.'));
						return refreshStatus();
					}).catch(function(err) {
						savePolicyBtn.disabled = false;
						nimbusApi.notifyError(err);
					});
				}
			}, _('Save Policy'));

			dom.content(policyBox, [
				E('h3', {}, _('Global Whitelist Policy')),
				E('div', { 'style': 'display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px;' }, [
					makeBadge(_('Effective nftables IPv4: %d').format(loaded.v4_count || 0), '#e6f4ea', '#137333'),
					makeBadge(_('Effective nftables IPv6: %d').format(loaded.v6_count || 0), '#e8f0fe', '#1967d2')
				]),
				E('div', { 'class': 'cbi-value' }, [
					E('label', { 'class': 'cbi-value-title' }, _('Enable Whitelist Bypass')),
					E('div', { 'class': 'cbi-value-field' }, [
						enabledCb,
						E('div', { 'class': 'cbi-value-description' }, _('Built-in private, LAN, and WAN reserved subnets always bypass the proxy regardless of this switch.'))
					])
				]),
				E('div', { 'class': 'cbi-value' }, [
					E('label', { 'class': 'cbi-value-title' }, _('Auto Update Remote Lists')),
					E('div', { 'class': 'cbi-value-field' }, autoCb)
				]),
				E('div', { 'class': 'cbi-value' }, [
					E('label', { 'class': 'cbi-value-title' }, _('Cron Schedule')),
					E('div', { 'class': 'cbi-value-field' }, [
						cronInput,
						E('div', { 'class': 'cbi-value-description' }, _('Standard 5-field cron expression, e.g. 30 4 * * *.'))
					])
				]),
				E('div', { 'style': 'margin-top:8px;' }, savePolicyBtn)
			]);
		}

		function renderSources() {
			var sources = statusData.sources || [];
			var hasUrl = sources.some(function(s) { return s.type === 'url' && s.enabled !== false; });

			var toolbar = E('div', { 'style': 'display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;margin-bottom:12px;' }, [
				E('div', { 'style': 'display:flex;gap:8px;flex-wrap:wrap;' }, [
					E('button', {
						'type': 'button',
						'class': 'btn cbi-button cbi-button-add',
						'disabled': busy ? 'disabled' : null,
						'click': function() { openSourceModal(null); }
					}, _('Add Source')),
					E('button', {
						'type': 'button',
						'class': 'btn cbi-button cbi-button-action',
						'disabled': (busy || !hasUrl) ? 'disabled' : null,
						'click': function() { runListUpdate(''); }
					}, _('Update All Remote Sources')),
					E('button', {
						'type': 'button',
						'class': 'btn cbi-button',
						'disabled': busy ? 'disabled' : null,
						'click': refreshStatus
					}, _('Refresh'))
				]),
				busy ? E('span', { 'class': 'spinning' }, _('Updating...')) : ''
			]);

			var rows = [
				E('tr', { 'class': 'tr cbi-section-table-titles' }, [
					E('th', { 'class': 'th' }, _('Name')),
					E('th', { 'class': 'th' }, _('Type')),
					E('th', { 'class': 'th' }, _('Family')),
					E('th', { 'class': 'th' }, _('Status')),
					E('th', { 'class': 'th' }, _('Target')),
					E('th', { 'class': 'th' }, _('Entries & File')),
					E('th', { 'class': 'th right' }, _('Actions'))
				])
			];

			if (sources.length === 0) {
				rows.push(E('tr', { 'class': 'tr' }, [
					E('td', { 'class': 'td center', 'colspan': '7' }, _('No whitelist sources configured.'))
				]));
			} else {
				sources.forEach(function(src) {
					var targetEl = src.type === 'local'
						? E('code', {}, src.filename || '-')
						: E('span', { 'style': 'display:inline-block;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;', 'title': src.url || '' }, src.url || '-');

					var statsEl = E('div', {}, [
						E('div', {}, _('IPv4: %d / IPv6: %d').format(src.v4_count || 0, src.v6_count || 0)),
						E('div', { 'style': 'font-size:85%;color:#666;' }, src.exists
							? '%s · %s'.format(nimbusApi.formatBytes(src.size_bytes || 0), nimbusApi.formatTimestamp(src.mtime))
							: _('Not cached / missing'))
					]);

					var actBtns = [];
					if (src.type === 'local') {
						actBtns.push(
							E('button', {
								'type': 'button',
								'class': 'btn cbi-button cbi-button-edit',
								'disabled': busy ? 'disabled' : null,
								'click': function() { openLocalEditor(src); }
							}, _('Edit')),
							E('button', {
								'type': 'button',
								'class': 'btn cbi-button cbi-button-neutral',
								'disabled': (busy || !src.exists) ? 'disabled' : null,
								'click': function() { openCleanedPreview(src); }
							}, _('Preview')),
							E('button', {
								'type': 'button',
								'class': 'btn cbi-button cbi-button-action',
								'disabled': busy ? 'disabled' : null,
								'click': function(ev) { handleUploadList(src, ev.currentTarget); }
							}, _('Upload .txt'))
						);
					} else {
						actBtns.push(E('button', {
							'type': 'button',
							'class': 'btn cbi-button cbi-button-action',
							'disabled': busy ? 'disabled' : null,
							'click': function() { runListUpdate(src.id); }
						}, _('Update')));
					}

					actBtns.push(
						E('button', {
							'type': 'button',
							'class': 'btn cbi-button',
							'disabled': busy ? 'disabled' : null,
							'click': function() { openSourceModal(src); }
						}, _('Meta')),
						E('button', {
							'type': 'button',
							'class': 'btn cbi-button cbi-button-negative',
							'disabled': busy ? 'disabled' : null,
							'click': function() { deleteSource(src); }
						}, _('Delete'))
					);

					rows.push(E('tr', { 'class': 'tr cbi-section-table-row' }, [
						E('td', { 'class': 'td' }, E('strong', {}, src.name || src.id)),
						E('td', { 'class': 'td' }, src.type === 'local' ? _('Local') : _('Remote URL')),
						E('td', { 'class': 'td' }, src.family || 'auto'),
						E('td', { 'class': 'td' }, src.enabled !== false
							? makeBadge(_('Enabled'), '#e6f4ea', '#137333')
							: makeBadge(_('Disabled'), '#f1f3f4', '#5f6368')),
						E('td', { 'class': 'td' }, targetEl),
						E('td', { 'class': 'td' }, statsEl),
						E('td', { 'class': 'td right' }, E('div', { 'style': 'display:flex;gap:4px;justify-content:flex-end;flex-wrap:wrap;' }, actBtns))
					]));
				});
			}

			dom.content(sourcesBox, [
				E('h3', {}, _('Whitelist Sources')),
				toolbar,
				E('table', { 'class': 'table cbi-section-table' }, rows)
			]);
		}

		function renderAll() {
			renderPolicy();
			renderSources();
		}

		renderAll();

		return E('div', { 'class': 'cbi-map' }, [
			E('h2', {}, _('Nimbus Whitelists')),
			E('div', { 'class': 'cbi-map-descr' },
				_('Manage direct-bypass IPv4/IPv6 CIDR lists. Edits and remote refreshes atomically hot-reload nftables sets without restarting sing-box.')),
			policyBox,
			sourcesBox
		]);
	}
});
