'use strict';
'require view';
'require dom';
'require ui';
'require nimbus.api as nimbusApi';

function isValidProfileFilename(name) {
	if (typeof name !== 'string' || !/^[A-Za-z0-9._-]+\.json$/.test(name))
		return false;
	return (name.indexOf('..') < 0 && name !== '.json');
}

function isHttpUrl(url) {
	return (typeof url === 'string' && /^https?:\/\/[^\s]+$/.test(url.trim()));
}

function makeBadge(text, bg, fg) {
	return E('span', {
		'class': 'label',
		'style': 'display:inline-block;padding:2px 7px;border-radius:3px;font-size:85%;font-weight:600;background:%s;color:%s;'.format(bg, fg)
	}, text);
}

return view.extend({
	handleSave: null,
	handleSaveApply: null,
	handleReset: null,

	load: function() {
		return nimbusApi.profileList();
	},

	render: function(initialData) {
		var listData = initialData || { active_profile: '', profiles: [] };
		var tableContainer = E('div', { 'class': 'cbi-section' });
		var busy = false;

		function refreshList() {
			return nimbusApi.profileList().then(function(res) {
				if (!res || res.ok === false) {
					nimbusApi.notifyError(res);
					return;
				}
				listData = res;
				renderTable();
			}).catch(function(err) {
				nimbusApi.notifyError(err);
			});
		}

		function maybeReloadActive(res) {
			if (!res || !res.reload_required)
				return Promise.resolve();
			return nimbusApi.confirmAction(
				_('Reload Service'),
				_('The active profile was updated and validated. Reload Nimbus service now to apply changes?')
			).then(function(yes) {
				if (!yes)
					return;
				return nimbusApi.serviceAction('reload').then(function(r) {
					if (!r || r.ok === false)
						nimbusApi.notifyError(r);
					else
						nimbusApi.notifySuccess(_('Service reloaded successfully.'));
				});
			});
		}

		function handleUploadJson(filename, validate, btn, onDone) {
			nimbusApi.uploadProfileFile(btn).then(function() {
				return nimbusApi.profileSave({
					filename: filename,
					from_upload: true,
					validate: validate
				});
			}).then(function(res) {
				if (!res || res.ok === false) {
					nimbusApi.notifyError(res);
					return;
				}
				nimbusApi.notifySuccess(res.checked
					? _('Profile "%s" uploaded and validated with sing-box.').format(filename)
					: _('Profile "%s" uploaded (JSON syntax checked).').format(filename));
				return refreshList().then(function() {
					return maybeReloadActive(res);
				}).then(function() {
					if (onDone)
						onDone(res);
				});
			}).catch(function(err) {
				if (!nimbusApi.isUploadCancelled(err))
					nimbusApi.notifyError(err);
			});
		}

		function openJsonEditor(profile) {
			nimbusApi.profileRead(profile.filename).then(function(res) {
				var content = '{\n}\n';
				if (res && res.ok)
					content = res.content || '';
				else if (res && res.code !== 'E_NOT_FOUND') {
					nimbusApi.notifyError(res);
					return;
				}

				var errBox = E('div', { 'style': 'display:none;' });
				var textarea = E('textarea', {
					'class': 'cbi-input-textarea',
					'rows': '18',
					'spellcheck': 'false',
					'style': 'width:100%;font-family:monospace;font-size:12px;resize:vertical;'
				}, content);

				var sizeLabel = E('span', { 'style': 'font-size:90%;color:#666;' });
				var validateCb = E('input', { 'type': 'checkbox', 'checked': 'checked' });
				var saveBtn = E('button', { 'type': 'button', 'class': 'btn cbi-button cbi-button-save' }, _('Save'));

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

				function showModalErr(msg) {
					errBox.style.display = 'block';
					dom.content(errBox, E('div', { 'class': 'alert-message error' }, msg));
				}

				saveBtn.addEventListener('click', function() {
					errBox.style.display = 'none';
					var raw = textarea.value;
					if (nimbusApi.utf8ByteLength(raw) > nimbusApi.MAX_DIRECT_TEXT_BYTES) {
						showModalErr(_('Content exceeds the 256 KiB inline transfer limit. Save locally and use "Upload .json" instead.'));
						return;
					}
					try {
						var parsed = JSON.parse(raw);
						if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
							showModalErr(_('Profile JSON must be a top-level object.'));
							return;
						}
					} catch (e) {
						showModalErr(_('Invalid JSON syntax: %s').format(e.message));
						return;
					}

					saveBtn.disabled = true;
					nimbusApi.profileSave({
						filename: profile.filename,
						content: raw,
						from_upload: false,
						validate: validateCb.checked
					}).then(function(sres) {
						saveBtn.disabled = false;
						if (!sres || sres.ok === false) {
							showModalErr(nimbusApi.formatError(sres));
							return;
						}
						ui.hideModal();
						nimbusApi.notifySuccess(sres.checked
							? _('Profile "%s" saved and validated with sing-box.').format(profile.filename)
							: _('Profile "%s" saved (JSON syntax checked).').format(profile.filename));
						return refreshList().then(function() {
							return maybeReloadActive(sres);
						});
					}).catch(function(err) {
						saveBtn.disabled = false;
						showModalErr(nimbusApi.formatError(err));
					});
				});

				ui.showModal(_('Edit Profile JSON: %s').format(profile.filename), [
					errBox,
					textarea,
					E('div', { 'style': 'display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;margin:8px 0 12px;' }, [
						sizeLabel,
						E('label', { 'style': 'display:flex;align-items:center;gap:6px;margin:0;font-weight:normal;' }, [
							validateCb,
							E('span', {}, _('Validate with sing-box check before saving'))
						])
					]),
					E('div', { 'style': 'display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px;' }, [
						E('button', {
							'type': 'button',
							'class': 'btn cbi-button cbi-button-action',
							'click': function(ev) {
								handleUploadJson(profile.filename, validateCb.checked, ev.currentTarget, function() {
									ui.hideModal();
								});
							}
						}, _('Upload .json File')),
						E('div', { 'style': 'display:flex;gap:8px;' }, [
							E('button', {
								'type': 'button',
								'class': 'btn cbi-button',
								'click': ui.hideModal
							}, _('Cancel')),
							saveBtn
						])
					])
				]);
			}).catch(function(err) {
				nimbusApi.notifyError(err);
			});
		}

		function openMetaModal(existing) {
			var isEdit = Boolean(existing && existing.id);
			var p = existing || {};
			var errBox = E('div', { 'style': 'display:none;' });

			var nameInput = E('input', {
				'type': 'text',
				'class': 'cbi-input-text',
				'value': p.name || '',
				'placeholder': _('e.g. Main Profile')
			});
			var typeSelect = E('select', { 'class': 'cbi-input-select' }, [
				E('option', { 'value': 'local', 'selected': (p.type || 'local') === 'local' ? 'selected' : null }, _('Local File')),
				E('option', { 'value': 'subscription', 'selected': p.type === 'subscription' ? 'selected' : null }, _('Remote Subscription'))
			]);
			var fileInput = E('input', {
				'type': 'text',
				'class': 'cbi-input-text',
				'value': p.filename || '',
				'placeholder': 'profile.json'
			});
			var urlInput = E('input', {
				'type': 'text',
				'class': 'cbi-input-text',
				'value': p.url || '',
				'placeholder': 'https://example.com/sing-box.json'
			});
			var uaInput = E('input', {
				'type': 'text',
				'class': 'cbi-input-text',
				'value': p.user_agent || 'sing-box/nimbus'
			});
			var viaProxyCb = E('input', {
				'type': 'checkbox',
				'checked': p.via_proxy ? 'checked' : null
			});
			var autoUpdateCb = E('input', {
				'type': 'checkbox',
				'checked': p.auto_update ? 'checked' : null
			});
			var intervalInput = E('input', {
				'type': 'number',
				'class': 'cbi-input-text',
				'min': '1',
				'max': '720',
				'value': String(p.update_interval_hours || 24)
			});

			var subRows = [
				E('div', { 'class': 'cbi-value' }, [
					E('label', { 'class': 'cbi-value-title' }, _('Subscription URL')),
					E('div', { 'class': 'cbi-value-field' }, urlInput)
				]),
				E('div', { 'class': 'cbi-value' }, [
					E('label', { 'class': 'cbi-value-title' }, _('User-Agent')),
					E('div', { 'class': 'cbi-value-field' }, uaInput)
				]),
				E('div', { 'class': 'cbi-value' }, [
					E('label', { 'class': 'cbi-value-title' }, _('Fetch via Proxy')),
					E('div', { 'class': 'cbi-value-field' }, viaProxyCb)
				]),
				E('div', { 'class': 'cbi-value' }, [
					E('label', { 'class': 'cbi-value-title' }, _('Auto Update')),
					E('div', { 'class': 'cbi-value-field' }, autoUpdateCb)
				]),
				E('div', { 'class': 'cbi-value' }, [
					E('label', { 'class': 'cbi-value-title' }, _('Update Interval (Hours)')),
					E('div', { 'class': 'cbi-value-field' }, [
						intervalInput,
						E('div', { 'class': 'cbi-value-description' }, _('Allowed range: 1 to 720 hours.'))
					])
				])
			];
			var subBox = E('div', {}, subRows);

			function syncTypeVisibility() {
				subBox.style.display = (typeSelect.value === 'subscription') ? 'block' : 'none';
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
				var ptype = typeSelect.value;
				var fname = fileInput.value.trim();
				var url = urlInput.value.trim();
				var intervalVal = null;

				if (!name) {
					showFormErr(_('Profile name is required.'));
					return;
				}
				if (!isValidProfileFilename(fname)) {
					showFormErr(_('Filename must match ^[A-Za-z0-9._-]+\\.json$ (no path separators or "..").'));
					return;
				}
				if (ptype === 'subscription') {
					if (!isHttpUrl(url)) {
						showFormErr(_('Subscription profile requires a valid http:// or https:// URL.'));
						return;
					}
					var parsedInt = parseInt(intervalInput.value, 10);
					if (isNaN(parsedInt) || parsedInt < 1 || parsedInt > 720 || String(parsedInt) !== intervalInput.value.trim()) {
						showFormErr(_('Update interval must be an integer between 1 and 720 hours.'));
						return;
					}
					intervalVal = parsedInt;
				}

				saveBtn.disabled = true;
				nimbusApi.profileMetaSave({
					section_id: isEdit ? p.id : '',
					name: name,
					type: ptype,
					filename: fname,
					url: ptype === 'subscription' ? url : '',
					user_agent: uaInput.value.trim() || 'sing-box/nimbus',
					via_proxy: ptype === 'subscription' ? viaProxyCb.checked : false,
					auto_update: ptype === 'subscription' ? autoUpdateCb.checked : false,
					update_interval_hours: intervalVal
				}).then(function(res) {
					saveBtn.disabled = false;
					if (!res || res.ok === false) {
						showFormErr(nimbusApi.formatError(res));
						return;
					}
					ui.hideModal();
					nimbusApi.notifySuccess(isEdit ? _('Profile metadata updated.') : _('Profile created.'));
					return refreshList();
				}).catch(function(err) {
					saveBtn.disabled = false;
					showFormErr(nimbusApi.formatError(err));
				});
			});

			ui.showModal(isEdit ? _('Edit Profile: %s').format(p.name || p.id) : _('Add Profile'), [
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
					E('label', { 'class': 'cbi-value-title' }, _('Filename')),
					E('div', { 'class': 'cbi-value-field' }, [
						fileInput,
						E('div', { 'class': 'cbi-value-description' }, _('Stored read-only under /etc/nimbus/profiles/, e.g. main_sub.json.'))
					])
				]),
				subBox,
				E('div', { 'class': 'right' }, [
					E('button', { 'type': 'button', 'class': 'btn cbi-button', 'click': ui.hideModal }, _('Cancel')),
					' ',
					saveBtn
				])
			]);
		}

		function runProfileUpdate(sectionId) {
			if (busy)
				return;
			busy = true;
			renderTable();

			nimbusApi.profileUpdate(sectionId || '').then(function(res) {
				busy = false;
				var results = (res && Array.isArray(res.results)) ? res.results : [];
				var updated = 0, unchanged = 0, failed = 0;
				var errs = [];
				results.forEach(function(r) {
					if (r.status === 'updated') updated++;
					else if (r.status === 'unchanged') unchanged++;
					else {
						failed++;
						errs.push('%s: %s'.format(r.id, r.error || _('failed')));
					}
				});
				if (!res || res.ok === false) {
					var msg = errs.length ? errs.join('; ') : nimbusApi.formatError(res);
					nimbusApi.notifyError(msg);
				} else {
					nimbusApi.notifySuccess(res.reloaded
						? _('Subscription update finished: %d updated, %d unchanged, service reloaded.').format(updated, unchanged)
						: _('Subscription update finished: %d updated, %d unchanged.').format(updated, unchanged));
				}
				return refreshList();
			}).catch(function(err) {
				busy = false;
				nimbusApi.notifyError(err);
				return refreshList();
			});
		}

		function activateProfile(profile) {
			if (busy)
				return;
			busy = true;
			renderTable();

			nimbusApi.profileActivate(profile.id, true).then(function(res) {
				busy = false;
				if (!res || res.ok === false) {
					nimbusApi.notifyError(res);
				} else {
					nimbusApi.notifySuccess(res.reloaded
						? _('Activated profile "%s" and reloaded service.').format(profile.name || profile.id)
						: _('Activated profile "%s".').format(profile.name || profile.id));
				}
				return refreshList();
			}).catch(function(err) {
				busy = false;
				nimbusApi.notifyError(err);
				return refreshList();
			});
		}

		function deleteProfile(profile) {
			nimbusApi.confirmAction(
				_('Delete Profile'),
				_('Delete profile "%s" (%s) and its configuration file?').format(profile.name || profile.id, profile.filename)
			).then(function(yes) {
				if (!yes)
					return;
				return nimbusApi.profileDelete(profile.id).then(function(res) {
					if (!res || res.ok === false)
						nimbusApi.notifyError(res);
					else
						nimbusApi.notifySuccess(_('Profile "%s" deleted.').format(profile.name || profile.id));
					return refreshList();
				});
			}).catch(function(err) {
				nimbusApi.notifyError(err);
			});
		}

		function renderTable() {
			var profiles = listData.profiles || [];
			var hasSubs = profiles.some(function(p) { return p.type === 'subscription'; });

			var toolbar = E('div', { 'style': 'display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;margin-bottom:12px;' }, [
				E('div', { 'style': 'display:flex;gap:8px;flex-wrap:wrap;' }, [
					E('button', {
						'type': 'button',
						'class': 'btn cbi-button cbi-button-add',
						'disabled': busy ? 'disabled' : null,
						'click': function() { openMetaModal(null); }
					}, _('Add Profile')),
					E('button', {
						'type': 'button',
						'class': 'btn cbi-button cbi-button-action',
						'disabled': (busy || !hasSubs) ? 'disabled' : null,
						'click': function() { runProfileUpdate(''); }
					}, _('Update All Subscriptions')),
					E('button', {
						'type': 'button',
						'class': 'btn cbi-button',
						'disabled': busy ? 'disabled' : null,
						'click': refreshList
					}, _('Refresh'))
				]),
				busy ? E('span', { 'class': 'spinning' }, _('Processing...')) : ''
			]);

			var rows = [
				E('tr', { 'class': 'tr cbi-section-table-titles' }, [
					E('th', { 'class': 'th' }, _('Name')),
					E('th', { 'class': 'th' }, _('Type')),
					E('th', { 'class': 'th' }, _('Filename')),
					E('th', { 'class': 'th' }, _('File Status')),
					E('th', { 'class': 'th' }, _('Subscription')),
					E('th', { 'class': 'th right' }, _('Actions'))
				])
			];

			if (profiles.length === 0) {
				rows.push(E('tr', { 'class': 'tr' }, [
					E('td', { 'class': 'td center', 'colspan': '6' }, _('No profiles configured. Click "Add Profile" to create one.'))
				]));
			} else {
				profiles.forEach(function(p) {
					var nameCell = E('div', { 'style': 'display:flex;align-items:center;gap:6px;flex-wrap:wrap;' }, [
						E('strong', {}, p.name || p.id),
						p.active ? makeBadge(_('Active'), '#e6f4ea', '#137333') : ''
					]);

					var fileCell = p.exists
						? E('div', {}, [
							E('div', {}, nimbusApi.formatBytes(p.size_bytes || 0)),
							E('div', { 'style': 'font-size:85%;color:#666;' }, nimbusApi.formatTimestamp(p.mtime))
						])
						: makeBadge(_('Missing'), '#fef7e0', '#b06000');

					var subCell = '-';
					if (p.type === 'subscription') {
						var metaParts = [];
						if (p.auto_update)
							metaParts.push(_('Auto: %dh').format(p.update_interval_hours || 24));
						else
							metaParts.push(_('Manual'));
						if (p.via_proxy)
							metaParts.push(_('Via Proxy'));
						subCell = E('div', {}, [
							E('div', { 'style': 'max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;', 'title': p.url || '' }, p.url || '-'),
							E('div', { 'style': 'font-size:85%;color:#666;' }, metaParts.join(' · '))
						]);
					}

					var actBtns = [
						E('button', {
							'type': 'button',
							'class': 'btn cbi-button cbi-button-apply',
							'disabled': (busy || p.active) ? 'disabled' : null,
							'click': function() { activateProfile(p); }
						}, _('Activate')),
						E('button', {
							'type': 'button',
							'class': 'btn cbi-button cbi-button-edit',
							'disabled': busy ? 'disabled' : null,
							'click': function() { openJsonEditor(p); }
						}, _('Edit JSON')),
						E('button', {
							'type': 'button',
							'class': 'btn cbi-button cbi-button-action',
							'disabled': busy ? 'disabled' : null,
							'click': function(ev) { handleUploadJson(p.filename, true, ev.currentTarget); }
						}, _('Upload .json'))
					];

					if (p.type === 'subscription') {
						actBtns.push(E('button', {
							'type': 'button',
							'class': 'btn cbi-button cbi-button-neutral',
							'disabled': busy ? 'disabled' : null,
							'click': function() { runProfileUpdate(p.id); }
						}, _('Update')));
					}

					actBtns.push(
						E('button', {
							'type': 'button',
							'class': 'btn cbi-button',
							'disabled': busy ? 'disabled' : null,
							'click': function() { openMetaModal(p); }
						}, _('Meta')),
						E('button', {
							'type': 'button',
							'class': 'btn cbi-button cbi-button-negative',
							'disabled': (busy || p.active) ? 'disabled' : null,
							'click': function() { deleteProfile(p); }
						}, _('Delete'))
					);

					rows.push(E('tr', { 'class': 'tr cbi-section-table-row' }, [
						E('td', { 'class': 'td' }, nameCell),
						E('td', { 'class': 'td' }, p.type === 'subscription' ? _('Subscription') : _('Local')),
						E('td', { 'class': 'td' }, E('code', {}, p.filename || '-')),
						E('td', { 'class': 'td' }, fileCell),
						E('td', { 'class': 'td' }, subCell),
						E('td', { 'class': 'td right' }, E('div', { 'style': 'display:flex;gap:4px;justify-content:flex-end;flex-wrap:wrap;' }, actBtns))
					]));
				});
			}

			dom.content(tableContainer, [
				toolbar,
				E('table', { 'class': 'table cbi-section-table' }, rows)
			]);
		}

		renderTable();

		return E('div', { 'class': 'cbi-map' }, [
			E('h2', {}, _('Nimbus Profiles')),
			E('div', { 'class': 'cbi-map-descr' },
				_('Manage sing-box JSON configurations and remote subscriptions. Source files in /etc/nimbus/profiles/ remain read-only; Nimbus generates runtime config in memory.')),
			tableContainer
		]);
	}
});
