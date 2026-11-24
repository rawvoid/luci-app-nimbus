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

return view.extend({
	handleSave: null,
	handleSaveApply: null,
	handleReset: null,

	load: function() {
		return nimbusApi.profileList();
	},

	render: function(initialData) {
		var rawList = initialData || null;
		if (rawList && rawList.ok === false)
			nimbusApi.notifyError(rawList);

		var listData = (rawList && rawList.ok !== false)
			? rawList
			: { active_profile: '', profiles: [] };

		var tableContainer = E('div', { 'class': 'cbi-section' });
		var busy = false;

		function isProfileInUse(profile) {
			if (!profile)
				return false;
			if (profile.active)
				return true;
			return (Array.isArray(profile.used_by_composers) && profile.used_by_composers.length > 0);
		}

		function refreshAll() {
			return nimbusApi.profileList().then(function(pRes) {
				if (!pRes || pRes.ok === false) {
					nimbusApi.notifyError(pRes);
					return;
				}
				listData = pRes;
				renderTable();
			}).catch(function(err) {
				nimbusApi.notifyError(err);
			});
		}

		function notifySaveSuccess(filename, res, verb) {
			var msg;
			if (verb === 'uploaded') {
				if (res.checked) {
					msg = res.reload_required
						? _('Profile "%s" uploaded and validated with sing-box. Reload service to apply changes.').format(filename)
						: _('Profile "%s" uploaded and validated with sing-box.').format(filename);
				} else {
					msg = res.reload_required
						? _('Profile "%s" uploaded (JSON syntax checked). Reload service to apply changes.').format(filename)
						: _('Profile "%s" uploaded (JSON syntax checked).').format(filename);
				}
			} else {
				if (res.checked) {
					msg = res.reload_required
						? _('Profile "%s" saved and validated with sing-box. Reload service to apply changes.').format(filename)
						: _('Profile "%s" saved and validated with sing-box.').format(filename);
				} else {
					msg = res.reload_required
						? _('Profile "%s" saved (JSON syntax checked). Reload service to apply changes.').format(filename)
						: _('Profile "%s" saved (JSON syntax checked).').format(filename);
				}
			}
			nimbusApi.notifySuccess(msg);
		}

		function handleUploadJson(filename, validate, btn, onDone) {
			return nimbusApi.uploadProfileFile(btn).then(function() {
				return nimbusApi.profileSave({
					filename: filename,
					from_upload: true,
					validate: validate !== false
				});
			}).then(function(res) {
				if (!res || res.ok === false) {
					nimbusApi.notifyError(res);
					return;
				}
				notifySaveSuccess(filename, res, 'uploaded');
				return refreshAll().then(function() {
					if (onDone)
						onDone(res);
				});
			}).catch(function(err) {
				if (!nimbusApi.isUploadCancelled(err))
					nimbusApi.notifyError(err);
			});
		}

		function openJsonEditor(profile) {
			return nimbusApi.profileRead(profile.filename).then(function(res) {
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
					'style': 'width:100%;font-family:monospace;resize:vertical;'
				}, content);

				var sizeLabel = E('small', { 'style': 'opacity:0.75;' });
				var validateCb = E('input', { 'type': 'checkbox', 'checked': 'checked' });
				var saveBtn = E('button', { 'type': 'button', 'class': 'btn cbi-button cbi-button-save' }, _('Save'));

				function updateByteCount() {
					var len = nimbusApi.utf8ByteLength(textarea.value);
					var over = len > nimbusApi.MAX_DIRECT_TEXT_BYTES;
					var txt = _('%s / %s direct limit').format(
						nimbusApi.formatBytes(len),
						nimbusApi.formatBytes(nimbusApi.MAX_DIRECT_TEXT_BYTES)
					);
					sizeLabel.style.opacity = over ? '1' : '0.75';
					dom.content(sizeLabel, over ? E('strong', {}, txt) : txt);
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
						if (profile.as_config) {
							if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
								showModalErr(_('Standalone configuration JSON must be a top-level object.'));
								return;
							}
						} else {
							if (!parsed || typeof parsed !== 'object' || (Array.isArray(parsed) && parsed.length === 0)) {
								showModalErr(_('Source JSON must be a top-level object or a non-empty array.'));
								return;
							}
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
						notifySaveSuccess(profile.filename, sres, 'saved');
						return refreshAll();
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
				E('option', { 'value': 'subscription', 'selected': (p.type || 'subscription') === 'subscription' ? 'selected' : null }, _('Remote Subscription')),
				E('option', { 'value': 'local', 'selected': p.type === 'local' ? 'selected' : null }, _('Local File'))
			]);
			var fileInput = E('input', {
				'type': 'text',
				'class': 'cbi-input-text',
				'value': p.filename || '',
				'placeholder': 'main_sub.json'
			});
			var initialType = p.type || 'subscription';
			var initialAsConfig = isEdit ? Boolean(p.as_config) : (initialType === 'local');
			var asConfigTouched = isEdit;
			var asConfigCb = E('input', {
				'type': 'checkbox',
				'checked': initialAsConfig ? 'checked' : null,
				'disabled': (isEdit && p.active) ? 'disabled' : null,
				'change': function() {
					asConfigTouched = true;
				}
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

			var subBox = E('div', {}, [
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
			]);

			function syncTypeVisibility() {
				var isSub = (typeSelect.value === 'subscription');
				subBox.style.display = isSub ? 'block' : 'none';
				if (!asConfigTouched)
					asConfigCb.checked = !isSub;
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
					as_config: asConfigCb.checked,
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
					nimbusApi.notifySuccess(isEdit ? _('Subscription metadata updated.') : _('Subscription created.'));
					return refreshAll();
				}).catch(function(err) {
					saveBtn.disabled = false;
					showFormErr(nimbusApi.formatError(err));
				});
			});

			ui.showModal(isEdit ? _('Edit Subscription: %s').format(p.name || p.id) : _('Add Subscription'), [
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
				E('div', { 'class': 'cbi-value' }, [
					E('label', { 'class': 'cbi-value-title' }, _('Allow as Active Config')),
					E('div', { 'class': 'cbi-value-field' }, [
						asConfigCb,
						E('div', { 'class': 'cbi-value-description' }, (isEdit && p.active)
							? _('Currently selected as the active configuration in Settings. Switch active configuration first to disable.')
							: _('Allow selecting this file directly as the Active Configuration in Settings (requires a complete sing-box JSON object).'))
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
				return Promise.resolve();
			busy = true;
			renderTable();

			return nimbusApi.profileUpdate(sectionId || '').then(function(res) {
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
				if (!res || (res.ok === false && failed === 0)) {
					nimbusApi.notifyError(res);
				} else if (failed > 0) {
					var summary = res.reloaded
						? _('Subscription update finished: %d updated, %d unchanged, %d failed, service reloaded.').format(updated, unchanged, failed)
						: _('Subscription update finished: %d updated, %d unchanged, %d failed.').format(updated, unchanged, failed);
					var notice = errs.length
						? E('div', {}, [ E('p', {}, summary), E('p', {}, errs.join('; ')) ])
						: E('p', {}, summary);
					ui.addNotification(null, notice, 'warning');
				} else {
					nimbusApi.notifySuccess(res.reloaded
						? _('Subscription update finished: %d updated, %d unchanged, service reloaded.').format(updated, unchanged)
						: _('Subscription update finished: %d updated, %d unchanged.').format(updated, unchanged));
				}
				return refreshAll();
			}).catch(function(err) {
				busy = false;
				nimbusApi.notifyError(err);
				return refreshAll();
			});
		}

		function deleteProfile(profile) {
			return nimbusApi.confirmAction(
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
					return refreshAll();
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
					}, _('Add Subscription')),
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
						'click': refreshAll
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
					E('td', { 'class': 'td center', 'colspan': '6' }, _('No subscriptions or profiles configured. Click "Add Subscription" to create one.'))
				]));
			} else {
				profiles.forEach(function(p) {
					var inUse = isProfileInUse(p);
					var usedBy = Array.isArray(p.used_by_composers) ? p.used_by_composers : [];
					var nameNodes = [ E('strong', {}, p.name || p.id) ];
					if (p.active)
						nameNodes.push(E('span', { 'class': 'label' }, _('Active')));
					else if (p.as_config)
						nameNodes.push(E('span', { 'class': 'label notice' }, _('Standalone Config')));

					var nameCellChildren = [
						E('div', { 'style': 'display:flex;align-items:center;gap:6px;flex-wrap:wrap;' }, nameNodes)
					];
					if (usedBy.length > 0) {
						var refNames = usedBy.map(function(r) { return r.name || r.id; }).join(', ');
						nameCellChildren.push(E('small', { 'style': 'opacity:0.75;' },
							_('Used by: %s').format(refNames)));
					}
					var nameCell = E('div', {}, nameCellChildren);

					var deleteTitle = null;
					if (p.active)
						deleteTitle = _('Cannot delete while selected as Active Configuration in Settings.');
					else if (usedBy.length > 0)
						deleteTitle = _('Cannot delete while enabled as a source in Composer: %s').format(
							usedBy.map(function(r) { return r.name || r.id; }).join(', ')
						);

					var fileCell = p.exists
						? E('div', {}, [
							E('div', {}, nimbusApi.formatBytes(p.size_bytes || 0)),
							E('small', { 'style': 'opacity:0.75;' }, nimbusApi.formatTimestamp(p.mtime))
						])
						: E('em', {}, _('Missing'));

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
							E('small', { 'style': 'opacity:0.75;' }, metaParts.join(' · '))
						]);
					}

					var actBtns = [
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
							'disabled': (busy || inUse) ? 'disabled' : null,
							'title': deleteTitle,
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
				E('div', { 'style': 'overflow-x:auto;' }, [
					E('table', { 'class': 'table cbi-section-table' }, rows)
				])
			]);
		}

		renderTable();

		return E('div', { 'class': 'cbi-map' }, [
			E('h2', {}, _('Nimbus Subscriptions')),
			E('div', { 'class': 'cbi-map-descr' },
				_('Manage remote sing-box subscriptions and local JSON files stored read-only under /etc/nimbus/profiles/. Enable "Allow as Active Config" to select a complete file directly in Settings, or use any item as a node source in Composer.')),
			tableContainer
		]);
	}
});
