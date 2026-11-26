'use strict';
'require view';
'require dom';
'require ui';
'require nimbus.api as nimbusApi';
'require nimbus.composer as composerView';
'require nimbus.composer_snippets as snippets';

function isValidComposerFilename(name) {
	if (typeof name !== 'string' || !/^[A-Za-z0-9._-]+\.json$/.test(name))
		return false;
	return (name.indexOf('..') < 0 && name !== '.json');
}

function showStandalonePreviewModal(profile) {
	var bodyBox = E('div', {}, [
		E('p', {}, E('span', { 'class': 'spinning' }, _('Synthesizing configuration and running sing-box check...')))
	]);

	ui.showModal(_('Preview & Check: %s').format(profile.name || profile.id), [
		bodyBox,
		E('div', { 'class': 'right', 'style': 'margin-top:12px;' }, [
			E('button', { 'type': 'button', 'class': 'btn cbi-button', 'click': ui.hideModal }, _('Close'))
		])
	]);

	return nimbusApi.profilePreview(profile.id, true).then(function(res) {
		if (!res || res.ok === false) {
			dom.content(bodyBox, E('div', { 'class': 'alert-message error' }, nimbusApi.formatError(res)));
			return;
		}

		var effectiveText = res.effective_json || snippets.prettyJson(res.effective || {});
		var statusBadge;
		if (res.checked) {
			statusBadge = res.check_ok
				? E('span', { 'class': 'label' }, _('sing-box check: Passed'))
				: E('strong', {}, _('sing-box check: Failed'));
		} else {
			statusBadge = E('em', {}, _('Preview Only (sing-box binary not installed)'));
		}

		var blocks = [
			E('div', { 'style': 'display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;margin-bottom:10px;' }, [
				statusBadge,
				E('code', {}, profile.filename || '-')
			])
		];

		if (res.checked && !res.check_ok && res.check_error) {
			blocks.push(E('div', { 'class': 'alert-message error', 'style': 'margin-bottom:10px;' }, [
				E('strong', {}, _('Validation Error:')),
				E('pre', { 'style': 'margin:6px 0 0;white-space:pre-wrap;word-break:break-word;font-size:11px;' }, res.check_error)
			]));
		}

		if (Array.isArray(res.warnings) && res.warnings.length > 0) {
			blocks.push(E('div', { 'class': 'alert-message warning', 'style': 'margin-bottom:10px;' }, [
				E('strong', {}, _('Warnings:')),
				E('ul', { 'style': 'margin:4px 0 0 18px;' }, res.warnings.map(function(w) {
					return E('li', {}, w);
				}))
			]));
		}

		blocks.push(E('div', { 'style': 'margin-bottom:6px;' }, [
			E('strong', {}, _('Effective Runtime JSON (Stage B)'))
		]));
		blocks.push(E('textarea', {
			'class': 'cbi-input-textarea',
			'rows': '17',
			'readonly': 'readonly',
			'spellcheck': 'false',
			'style': 'width:100%;font-family:monospace;font-size:12px;resize:vertical;'
		}, effectiveText));
		blocks.push(E('div', { 'style': 'display:flex;justify-content:flex-start;margin-top:8px;' }, [
			E('button', {
				'type': 'button',
				'class': 'btn cbi-button cbi-button-action',
				'click': function() {
					nimbusApi.copyToClipboard(effectiveText).then(function() {
						nimbusApi.notifySuccess(_('JSON copied to clipboard.'));
					}, function() {
						nimbusApi.notifyError(_('Failed to copy to clipboard.'));
					});
				}
			}, _('Copy JSON'))
		]));

		dom.content(bodyBox, blocks);
	}).catch(function(err) {
		dom.content(bodyBox, E('div', { 'class': 'alert-message error' }, nimbusApi.formatError(err)));
	});
}

return view.extend({
	load: function() {
		return Promise.all([
			nimbusApi.composerList(),
			nimbusApi.profileList()
		]);
	},

	addFooter: function() {
		var frag = this.super('addFooter', []);
		var actions = null;
		if (frag) {
			if (frag.nodeType === 1)
				actions = frag;
			else if (typeof frag.querySelector === 'function')
				actions = frag.querySelector('.cbi-page-actions') || frag.firstElementChild || null;
		}
		this._footerEl = actions;
		if (typeof this._syncFooter === 'function')
			this._syncFooter();
		return frag;
	},

	handleSave: function() {
		if (this._composerCtrl && typeof this._composerCtrl.save === 'function')
			return this._composerCtrl.save(false);
		return Promise.resolve();
	},

	handleSaveApply: function() {
		if (this._composerCtrl && typeof this._composerCtrl.save === 'function')
			return this._composerCtrl.save(true);
		return Promise.resolve();
	},

	handleReset: function() {
		if (this._composerCtrl && typeof this._composerCtrl.reset === 'function')
			return this._composerCtrl.reset();
		return Promise.resolve();
	},

	render: function(initialData) {
		var self = this;
		var rawComposers = (initialData && initialData[0]) ? initialData[0] : null;
		var rawProfiles = (initialData && initialData[1]) ? initialData[1] : null;
		if (rawComposers && rawComposers.ok === false)
			nimbusApi.notifyError(rawComposers);
		if (rawProfiles && rawProfiles.ok === false)
			nimbusApi.notifyError(rawProfiles);

		var composerListData = (rawComposers && rawComposers.ok !== false)
			? rawComposers
			: { active_profile: '', composers: [] };
		var profileListData = (rawProfiles && rawProfiles.ok !== false)
			? rawProfiles
			: { active_profile: '', profiles: [] };

		var editingId = null;
		var busy = false;
		self._composerCtrl = null;

		var composersSection = E('div', { 'class': 'cbi-section' });
		var standaloneSection = E('div', { 'class': 'cbi-section' });
		var listWrap = E('div', {}, [ composersSection, standaloneSection ]);
		var editorWrap = E('div', { 'style': 'display:none;' });

		self._syncFooter = function() {
			if (self._footerEl && self._footerEl.style)
				self._footerEl.style.display = editingId ? '' : 'none';
		};

		function destroyEditorCtrl() {
			if (self._composerCtrl && typeof self._composerCtrl.destroy === 'function')
				self._composerCtrl.destroy();
			self._composerCtrl = null;
		}

		function refreshLists() {
			return Promise.all([
				nimbusApi.composerList(),
				nimbusApi.profileList()
			]).then(function(results) {
				var cRes = results[0];
				var pRes = results[1];
				if (cRes && cRes.ok !== false)
					composerListData = cRes;
				else if (cRes && cRes.ok === false)
					nimbusApi.notifyError(cRes);

				if (pRes && pRes.ok !== false)
					profileListData = pRes;
				else if (pRes && pRes.ok === false)
					nimbusApi.notifyError(pRes);

				renderListViews();
			}).catch(function(err) {
				nimbusApi.notifyError(err);
			});
		}

		function closeEditor() {
			var finish = function() {
				destroyEditorCtrl();
				editingId = null;
				dom.content(editorWrap, '');
				editorWrap.style.display = 'none';
				listWrap.style.display = '';
				self._syncFooter();
				return refreshLists();
			};

			if (self._composerCtrl && typeof self._composerCtrl.isDirty === 'function' && self._composerCtrl.isDirty()) {
				return nimbusApi.confirmAction(
					_('Discard Unsaved Changes'),
					_('You have unsaved changes in this Composer configuration. Discard them and return to the list?')
				).then(function(yes) {
					if (yes)
						return finish();
				});
			}
			return finish();
		}

		function openEditor(sectionId) {
			if (busy)
				return Promise.resolve();
			busy = true;
			renderListViews();

			return Promise.all([
				nimbusApi.composerGet(sectionId),
				nimbusApi.profileList()
			]).then(function(results) {
				busy = false;
				var cRes = results[0];
				var pRes = results[1];
				if (!cRes || cRes.ok === false) {
					nimbusApi.notifyError(cRes);
					renderListViews();
					return;
				}
				if (pRes && pRes.ok !== false)
					profileListData = pRes;

				destroyEditorCtrl();
				editingId = sectionId;
				var ws = composerView.renderWorkspace({
					sectionId: sectionId,
					initialComposerData: cRes,
					initialProfileList: profileListData,
					onBack: function() {
						closeEditor();
					},
					onController: function(ctrl) {
						self._composerCtrl = ctrl;
					},
					onSaved: function() {
						refreshLists();
					}
				});

				dom.content(editorWrap, ws);
				listWrap.style.display = 'none';
				editorWrap.style.display = '';
				self._syncFooter();
			}).catch(function(err) {
				busy = false;
				nimbusApi.notifyError(err);
				renderListViews();
			});
		}

		function openCreateModal(presetOpts) {
			var opts = presetOpts || {};
			var isClone = Boolean(opts.cloneFrom);
			var allProfiles = profileListData.profiles || [];
			var errBox = E('div', { 'style': 'display:none;' });

			var nameInput = E('input', {
				'type': 'text',
				'class': 'cbi-input-text',
				'value': opts.defaultName || '',
				'placeholder': _('e.g. Main Router')
			});
			var fileInput = E('input', {
				'type': 'text',
				'class': 'cbi-input-text',
				'value': '',
				'placeholder': _('Auto-generated if empty, e.g. main_router.json')
			});

			var initSelect = E('select', { 'class': 'cbi-input-select' }, [
				E('option', { 'value': 'standard', 'selected': (!opts.initMode || opts.initMode === 'standard') ? 'selected' : null }, _('1.14 Standard Router Split')),
				E('option', { 'value': 'blank', 'selected': opts.initMode === 'blank' ? 'selected' : null }, _('Blank Canvas')),
				E('option', { 'value': 'import_profile', 'selected': opts.initMode === 'import_profile' ? 'selected' : null }, _('Import from Subscription / Local File')),
				E('option', { 'value': 'import_json', 'selected': opts.initMode === 'import_json' ? 'selected' : null }, _('Import from Raw sing-box JSON'))
			]);

			var profSelect = E('select', { 'class': 'cbi-input-select' }, [
				E('option', { 'value': '' }, _('-- Select Profile --'))
			].concat(allProfiles.map(function(p) {
				var label = p.name ? '%s (%s)'.format(p.name, p.filename) : p.id;
				return E('option', {
					'value': p.id,
					'selected': (opts.importProfileId && opts.importProfileId === p.id) ? 'selected' : null
				}, label);
			})));

			var jsonTextarea = E('textarea', {
				'class': 'cbi-input-textarea',
				'rows': '8',
				'spellcheck': 'false',
				'placeholder': _('Paste full sing-box JSON object here...'),
				'style': 'width:100%;font-family:monospace;font-size:12px;resize:vertical;'
			});

			var importProfRow = E('div', { 'class': 'cbi-value' }, [
				E('label', { 'class': 'cbi-value-title' }, _('Source Profile')),
				E('div', { 'class': 'cbi-value-field' }, profSelect)
			]);
			var importJsonRow = E('div', { 'class': 'cbi-value' }, [
				E('label', { 'class': 'cbi-value-title' }, _('sing-box JSON')),
				E('div', { 'class': 'cbi-value-field' }, jsonTextarea)
			]);

			function syncModeRows() {
				var mode = isClone ? 'clone' : initSelect.value;
				importProfRow.style.display = (mode === 'import_profile') ? '' : 'none';
				importJsonRow.style.display = (mode === 'import_json') ? '' : 'none';
			}
			initSelect.addEventListener('change', syncModeRows);
			syncModeRows();

			function showFormErr(msg) {
				errBox.style.display = 'block';
				dom.content(errBox, E('div', { 'class': 'alert-message error' }, msg));
			}

			var createBtn = E('button', {
				'type': 'button',
				'class': 'btn cbi-button cbi-button-save'
			}, isClone ? _('Clone') : _('Create'));

			createBtn.addEventListener('click', function() {
				errBox.style.display = 'none';
				var name = nameInput.value.trim();
				var fname = fileInput.value.trim();
				var mode = isClone ? 'clone' : initSelect.value;

				if (!name) {
					showFormErr(_('Configuration name is required.'));
					return;
				}
				if (fname && !isValidComposerFilename(fname)) {
					showFormErr(_('Filename must match ^[A-Za-z0-9._-]+\\.json$ (no path separators or "..").'));
					return;
				}

				var payload = {
					name: name,
					filename: fname || undefined,
					init_mode: mode
				};

				if (mode === 'clone') {
					payload.clone_from = opts.cloneFrom;
				} else if (mode === 'import_profile') {
					var pid = profSelect.value;
					if (!pid) {
						showFormErr(_('Please select a profile to import.'));
						return;
					}
					payload.import_profile_id = pid;
				} else if (mode === 'import_json') {
					var raw = jsonTextarea.value;
					if (!raw.trim()) {
						showFormErr(_('Please paste a sing-box JSON configuration.'));
						return;
					}
					if (nimbusApi.utf8ByteLength(raw) > nimbusApi.MAX_DIRECT_TEXT_BYTES) {
						showFormErr(_('Content exceeds the 256 KiB inline transfer limit.'));
						return;
					}
					var parsed = snippets.parseJsonObject(raw);
					if (!parsed.ok) {
						showFormErr(parsed.error);
						return;
					}
					payload.content = raw;
				}

				createBtn.disabled = true;
				nimbusApi.composerCreate(payload).then(function(res) {
					createBtn.disabled = false;
					if (!res || res.ok === false) {
						showFormErr(nimbusApi.formatError(res));
						return;
					}
					ui.hideModal();
					if (Array.isArray(res.warnings) && res.warnings.length > 0) {
						ui.addNotification(null, E('div', {}, [
							E('strong', {}, _('Import Warnings:')),
							E('ul', { 'style': 'margin:4px 0 0 18px;' }, res.warnings.map(function(w) {
								return E('li', {}, w);
							}))
						]), 'warning');
					}
					if (isClone) {
						nimbusApi.notifySuccess(_('Composer "%s" cloned.').format(res.name || name));
						return refreshLists();
					}
					nimbusApi.notifySuccess(_('Composer "%s" created.').format(res.name || name));
					return refreshLists().then(function() {
						return openEditor(res.section_id);
					});
				}).catch(function(err) {
					createBtn.disabled = false;
					showFormErr(nimbusApi.formatError(err));
				});
			});

			var fields = [
				errBox,
				E('div', { 'class': 'cbi-value' }, [
					E('label', { 'class': 'cbi-value-title' }, _('Name')),
					E('div', { 'class': 'cbi-value-field' }, nameInput)
				]),
				E('div', { 'class': 'cbi-value' }, [
					E('label', { 'class': 'cbi-value-title' }, _('Filename')),
					E('div', { 'class': 'cbi-value-field' }, [
						fileInput,
						E('div', { 'class': 'cbi-value-description' }, _('Stored under /etc/nimbus/composers/. Leave empty to auto-generate.'))
					])
				])
			];

			if (isClone) {
				fields.push(E('div', { 'class': 'cbi-value' }, [
					E('label', { 'class': 'cbi-value-title' }, _('Clone Source')),
					E('div', { 'class': 'cbi-value-field' }, E('strong', {}, opts.cloneSourceName || opts.cloneFrom))
				]));
			} else {
				fields.push(E('div', { 'class': 'cbi-value' }, [
					E('label', { 'class': 'cbi-value-title' }, _('Initialization')),
					E('div', { 'class': 'cbi-value-field' }, initSelect)
				]));
				fields.push(importProfRow);
				fields.push(importJsonRow);
			}

			fields.push(E('div', { 'class': 'right' }, [
				E('button', { 'type': 'button', 'class': 'btn cbi-button', 'click': ui.hideModal }, _('Cancel')),
				' ',
				createBtn
			]));

			ui.showModal(
				isClone
					? _('Clone Composer: %s').format(opts.cloneSourceName || opts.cloneFrom)
					: _('Add Composer Configuration'),
				fields
			);
		}

		function deleteComposer(comp) {
			return nimbusApi.confirmAction(
				_('Delete Composer Configuration'),
				_('Delete Composer "%s" (%s) and its JSON file?').format(comp.name || comp.id, comp.filename)
			).then(function(yes) {
				if (!yes)
					return;
				return nimbusApi.composerDelete(comp.id).then(function(res) {
					if (!res || res.ok === false)
						nimbusApi.notifyError(res);
					else
						nimbusApi.notifySuccess(_('Composer "%s" deleted.').format(comp.name || comp.id));
					return refreshLists();
				});
			}).catch(function(err) {
				nimbusApi.notifyError(err);
			});
		}

		function renderComposersSection() {
			var composers = composerListData.composers || [];
			var settingsUrl = L.url('admin', 'services', 'nimbus', 'settings');

			var toolbar = E('div', { 'style': 'display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;margin-bottom:12px;' }, [
				E('div', { 'style': 'display:flex;gap:8px;flex-wrap:wrap;' }, [
					E('button', {
						'type': 'button',
						'class': 'btn cbi-button cbi-button-add',
						'disabled': busy ? 'disabled' : null,
						'click': function() { openCreateModal(); }
					}, _('Add Composer')),
					E('button', {
						'type': 'button',
						'class': 'btn cbi-button',
						'disabled': busy ? 'disabled' : null,
						'click': refreshLists
					}, _('Refresh'))
				]),
				busy ? E('span', { 'class': 'spinning' }, _('Processing...')) : ''
			]);

			var rows = [
				E('tr', { 'class': 'tr cbi-section-table-titles' }, [
					E('th', { 'class': 'th' }, _('Name')),
					E('th', { 'class': 'th' }, _('Filename')),
					E('th', { 'class': 'th' }, _('Summary')),
					E('th', { 'class': 'th' }, _('Last Updated')),
					E('th', { 'class': 'th right' }, _('Actions'))
				])
			];

			if (composers.length === 0) {
				rows.push(E('tr', { 'class': 'tr' }, [
					E('td', { 'class': 'td center', 'colspan': '5' },
						_('No Composer configurations yet. Click "Add Composer" to create one.'))
				]));
			} else {
				composers.forEach(function(c) {
					var nameNodes = [ E('strong', {}, c.name || c.id) ];
					if (c.active)
						nameNodes.push(E('span', { 'class': 'label' }, _('Active')));
					var nameCell = E('div', { 'style': 'display:flex;align-items:center;gap:6px;flex-wrap:wrap;' }, nameNodes);

					var sum = c.summary || {};
					var summaryEl = c.exists
						? E('small', { 'style': 'opacity:0.85;' }, _('%d sources · %d nodes · %d groups · %d rules').format(
							sum.enabled_sources || 0,
							sum.extracted_nodes || 0,
							sum.groups || 0,
							sum.route_rules || 0
						))
						: E('em', {}, _('Missing'));

					var actBtns = [
						E('button', {
							'type': 'button',
							'class': 'btn cbi-button cbi-button-edit',
							'disabled': busy ? 'disabled' : null,
							'click': function() { openEditor(c.id); }
						}, _('Edit')),
						E('button', {
							'type': 'button',
							'class': 'btn cbi-button cbi-button-action',
							'disabled': (busy || !c.exists) ? 'disabled' : null,
							'click': function() {
								composerView.showPreviewModal(_('Preview & Check: %s').format(c.name || c.id), {
									section_id: c.id,
									validate: true
								});
							}
						}, _('Preview & Check')),
						E('button', {
							'type': 'button',
							'class': 'btn cbi-button',
							'disabled': (busy || !c.exists) ? 'disabled' : null,
							'click': function() {
								openCreateModal({
									cloneFrom: c.id,
									cloneSourceName: c.name || c.id,
									defaultName: _('%s (Copy)').format(c.name || c.id)
								});
							}
						}, _('Clone')),
						E('button', {
							'type': 'button',
							'class': 'btn cbi-button cbi-button-negative',
							'disabled': (busy || c.active) ? 'disabled' : null,
							'title': c.active ? _('Cannot delete while selected as Active Configuration in Settings.') : null,
							'click': function() { deleteComposer(c); }
						}, _('Delete'))
					];

					rows.push(E('tr', { 'class': 'tr cbi-section-table-row' }, [
						E('td', { 'class': 'td' }, nameCell),
						E('td', { 'class': 'td' }, E('code', {}, c.filename || '-')),
						E('td', { 'class': 'td' }, summaryEl),
						E('td', { 'class': 'td' }, c.mtime ? nimbusApi.formatTimestamp(c.mtime) : '-'),
						E('td', { 'class': 'td right', 'style': 'white-space:nowrap;' }, E('div', {
							'style': 'display:flex;gap:4px;justify-content:flex-end;flex-wrap:wrap;'
						}, actBtns))
					]));
				});
			}

			dom.content(composersSection, [
				E('h3', {}, _('Composer Configurations')),
				E('div', { 'class': 'cbi-section-descr' }, [
					E('span', {}, _('Maintain multiple structured sing-box Composer blueprints under /etc/nimbus/composers/. Select the active configuration in: ')),
					E('a', { 'href': settingsUrl }, _('Settings'))
				]),
				toolbar,
				E('div', { 'style': 'overflow-x:auto;' }, [
					E('table', { 'class': 'table cbi-section-table' }, rows)
				])
			]);
		}

		function renderStandaloneSection() {
			var standalone = (profileListData.profiles || []).filter(function(p) {
				return Boolean(p && p.as_config);
			});
			var subUrl = L.url('admin', 'services', 'nimbus', 'subscriptions');
			var settingsUrl = L.url('admin', 'services', 'nimbus', 'settings');

			var rows = [
				E('tr', { 'class': 'tr cbi-section-table-titles' }, [
					E('th', { 'class': 'th' }, _('Name')),
					E('th', { 'class': 'th' }, _('Type')),
					E('th', { 'class': 'th' }, _('Filename')),
					E('th', { 'class': 'th' }, _('File Status')),
					E('th', { 'class': 'th right' }, _('Actions'))
				])
			];

			if (standalone.length === 0) {
				rows.push(E('tr', { 'class': 'tr' }, [
					E('td', { 'class': 'td center', 'colspan': '5' }, [
						E('span', {}, _('No standalone subscriptions or local JSON configurations enabled. Enable "Allow as Active Config" in: ')),
						E('a', { 'href': subUrl }, _('Subscriptions'))
					])
				]));
			} else {
				standalone.forEach(function(p) {
					var nameNodes = [ E('strong', {}, p.name || p.id) ];
					if (p.active)
						nameNodes.push(E('span', { 'class': 'label' }, _('Active')));

					var fileCell = p.exists
						? E('div', {}, [
							E('div', {}, nimbusApi.formatBytes(p.size_bytes || 0)),
							E('small', { 'style': 'opacity:0.75;' }, nimbusApi.formatTimestamp(p.mtime))
						])
						: E('em', {}, _('Missing'));

					var actBtns = [
						E('button', {
							'type': 'button',
							'class': 'btn cbi-button cbi-button-action',
							'disabled': (busy || !p.exists) ? 'disabled' : null,
							'click': function() { showStandalonePreviewModal(p); }
						}, _('Preview & Check')),
						E('button', {
							'type': 'button',
							'class': 'btn cbi-button',
							'disabled': (busy || !p.exists) ? 'disabled' : null,
							'click': function() {
								openCreateModal({
									initMode: 'import_profile',
									importProfileId: p.id,
									defaultName: _('%s (Composer)').format(p.name || p.id)
								});
							}
						}, _('Import to Composer'))
					];

					rows.push(E('tr', { 'class': 'tr cbi-section-table-row' }, [
						E('td', { 'class': 'td' }, E('div', { 'style': 'display:flex;align-items:center;gap:6px;flex-wrap:wrap;' }, nameNodes)),
						E('td', { 'class': 'td' }, p.type === 'subscription' ? _('Subscription') : _('Local')),
						E('td', { 'class': 'td' }, E('code', {}, p.filename || '-')),
						E('td', { 'class': 'td' }, fileCell),
						E('td', { 'class': 'td right', 'style': 'white-space:nowrap;' }, E('div', {
							'style': 'display:flex;gap:4px;justify-content:flex-end;flex-wrap:wrap;'
						}, actBtns))
					]));
				});
			}

			dom.content(standaloneSection, [
				E('h3', {}, _('Standalone Subscriptions & Local Files')),
				E('div', { 'class': 'cbi-section-descr' }, [
					E('span', {}, _('Complete sing-box JSON files with "Allow as Active Config" enabled. Manage or activate in: ')),
					E('a', { 'href': subUrl }, _('Subscriptions')),
					E('span', {}, ' / '),
					E('a', { 'href': settingsUrl }, _('Settings'))
				]),
				E('div', { 'style': 'overflow-x:auto;' }, [
					E('table', { 'class': 'table cbi-section-table' }, rows)
				])
			]);
		}

		function renderListViews() {
			renderComposersSection();
			renderStandaloneSection();
		}

		renderListViews();

		return E('div', { 'class': 'cbi-map' }, [
			E('h2', {}, _('Nimbus Configuration')),
			E('div', { 'class': 'cbi-map-descr' },
				_('Manage multiple sing-box Composer configurations and inspect standalone profiles. Editing any configuration never changes which configuration is currently active.')),
			listWrap,
			editorWrap
		]);
	}
});
