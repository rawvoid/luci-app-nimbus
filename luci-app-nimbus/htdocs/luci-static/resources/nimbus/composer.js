'use strict';
'require baseclass';
'require dom';
'require ui';
'require nimbus.api as nimbusApi';
'require nimbus.composer_snippets as snippets';

var DEFAULT_EXCLUDE_TYPES = [ 'selector', 'urltest', 'direct', 'block', 'dns' ];
var DEFAULT_STRIP_FIELDS = [ 'domain_resolver', 'routing_mark' ];

function makeBadge(text, bg, fg) {
	return E('span', {
		'class': 'label',
		'style': 'display:inline-block;padding:2px 7px;border-radius:3px;font-size:85%;font-weight:600;background:%s;color:%s;'.format(bg, fg)
	}, text);
}

function parseCsvList(str) {
	return String(str || '')
		.split(/[\n,]+/)
		.map(function(s) { return s.trim(); })
		.filter(Boolean);
}

function parseUniqueList(str) {
	var seen = {};
	var out = [];
	parseCsvList(str).forEach(function(item) {
		if (!seen[item]) {
			seen[item] = true;
			out.push(item);
		}
	});
	return out;
}

function normalizeDraft(raw) {
	var d = (raw && typeof raw === 'object' && !Array.isArray(raw))
		? snippets.deepClone(raw)
		: snippets.createBlankPreset();

	d.schema_version = 1;
	d.sources = (d.sources && typeof d.sources === 'object' && !Array.isArray(d.sources)) ? d.sources : {};
	d.inbounds = Array.isArray(d.inbounds) ? d.inbounds : [];
	d.outbound_groups = Array.isArray(d.outbound_groups) ? d.outbound_groups : [];
	d.outbounds = Array.isArray(d.outbounds) ? d.outbounds : [];

	d.dns = (d.dns && typeof d.dns === 'object' && !Array.isArray(d.dns)) ? d.dns : {};
	d.dns.final = typeof d.dns.final === 'string' ? d.dns.final : '';
	d.dns.strategy = typeof d.dns.strategy === 'string' ? d.dns.strategy : '';
	d.dns.extra = (d.dns.extra && typeof d.dns.extra === 'object' && !Array.isArray(d.dns.extra)) ? d.dns.extra : {};
	d.dns.servers = Array.isArray(d.dns.servers) ? d.dns.servers : [];
	d.dns.rules = Array.isArray(d.dns.rules) ? d.dns.rules : [];

	d.rule_sets = Array.isArray(d.rule_sets) ? d.rule_sets : [];

	d.route = (d.route && typeof d.route === 'object' && !Array.isArray(d.route)) ? d.route : {};
	d.route.final = typeof d.route.final === 'string' ? d.route.final : '';
	d.route.default_domain_resolver = typeof d.route.default_domain_resolver === 'string' ? d.route.default_domain_resolver : '';
	d.route.extra = (d.route.extra && typeof d.route.extra === 'object' && !Array.isArray(d.route.extra)) ? d.route.extra : {};
	d.route.rules = Array.isArray(d.route.rules) ? d.route.rules : [];

	d.override = (d.override && typeof d.override === 'object' && !Array.isArray(d.override)) ? d.override : {};
	return d;
}

function parseComposerFromPayload(payload) {
	if (payload && typeof payload.composer_json === 'string' && payload.composer_json.trim()) {
		try {
			var parsed = JSON.parse(payload.composer_json);
			if (parsed && typeof parsed === 'object' && !Array.isArray(parsed))
				return normalizeDraft(parsed);
		} catch (e) {
		}
	}
	return normalizeDraft(payload ? payload.composer : null);
}

function defaultSourceConfig(existing) {
	var s = (existing && typeof existing === 'object') ? existing : {};
	return {
		enabled: s.enabled === true,
		tag_prefix: typeof s.tag_prefix === 'string' ? s.tag_prefix : '',
		include_regex: typeof s.include_regex === 'string' ? s.include_regex : '',
		exclude_regex: typeof s.exclude_regex === 'string' ? s.exclude_regex : '',
		exclude_types: Array.isArray(s.exclude_types) ? s.exclude_types.slice() : DEFAULT_EXCLUDE_TYPES.slice(),
		strip_fields: Array.isArray(s.strip_fields) ? s.strip_fields.slice() : DEFAULT_STRIP_FIELDS.slice(),
		node_override: (s.node_override && typeof s.node_override === 'object' && !Array.isArray(s.node_override))
			? snippets.deepClone(s.node_override)
			: {}
	};
}

function mergeOverridePatch(target, patch) {
	if (patch === null || typeof patch !== 'object' || Array.isArray(patch))
		return snippets.deepClone(patch);

	var out = (target && typeof target === 'object' && !Array.isArray(target))
		? snippets.deepClone(target)
		: {};

	Object.keys(patch).forEach(function(k) {
		var pv = patch[k];
		var tv = out[k];
		if (pv === null) {
			out[k] = null;
		} else if (Array.isArray(pv) && Array.isArray(tv)) {
			var merged = tv.map(snippets.deepClone);
			pv.forEach(function(item) {
				if (item && typeof item === 'object' && typeof item.tag === 'string' && item.tag) {
					var idx = -1;
					for (var i = 0; i < merged.length; i++) {
						if (merged[i] && typeof merged[i] === 'object' && merged[i].tag === item.tag) {
							idx = i;
							break;
						}
					}
					if (idx >= 0)
						merged[idx] = snippets.deepClone(item);
					else
						merged.push(snippets.deepClone(item));
				} else {
					merged.push(snippets.deepClone(item));
				}
			});
			out[k] = merged;
		} else if (typeof pv === 'object' && !Array.isArray(pv)) {
			out[k] = mergeOverridePatch(tv, pv);
		} else {
			out[k] = snippets.deepClone(pv);
		}
	});
	return out;
}

function showModalError(errBox, msg) {
	errBox.style.display = 'block';
	dom.content(errBox, E('div', { 'class': 'alert-message error' }, msg));
}

function hideModalError(errBox) {
	errBox.style.display = 'none';
	dom.content(errBox, '');
}

function buildSnippetTextarea(initialObj, snippetList, onApplySnippet, errBox, rows) {
	var textarea = E('textarea', {
		'class': 'cbi-input-textarea',
		'rows': String(rows || 10),
		'spellcheck': 'false',
		'style': 'width:100%;font-family:monospace;font-size:12px;resize:vertical;'
	}, snippets.prettyJson(initialObj));

	var snipSelect = E('select', { 'class': 'cbi-input-select', 'style': 'max-width:260px;' }, [
		E('option', { 'value': '' }, _('-- Select 1.14 Snippet --'))
	].concat((snippetList || []).map(function(s) {
		return E('option', { 'value': s.id }, s.label);
	})));

	var applyBtn = E('button', {
		'type': 'button',
		'class': 'btn cbi-button cbi-button-action',
		'click': function() {
			var sid = snipSelect.value;
			if (!sid)
				return;
			var found = null;
			(snippetList || []).forEach(function(s) {
				if (s.id === sid)
					found = s;
			});
			if (!found)
				return;
			if (errBox)
				hideModalError(errBox);
			if (onApplySnippet)
				onApplySnippet(found, textarea);
		}
	}, _('Apply Snippet'));

	var formatBtn = E('button', {
		'type': 'button',
		'class': 'btn cbi-button',
		'click': function() {
			var parsed = snippets.parseJsonObject(textarea.value);
			if (!parsed.ok) {
				if (errBox)
					showModalError(errBox, parsed.error);
				return;
			}
			if (errBox)
				hideModalError(errBox);
			textarea.value = snippets.prettyJson(parsed.value);
		}
	}, _('Format JSON'));

	var wrapper = E('div', {}, [
		E('div', { 'style': 'display:flex;gap:6px;align-items:center;flex-wrap:wrap;margin-bottom:6px;' }, [
			snipSelect,
			applyBtn,
			formatBtn
		]),
		textarea
	]);

	return {
		el: wrapper,
		textarea: textarea,
		parse: function() {
			return snippets.parseJsonObject(textarea.value);
		}
	};
}

function renderWorkspace(opts) {
	var options = opts || {};
	var initComp = options.initialComposerData || {};
	var initProf = options.initialProfileList || {};
	var sharedActions = options.sharedProfileActions || {};

	var draft = parseComposerFromPayload(initComp);
	var profiles = (Array.isArray(initProf.profiles) && initProf.profiles.length > 0)
		? initProf.profiles.slice()
		: (Array.isArray(initComp.profiles) ? initComp.profiles.slice() : []);
	var autoInbounds = initComp.auto_inbounds || {
		proxy_mode: 'tproxy_redirect',
		redirect_port: 7891,
		tproxy_port: 7892,
		dns_mode: 'none',
		singbox_dns_port: 5353
	};

	var savedExists = Boolean(initComp.exists);
	var savedMtime = initComp.mtime || null;
	var dirty = false;
	var busy = false;
	var destroyed = false;
	var unloadAttached = false;
	var activeTab = 'sources';

	var overrideText = snippets.prettyJson(draft.override);
	var overrideError = null;

	var headerBox = E('div', { 'class': 'cbi-section' });
	var tabMenu = E('ul', { 'class': 'cbi-tabmenu' });
	var tabPanel = E('div', { 'class': 'cbi-section' });
	var rootEl = E('div', { 'class': 'nimbus-composer-workspace' }, [
		headerBox,
		tabMenu,
		tabPanel
	]);

	var TABS = [
		{ id: 'sources', label: _('Sources') },
		{ id: 'outbounds', label: _('Outbounds') },
		{ id: 'inbounds', label: _('Inbounds') },
		{ id: 'dns', label: _('DNS') },
		{ id: 'route', label: _('Route & Rule Sets') },
		{ id: 'override', label: _('Override') }
	];

	function handleBeforeUnload(ev) {
		if (destroyed || !dirty || !rootEl || rootEl.isConnected === false) {
			setBeforeUnload(false);
			return;
		}
		ev.preventDefault();
		ev.returnValue = '';
		return '';
	}

	function setBeforeUnload(attach) {
		if (attach && !unloadAttached) {
			window.addEventListener('beforeunload', handleBeforeUnload);
			unloadAttached = true;
		} else if (!attach && unloadAttached) {
			window.removeEventListener('beforeunload', handleBeforeUnload);
			unloadAttached = false;
		}
	}

	function syncOverrideTextFromDraft() {
		overrideText = snippets.prettyJson(draft.override);
		overrideError = null;
	}

	function markDirty(optsDirty) {
		dirty = true;
		setBeforeUnload(true);
		renderHeader();
		if (!optsDirty || !optsDirty.skipTabRender)
			renderActiveTab();
	}

	function getProfileMap() {
		var map = {};
		profiles.forEach(function(p) {
			if (p && p.id)
				map[p.id] = p;
		});
		return map;
	}

	function getKnownDnsTags() {
		var tags = [];
		var seen = {};
		draft.dns.servers.forEach(function(s) {
			if (s && s.tag && !seen[s.tag]) {
				seen[s.tag] = true;
				tags.push(s.tag);
			}
		});
		return tags;
	}

	function getKnownOutboundTags(excludeTag) {
		var tags = [];
		var seen = {};
		function add(t) {
			if (t && t !== excludeTag && !seen[t]) {
				seen[t] = true;
				tags.push(t);
			}
		}
		draft.outbound_groups.forEach(function(g) { add(g.tag); });
		draft.outbounds.forEach(function(o) { add(o.tag); });
		add('direct');
		add('block');
		return tags;
	}

	function getEnabledSourceIds() {
		var ids = [];
		var pmap = getProfileMap();
		profiles.forEach(function(p) {
			if (draft.sources[p.id] && draft.sources[p.id].enabled === true)
				ids.push(p.id);
		});
		Object.keys(draft.sources).forEach(function(sid) {
			if (!pmap[sid] && draft.sources[sid] && draft.sources[sid].enabled === true)
				ids.push(sid);
		});
		return ids;
	}

	function getGroupAttachedSummary(profileId) {
		var attached = [];
		draft.outbound_groups.forEach(function(g) {
			var provs = Array.isArray(g.providers) ? g.providers : [];
			var hasWildcard = false;
			var hasDirect = false;
			provs.forEach(function(pv) {
				if (pv && pv.profile_id === '*')
					hasWildcard = true;
				else if (pv && pv.profile_id === profileId)
					hasDirect = true;
			});
			if (hasDirect || hasWildcard) {
				attached.push({
					tag: g.tag || g.id,
					enabled: g.enabled !== false,
					viaWildcard: hasWildcard && !hasDirect
				});
			}
		});
		return attached;
	}

	function computeStats() {
		var enabledSources = 0;
		profiles.forEach(function(p) {
			if (draft.sources[p.id] && draft.sources[p.id].enabled === true)
				enabledSources++;
		});
		var groups = draft.outbound_groups.filter(function(g) { return g.enabled !== false; }).length;
		var manualOutbounds = draft.outbounds.filter(function(o) { return o.enabled !== false; }).length;
		var rules = draft.route.rules.filter(function(r) { return r.enabled !== false; }).length;
		return {
			enabledSources: enabledSources,
			groups: groups,
			manualOutbounds: manualOutbounds,
			rules: rules
		};
	}

	function validateBeforeComposerSend() {
		if (overrideError) {
			nimbusApi.notifyError(_('Override JSON contains syntax errors: %s').format(overrideError));
			switchTab('override');
			return false;
		}
		var prettyStr = JSON.stringify(draft, null, 2) + '\n';
		if (nimbusApi.utf8ByteLength(prettyStr) > nimbusApi.MAX_DIRECT_TEXT_BYTES) {
			nimbusApi.notifyError(_('Composer configuration exceeds the 256 KiB inline transfer limit.'));
			return false;
		}
		return JSON.stringify(draft);
	}

	function refreshProfilesOnly() {
		return nimbusApi.profileList().then(function(res) {
			if (destroyed)
				return;
			if (!res || res.ok === false) {
				nimbusApi.notifyError(res);
				return;
			}
			profiles = Array.isArray(res.profiles) ? res.profiles.slice() : [];
			renderHeader();
			renderActiveTab();
		}).catch(function(err) {
			if (!destroyed)
				nimbusApi.notifyError(err);
		});
	}

	function saveComposer(reload) {
		if (busy)
			return;
		var jsonStr = validateBeforeComposerSend();
		if (!jsonStr)
			return;

		busy = true;
		renderHeader();

		nimbusApi.composerSave({
			composer_json: jsonStr,
			validate: true,
			reload: reload === true
		}).then(function(res) {
			busy = false;
			if (destroyed)
				return;
			if (!res || res.ok === false) {
				nimbusApi.notifyError(res);
				if (res && Array.isArray(res.warnings) && res.warnings.length > 0) {
					ui.addNotification(null, E('ul', { 'style': 'margin:0 0 0 18px;' }, res.warnings.map(function(w) {
						return E('li', {}, w);
					})), 'warning');
				}
				renderHeader();
				return;
			}

			draft = parseComposerFromPayload(res);
			syncOverrideTextFromDraft();
			dirty = false;
			savedExists = true;
			savedMtime = res.mtime || Math.floor(Date.now() / 1000);
			setBeforeUnload(false);

			if (reload && res.reloaded)
				nimbusApi.notifySuccess(_('Composer configuration saved, validated, and applied.'));
			else if (res.reload_required)
				nimbusApi.notifySuccess(_('Composer configuration saved and validated. Reload service to apply changes.'));
			else if (res.checked)
				nimbusApi.notifySuccess(_('Composer configuration saved and validated with sing-box.'));
			else
				nimbusApi.notifySuccess(_('Composer configuration saved.'));

			if (Array.isArray(res.warnings) && res.warnings.length > 0) {
				ui.addNotification(null, E('div', {}, [
					E('strong', {}, _('Composer Warnings:')),
					E('ul', { 'style': 'margin:4px 0 0 18px;' }, res.warnings.map(function(w) {
						return E('li', {}, w);
					}))
				]), 'warning');
			}

			renderHeader();
			renderActiveTab();
			if (typeof options.onSaved === 'function')
				options.onSaved(res);
		}).catch(function(err) {
			busy = false;
			if (!destroyed) {
				nimbusApi.notifyError(err);
				renderHeader();
			}
		});
	}

	function openPreviewModal() {
		var jsonStr = validateBeforeComposerSend();
		if (!jsonStr)
			return;

		var bodyBox = E('div', {}, [
			E('p', {}, E('span', { 'class': 'spinning' }, _('Synthesizing configuration and running sing-box check...')))
		]);

		ui.showModal(_('Preview & Check'), [
			bodyBox,
			E('div', { 'class': 'right', 'style': 'margin-top:12px;' }, [
				E('button', { 'type': 'button', 'class': 'btn cbi-button', 'click': ui.hideModal }, _('Close'))
			])
		]);

		nimbusApi.composerPreview({
			composer_json: jsonStr,
			validate: true
		}).then(function(res) {
			if (!res || res.ok === false) {
				dom.content(bodyBox, E('div', { 'class': 'alert-message error' }, nimbusApi.formatError(res)));
				return;
			}

			var effectiveText = res.effective_json || snippets.prettyJson(res.effective || {});
			var composedText = res.composed_json || snippets.prettyJson(res.composed || {});
			var previewTab = 'effective';

			var statusBadge;
			if (res.checked) {
				statusBadge = res.check_ok
					? makeBadge(_('sing-box check: Passed'), '#e6f4ea', '#137333')
					: makeBadge(_('sing-box check: Failed'), '#fce8e6', '#c5221f');
			} else {
				statusBadge = makeBadge(_('Preview Only (sing-box binary not installed)'), '#fef7e0', '#b06000');
			}

			var sum = res.summary || {};
			var summaryLine = E('span', { 'style': 'font-size:90%;color:#666;' },
				_('%d sources · %d nodes · %d groups · %d inbounds · %d DNS · %d rules · %d rule sets').format(
					sum.enabled_sources || 0,
					sum.extracted_nodes || 0,
					sum.groups || 0,
					sum.inbounds || 0,
					sum.dns_servers || 0,
					sum.route_rules || 0,
					sum.rule_sets || 0
				));

			var previewTextarea = E('textarea', {
				'class': 'cbi-input-textarea',
				'rows': '17',
				'readonly': 'readonly',
				'spellcheck': 'false',
				'style': 'width:100%;font-family:monospace;font-size:12px;resize:vertical;'
			}, effectiveText);

			var effLi = E('li', { 'class': 'cbi-tab' }, [
				E('a', {
					'href': '#',
					'click': function(ev) {
						ev.preventDefault();
						previewTab = 'effective';
						effLi.className = 'cbi-tab';
						compLi.className = 'cbi-tab-disabled';
						previewTextarea.value = effectiveText;
					}
				}, _('Effective Runtime JSON (Stage B)'))
			]);
			var compLi = E('li', { 'class': 'cbi-tab-disabled' }, [
				E('a', {
					'href': '#',
					'click': function(ev) {
						ev.preventDefault();
						previewTab = 'composed';
						effLi.className = 'cbi-tab-disabled';
						compLi.className = 'cbi-tab';
						previewTextarea.value = composedText;
					}
				}, _('Composed JSON (Stage A)'))
			]);

			var copyBtn = E('button', {
				'type': 'button',
				'class': 'btn cbi-button cbi-button-action',
				'click': function() {
					var text = (previewTab === 'composed') ? composedText : effectiveText;
					nimbusApi.copyToClipboard(text).then(function() {
						nimbusApi.notifySuccess(_('JSON copied to clipboard.'));
					}, function() {
						nimbusApi.notifyError(_('Failed to copy to clipboard.'));
					});
				}
			}, _('Copy JSON'));

			var blocks = [
				E('div', { 'style': 'display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;margin-bottom:10px;' }, [
					statusBadge,
					summaryLine
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

			blocks.push(E('ul', { 'class': 'cbi-tabmenu' }, [ effLi, compLi ]));
			blocks.push(previewTextarea);
			blocks.push(E('div', { 'style': 'display:flex;justify-content:flex-start;margin-top:8px;' }, [ copyBtn ]));

			dom.content(bodyBox, blocks);
		}).catch(function(err) {
			dom.content(bodyBox, E('div', { 'class': 'alert-message error' }, nimbusApi.formatError(err)));
		});
	}

	function openPresetsImportModal() {
		var errBox = E('div', { 'style': 'display:none;' });
		var confirmBox = E('div', { 'style': 'display:none;margin-bottom:10px;' });
		var pendingReplaceFn = null;

		var profileSelect = E('select', { 'class': 'cbi-input-select', 'style': 'min-width:220px;flex:1;' }, [
			E('option', { 'value': '' }, _('-- Select Profile --'))
		].concat(profiles.map(function(p) {
			var label = p.name ? '%s (%s)'.format(p.name, p.filename) : p.id;
			return E('option', { 'value': p.id }, label);
		})));

		var rawTextarea = E('textarea', {
			'class': 'cbi-input-textarea',
			'rows': '8',
			'spellcheck': 'false',
			'placeholder': _('Paste full sing-box JSON object here...'),
			'style': 'width:100%;font-family:monospace;font-size:12px;resize:vertical;'
		});

		function applyNewDraft(newDraft, warnings) {
			draft = normalizeDraft(newDraft);
			syncOverrideTextFromDraft();
			markDirty();
			ui.hideModal();
			nimbusApi.notifySuccess(_('Composer draft replaced. Click "Save" or "Save & Apply" to persist changes.'));
			if (Array.isArray(warnings) && warnings.length > 0) {
				ui.addNotification(null, E('div', {}, [
					E('strong', {}, _('Import Warnings:')),
					E('ul', { 'style': 'margin:4px 0 0 18px;' }, warnings.map(function(w) {
						return E('li', {}, w);
					}))
				]), 'warning');
			}
		}

		function requestReplace(actionLabel, executor) {
			hideModalError(errBox);
			if (!dirty) {
				executor();
				return;
			}
			pendingReplaceFn = executor;
			confirmBox.style.display = 'block';
			dom.content(confirmBox, E('div', { 'class': 'alert-message warning' }, [
				E('p', { 'style': 'margin:0 0 8px;' },
					_('You have unsaved changes. Confirm "%s" to overwrite the current draft?').format(actionLabel)),
				E('div', { 'style': 'display:flex;gap:8px;' }, [
					E('button', {
						'type': 'button',
						'class': 'btn cbi-button cbi-button-negative',
						'click': function() {
							confirmBox.style.display = 'none';
							var fn = pendingReplaceFn;
							pendingReplaceFn = null;
							if (fn)
								fn();
						}
					}, _('Overwrite Draft')),
					E('button', {
						'type': 'button',
						'class': 'btn cbi-button',
						'click': function() {
							confirmBox.style.display = 'none';
							pendingReplaceFn = null;
						}
					}, _('Cancel'))
				])
			]));
		}

		var importProfBtn = E('button', {
			'type': 'button',
			'class': 'btn cbi-button cbi-button-action',
			'disabled': profiles.length === 0 ? 'disabled' : null,
			'click': function() {
				var pid = profileSelect.value;
				if (!pid) {
					showModalError(errBox, _('Please select a profile to import.'));
					return;
				}
				requestReplace(_('Import Profile'), function() {
					importProfBtn.disabled = true;
					nimbusApi.composerImport({
						source: 'profile',
						profile_id: pid
					}).then(function(res) {
						importProfBtn.disabled = false;
						if (!res || res.ok === false) {
							showModalError(errBox, nimbusApi.formatError(res));
							return;
						}
						applyNewDraft(parseComposerFromPayload(res), res.warnings);
					}).catch(function(err) {
						importProfBtn.disabled = false;
						showModalError(errBox, nimbusApi.formatError(err));
					});
				});
			}
		}, _('Import Profile'));

		var importJsonBtn = E('button', {
			'type': 'button',
			'class': 'btn cbi-button cbi-button-action',
			'click': function() {
				var raw = rawTextarea.value;
				if (!raw.trim()) {
					showModalError(errBox, _('Please paste a sing-box JSON configuration.'));
					return;
				}
				if (nimbusApi.utf8ByteLength(raw) > nimbusApi.MAX_DIRECT_TEXT_BYTES) {
					showModalError(errBox, _('Content exceeds the 256 KiB inline transfer limit.'));
					return;
				}
				var parsed = snippets.parseJsonObject(raw);
				if (!parsed.ok) {
					showModalError(errBox, parsed.error);
					return;
				}
				requestReplace(_('Import Raw JSON'), function() {
					importJsonBtn.disabled = true;
					nimbusApi.composerImport({
						source: 'json',
						content: raw
					}).then(function(res) {
						importJsonBtn.disabled = false;
						if (!res || res.ok === false) {
							showModalError(errBox, nimbusApi.formatError(res));
							return;
						}
						applyNewDraft(parseComposerFromPayload(res), res.warnings);
					}).catch(function(err) {
						importJsonBtn.disabled = false;
						showModalError(errBox, nimbusApi.formatError(err));
					});
				});
			}
		}, _('Import JSON'));

		ui.showModal(_('Presets & Import'), [
			errBox,
			confirmBox,
			dirty ? E('div', { 'class': 'alert-message warning', 'style': 'margin-bottom:10px;' },
				_('Unsaved draft changes are present. Applying a preset or importing will replace the current draft.')) : '',
			E('div', { 'style': 'margin-bottom:14px;' }, [
				E('h4', { 'style': 'margin:0 0 6px;' }, _('Starter Presets')),
				E('p', { 'style': 'margin:0 0 8px;font-size:90%;color:#666;' },
					_('Load a clean sing-box 1.14 composer blueprint (no deprecated fields).')),
				E('div', { 'style': 'display:flex;gap:8px;flex-wrap:wrap;' }, [
					E('button', {
						'type': 'button',
						'class': 'btn cbi-button cbi-button-apply',
						'click': function() {
							requestReplace(_('1.14 Standard Router Split'), function() {
								applyNewDraft(snippets.createStandard114Preset(), []);
							});
						}
					}, _('1.14 Standard Router Split')),
					E('button', {
						'type': 'button',
						'class': 'btn cbi-button',
						'click': function() {
							requestReplace(_('Blank Canvas'), function() {
								applyNewDraft(snippets.createBlankPreset(), []);
							});
						}
					}, _('Blank Canvas'))
				])
			]),
			E('div', { 'style': 'margin-bottom:14px;padding-top:10px;border-top:1px solid #eee;' }, [
				E('h4', { 'style': 'margin:0 0 6px;' }, _('Import from Existing Profile')),
				E('div', { 'style': 'display:flex;gap:8px;align-items:center;flex-wrap:wrap;' }, [
					profileSelect,
					importProfBtn
				])
			]),
			E('div', { 'style': 'margin-bottom:12px;padding-top:10px;border-top:1px solid #eee;' }, [
				E('h4', { 'style': 'margin:0 0 6px;' }, _('Import from Raw sing-box JSON')),
				rawTextarea,
				E('div', { 'style': 'margin-top:8px;' }, [ importJsonBtn ])
			]),
			E('div', { 'class': 'right' }, [
				E('button', { 'type': 'button', 'class': 'btn cbi-button', 'click': ui.hideModal }, _('Close'))
			])
		]);
	}

	function renderHeader() {
		var stats = computeStats();
		var statusBadge;
		if (dirty)
			statusBadge = makeBadge(_('Unsaved Changes'), '#fef0e1', '#c25e00');
		else if (!savedExists)
			statusBadge = makeBadge(_('Not Saved Yet'), '#fef7e0', '#b06000');
		else
			statusBadge = makeBadge(_('Synced'), '#e6f4ea', '#137333');

		var statsText = _('%d sources · %d groups · %d manual outbounds · %d rules').format(
			stats.enabledSources,
			stats.groups,
			stats.manualOutbounds,
			stats.rules
		);

		var leftSide = E('div', { 'style': 'display:flex;align-items:center;gap:10px;flex-wrap:wrap;' }, [
			statusBadge,
			E('span', { 'style': 'font-size:90%;color:#555;' }, statsText),
			(savedExists && savedMtime)
				? E('span', { 'style': 'font-size:85%;color:#888;' }, _('Saved: %s').format(nimbusApi.formatTimestamp(savedMtime)))
				: '',
			busy ? E('span', { 'class': 'spinning', 'style': 'font-size:90%;' }, _('Processing...')) : ''
		]);

		var rightSide = E('div', { 'style': 'display:flex;gap:8px;flex-wrap:wrap;' }, [
			E('button', {
				'type': 'button',
				'class': 'btn cbi-button',
				'disabled': busy ? 'disabled' : null,
				'click': openPresetsImportModal
			}, _('Presets / Import')),
			E('button', {
				'type': 'button',
				'class': 'btn cbi-button cbi-button-action',
				'disabled': busy ? 'disabled' : null,
				'click': openPreviewModal
			}, _('Preview & Check')),
			E('button', {
				'type': 'button',
				'class': 'btn cbi-button cbi-button-save',
				'disabled': busy ? 'disabled' : null,
				'click': function() { saveComposer(false); }
			}, _('Save')),
			E('button', {
				'type': 'button',
				'class': 'btn cbi-button cbi-button-apply',
				'disabled': busy ? 'disabled' : null,
				'click': function() { saveComposer(true); }
			}, _('Save & Apply'))
		]);

		dom.content(headerBox, E('div', {
			'style': 'display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;padding:10px 12px;border:1px solid #e0e0e0;border-radius:4px;background:#fafafa;'
		}, [ leftSide, rightSide ]));
	}

	function renderTabMenu() {
		dom.content(tabMenu, TABS.map(function(t) {
			var isActive = (t.id === activeTab);
			return E('li', { 'class': isActive ? 'cbi-tab' : 'cbi-tab-disabled' }, [
				E('a', {
					'href': '#',
					'click': function(ev) {
						ev.preventDefault();
						switchTab(t.id);
					}
				}, t.label)
			]);
		}));
	}

	function switchTab(tabId) {
		if (activeTab === tabId)
			return;
		activeTab = tabId;
		renderTabMenu();
		renderActiveTab();
	}

	function renderNodesListBox(res, emptyText) {
		if (!res || res.ok === false)
			return E('div', { 'class': 'alert-message error' }, nimbusApi.formatError(res));

		var nodes = Array.isArray(res.nodes) ? res.nodes : [];
		var warnings = Array.isArray(res.warnings) ? res.warnings : [];
		var blocks = [];

		if (warnings.length > 0) {
			blocks.push(E('div', { 'class': 'alert-message warning', 'style': 'margin-bottom:8px;' }, [
				E('ul', { 'style': 'margin:0 0 0 16px;' }, warnings.map(function(w) {
					return E('li', {}, w);
				}))
			]));
		}

		blocks.push(E('div', { 'style': 'margin-bottom:6px;font-size:90%;color:#555;' },
			_('Matched %d node(s).').format(nodes.length)));

		if (nodes.length === 0) {
			blocks.push(E('div', { 'style': 'font-size:90%;color:#777;' }, emptyText || _('No nodes matched.')));
		} else {
			var rows = [
				E('tr', { 'class': 'tr cbi-section-table-titles' }, [
					E('th', { 'class': 'th' }, _('Final Tag')),
					E('th', { 'class': 'th' }, _('Original Tag')),
					E('th', { 'class': 'th' }, _('Type')),
					E('th', { 'class': 'th' }, _('Server'))
				])
			];
			nodes.forEach(function(n) {
				var srv = n.server
					? (n.server_port ? '%s:%s'.format(n.server, n.server_port) : String(n.server))
					: '-';
				rows.push(E('tr', { 'class': 'tr cbi-section-table-row' }, [
					E('td', { 'class': 'td' }, E('code', {}, n.tag || '-')),
					E('td', { 'class': 'td' }, n.original_tag || '-'),
					E('td', { 'class': 'td' }, n.type || '-'),
					E('td', { 'class': 'td' }, srv)
				]));
			});
			blocks.push(E('div', { 'style': 'max-height:240px;overflow:auto;border:1px solid #e5e5e5;border-radius:3px;' }, [
				E('table', { 'class': 'table cbi-section-table', 'style': 'margin:0;' }, rows)
			]));
		}

		return E('div', {}, blocks);
	}

	function openNodesModal(profile) {
		var contentBox = E('div', {}, [
			E('p', {}, E('span', { 'class': 'spinning' }, _('Extracting nodes...')))
		]);

		ui.showModal(_('Extracted Nodes: %s').format(profile.name || profile.id), [
			contentBox,
			E('div', { 'class': 'right', 'style': 'margin-top:12px;' }, [
				E('button', { 'type': 'button', 'class': 'btn cbi-button', 'click': ui.hideModal }, _('Close'))
			])
		]);

		var jsonStr = JSON.stringify(draft);
		if (nimbusApi.utf8ByteLength(jsonStr) > nimbusApi.MAX_DIRECT_TEXT_BYTES) {
			dom.content(contentBox, E('div', { 'class': 'alert-message error' },
				_('Composer draft exceeds the 256 KiB inline transfer limit.')));
			return;
		}

		nimbusApi.composerNodes({
			profile_id: profile.id,
			composer_json: jsonStr
		}).then(function(res) {
			dom.content(contentBox, renderNodesListBox(res, _('No nodes extracted from this source with current rules.')));
		}).catch(function(err) {
			dom.content(contentBox, E('div', { 'class': 'alert-message error' }, nimbusApi.formatError(err)));
		});
	}

	function openExtractModal(profile) {
		var src = defaultSourceConfig(draft.sources[profile.id]);
		var errBox = E('div', { 'style': 'display:none;' });
		var testResultBox = E('div', { 'style': 'margin-top:10px;' });

		var enabledCb = E('input', { 'type': 'checkbox', 'checked': src.enabled ? 'checked' : null });
		var prefixInput = E('input', {
			'type': 'text',
			'class': 'cbi-input-text',
			'value': src.tag_prefix,
			'placeholder': '[A] '
		});
		var incInput = E('input', {
			'type': 'text',
			'class': 'cbi-input-text',
			'value': src.include_regex,
			'placeholder': 'HK|SG|JP'
		});
		var excInput = E('input', {
			'type': 'text',
			'class': 'cbi-input-text',
			'value': src.exclude_regex,
			'placeholder': 'Traffic|Expire'
		});
		var excTypesInput = E('input', {
			'type': 'text',
			'class': 'cbi-input-text',
			'value': src.exclude_types.join(', '),
			'placeholder': DEFAULT_EXCLUDE_TYPES.join(', ')
		});
		var stripInput = E('input', {
			'type': 'text',
			'class': 'cbi-input-text',
			'value': src.strip_fields.join(', '),
			'placeholder': DEFAULT_STRIP_FIELDS.join(', ')
		});
		var nodeOvTextarea = E('textarea', {
			'class': 'cbi-input-textarea',
			'rows': '6',
			'spellcheck': 'false',
			'style': 'width:100%;font-family:monospace;font-size:12px;resize:vertical;'
		}, snippets.prettyJson(src.node_override));

		var groupCheckboxes = draft.outbound_groups.map(function(g) {
			var provs = Array.isArray(g.providers) ? g.providers : [];
			var hasDirect = provs.some(function(pv) { return pv && pv.profile_id === profile.id; });
			var hasWild = provs.some(function(pv) { return pv && pv.profile_id === '*'; });
			var cb = E('input', {
				'type': 'checkbox',
				'checked': (hasDirect || hasWild) ? 'checked' : null
			});
			return {
				group: g,
				cb: cb,
				hasWildcard: hasWild
			};
		});

		function readSourceForm() {
			var ov = snippets.parseJsonObject(nodeOvTextarea.value);
			if (!ov.ok)
				return { ok: false, error: ov.error };
			return {
				ok: true,
				source: {
					enabled: enabledCb.checked,
					tag_prefix: prefixInput.value,
					include_regex: incInput.value,
					exclude_regex: excInput.value,
					exclude_types: parseCsvList(excTypesInput.value),
					strip_fields: parseCsvList(stripInput.value),
					node_override: ov.value
				}
			};
		}

		var testBtn = E('button', {
			'type': 'button',
			'class': 'btn cbi-button cbi-button-action',
			'click': function() {
				hideModalError(errBox);
				var formRes = readSourceForm();
				if (!formRes.ok) {
					showModalError(errBox, formRes.error);
					return;
				}
				var tempDraft = snippets.deepClone(draft);
				tempDraft.sources[profile.id] = formRes.source;
				var jsonStr = JSON.stringify(tempDraft);
				if (nimbusApi.utf8ByteLength(jsonStr) > nimbusApi.MAX_DIRECT_TEXT_BYTES) {
					showModalError(errBox, _('Composer draft exceeds the 256 KiB inline transfer limit.'));
					return;
				}

				testBtn.disabled = true;
				dom.content(testResultBox, E('span', { 'class': 'spinning' }, _('Testing extraction...')));
				nimbusApi.composerNodes({
					profile_id: profile.id,
					composer_json: jsonStr
				}).then(function(res) {
					testBtn.disabled = false;
					dom.content(testResultBox, renderNodesListBox(res, _('No nodes matched these extraction rules.')));
				}).catch(function(err) {
					testBtn.disabled = false;
					dom.content(testResultBox, '');
					showModalError(errBox, nimbusApi.formatError(err));
				});
			}
		}, _('Test Extract'));

		var saveBtn = E('button', {
			'type': 'button',
			'class': 'btn cbi-button cbi-button-save',
			'click': function() {
				hideModalError(errBox);
				var formRes = readSourceForm();
				if (!formRes.ok) {
					showModalError(errBox, formRes.error);
					return;
				}
				draft.sources[profile.id] = formRes.source;

				var otherEnabled = getEnabledSourceIds().filter(function(sid) { return sid !== profile.id; });
				groupCheckboxes.forEach(function(item) {
					var g = item.group;
					var provs = Array.isArray(g.providers) ? g.providers.slice() : [];
					var hasDirect = provs.some(function(pv) { return pv && pv.profile_id === profile.id; });
					var hasWild = provs.some(function(pv) { return pv && pv.profile_id === '*'; });

					if (item.cb.checked) {
						if (!hasDirect && !hasWild) {
							provs.push({
								profile_id: profile.id,
								include_regex: '',
								exclude_regex: ''
							});
						}
					} else {
						provs = provs.filter(function(pv) { return pv && pv.profile_id !== profile.id; });
						if (hasWild) {
							var expanded = [];
							provs.forEach(function(pv) {
								if (pv.profile_id === '*') {
									otherEnabled.forEach(function(oid) {
										if (!expanded.some(function(ep) { return ep.profile_id === oid; })) {
											expanded.push({
												profile_id: oid,
												include_regex: pv.include_regex || '',
												exclude_regex: pv.exclude_regex || ''
											});
										}
									});
								} else {
									expanded.push(pv);
								}
							});
							provs = expanded;
						}
					}
					g.providers = provs;
				});

				markDirty();
				ui.hideModal();
			}
		}, _('Save'));

		var groupAttachEl = groupCheckboxes.length === 0
			? E('span', { 'style': 'color:#777;font-size:90%;' }, _('No outbound groups defined.'))
			: E('div', { 'style': 'display:flex;flex-wrap:wrap;gap:10px;' }, groupCheckboxes.map(function(item) {
				return E('label', { 'style': 'display:inline-flex;align-items:center;gap:5px;margin:0;font-weight:normal;' }, [
					item.cb,
					E('span', {}, item.group.tag || item.group.id),
					item.hasWildcard ? makeBadge('* ' + _('All'), '#e8f0fe', '#1967d2') : ''
				]);
			}));

		ui.showModal(_('Extract Config: %s').format(profile.name || profile.id), [
			errBox,
			E('div', { 'class': 'cbi-value' }, [
				E('label', { 'class': 'cbi-value-title' }, _('Extract Nodes')),
				E('div', { 'class': 'cbi-value-field' }, enabledCb)
			]),
			E('div', { 'class': 'cbi-value' }, [
				E('label', { 'class': 'cbi-value-title' }, _('Tag Prefix')),
				E('div', { 'class': 'cbi-value-field' }, prefixInput)
			]),
			E('div', { 'class': 'cbi-value' }, [
				E('label', { 'class': 'cbi-value-title' }, _('Include Regex')),
				E('div', { 'class': 'cbi-value-field' }, [
					incInput,
					E('div', { 'class': 'cbi-value-description' }, _('POSIX ERE (case-insensitive) matched against original node tag.'))
				])
			]),
			E('div', { 'class': 'cbi-value' }, [
				E('label', { 'class': 'cbi-value-title' }, _('Exclude Regex')),
				E('div', { 'class': 'cbi-value-field' }, excInput)
			]),
			E('div', { 'class': 'cbi-value' }, [
				E('label', { 'class': 'cbi-value-title' }, _('Exclude Types (CSV)')),
				E('div', { 'class': 'cbi-value-field' }, excTypesInput)
			]),
			E('div', { 'class': 'cbi-value' }, [
				E('label', { 'class': 'cbi-value-title' }, _('Strip Fields (CSV)')),
				E('div', { 'class': 'cbi-value-field' }, stripInput)
			]),
			E('div', { 'class': 'cbi-value' }, [
				E('label', { 'class': 'cbi-value-title' }, _('Attach to Outbound Groups')),
				E('div', { 'class': 'cbi-value-field' }, groupAttachEl)
			]),
			E('div', { 'class': 'cbi-value' }, [
				E('label', { 'class': 'cbi-value-title' }, _('Node Override (JSON)')),
				E('div', { 'class': 'cbi-value-field' }, [
					E('div', { 'style': 'margin-bottom:6px;' }, [
						E('button', {
							'type': 'button',
							'class': 'btn cbi-button',
							'click': function() {
								var res = snippets.parseJsonObject(nodeOvTextarea.value);
								if (!res.ok) {
									showModalError(errBox, res.error);
									return;
								}
								hideModalError(errBox);
								nodeOvTextarea.value = snippets.prettyJson(res.value);
							}
						}, _('Format JSON'))
					]),
					nodeOvTextarea,
					E('div', { 'class': 'cbi-value-description' }, _('RFC 7396 Merge Patch applied to every extracted node (null deletes a field).'))
				])
			]),
			testResultBox,
			E('div', { 'style': 'display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px;margin-top:12px;' }, [
				testBtn,
				E('div', { 'style': 'display:flex;gap:8px;' }, [
					E('button', { 'type': 'button', 'class': 'btn cbi-button', 'click': ui.hideModal }, _('Cancel')),
					saveBtn
				])
			])
		]);
	}

	function renderSourcesTab() {
		var hasSubs = profiles.some(function(p) { return p.type === 'subscription'; });
		var pmap = getProfileMap();
		var orphanIds = Object.keys(draft.sources).filter(function(sid) { return !pmap[sid]; });

		var toolbar = E('div', { 'style': 'display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;margin-bottom:10px;' }, [
			E('div', { 'style': 'display:flex;gap:8px;flex-wrap:wrap;' }, [
				E('button', {
					'type': 'button',
					'class': 'btn cbi-button cbi-button-add',
					'disabled': busy ? 'disabled' : null,
					'click': function() {
						if (typeof sharedActions.openMetaModal === 'function')
							sharedActions.openMetaModal(null);
					}
				}, _('Add Source / Profile')),
				E('button', {
					'type': 'button',
					'class': 'btn cbi-button cbi-button-action',
					'disabled': (busy || !hasSubs) ? 'disabled' : null,
					'click': function() {
						if (typeof sharedActions.runProfileUpdate === 'function')
							sharedActions.runProfileUpdate('');
					}
				}, _('Update All Subscriptions')),
				E('button', {
					'type': 'button',
					'class': 'btn cbi-button',
					'disabled': busy ? 'disabled' : null,
					'click': refreshProfilesOnly
				}, _('Refresh'))
			]),
			E('span', { 'style': 'font-size:90%;color:#666;' },
				_('Shared profiles under /etc/nimbus/profiles/. Toggle Extract to include nodes in Composer.'))
		]);

		var blocks = [ toolbar ];

		if (orphanIds.length > 0) {
			blocks.push(E('div', {
				'class': 'alert-message warning',
				'style': 'display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;margin-bottom:10px;'
			}, [
				E('span', {}, _('Composer references %d missing profile source(s): %s').format(orphanIds.length, orphanIds.join(', '))),
				E('button', {
					'type': 'button',
					'class': 'btn cbi-button cbi-button-negative',
					'click': function() {
						orphanIds.forEach(function(oid) { delete draft.sources[oid]; });
						markDirty();
					}
				}, _('Remove Missing Sources'))
			]));
		}

		var rows = [
			E('tr', { 'class': 'tr cbi-section-table-titles' }, [
				E('th', { 'class': 'th' }, _('Extract')),
				E('th', { 'class': 'th' }, _('Name & File')),
				E('th', { 'class': 'th' }, _('Subscription')),
				E('th', { 'class': 'th' }, _('Extraction Rules')),
				E('th', { 'class': 'th' }, _('Attached Groups')),
				E('th', { 'class': 'th right' }, _('Actions'))
			])
		];

		if (profiles.length === 0) {
			rows.push(E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td center', 'colspan': '6' }, _('No profiles configured yet. Click "Add Source / Profile" to add one.'))
			]));
		} else {
			profiles.forEach(function(p) {
				var src = draft.sources[p.id] ? defaultSourceConfig(draft.sources[p.id]) : null;
				var extractCb = E('input', {
					'type': 'checkbox',
					'checked': (src && src.enabled) ? 'checked' : null,
					'change': function() {
						var next = defaultSourceConfig(draft.sources[p.id]);
						next.enabled = extractCb.checked;
						draft.sources[p.id] = next;
						markDirty();
					}
				});

				var fileMeta = p.exists
					? '%s · %s'.format(nimbusApi.formatBytes(p.size_bytes || 0), nimbusApi.formatTimestamp(p.mtime))
					: _('File missing');

				var nameCell = E('div', {}, [
					E('div', { 'style': 'font-weight:600;' }, p.name || p.id),
					E('div', { 'style': 'font-size:85%;color:#666;' }, [
						E('code', {}, p.filename || '-'),
						' · ',
						p.exists ? fileMeta : makeBadge(_('Missing'), '#fef7e0', '#b06000')
					])
				]);

				var subCell = '-';
				if (p.type === 'subscription') {
					var subParts = [];
					subParts.push(p.auto_update ? _('Auto: %dh').format(p.update_interval_hours || 24) : _('Manual'));
					if (p.via_proxy)
						subParts.push(_('Via Proxy'));
					subCell = E('div', {}, [
						E('div', { 'style': 'max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;', 'title': p.url || '' }, p.url || '-'),
						E('div', { 'style': 'font-size:85%;color:#666;' }, subParts.join(' · '))
					]);
				} else {
					subCell = _('Local');
				}

				var ruleParts = [];
				if (src) {
					if (src.tag_prefix)
						ruleParts.push(_('Prefix: %s').format(src.tag_prefix));
					if (src.include_regex)
						ruleParts.push(_('Include: /%s/').format(src.include_regex));
					if (src.exclude_regex)
						ruleParts.push(_('Exclude: /%s/').format(src.exclude_regex));
					if (src.node_override && Object.keys(src.node_override).length > 0)
						ruleParts.push(_('Override: %d keys').format(Object.keys(src.node_override).length));
				}
				var rulesCell = ruleParts.length > 0
					? E('div', { 'style': 'font-size:85%;color:#444;' }, ruleParts.join(' · '))
					: E('span', { 'style': 'color:#888;' }, _('Default'));

				var attached = getGroupAttachedSummary(p.id);
				var attachedCell = attached.length > 0
					? E('div', { 'style': 'display:flex;gap:4px;flex-wrap:wrap;' }, attached.map(function(a) {
						var lbl = a.viaWildcard ? '%s (*)'.format(a.tag) : a.tag;
						return makeBadge(lbl, a.enabled ? '#e8f0fe' : '#f1f3f4', a.enabled ? '#1967d2' : '#5f6368');
					}))
					: E('span', { 'style': 'color:#888;' }, '-');

				var actBtns = [
					E('button', {
						'type': 'button',
						'class': 'btn cbi-button cbi-button-edit',
						'click': function() { openExtractModal(p); }
					}, _('Extract Config')),
					E('button', {
						'type': 'button',
						'class': 'btn cbi-button cbi-button-action',
						'click': function() { openNodesModal(p); }
					}, _('Nodes'))
				];

				if (p.type === 'subscription') {
					actBtns.push(E('button', {
						'type': 'button',
						'class': 'btn cbi-button cbi-button-neutral',
						'click': function() {
							if (typeof sharedActions.runProfileUpdate === 'function')
								sharedActions.runProfileUpdate(p.id);
						}
					}, _('Update')));
				}

				actBtns.push(
					E('button', {
						'type': 'button',
						'class': 'btn cbi-button',
						'click': function() {
							if (typeof sharedActions.openJsonEditor === 'function')
								sharedActions.openJsonEditor(p);
						}
					}, _('Edit JSON')),
					E('button', {
						'type': 'button',
						'class': 'btn cbi-button',
						'click': function(ev) {
							if (typeof sharedActions.handleUploadJson === 'function')
								sharedActions.handleUploadJson(p.filename, true, ev.currentTarget);
						}
					}, _('Upload')),
					E('button', {
						'type': 'button',
						'class': 'btn cbi-button',
						'click': function() {
							if (typeof sharedActions.openMetaModal === 'function')
								sharedActions.openMetaModal(p);
						}
					}, _('Meta')),
					E('button', {
						'type': 'button',
						'class': 'btn cbi-button cbi-button-negative',
						'click': function() {
							if (typeof sharedActions.deleteProfile === 'function')
								sharedActions.deleteProfile(p);
						}
					}, _('Delete'))
				);

				rows.push(E('tr', { 'class': 'tr cbi-section-table-row' }, [
					E('td', { 'class': 'td' }, extractCb),
					E('td', { 'class': 'td' }, nameCell),
					E('td', { 'class': 'td' }, subCell),
					E('td', { 'class': 'td' }, rulesCell),
					E('td', { 'class': 'td' }, attachedCell),
					E('td', { 'class': 'td right' }, E('div', { 'style': 'display:flex;gap:4px;justify-content:flex-end;flex-wrap:wrap;' }, actBtns))
				]));
			});
		}

		blocks.push(E('div', { 'style': 'overflow-x:auto;' }, [
			E('table', { 'class': 'table cbi-section-table' }, rows)
		]));
		dom.content(tabPanel, blocks);
	}

	function moveArrayItem(arr, idx, delta) {
		var nextIdx = idx + delta;
		if (!Array.isArray(arr) || idx < 0 || idx >= arr.length || nextIdx < 0 || nextIdx >= arr.length)
			return;
		var tmp = arr[idx];
		arr[idx] = arr[nextIdx];
		arr[nextIdx] = tmp;
		markDirty();
	}

	function confirmDeleteRow(title, label, onConfirmed) {
		nimbusApi.confirmAction(
			title,
			_('Remove "%s" from the Composer draft?').format(label)
		).then(function(yes) {
			if (yes)
				onConfirmed();
		});
	}

	function openGroupModal(editIndex) {
		var isEdit = (editIndex != null && editIndex >= 0);
		var g = isEdit
			? snippets.deepClone(draft.outbound_groups[editIndex])
			: {
				id: snippets.makeId('grp'),
				enabled: true,
				type: 'selector',
				tag: '',
				remark: '',
				outbounds: [ 'direct' ],
				providers: [ { profile_id: '*', include_regex: '', exclude_regex: '' } ],
				fallback_outbound: 'direct',
				config: {}
			};

		var errBox = E('div', { 'style': 'display:none;' });
		var previewBox = E('div', { 'style': 'margin-top:8px;' });
		var enabledCb = E('input', { 'type': 'checkbox', 'checked': g.enabled !== false ? 'checked' : null });
		var typeCombo = snippets.createComboInput(g.type || 'selector', snippets.GROUP_TYPES, 'selector');
		var tagInput = E('input', {
			'type': 'text',
			'class': 'cbi-input-text',
			'value': g.tag || '',
			'placeholder': 'Proxy'
		});
		var remarkInput = E('input', {
			'type': 'text',
			'class': 'cbi-input-text',
			'value': g.remark || '',
			'placeholder': _('Optional remark')
		});

		var staticTextarea = E('textarea', {
			'class': 'cbi-input-textarea',
			'rows': '2',
			'spellcheck': 'false',
			'placeholder': _('Comma or newline separated tags, e.g. Auto, direct'),
			'style': 'width:100%;font-family:monospace;font-size:12px;resize:vertical;'
		}, (Array.isArray(g.outbounds) ? g.outbounds : []).join(', '));

		var tagPicker = E('select', {
			'class': 'cbi-input-select',
			'style': 'max-width:220px;',
			'change': function() {
				var picked = tagPicker.value;
				if (!picked)
					return;
				var cur = parseUniqueList(staticTextarea.value);
				if (cur.indexOf(picked) < 0) {
					cur.push(picked);
					staticTextarea.value = cur.join(', ');
				}
				tagPicker.value = '';
			}
		}, [
			E('option', { 'value': '' }, _('+ Pick Existing Tag'))
		].concat(getKnownOutboundTags(g.tag).map(function(t) {
			return E('option', { 'value': t }, t);
		})));

		var fallbackCombo = snippets.createComboInput(
			g.fallback_outbound != null ? g.fallback_outbound : 'direct',
			getKnownOutboundTags(g.tag),
			'direct'
		);

		var providers = Array.isArray(g.providers) ? snippets.deepClone(g.providers) : [];
		var providersBox = E('div', {});

		var lastSnipTag = null;
		var lastSnipRemark = null;
		var jsonEditor = buildSnippetTextarea(
			g.config || {},
			snippets.GROUP_SNIPPETS,
			function(snip, ta) {
				typeCombo.input.value = snip.type;
				if (!isEdit && (!tagInput.value.trim() || tagInput.value === lastSnipTag)) {
					tagInput.value = snip.tag || '';
					lastSnipTag = tagInput.value;
				}
				if (!isEdit && (!remarkInput.value.trim() || remarkInput.value === lastSnipRemark)) {
					remarkInput.value = snip.remark || '';
					lastSnipRemark = remarkInput.value;
				}
				if (!isEdit && Array.isArray(snip.outbounds))
					staticTextarea.value = snip.outbounds.join(', ');
				if (!isEdit && snip.fallback_outbound != null)
					fallbackCombo.input.value = snip.fallback_outbound;
				ta.value = snippets.prettyJson(snip.config || {});
			},
			errBox,
			8
		);

		function buildDraftWithCurrentGroup(parsedCfg) {
			var tempDraft = snippets.deepClone(draft);
			var cand = {
				id: g.id || snippets.makeId('grp'),
				enabled: enabledCb.checked,
				type: typeCombo.input.value.trim(),
				tag: tagInput.value.trim(),
				remark: remarkInput.value.trim(),
				outbounds: parseUniqueList(staticTextarea.value),
				providers: providers.map(function(pv) {
					return {
						profile_id: pv.profile_id || '*',
						include_regex: pv.include_regex || '',
						exclude_regex: pv.exclude_regex || ''
					};
				}),
				fallback_outbound: fallbackCombo.input.value.trim(),
				config: parsedCfg
			};
			if (isEdit)
				tempDraft.outbound_groups[editIndex] = cand;
			else
				tempDraft.outbound_groups.push(cand);
			return { draft: tempDraft, group: cand };
		}

		function renderProviders() {
			if (providers.length === 0) {
				dom.content(providersBox, E('div', { 'style': 'font-size:90%;color:#777;margin-bottom:6px;' },
					_('No subscription bindings configured (group uses static outbounds only).')));
				return;
			}

			var rows = providers.map(function(pv, idx) {
				var srcSelect = E('select', {
					'class': 'cbi-input-select',
					'style': 'min-width:140px;max-width:190px;',
					'change': function() { pv.profile_id = srcSelect.value; }
				}, [
					E('option', { 'value': '*', 'selected': (pv.profile_id || '*') === '*' ? 'selected' : null }, _('* (All enabled sources)'))
				].concat(profiles.map(function(p) {
					return E('option', {
						'value': p.id,
						'selected': pv.profile_id === p.id ? 'selected' : null
					}, p.name || p.id);
				})));

				var pInc = E('input', {
					'type': 'text',
					'class': 'cbi-input-text',
					'value': pv.include_regex || '',
					'placeholder': _('Include regex (e.g. HK|SG)'),
					'style': 'min-width:130px;flex:1;',
					'input': function() { pv.include_regex = pInc.value; }
				});
				var pExc = E('input', {
					'type': 'text',
					'class': 'cbi-input-text',
					'value': pv.exclude_regex || '',
					'placeholder': _('Exclude regex'),
					'style': 'min-width:120px;flex:1;',
					'input': function() { pv.exclude_regex = pExc.value; }
				});

				var prevBtn = E('button', {
					'type': 'button',
					'class': 'btn cbi-button cbi-button-action',
					'click': function() {
						hideModalError(errBox);
						var parsedCfg = jsonEditor.parse();
						if (!parsedCfg.ok) {
							showModalError(errBox, parsedCfg.error);
							return;
						}
						var built = buildDraftWithCurrentGroup(parsedCfg.value);
						var jsonStr = JSON.stringify(built.draft);
						if (nimbusApi.utf8ByteLength(jsonStr) > nimbusApi.MAX_DIRECT_TEXT_BYTES) {
							showModalError(errBox, _('Composer draft exceeds the 256 KiB inline transfer limit.'));
							return;
						}
						prevBtn.disabled = true;
						dom.content(previewBox, E('span', { 'class': 'spinning' }, _('Matching nodes...')));
						nimbusApi.composerNodes({
							profile_id: (pv.profile_id && pv.profile_id !== '*') ? pv.profile_id : '',
							composer_json: jsonStr,
							include_regex: pv.include_regex || '',
							exclude_regex: pv.exclude_regex || ''
						}).then(function(res) {
							prevBtn.disabled = false;
							dom.content(previewBox, renderNodesListBox(res, _('No nodes matched this provider binding.')));
						}).catch(function(err) {
							prevBtn.disabled = false;
							dom.content(previewBox, '');
							showModalError(errBox, nimbusApi.formatError(err));
						});
					}
				}, _('Preview'));

				var rmBtn = E('button', {
					'type': 'button',
					'class': 'btn cbi-button cbi-button-negative',
					'click': function() {
						providers.splice(idx, 1);
						renderProviders();
					}
				}, _('Remove'));

				return E('div', {
					'style': 'display:flex;gap:6px;align-items:center;flex-wrap:wrap;margin-bottom:6px;padding:6px;border:1px solid #ececec;border-radius:3px;background:#fcfcfc;'
				}, [ srcSelect, pInc, pExc, prevBtn, rmBtn ]);
			});

			dom.content(providersBox, rows);
		}

		renderProviders();

		var saveBtn = E('button', {
			'type': 'button',
			'class': 'btn cbi-button cbi-button-save',
			'click': function() {
				hideModalError(errBox);
				var parsedCfg = jsonEditor.parse();
				if (!parsedCfg.ok) {
					showModalError(errBox, parsedCfg.error);
					return;
				}
				var gtype = typeCombo.input.value.trim();
				var gtag = tagInput.value.trim();
				if (enabledCb.checked) {
					if (!gtype) {
						showModalError(errBox, _('Group type is required when enabled.'));
						return;
					}
					if (!gtag) {
						showModalError(errBox, _('Group tag is required when enabled.'));
						return;
					}
				}
				var built = buildDraftWithCurrentGroup(parsedCfg.value);
				if (isEdit)
					draft.outbound_groups[editIndex] = built.group;
				else
					draft.outbound_groups.push(built.group);
				markDirty();
				ui.hideModal();
			}
		}, _('Save'));

		ui.showModal(isEdit ? _('Edit Outbound Group: %s').format(g.tag || g.id) : _('Add Outbound Group'), [
			errBox,
			E('div', { 'class': 'cbi-value' }, [
				E('label', { 'class': 'cbi-value-title' }, _('Enabled')),
				E('div', { 'class': 'cbi-value-field' }, enabledCb)
			]),
			E('div', { 'class': 'cbi-value' }, [
				E('label', { 'class': 'cbi-value-title' }, _('Type')),
				E('div', { 'class': 'cbi-value-field' }, typeCombo.container)
			]),
			E('div', { 'class': 'cbi-value' }, [
				E('label', { 'class': 'cbi-value-title' }, _('Tag')),
				E('div', { 'class': 'cbi-value-field' }, tagInput)
			]),
			E('div', { 'class': 'cbi-value' }, [
				E('label', { 'class': 'cbi-value-title' }, _('Remark')),
				E('div', { 'class': 'cbi-value-field' }, remarkInput)
			]),
			E('div', { 'class': 'cbi-value' }, [
				E('label', { 'class': 'cbi-value-title' }, _('Static Outbounds')),
				E('div', { 'class': 'cbi-value-field' }, [
					staticTextarea,
					E('div', { 'style': 'margin-top:6px;display:flex;gap:8px;align-items:center;flex-wrap:wrap;' }, [
						tagPicker,
						E('span', { 'class': 'cbi-value-description', 'style': 'margin:0;' }, _('Included before matched subscription nodes.'))
					])
				])
			]),
			E('div', { 'class': 'cbi-value' }, [
				E('label', { 'class': 'cbi-value-title' }, _('Fallback Outbound')),
				E('div', { 'class': 'cbi-value-field' }, [
					fallbackCombo.container,
					E('div', { 'class': 'cbi-value-description' }, _('Used automatically if this group resolves to zero members.'))
				])
			]),
			E('div', { 'class': 'cbi-value' }, [
				E('label', { 'class': 'cbi-value-title' }, _('Provider Bindings')),
				E('div', { 'class': 'cbi-value-field' }, [
					providersBox,
					E('button', {
						'type': 'button',
						'class': 'btn cbi-button cbi-button-add',
						'click': function() {
							providers.push({ profile_id: '*', include_regex: '', exclude_regex: '' });
							renderProviders();
						}
					}, _('Add Binding')),
					previewBox
				])
			]),
			E('div', { 'class': 'cbi-value' }, [
				E('label', { 'class': 'cbi-value-title' }, _('Config JSON')),
				E('div', { 'class': 'cbi-value-field' }, jsonEditor.el)
			]),
			E('div', { 'class': 'right', 'style': 'margin-top:12px;' }, [
				E('button', { 'type': 'button', 'class': 'btn cbi-button', 'click': ui.hideModal }, _('Cancel')),
				' ',
				saveBtn
			])
		]);
	}

	function openTypedItemModal(cfg) {
		var isEdit = (cfg.editIndex != null && cfg.editIndex >= 0);
		var item = isEdit
			? snippets.deepClone(cfg.list[cfg.editIndex])
			: {
				id: snippets.makeId(cfg.idPrefix),
				enabled: true,
				type: cfg.defaultType || '',
				tag: '',
				format: cfg.showFormat ? 'binary' : undefined,
				remark: '',
				config: {}
			};

		var errBox = E('div', { 'style': 'display:none;' });
		var enabledCb = E('input', { 'type': 'checkbox', 'checked': item.enabled !== false ? 'checked' : null });
		var typeCombo = snippets.createComboInput(item.type || '', cfg.typeSuggestions, cfg.defaultType || '');
		var formatCombo = cfg.showFormat
			? snippets.createComboInput(item.format || '', cfg.formatSuggestions, 'binary')
			: null;
		var tagInput = E('input', {
			'type': 'text',
			'class': 'cbi-input-text',
			'value': item.tag || '',
			'placeholder': cfg.tagPlaceholder || ''
		});
		var remarkInput = E('input', {
			'type': 'text',
			'class': 'cbi-input-text',
			'value': item.remark || '',
			'placeholder': _('Optional remark')
		});

		var formatRow = cfg.showFormat
			? E('div', { 'class': 'cbi-value' }, [
				E('label', { 'class': 'cbi-value-title' }, _('Format')),
				E('div', { 'class': 'cbi-value-field' }, [
					formatCombo.container,
					E('div', { 'class': 'cbi-value-description' }, _('Required for remote/local (binary or source); omitted for inline.'))
				])
			])
			: null;

		function syncFormatVisibility() {
			if (!cfg.showFormat || !formatRow)
				return;
			var isInline = (typeCombo.input.value.trim() === 'inline');
			formatRow.style.display = isInline ? 'none' : '';
			if (isInline)
				formatCombo.input.value = '';
		}

		if (cfg.showFormat) {
			typeCombo.input.addEventListener('input', syncFormatVisibility);
			typeCombo.input.addEventListener('change', syncFormatVisibility);
			syncFormatVisibility();
		}

		var lastSnipTag = null;
		var lastSnipRemark = null;
		var jsonEditor = buildSnippetTextarea(
			item.config || {},
			cfg.snippets,
			function(snip, ta) {
				typeCombo.input.value = snip.type || '';
				if (cfg.showFormat && formatCombo)
					formatCombo.input.value = snip.format || '';
				syncFormatVisibility();
				if (!isEdit && (!tagInput.value.trim() || tagInput.value === lastSnipTag)) {
					tagInput.value = snip.tag || '';
					lastSnipTag = tagInput.value;
				}
				if (!isEdit && (!remarkInput.value.trim() || remarkInput.value === lastSnipRemark)) {
					remarkInput.value = snip.remark || '';
					lastSnipRemark = remarkInput.value;
				}
				ta.value = snippets.prettyJson(snip.config || {});
			},
			errBox,
			10
		);

		var saveBtn = E('button', {
			'type': 'button',
			'class': 'btn cbi-button cbi-button-save',
			'click': function() {
				hideModalError(errBox);
				var parsedCfg = jsonEditor.parse();
				if (!parsedCfg.ok) {
					showModalError(errBox, parsedCfg.error);
					return;
				}
				var itype = typeCombo.input.value.trim();
				var itag = tagInput.value.trim();
				if (enabledCb.checked) {
					if (!itype) {
						showModalError(errBox, _('Type is required when enabled.'));
						return;
					}
					if (!itag) {
						showModalError(errBox, _('Tag is required when enabled.'));
						return;
					}
				}
				var saved = {
					id: item.id || snippets.makeId(cfg.idPrefix),
					enabled: enabledCb.checked,
					type: itype,
					tag: itag,
					remark: remarkInput.value.trim(),
					config: parsedCfg.value
				};
				if (cfg.showFormat)
					saved.format = (itype === 'inline') ? '' : formatCombo.input.value.trim();

				if (isEdit)
					cfg.list[cfg.editIndex] = saved;
				else
					cfg.list.push(saved);

				markDirty();
				ui.hideModal();
			}
		}, _('Save'));

		var modalNodes = [
			errBox,
			E('div', { 'class': 'cbi-value' }, [
				E('label', { 'class': 'cbi-value-title' }, _('Enabled')),
				E('div', { 'class': 'cbi-value-field' }, enabledCb)
			]),
			E('div', { 'class': 'cbi-value' }, [
				E('label', { 'class': 'cbi-value-title' }, _('Type')),
				E('div', { 'class': 'cbi-value-field' }, typeCombo.container)
			])
		];
		if (formatRow)
			modalNodes.push(formatRow);
		modalNodes.push(
			E('div', { 'class': 'cbi-value' }, [
				E('label', { 'class': 'cbi-value-title' }, _('Tag')),
				E('div', { 'class': 'cbi-value-field' }, tagInput)
			]),
			E('div', { 'class': 'cbi-value' }, [
				E('label', { 'class': 'cbi-value-title' }, _('Remark')),
				E('div', { 'class': 'cbi-value-field' }, remarkInput)
			]),
			E('div', { 'class': 'cbi-value' }, [
				E('label', { 'class': 'cbi-value-title' }, _('Config JSON')),
				E('div', { 'class': 'cbi-value-field' }, jsonEditor.el)
			]),
			E('div', { 'class': 'right', 'style': 'margin-top:12px;' }, [
				E('button', { 'type': 'button', 'class': 'btn cbi-button', 'click': ui.hideModal }, _('Cancel')),
				' ',
				saveBtn
			])
		);

		ui.showModal(isEdit ? cfg.editTitle.format(item.tag || item.id) : cfg.addTitle, modalNodes);
	}

	function openRuleItemModal(cfg) {
		var isEdit = (cfg.editIndex != null && cfg.editIndex >= 0);
		var rule = isEdit
			? snippets.deepClone(cfg.list[cfg.editIndex])
			: {
				id: snippets.makeId(cfg.idPrefix),
				enabled: true,
				remark: '',
				action: 'route',
				config: {}
			};
		if (!isEdit)
			rule[cfg.targetKey] = '';

		var errBox = E('div', { 'style': 'display:none;' });
		var enabledCb = E('input', { 'type': 'checkbox', 'checked': rule.enabled !== false ? 'checked' : null });
		var actionCombo = snippets.createComboInput(rule.action || '', cfg.actionSuggestions, 'route');
		var targetCombo = snippets.createComboInput(rule[cfg.targetKey] || '', cfg.targetSuggestions, cfg.targetPlaceholder || '');
		var remarkInput = E('input', {
			'type': 'text',
			'class': 'cbi-input-text',
			'value': rule.remark || '',
			'placeholder': _('Optional remark')
		});

		var lastSnipRemark = null;
		var jsonEditor = buildSnippetTextarea(
			rule.config || {},
			cfg.snippets,
			function(snip, ta) {
				actionCombo.input.value = snip.action || '';
				targetCombo.input.value = snip[cfg.targetKey] || '';
				if (!isEdit && (!remarkInput.value.trim() || remarkInput.value === lastSnipRemark)) {
					remarkInput.value = snip.remark || '';
					lastSnipRemark = remarkInput.value;
				}
				ta.value = snippets.prettyJson(snip.config || {});
			},
			errBox,
			10
		);

		var saveBtn = E('button', {
			'type': 'button',
			'class': 'btn cbi-button cbi-button-save',
			'click': function() {
				hideModalError(errBox);
				var parsedCfg = jsonEditor.parse();
				if (!parsedCfg.ok) {
					showModalError(errBox, parsedCfg.error);
					return;
				}
				var saved = {
					id: rule.id || snippets.makeId(cfg.idPrefix),
					enabled: enabledCb.checked,
					remark: remarkInput.value.trim(),
					action: actionCombo.input.value.trim(),
					config: parsedCfg.value
				};
				saved[cfg.targetKey] = targetCombo.input.value.trim();

				if (isEdit)
					cfg.list[cfg.editIndex] = saved;
				else
					cfg.list.push(saved);

				markDirty();
				ui.hideModal();
			}
		}, _('Save'));

		ui.showModal(isEdit ? cfg.editTitle : cfg.addTitle, [
			errBox,
			E('div', { 'class': 'cbi-value' }, [
				E('label', { 'class': 'cbi-value-title' }, _('Enabled')),
				E('div', { 'class': 'cbi-value-field' }, enabledCb)
			]),
			E('div', { 'class': 'cbi-value' }, [
				E('label', { 'class': 'cbi-value-title' }, _('Action')),
				E('div', { 'class': 'cbi-value-field' }, actionCombo.container)
			]),
			E('div', { 'class': 'cbi-value' }, [
				E('label', { 'class': 'cbi-value-title' }, cfg.targetLabel),
				E('div', { 'class': 'cbi-value-field' }, targetCombo.container)
			]),
			E('div', { 'class': 'cbi-value' }, [
				E('label', { 'class': 'cbi-value-title' }, _('Remark')),
				E('div', { 'class': 'cbi-value-field' }, remarkInput)
			]),
			E('div', { 'class': 'cbi-value' }, [
				E('label', { 'class': 'cbi-value-title' }, _('Match Config JSON')),
				E('div', { 'class': 'cbi-value-field' }, jsonEditor.el)
			]),
			E('div', { 'class': 'right', 'style': 'margin-top:12px;' }, [
				E('button', { 'type': 'button', 'class': 'btn cbi-button', 'click': ui.hideModal }, _('Cancel')),
				' ',
				saveBtn
			])
		]);
	}

	function openExtraJsonModal(title, descr, currentObj, onApply) {
		var errBox = E('div', { 'style': 'display:none;' });
		var textarea = E('textarea', {
			'class': 'cbi-input-textarea',
			'rows': '12',
			'spellcheck': 'false',
			'style': 'width:100%;font-family:monospace;font-size:12px;resize:vertical;'
		}, snippets.prettyJson(currentObj || {}));

		var saveBtn = E('button', {
			'type': 'button',
			'class': 'btn cbi-button cbi-button-save',
			'click': function() {
				hideModalError(errBox);
				var parsed = snippets.parseJsonObject(textarea.value);
				if (!parsed.ok) {
					showModalError(errBox, parsed.error);
					return;
				}
				onApply(parsed.value);
				markDirty();
				ui.hideModal();
			}
		}, _('Save'));

		ui.showModal(title, [
			errBox,
			E('p', { 'style': 'font-size:90%;color:#666;margin-top:0;' }, descr),
			E('div', { 'style': 'margin-bottom:6px;' }, [
				E('button', {
					'type': 'button',
					'class': 'btn cbi-button',
					'click': function() {
						var parsed = snippets.parseJsonObject(textarea.value);
						if (!parsed.ok) {
							showModalError(errBox, parsed.error);
							return;
						}
						hideModalError(errBox);
						textarea.value = snippets.prettyJson(parsed.value);
					}
				}, _('Format JSON'))
			]),
			textarea,
			E('div', { 'class': 'right', 'style': 'margin-top:12px;' }, [
				E('button', { 'type': 'button', 'class': 'btn cbi-button', 'click': ui.hideModal }, _('Cancel')),
				' ',
				saveBtn
			])
		]);
	}

	function renderOutboundsTab() {
		// Section A: Outbound Groups
		var grpHeader = E('div', { 'style': 'display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;margin-bottom:8px;' }, [
			E('h3', { 'style': 'margin:0;' }, _('Outbound Groups (selector / urltest)')),
			E('button', {
				'type': 'button',
				'class': 'btn cbi-button cbi-button-add',
				'click': function() { openGroupModal(null); }
			}, _('Add Group'))
		]);

		var grpRows = [
			E('tr', { 'class': 'tr cbi-section-table-titles' }, [
				E('th', { 'class': 'th' }, _('Order')),
				E('th', { 'class': 'th' }, _('Enabled')),
				E('th', { 'class': 'th' }, _('Tag')),
				E('th', { 'class': 'th' }, _('Type')),
				E('th', { 'class': 'th' }, _('Members & Subscriptions')),
				E('th', { 'class': 'th right' }, _('Actions'))
			])
		];

		if (draft.outbound_groups.length === 0) {
			grpRows.push(E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td center', 'colspan': '6' }, _('No outbound groups defined.'))
			]));
		} else {
			draft.outbound_groups.forEach(function(g, idx) {
				var enCb = E('input', {
					'type': 'checkbox',
					'checked': g.enabled !== false ? 'checked' : null,
					'change': function() {
						g.enabled = enCb.checked;
						markDirty();
					}
				});

				var staticList = Array.isArray(g.outbounds) ? g.outbounds : [];
				var provList = Array.isArray(g.providers) ? g.providers : [];
				var summaryParts = [];
				if (staticList.length > 0)
					summaryParts.push(_('Static: %s').format(staticList.join(', ')));
				if (provList.length > 0) {
					var provDesc = provList.map(function(pv) {
						var base = (pv.profile_id === '*') ? _('* All') : pv.profile_id;
						if (pv.include_regex)
							base += ' /%s/'.format(pv.include_regex);
						if (pv.exclude_regex)
							base += ' !/%s/'.format(pv.exclude_regex);
						return base;
					}).join('; ');
					summaryParts.push(_('Sources: %s').format(provDesc));
				}
				if (g.fallback_outbound)
					summaryParts.push(_('Fallback: %s').format(g.fallback_outbound));

				var summaryCell = E('div', {}, [
					E('div', { 'style': 'font-size:90%;' }, summaryParts.length ? summaryParts.join(' · ') : '-'),
					g.remark ? E('div', { 'style': 'font-size:85%;color:#666;' }, g.remark) : ''
				]);

				grpRows.push(E('tr', { 'class': 'tr cbi-section-table-row' }, [
					E('td', { 'class': 'td', 'style': 'white-space:nowrap;' }, [
						E('button', {
							'type': 'button',
							'class': 'btn cbi-button',
							'disabled': idx === 0 ? 'disabled' : null,
							'click': function() { moveArrayItem(draft.outbound_groups, idx, -1); }
						}, '↑'),
						' ',
						E('button', {
							'type': 'button',
							'class': 'btn cbi-button',
							'disabled': idx === draft.outbound_groups.length - 1 ? 'disabled' : null,
							'click': function() { moveArrayItem(draft.outbound_groups, idx, 1); }
						}, '↓')
					]),
					E('td', { 'class': 'td' }, enCb),
					E('td', { 'class': 'td' }, E('code', {}, g.tag || '-')),
					E('td', { 'class': 'td' }, g.type || '-'),
					E('td', { 'class': 'td' }, summaryCell),
					E('td', { 'class': 'td right', 'style': 'white-space:nowrap;' }, [
						E('button', {
							'type': 'button',
							'class': 'btn cbi-button cbi-button-edit',
							'click': function() { openGroupModal(idx); }
						}, _('Edit')),
						' ',
						E('button', {
							'type': 'button',
							'class': 'btn cbi-button cbi-button-negative',
							'click': function() {
								confirmDeleteRow(_('Delete Group'), g.tag || g.id, function() {
									draft.outbound_groups.splice(idx, 1);
									markDirty();
								});
							}
						}, _('Delete'))
					])
				]));
			});
		}

		// Section B: Manual Outbounds
		var outHeader = E('div', { 'style': 'display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;margin:18px 0 8px;' }, [
			E('h3', { 'style': 'margin:0;' }, _('Manual Outbounds')),
			E('button', {
				'type': 'button',
				'class': 'btn cbi-button cbi-button-add',
				'click': function() {
					openTypedItemModal({
						addTitle: _('Add Manual Outbound'),
						editTitle: _('Edit Outbound: %s'),
						idPrefix: 'out',
						list: draft.outbounds,
						editIndex: null,
						defaultType: 'direct',
						typeSuggestions: snippets.OUTBOUND_TYPES,
						snippets: snippets.OUTBOUND_SNIPPETS,
						tagPlaceholder: 'direct'
					});
				}
			}, _('Add Outbound'))
		]);

		var outRows = [
			E('tr', { 'class': 'tr cbi-section-table-titles' }, [
				E('th', { 'class': 'th' }, _('Enabled')),
				E('th', { 'class': 'th' }, _('Tag')),
				E('th', { 'class': 'th' }, _('Type')),
				E('th', { 'class': 'th' }, _('Summary')),
				E('th', { 'class': 'th' }, _('Remark')),
				E('th', { 'class': 'th right' }, _('Actions'))
			])
		];

		if (draft.outbounds.length === 0) {
			outRows.push(E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td center', 'colspan': '6' }, _('No manual outbounds defined.'))
			]));
		} else {
			draft.outbounds.forEach(function(o, idx) {
				var enCb = E('input', {
					'type': 'checkbox',
					'checked': o.enabled !== false ? 'checked' : null,
					'change': function() {
						o.enabled = enCb.checked;
						markDirty();
					}
				});

				outRows.push(E('tr', { 'class': 'tr cbi-section-table-row' }, [
					E('td', { 'class': 'td' }, enCb),
					E('td', { 'class': 'td' }, E('code', {}, o.tag || '-')),
					E('td', { 'class': 'td' }, o.type || '-'),
					E('td', { 'class': 'td' }, snippets.summarizeOutbound(o)),
					E('td', { 'class': 'td' }, o.remark || '-'),
					E('td', { 'class': 'td right', 'style': 'white-space:nowrap;' }, [
						E('button', {
							'type': 'button',
							'class': 'btn cbi-button cbi-button-edit',
							'click': function() {
								openTypedItemModal({
									addTitle: _('Add Manual Outbound'),
									editTitle: _('Edit Outbound: %s'),
									idPrefix: 'out',
									list: draft.outbounds,
									editIndex: idx,
									defaultType: 'direct',
									typeSuggestions: snippets.OUTBOUND_TYPES,
									snippets: snippets.OUTBOUND_SNIPPETS,
									tagPlaceholder: 'direct'
								});
							}
						}, _('Edit')),
						' ',
						E('button', {
							'type': 'button',
							'class': 'btn cbi-button cbi-button-negative',
							'click': function() {
								confirmDeleteRow(_('Delete Outbound'), o.tag || o.id, function() {
									draft.outbounds.splice(idx, 1);
									markDirty();
								});
							}
						}, _('Delete'))
					])
				]));
			});
		}

		dom.content(tabPanel, [
			grpHeader,
			E('div', { 'style': 'overflow-x:auto;' }, [ E('table', { 'class': 'table cbi-section-table' }, grpRows) ]),
			outHeader,
			E('div', { 'style': 'overflow-x:auto;' }, [ E('table', { 'class': 'table cbi-section-table' }, outRows) ])
		]);
	}

	function renderInboundsTab() {
		var dnsPortNote = (autoInbounds.dns_mode === 'singbox')
			? _('DNS Mode: singbox (port %d)').format(autoInbounds.singbox_dns_port || 5353)
			: _('DNS Mode: %s').format(autoInbounds.dns_mode || 'none');

		var banner = E('div', { 'class': 'alert-message info', 'style': 'margin-bottom:12px;' }, [
			E('strong', {}, _('Managed Dataplane Inbounds (%s): ').format(autoInbounds.proxy_mode || 'tproxy_redirect')),
			E('span', {},
				_('Redirect TCP port %d · TPROXY UDP port %d · %s. Nimbus automatically injects missing transparent proxy or DNS inbounds at runtime and reuses matching user-defined ones (conflicting tun inbounds are stripped).')
					.format(autoInbounds.redirect_port || 7891, autoInbounds.tproxy_port || 7892, dnsPortNote))
		]);

		var header = E('div', { 'style': 'display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;margin-bottom:8px;' }, [
			E('h3', { 'style': 'margin:0;' }, _('Custom Inbounds')),
			E('button', {
				'type': 'button',
				'class': 'btn cbi-button cbi-button-add',
				'click': function() {
					openTypedItemModal({
						addTitle: _('Add Inbound'),
						editTitle: _('Edit Inbound: %s'),
						idPrefix: 'in',
						list: draft.inbounds,
						editIndex: null,
						defaultType: 'mixed',
						typeSuggestions: snippets.INBOUND_TYPES,
						snippets: snippets.INBOUND_SNIPPETS,
						tagPlaceholder: 'mixed-in'
					});
				}
			}, _('Add Inbound'))
		]);

		var rows = [
			E('tr', { 'class': 'tr cbi-section-table-titles' }, [
				E('th', { 'class': 'th' }, _('Enabled')),
				E('th', { 'class': 'th' }, _('Tag')),
				E('th', { 'class': 'th' }, _('Type')),
				E('th', { 'class': 'th' }, _('Listen Summary')),
				E('th', { 'class': 'th' }, _('Remark')),
				E('th', { 'class': 'th right' }, _('Actions'))
			])
		];

		if (draft.inbounds.length === 0) {
			rows.push(E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td center', 'colspan': '6' }, _('No custom inbounds configured.'))
			]));
		} else {
			draft.inbounds.forEach(function(inb, idx) {
				var enCb = E('input', {
					'type': 'checkbox',
					'checked': inb.enabled !== false ? 'checked' : null,
					'change': function() {
						inb.enabled = enCb.checked;
						markDirty();
					}
				});

				rows.push(E('tr', { 'class': 'tr cbi-section-table-row' }, [
					E('td', { 'class': 'td' }, enCb),
					E('td', { 'class': 'td' }, E('code', {}, inb.tag || '-')),
					E('td', { 'class': 'td' }, inb.type || '-'),
					E('td', { 'class': 'td' }, snippets.summarizeInbound(inb)),
					E('td', { 'class': 'td' }, inb.remark || '-'),
					E('td', { 'class': 'td right', 'style': 'white-space:nowrap;' }, [
						E('button', {
							'type': 'button',
							'class': 'btn cbi-button cbi-button-edit',
							'click': function() {
								openTypedItemModal({
									addTitle: _('Add Inbound'),
									editTitle: _('Edit Inbound: %s'),
									idPrefix: 'in',
									list: draft.inbounds,
									editIndex: idx,
									defaultType: 'mixed',
									typeSuggestions: snippets.INBOUND_TYPES,
									snippets: snippets.INBOUND_SNIPPETS,
									tagPlaceholder: 'mixed-in'
								});
							}
						}, _('Edit')),
						' ',
						E('button', {
							'type': 'button',
							'class': 'btn cbi-button cbi-button-negative',
							'click': function() {
								confirmDeleteRow(_('Delete Inbound'), inb.tag || inb.id, function() {
									draft.inbounds.splice(idx, 1);
									markDirty();
								});
							}
						}, _('Delete'))
					])
				]));
			});
		}

		dom.content(tabPanel, [
			banner,
			header,
			E('div', { 'style': 'overflow-x:auto;' }, [ E('table', { 'class': 'table cbi-section-table' }, rows) ])
		]);
	}

	function renderDnsTab() {
		var dnsTags = getKnownDnsTags();
		var finalCombo = snippets.createComboInput(draft.dns.final || '', dnsTags, 'dns-proxy');
		finalCombo.container.style.maxWidth = '200px';
		finalCombo.input.addEventListener('input', function() {
			draft.dns.final = finalCombo.input.value.trim();
			markDirty({ skipTabRender: true });
		});

		var strategySelect = E('select', {
			'class': 'cbi-input-select',
			'style': 'max-width:170px;',
			'change': function() {
				draft.dns.strategy = strategySelect.value;
				markDirty({ skipTabRender: true });
			}
		}, snippets.DNS_STRATEGIES.map(function(st) {
			return E('option', {
				'value': st,
				'selected': (draft.dns.strategy || '') === st ? 'selected' : null
			}, st || _('(Default)'));
		}));

		var extraBtn = E('button', {
			'type': 'button',
			'class': 'btn cbi-button',
			'click': function() {
				openExtraJsonModal(
					_('Advanced DNS JSON (dns.extra)'),
					_('Additional top-level sing-box 1.14 dns fields (e.g. disable_cache, disable_expire, reverse_mapping, client_subnet). Do not use removed independent_cache.'),
					draft.dns.extra,
					function(obj) { draft.dns.extra = obj; }
				);
			}
		}, _('Advanced DNS JSON...'));

		var globalBar = E('div', {
			'style': 'display:flex;align-items:center;gap:14px;flex-wrap:wrap;padding:8px 10px;border:1px solid #e5e5e5;border-radius:4px;background:#fcfcfc;margin-bottom:14px;'
		}, [
			E('label', { 'style': 'display:inline-flex;align-items:center;gap:6px;margin:0;' }, [
				E('span', { 'style': 'font-weight:600;' }, _('Final Server')),
				finalCombo.container
			]),
			E('label', { 'style': 'display:inline-flex;align-items:center;gap:6px;margin:0;' }, [
				E('span', { 'style': 'font-weight:600;' }, _('Strategy')),
				strategySelect
			]),
			extraBtn
		]);

		// Section A: DNS Servers
		var srvHeader = E('div', { 'style': 'display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;margin-bottom:8px;' }, [
			E('h3', { 'style': 'margin:0;' }, _('DNS Servers')),
			E('button', {
				'type': 'button',
				'class': 'btn cbi-button cbi-button-add',
				'click': function() {
					openTypedItemModal({
						addTitle: _('Add DNS Server'),
						editTitle: _('Edit DNS Server: %s'),
						idPrefix: 'dns',
						list: draft.dns.servers,
						editIndex: null,
						defaultType: 'udp',
						typeSuggestions: snippets.DNS_SERVER_TYPES,
						snippets: snippets.DNS_SERVER_SNIPPETS,
						tagPlaceholder: 'dns-cn'
					});
				}
			}, _('Add DNS Server'))
		]);

		var srvRows = [
			E('tr', { 'class': 'tr cbi-section-table-titles' }, [
				E('th', { 'class': 'th' }, _('Enabled')),
				E('th', { 'class': 'th' }, _('Tag')),
				E('th', { 'class': 'th' }, _('Type')),
				E('th', { 'class': 'th' }, _('Summary')),
				E('th', { 'class': 'th' }, _('Remark')),
				E('th', { 'class': 'th right' }, _('Actions'))
			])
		];

		if (draft.dns.servers.length === 0) {
			srvRows.push(E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td center', 'colspan': '6' }, _('No DNS servers defined.'))
			]));
		} else {
			draft.dns.servers.forEach(function(srv, idx) {
				var enCb = E('input', {
					'type': 'checkbox',
					'checked': srv.enabled !== false ? 'checked' : null,
					'change': function() {
						srv.enabled = enCb.checked;
						markDirty();
					}
				});

				srvRows.push(E('tr', { 'class': 'tr cbi-section-table-row' }, [
					E('td', { 'class': 'td' }, enCb),
					E('td', { 'class': 'td' }, E('code', {}, srv.tag || '-')),
					E('td', { 'class': 'td' }, srv.type || '-'),
					E('td', { 'class': 'td' }, snippets.summarizeDnsServer(srv)),
					E('td', { 'class': 'td' }, srv.remark || '-'),
					E('td', { 'class': 'td right', 'style': 'white-space:nowrap;' }, [
						E('button', {
							'type': 'button',
							'class': 'btn cbi-button cbi-button-edit',
							'click': function() {
								openTypedItemModal({
									addTitle: _('Add DNS Server'),
									editTitle: _('Edit DNS Server: %s'),
									idPrefix: 'dns',
									list: draft.dns.servers,
									editIndex: idx,
									defaultType: 'udp',
									typeSuggestions: snippets.DNS_SERVER_TYPES,
									snippets: snippets.DNS_SERVER_SNIPPETS,
									tagPlaceholder: 'dns-cn'
								});
							}
						}, _('Edit')),
						' ',
						E('button', {
							'type': 'button',
							'class': 'btn cbi-button cbi-button-negative',
							'click': function() {
								confirmDeleteRow(_('Delete DNS Server'), srv.tag || srv.id, function() {
									draft.dns.servers.splice(idx, 1);
									markDirty();
								});
							}
						}, _('Delete'))
					])
				]));
			});
		}

		// Section B: DNS Rules
		var drHeader = E('div', { 'style': 'display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;margin:18px 0 8px;' }, [
			E('h3', { 'style': 'margin:0;' }, _('DNS Rules')),
			E('button', {
				'type': 'button',
				'class': 'btn cbi-button cbi-button-add',
				'click': function() {
					openRuleItemModal({
						addTitle: _('Add DNS Rule'),
						editTitle: _('Edit DNS Rule'),
						idPrefix: 'dr',
						list: draft.dns.rules,
						editIndex: null,
						targetKey: 'server',
						targetLabel: _('Target Server'),
						targetPlaceholder: 'dns-cn',
						actionSuggestions: snippets.DNS_RULE_ACTIONS,
						targetSuggestions: getKnownDnsTags(),
						snippets: snippets.DNS_RULE_SNIPPETS
					});
				}
			}, _('Add DNS Rule'))
		]);

		var drRows = [
			E('tr', { 'class': 'tr cbi-section-table-titles' }, [
				E('th', { 'class': 'th' }, _('Order')),
				E('th', { 'class': 'th' }, _('Enabled')),
				E('th', { 'class': 'th' }, _('Action')),
				E('th', { 'class': 'th' }, _('Target Server')),
				E('th', { 'class': 'th' }, _('Match Summary')),
				E('th', { 'class': 'th' }, _('Remark')),
				E('th', { 'class': 'th right' }, _('Actions'))
			])
		];

		if (draft.dns.rules.length === 0) {
			drRows.push(E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td center', 'colspan': '7' }, _('No DNS rules defined.'))
			]));
		} else {
			draft.dns.rules.forEach(function(r, idx) {
				var enCb = E('input', {
					'type': 'checkbox',
					'checked': r.enabled !== false ? 'checked' : null,
					'change': function() {
						r.enabled = enCb.checked;
						markDirty();
					}
				});

				drRows.push(E('tr', { 'class': 'tr cbi-section-table-row' }, [
					E('td', { 'class': 'td', 'style': 'white-space:nowrap;' }, [
						E('button', {
							'type': 'button',
							'class': 'btn cbi-button',
							'disabled': idx === 0 ? 'disabled' : null,
							'click': function() { moveArrayItem(draft.dns.rules, idx, -1); }
						}, '↑'),
						' ',
						E('button', {
							'type': 'button',
							'class': 'btn cbi-button',
							'disabled': idx === draft.dns.rules.length - 1 ? 'disabled' : null,
							'click': function() { moveArrayItem(draft.dns.rules, idx, 1); }
						}, '↓')
					]),
					E('td', { 'class': 'td' }, enCb),
					E('td', { 'class': 'td' }, r.action || '-'),
					E('td', { 'class': 'td' }, r.server ? E('code', {}, r.server) : '-'),
					E('td', { 'class': 'td' }, snippets.summarizeRule(r)),
					E('td', { 'class': 'td' }, r.remark || '-'),
					E('td', { 'class': 'td right', 'style': 'white-space:nowrap;' }, [
						E('button', {
							'type': 'button',
							'class': 'btn cbi-button cbi-button-edit',
							'click': function() {
								openRuleItemModal({
									addTitle: _('Add DNS Rule'),
									editTitle: _('Edit DNS Rule'),
									idPrefix: 'dr',
									list: draft.dns.rules,
									editIndex: idx,
									targetKey: 'server',
									targetLabel: _('Target Server'),
									targetPlaceholder: 'dns-cn',
									actionSuggestions: snippets.DNS_RULE_ACTIONS,
									targetSuggestions: getKnownDnsTags(),
									snippets: snippets.DNS_RULE_SNIPPETS
								});
							}
						}, _('Edit')),
						' ',
						E('button', {
							'type': 'button',
							'class': 'btn cbi-button cbi-button-negative',
							'click': function() {
								confirmDeleteRow(_('Delete DNS Rule'), r.remark || r.action || r.id, function() {
									draft.dns.rules.splice(idx, 1);
									markDirty();
								});
							}
						}, _('Delete'))
					])
				]));
			});
		}

		dom.content(tabPanel, [
			globalBar,
			srvHeader,
			E('div', { 'style': 'overflow-x:auto;' }, [ E('table', { 'class': 'table cbi-section-table' }, srvRows) ]),
			drHeader,
			E('div', { 'style': 'overflow-x:auto;' }, [ E('table', { 'class': 'table cbi-section-table' }, drRows) ])
		]);
	}

	function renderRouteTab() {
		var outTags = getKnownOutboundTags();
		var dnsTags = getKnownDnsTags();

		var finalCombo = snippets.createComboInput(draft.route.final || '', outTags, 'Proxy');
		finalCombo.container.style.maxWidth = '200px';
		finalCombo.input.addEventListener('input', function() {
			draft.route.final = finalCombo.input.value.trim();
			markDirty({ skipTabRender: true });
		});

		var resolverCombo = snippets.createComboInput(draft.route.default_domain_resolver || '', dnsTags, 'dns-cn');
		resolverCombo.container.style.maxWidth = '200px';
		resolverCombo.input.addEventListener('input', function() {
			draft.route.default_domain_resolver = resolverCombo.input.value.trim();
			markDirty({ skipTabRender: true });
		});

		var extraBtn = E('button', {
			'type': 'button',
			'class': 'btn cbi-button',
			'click': function() {
				openExtraJsonModal(
					_('Advanced Route JSON (route.extra)'),
					_('Additional top-level sing-box 1.14 route fields (e.g. auto_detect_interface, default_interface, default_mark).'),
					draft.route.extra,
					function(obj) { draft.route.extra = obj; }
				);
			}
		}, _('Advanced Route JSON...'));

		var globalBar = E('div', {
			'style': 'display:flex;align-items:center;gap:14px;flex-wrap:wrap;padding:8px 10px;border:1px solid #e5e5e5;border-radius:4px;background:#fcfcfc;margin-bottom:14px;'
		}, [
			E('label', { 'style': 'display:inline-flex;align-items:center;gap:6px;margin:0;' }, [
				E('span', { 'style': 'font-weight:600;' }, _('Final Outbound')),
				finalCombo.container
			]),
			E('label', { 'style': 'display:inline-flex;align-items:center;gap:6px;margin:0;' }, [
				E('span', { 'style': 'font-weight:600;' }, _('Default Domain Resolver')),
				resolverCombo.container
			]),
			extraBtn
		]);

		// Section A: Route Rules
		var rrHeader = E('div', { 'style': 'display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;margin-bottom:8px;' }, [
			E('h3', { 'style': 'margin:0;' }, _('Route Rules')),
			E('button', {
				'type': 'button',
				'class': 'btn cbi-button cbi-button-add',
				'click': function() {
					openRuleItemModal({
						addTitle: _('Add Route Rule'),
						editTitle: _('Edit Route Rule'),
						idPrefix: 'rr',
						list: draft.route.rules,
						editIndex: null,
						targetKey: 'outbound',
						targetLabel: _('Target Outbound'),
						targetPlaceholder: 'Proxy',
						actionSuggestions: snippets.ROUTE_RULE_ACTIONS,
						targetSuggestions: getKnownOutboundTags(),
						snippets: snippets.ROUTE_RULE_SNIPPETS
					});
				}
			}, _('Add Route Rule'))
		]);

		var rrRows = [
			E('tr', { 'class': 'tr cbi-section-table-titles' }, [
				E('th', { 'class': 'th' }, _('Order')),
				E('th', { 'class': 'th' }, _('Enabled')),
				E('th', { 'class': 'th' }, _('Action')),
				E('th', { 'class': 'th' }, _('Target Outbound')),
				E('th', { 'class': 'th' }, _('Match Summary')),
				E('th', { 'class': 'th' }, _('Remark')),
				E('th', { 'class': 'th right' }, _('Actions'))
			])
		];

		if (draft.route.rules.length === 0) {
			rrRows.push(E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td center', 'colspan': '7' }, _('No route rules defined.'))
			]));
		} else {
			draft.route.rules.forEach(function(r, idx) {
				var enCb = E('input', {
					'type': 'checkbox',
					'checked': r.enabled !== false ? 'checked' : null,
					'change': function() {
						r.enabled = enCb.checked;
						markDirty();
					}
				});

				rrRows.push(E('tr', { 'class': 'tr cbi-section-table-row' }, [
					E('td', { 'class': 'td', 'style': 'white-space:nowrap;' }, [
						E('button', {
							'type': 'button',
							'class': 'btn cbi-button',
							'disabled': idx === 0 ? 'disabled' : null,
							'click': function() { moveArrayItem(draft.route.rules, idx, -1); }
						}, '↑'),
						' ',
						E('button', {
							'type': 'button',
							'class': 'btn cbi-button',
							'disabled': idx === draft.route.rules.length - 1 ? 'disabled' : null,
							'click': function() { moveArrayItem(draft.route.rules, idx, 1); }
						}, '↓')
					]),
					E('td', { 'class': 'td' }, enCb),
					E('td', { 'class': 'td' }, r.action || '-'),
					E('td', { 'class': 'td' }, r.outbound ? E('code', {}, r.outbound) : '-'),
					E('td', { 'class': 'td' }, snippets.summarizeRule(r)),
					E('td', { 'class': 'td' }, r.remark || '-'),
					E('td', { 'class': 'td right', 'style': 'white-space:nowrap;' }, [
						E('button', {
							'type': 'button',
							'class': 'btn cbi-button cbi-button-edit',
							'click': function() {
								openRuleItemModal({
									addTitle: _('Add Route Rule'),
									editTitle: _('Edit Route Rule'),
									idPrefix: 'rr',
									list: draft.route.rules,
									editIndex: idx,
									targetKey: 'outbound',
									targetLabel: _('Target Outbound'),
									targetPlaceholder: 'Proxy',
									actionSuggestions: snippets.ROUTE_RULE_ACTIONS,
									targetSuggestions: getKnownOutboundTags(),
									snippets: snippets.ROUTE_RULE_SNIPPETS
								});
							}
						}, _('Edit')),
						' ',
						E('button', {
							'type': 'button',
							'class': 'btn cbi-button cbi-button-negative',
							'click': function() {
								confirmDeleteRow(_('Delete Route Rule'), r.remark || r.action || r.id, function() {
									draft.route.rules.splice(idx, 1);
									markDirty();
								});
							}
						}, _('Delete'))
					])
				]));
			});
		}

		// Section B: Rule Sets
		var rsHeader = E('div', { 'style': 'display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;margin:18px 0 8px;' }, [
			E('h3', { 'style': 'margin:0;' }, _('Rule Sets (rule_set)')),
			E('button', {
				'type': 'button',
				'class': 'btn cbi-button cbi-button-add',
				'click': function() {
					openTypedItemModal({
						addTitle: _('Add Rule Set'),
						editTitle: _('Edit Rule Set: %s'),
						idPrefix: 'rs',
						list: draft.rule_sets,
						editIndex: null,
						defaultType: 'remote',
						typeSuggestions: snippets.RULE_SET_TYPES,
						showFormat: true,
						formatSuggestions: snippets.RULE_SET_FORMATS,
						snippets: snippets.RULE_SET_SNIPPETS,
						tagPlaceholder: 'geosite-cn'
					});
				}
			}, _('Add Rule Set'))
		]);

		var rsRows = [
			E('tr', { 'class': 'tr cbi-section-table-titles' }, [
				E('th', { 'class': 'th' }, _('Enabled')),
				E('th', { 'class': 'th' }, _('Tag')),
				E('th', { 'class': 'th' }, _('Type')),
				E('th', { 'class': 'th' }, _('Format')),
				E('th', { 'class': 'th' }, _('Summary')),
				E('th', { 'class': 'th' }, _('Remark')),
				E('th', { 'class': 'th right' }, _('Actions'))
			])
		];

		if (draft.rule_sets.length === 0) {
			rsRows.push(E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td center', 'colspan': '7' }, _('No rule sets defined.'))
			]));
		} else {
			draft.rule_sets.forEach(function(rs, idx) {
				var enCb = E('input', {
					'type': 'checkbox',
					'checked': rs.enabled !== false ? 'checked' : null,
					'change': function() {
						rs.enabled = enCb.checked;
						markDirty();
					}
				});

				rsRows.push(E('tr', { 'class': 'tr cbi-section-table-row' }, [
					E('td', { 'class': 'td' }, enCb),
					E('td', { 'class': 'td' }, E('code', {}, rs.tag || '-')),
					E('td', { 'class': 'td' }, rs.type || '-'),
					E('td', { 'class': 'td' }, rs.type === 'inline' ? '-' : (rs.format || '-')),
					E('td', { 'class': 'td' }, snippets.summarizeRuleSet(rs)),
					E('td', { 'class': 'td' }, rs.remark || '-'),
					E('td', { 'class': 'td right', 'style': 'white-space:nowrap;' }, [
						E('button', {
							'type': 'button',
							'class': 'btn cbi-button cbi-button-edit',
							'click': function() {
								openTypedItemModal({
									addTitle: _('Add Rule Set'),
									editTitle: _('Edit Rule Set: %s'),
									idPrefix: 'rs',
									list: draft.rule_sets,
									editIndex: idx,
									defaultType: 'remote',
									typeSuggestions: snippets.RULE_SET_TYPES,
									showFormat: true,
									formatSuggestions: snippets.RULE_SET_FORMATS,
									snippets: snippets.RULE_SET_SNIPPETS,
									tagPlaceholder: 'geosite-cn'
								});
							}
						}, _('Edit')),
						' ',
						E('button', {
							'type': 'button',
							'class': 'btn cbi-button cbi-button-negative',
							'click': function() {
								confirmDeleteRow(_('Delete Rule Set'), rs.tag || rs.id, function() {
									draft.rule_sets.splice(idx, 1);
									markDirty();
								});
							}
						}, _('Delete'))
					])
				]));
			});
		}

		dom.content(tabPanel, [
			globalBar,
			rrHeader,
			E('div', { 'style': 'overflow-x:auto;' }, [ E('table', { 'class': 'table cbi-section-table' }, rrRows) ]),
			rsHeader,
			E('div', { 'style': 'overflow-x:auto;' }, [ E('table', { 'class': 'table cbi-section-table' }, rsRows) ])
		]);
	}

	function renderOverrideTab() {
		var errBox = E('div', {
			'style': overrideError ? 'display:block;margin-bottom:8px;' : 'display:none;margin-bottom:8px;'
		}, overrideError ? E('div', { 'class': 'alert-message error' }, overrideError) : '');

		var textarea = E('textarea', {
			'class': 'cbi-input-textarea',
			'rows': '20',
			'spellcheck': 'false',
			'style': 'width:100%;font-family:monospace;font-size:12px;resize:vertical;'
		}, overrideText);

		function validateOverrideText() {
			overrideText = textarea.value;
			var res = snippets.parseJsonObject(overrideText);
			if (res.ok) {
				draft.override = res.value;
				overrideError = null;
				hideModalError(errBox);
			} else {
				overrideError = res.error;
				showModalError(errBox, res.error);
			}
		}

		textarea.addEventListener('input', function() {
			validateOverrideText();
			markDirty({ skipTabRender: true });
		});

		textarea.addEventListener('blur', validateOverrideText);

		var snipSelect = E('select', { 'class': 'cbi-input-select', 'style': 'max-width:280px;' }, [
			E('option', { 'value': '' }, _('-- Select Override Snippet --'))
		].concat(snippets.OVERRIDE_SNIPPETS.map(function(s) {
			return E('option', { 'value': s.id }, s.label);
		})));

		var mergeBtn = E('button', {
			'type': 'button',
			'class': 'btn cbi-button cbi-button-action',
			'click': function() {
				var sid = snipSelect.value;
				if (!sid)
					return;
				var found = null;
				snippets.OVERRIDE_SNIPPETS.forEach(function(s) {
					if (s.id === sid)
						found = s;
				});
				if (!found)
					return;
				var cur = snippets.parseJsonObject(textarea.value);
				if (!cur.ok) {
					overrideError = cur.error;
					showModalError(errBox, cur.error);
					return;
				}
				hideModalError(errBox);
				draft.override = mergeOverridePatch(cur.value, found.patch || {});
				syncOverrideTextFromDraft();
				textarea.value = overrideText;
				markDirty({ skipTabRender: true });
			}
		}, _('Insert / Merge Snippet'));

		var formatBtn = E('button', {
			'type': 'button',
			'class': 'btn cbi-button',
			'click': function() {
				var cur = snippets.parseJsonObject(textarea.value);
				if (!cur.ok) {
					overrideError = cur.error;
					showModalError(errBox, cur.error);
					return;
				}
				hideModalError(errBox);
				draft.override = cur.value;
				syncOverrideTextFromDraft();
				textarea.value = overrideText;
			}
		}, _('Format JSON'));

		dom.content(tabPanel, [
			E('p', { 'style': 'margin:0 0 10px;font-size:90%;color:#555;' },
				_('Top-level RFC 7396 JSON Merge Patch applied before dataplane synthesis (null deletes keys; arrays replace). Supports services (api, hysteria-realm), endpoints, http_clients, experimental, ntp, etc.')),
			E('div', { 'style': 'display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:8px;' }, [
				snipSelect,
				mergeBtn,
				formatBtn
			]),
			errBox,
			textarea
		]);
	}

	function renderActiveTab() {
		switch (activeTab) {
		case 'sources':
			renderSourcesTab();
			break;
		case 'outbounds':
			renderOutboundsTab();
			break;
		case 'inbounds':
			renderInboundsTab();
			break;
		case 'dns':
			renderDnsTab();
			break;
		case 'route':
			renderRouteTab();
			break;
		case 'override':
			renderOverrideTab();
			break;
		default:
			renderSourcesTab();
			break;
		}
	}

	renderHeader();
	renderTabMenu();
	renderActiveTab();

	if (typeof options.onController === 'function') {
		options.onController({
			isDirty: function() {
				return dirty;
			},
			updateData: function(freshProfileList, freshComposerData) {
				if (destroyed)
					return;
				if (freshProfileList && Array.isArray(freshProfileList.profiles))
					profiles = freshProfileList.profiles.slice();
				else if (freshComposerData && Array.isArray(freshComposerData.profiles))
					profiles = freshComposerData.profiles.slice();

				if (freshComposerData && typeof freshComposerData === 'object') {
					if (freshComposerData.auto_inbounds)
						autoInbounds = freshComposerData.auto_inbounds;
					if (!dirty) {
						draft = parseComposerFromPayload(freshComposerData);
						savedExists = Boolean(freshComposerData.exists);
						savedMtime = freshComposerData.mtime || null;
						syncOverrideTextFromDraft();
					}
				}
				renderHeader();
				renderActiveTab();
			},
			destroy: function() {
				destroyed = true;
				setBeforeUnload(false);
			}
		});
	}

	return rootEl;
}

return baseclass.extend({
	renderWorkspace: renderWorkspace
});
