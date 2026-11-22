'use strict';
'require view';
'require dom';
'require poll';
'require ui';
'require nimbus.api as nimbusApi';

function makeBadge(text, bg, fg) {
	return E('span', {
		'class': 'label',
		'style': 'display:inline-block;padding:2px 8px;border-radius:3px;font-size:85%;font-weight:600;background:%s;color:%s;'.format(bg, fg)
	}, text);
}

function renderStateBadge(state) {
	switch (state) {
	case 'running':
		return makeBadge(_('Running'), '#e6f4ea', '#137333');
	case 'preparing':
		return makeBadge(_('Preparing'), '#e8f0fe', '#1967d2');
	case 'lockdown':
		return makeBadge(_('Lockdown'), '#fce8e6', '#c5221f');
	default:
		return makeBadge(_('Stopped'), '#f1f3f4', '#5f6368');
	}
}

function renderKeyValueRows(rows) {
	return E('table', { 'class': 'table' }, rows.map(function(row) {
		return E('tr', { 'class': 'tr' }, [
			E('td', { 'class': 'td left', 'style': 'width:34%;font-weight:600;' }, row[0]),
			E('td', { 'class': 'td left' }, row[1])
		]);
	}));
}

function showSecretModal(title, url, secretVal, hasSecret) {
	var masked = true;
	var secretText = secretVal || '';
	var secretInput = E('input', {
		'type': 'password',
		'class': 'cbi-input-text',
		'readonly': 'readonly',
		'style': 'width:100%;font-family:monospace;',
		'value': secretText
	});

	var body = [
		E('div', { 'class': 'cbi-value' }, [
			E('label', { 'class': 'cbi-value-title' }, _('Endpoint URL')),
			E('div', { 'class': 'cbi-value-field', 'style': 'display:flex;gap:8px;align-items:center;' }, [
				E('code', { 'style': 'word-break:break-all;' }, url || '-'),
				url ? E('button', {
					'type': 'button',
					'class': 'btn cbi-button cbi-button-action',
					'click': function() {
						nimbusApi.copyToClipboard(url).then(function() {
							nimbusApi.notifySuccess(_('Endpoint URL copied to clipboard.'));
						}, function() {
							nimbusApi.notifyError(_('Failed to copy to clipboard.'));
						});
					}
				}, _('Copy')) : ''
			])
		])
	];

	if (hasSecret && secretText) {
		body.push(E('div', { 'class': 'cbi-value' }, [
			E('label', { 'class': 'cbi-value-title' }, _('API Secret')),
			E('div', { 'class': 'cbi-value-field', 'style': 'display:flex;gap:8px;align-items:center;' }, [
				secretInput,
				E('button', {
					'type': 'button',
					'class': 'btn cbi-button',
					'click': function(ev) {
						masked = !masked;
						secretInput.type = masked ? 'password' : 'text';
						dom.content(ev.currentTarget, masked ? _('Show') : _('Hide'));
					}
				}, _('Show')),
				E('button', {
					'type': 'button',
					'class': 'btn cbi-button cbi-button-action',
					'click': function() {
						nimbusApi.copyToClipboard(secretText).then(function() {
							nimbusApi.notifySuccess(_('API secret copied to clipboard.'));
						}, function() {
							nimbusApi.notifyError(_('Failed to copy to clipboard.'));
						});
					}
				}, _('Copy'))
			])
		]));
	} else {
		body.push(E('p', { 'class': 'cbi-section-descr' },
			hasSecret ? _('Secret is not available in the current runtime configuration.') : _('No API secret is configured.')));
	}

	body.push(E('div', { 'class': 'right' }, [
		E('button', {
			'type': 'button',
			'class': 'btn cbi-button',
			'click': ui.hideModal
		}, _('Close'))
	]));

	ui.showModal(title, body);
}

return view.extend({
	handleSave: null,
	handleSaveApply: null,
	handleReset: null,

	load: function() {
		return Promise.all([
			nimbusApi.status(),
			nimbusApi.profileList().catch(function() { return { ok: false, profiles: [] }; })
		]);
	},

	render: function(data) {
		var status = data[0] || {};
		var plist = data[1] || {};
		var profileMap = {};
		var actionPending = false;
		var pollInFlight = false;

		(plist.profiles || []).forEach(function(p) {
			profileMap[p.id] = p;
		});

		var alertsBox = E('div', { 'id': 'nimbus-alerts' });
		var controlBox = E('div', { 'class': 'cbi-section' });
		var telemetryBox = E('div', { 'class': 'cbi-section' });
		var dataplaneBox = E('div', { 'class': 'cbi-section' });
		var countersBox = E('div', { 'class': 'cbi-section' });
		var apisBox = E('div', { 'class': 'cbi-section' });

		function runAction(action) {
			if (actionPending)
				return;
			actionPending = true;
			renderAll(status);

			nimbusApi.serviceAction(action).then(function(res) {
				actionPending = false;
				if (!res || res.ok === false)
					nimbusApi.notifyError(res);
				else
					nimbusApi.notifySuccess(_('Service action "%s" completed.').format(action));
				return refreshStatus();
			}).catch(function(err) {
				actionPending = false;
				nimbusApi.notifyError(err);
				return refreshStatus();
			});
		}

		function openSecretCredentials(kind, apiInfo, url) {
			nimbusApi.apiSecret().then(function(res) {
				if (!res || res.ok === false) {
					nimbusApi.notifyError(res);
					return;
				}
				var secret = kind === 'singbox' ? res.singbox_api_secret : res.clash_api_secret;
				var title = kind === 'singbox' ? _('sing-box Native API Credentials') : _('Clash API Credentials');
				showSecretModal(title, url, secret, apiInfo.has_secret);
			}).catch(function(err) {
				nimbusApi.notifyError(err);
			});
		}

		function renderAlerts(st) {
			var nodes = [];
			var eff = st.effective || {};
			var core = st.core || {};
			var isLockdownDns = (st.state === 'lockdown' && eff.dns_mode === 'singbox');

			if (st.state === 'lockdown') {
				var lockChildren = [
					E('strong', {}, _('Fail-Closed Lockdown Active: ')),
					E('span', {}, _('Non-whitelist LAN forwarding traffic is blocked to prevent IP leaks. Router management (SSH and LuCI) remains accessible.'))
				];
				if (isLockdownDns) {
					lockChildren.push(E('div', { 'style': 'margin-top:6px;' }, [
						E('strong', {}, _('Router DNS Notice: ')),
						E('span', {}, _('DNS mode is set to "singbox", so dnsmasq remains pointed at 127.0.0.1 to prevent DNS leaks. The router itself cannot resolve external domains (for core or subscription updates) until you click "Stop" to restore dnsmasq.'))
					]));
				}
				nodes.push(E('div', { 'class': 'alert-message error' }, lockChildren));
			}

			if (st.last_error) {
				nodes.push(E('div', { 'class': 'alert-message error' }, [
					E('strong', {}, _('Last Error: ')),
					E('span', {}, st.last_error)
				]));
			}

			if (!core.installed) {
				nodes.push(E('div', { 'class': 'alert-message warning' }, [
					E('span', {}, _('sing-box core binary is not installed yet. ')),
					E('a', { 'href': L.url('admin/services/nimbus/core') }, _('Go to Core Management'))
				]));
			}

			if (!st.active_profile) {
				nodes.push(E('div', { 'class': 'alert-message warning' }, [
					E('span', {}, _('No active sing-box profile is selected. ')),
					E('a', { 'href': L.url('admin/services/nimbus/profiles') }, _('Go to Profiles'))
				]));
			}

			var extraWarnings = (st.warnings || []).filter(function(w) {
				return !(isLockdownDns && String(w).indexOf('LOCKDOWN active while dns.mode="singbox"') >= 0);
			});
			if (extraWarnings.length > 0) {
				nodes.push(E('div', { 'class': 'alert-message warning' }, [
					E('strong', {}, _('Warnings:')),
					E('ul', { 'style': 'margin:4px 0 0 18px;' }, extraWarnings.map(function(w) {
						return E('li', {}, String(w));
					}))
				]));
			}

			dom.content(alertsBox, nodes);
		}

		function renderControlAndTelemetry(st) {
			var state = st.state || 'stopped';
			var proc = st.process || {};
			var core = st.core || {};
			var prof = st.active_profile ? profileMap[st.active_profile] : null;
			var profLabel = st.active_profile
				? (prof && prof.name ? '%s (%s)'.format(prof.name, st.active_profile) : st.active_profile)
				: _('None');

			var btnStart = E('button', {
				'type': 'button',
				'class': 'btn cbi-button cbi-button-apply',
				'disabled': (actionPending || state === 'running' || state === 'preparing') ? 'disabled' : null,
				'click': function() { runAction('start'); }
			}, _('Start'));

			var btnStop = E('button', {
				'type': 'button',
				'class': 'btn cbi-button cbi-button-negative',
				'disabled': (actionPending || state === 'stopped') ? 'disabled' : null,
				'click': function() { runAction('stop'); }
			}, _('Stop'));

			var btnRestart = E('button', {
				'type': 'button',
				'class': 'btn cbi-button cbi-button-action',
				'disabled': (actionPending || state === 'stopped') ? 'disabled' : null,
				'click': function() { runAction('restart'); }
			}, _('Restart'));

			var btnReload = E('button', {
				'type': 'button',
				'class': 'btn cbi-button cbi-button-neutral',
				'disabled': (actionPending || state === 'stopped') ? 'disabled' : null,
				'click': function() { runAction('reload'); }
			}, _('Reload'));

			dom.content(controlBox, [
				E('h3', {}, _('Service Status')),
				E('div', { 'style': 'display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;margin-bottom:12px;' }, [
					E('div', { 'style': 'display:flex;align-items:center;gap:10px;' }, [
						renderStateBadge(state),
						actionPending ? E('span', { 'class': 'spinning' }, _('Applying action...')) : ''
					]),
					E('div', { 'style': 'display:flex;gap:8px;flex-wrap:wrap;' }, [
						btnStart, btnStop, btnRestart, btnReload
					])
				])
			]);

			var coreText = core.installed
				? '%s (%s)'.format(core.version || _('unknown'), core.bin_path || '-')
				: '%s (%s)'.format(_('Not installed'), core.bin_path || '-');

			var procText = proc.running
				? _('Running (PID %d)').format(proc.pid)
				: _('Not running');

			dom.content(telemetryBox, [
				E('h3', {}, _('Runtime Overview')),
				renderKeyValueRows([
					[ _('Boot / UCI Enabled'), st.enabled ? _('Enabled') : _('Disabled') ],
					[ _('Active Profile'), profLabel ],
					[ _('Network Topology'), st.topology === 'side' ? _('Side Router') : _('Main Router') ],
					[ _('Proxy Mode'), st.proxy_mode || 'tproxy_redirect' ],
					[ _('Failure Policy'), st.fail_open ? _('Fail-Open (Direct Fallback)') : _('Fail-Closed (Lockdown)') ],
					[ _('sing-box Core'), coreText ],
					[ _('Process'), procText ],
					[ _('Uptime'), proc.running ? nimbusApi.formatUptime(proc.uptime) : '-' ],
					[ _('Memory (RSS)'), proc.running ? nimbusApi.formatBytes((proc.rss_kb || 0) * 1024) : '-' ]
				])
			]);
		}

		function renderDataplane(st) {
			var eff = st.effective || {};
			var src = eff.inbound_sources || {};
			var fk = eff.fakeip || {};
			var wl = st.whitelist || {};

			function fmtPortSource(port, s) {
				if (!port)
					return '-';
				var tag = s === 'user' ? _('user inbound') : (s === 'auto' ? _('auto-injected') : '');
				return tag ? '%d (%s)'.format(port, tag) : String(port);
			}

			var fakeipParts = [];
			if (fk.ipv4 && fk.ipv4.length)
				fakeipParts.push('IPv4: ' + fk.ipv4.join(', '));
			if (fk.ipv6 && fk.ipv6.length)
				fakeipParts.push('IPv6: ' + fk.ipv6.join(', '));

			var dnsText = eff.dns_mode || 'none';
			if (eff.dns_mode === 'singbox' && eff.dns_port)
				dnsText = '%s (127.0.0.1:%d)'.format(eff.dns_mode, eff.dns_port);

			dom.content(dataplaneBox, [
				E('h3', {}, _('Effective Data Plane & Whitelist')),
				renderKeyValueRows([
					[ _('TCP Redirect Port'), fmtPortSource(eff.redirect_port, src.redirect) ],
					[ _('UDP TPROXY Port'), fmtPortSource(eff.tproxy_port, src.tproxy) ],
					[ _('Outbound Mark'), eff.outbound_mark || '-' ],
					[ _('DNS Takeover'), dnsText ],
					[ _('Fake-IP Ranges'), fakeipParts.length ? fakeipParts.join(' | ') : _('None detected') ],
					[ _('Whitelist Bypass'), '%s (%s: %d, %s: %d)'.format(
						wl.enabled ? _('Enabled') : _('Disabled'),
						_('IPv4'), wl.v4_count || 0,
						_('IPv6'), wl.v6_count || 0
					) ]
				])
			]);
		}

		function renderCounters(st) {
			var cnt = st.counters || {};
			var rows = [
				[ _('TCP Proxied'), _('%d packets (%s)').format(cnt.tcp_packets || 0, nimbusApi.formatBytes(cnt.tcp_bytes || 0)) ],
				[ _('UDP Proxied'), _('%d packets (%s)').format(cnt.udp_packets || 0, nimbusApi.formatBytes(cnt.udp_bytes || 0)) ],
				[ _('Lockdown Rejected'), _('%d packets').format(cnt.lockdown_rejected_packets || 0) ]
			];
			if ((cnt.tun_packets || 0) > 0 || (cnt.tun_bytes || 0) > 0) {
				rows.splice(2, 0, [
					_('TUN Proxied'),
					_('%d packets (%s)').format(cnt.tun_packets || 0, nimbusApi.formatBytes(cnt.tun_bytes || 0))
				]);
			}

			dom.content(countersBox, [
				E('h3', {}, _('nftables Traffic Counters')),
				renderKeyValueRows(rows)
			]);
		}

		function renderApiCard(title, kind, apiInfo, pathSuffix, openLabel) {
			if (!apiInfo || !apiInfo.detected) {
				return E('div', { 'style': 'margin-bottom:12px;' }, [
					E('h4', {}, title),
					E('p', { 'class': 'cbi-section-descr' }, _('Not configured in the active profile.'))
				]);
			}

			var url = nimbusApi.buildApiUrl(apiInfo, pathSuffix);
			var flags = [];
			if (apiInfo.loopback_only)
				flags.push(makeBadge(_('Loopback Only'), '#fef7e0', '#b06000'));
			if (apiInfo.no_secret)
				flags.push(makeBadge(_('No Secret Configured'), '#fce8e6', '#c5221f'));
			if (apiInfo.has_secret)
				flags.push(makeBadge(_('Secret Protected'), '#e6f4ea', '#137333'));

			var buttons = [];
			var canOpen = (kind === 'singbox')
				? (apiInfo.dashboard_enabled && !apiInfo.loopback_only && url)
				: (apiInfo.external_ui && !apiInfo.loopback_only && url);

			if (canOpen) {
				buttons.push(E('a', {
					'class': 'btn cbi-button cbi-button-apply',
					'href': url,
					'target': '_blank',
					'rel': 'noopener noreferrer'
				}, openLabel));
			}

			buttons.push(E('button', {
				'type': 'button',
				'class': 'btn cbi-button cbi-button-action',
				'click': function() { openSecretCredentials(kind, apiInfo, url); }
			}, _('Reveal / Copy Credentials')));

			var rows = [
				[ _('Listen Address'), '%s:%s'.format(apiInfo.listen || '-', apiInfo.port != null ? apiInfo.port : '-') ],
				[ _('Status Flags'), flags.length ? E('div', { 'style': 'display:flex;gap:6px;flex-wrap:wrap;' }, flags) : '-' ]
			];
			if (kind === 'singbox') {
				rows.push([ _('Built-in Dashboard'), apiInfo.dashboard_enabled ? _('Enabled (%s)').format(apiInfo.dashboard_path || '/dashboard/') : _('Disabled') ]);
			} else {
				rows.push([ _('External UI'), apiInfo.external_ui ? _('Configured') : _('Disabled') ]);
			}
			rows.push([ _('Actions'), E('div', { 'style': 'display:flex;gap:8px;flex-wrap:wrap;' }, buttons) ]);

			return E('div', { 'style': 'margin-bottom:14px;' }, [
				E('h4', {}, title),
				renderKeyValueRows(rows)
			]);
		}

		function renderApis(st) {
			var apis = st.apis || {};
			var sb = apis.singbox_api || {};
			var ca = apis.clash_api || {};

			dom.content(apisBox, [
				E('h3', {}, _('Control APIs & Dashboards')),
				renderApiCard(_('sing-box Native API'), 'singbox', sb, sb.dashboard_path || '/dashboard/', _('Open Dashboard')),
				renderApiCard(_('Clash API'), 'clash', ca, '/ui/', _('Open External UI'))
			]);
		}

		function renderAll(st) {
			status = st || {};
			renderAlerts(status);
			renderControlAndTelemetry(status);
			renderDataplane(status);
			renderCounters(status);
			renderApis(status);
		}

		function refreshStatus() {
			return nimbusApi.status().then(function(st) {
				if (st && st.ok !== false)
					renderAll(st);
			}).catch(function() {});
		}

		renderAll(status);

		poll.add(function() {
			if (pollInFlight || actionPending)
				return Promise.resolve();
			pollInFlight = true;
			return nimbusApi.status().then(function(st) {
				pollInFlight = false;
				if (st && st.ok !== false)
					renderAll(st);
			}, function() {
				pollInFlight = false;
			});
		}, 3);

		return E('div', { 'class': 'cbi-map' }, [
			E('h2', {}, _('Nimbus Overview')),
			alertsBox,
			controlBox,
			telemetryBox,
			countersBox,
			dataplaneBox,
			apisBox
		]);
	}
});
