'use strict';
'require baseclass';

var comboSeq = 0;
var idSeq = 0;

var INBOUND_TYPES = [
	'mixed', 'socks', 'http', 'redirect', 'tproxy', 'direct', 'tun',
	'vless', 'vmess', 'shadowsocks', 'trojan', 'hysteria2', 'anytls'
];

var OUTBOUND_TYPES = [
	'direct', 'block', 'vless', 'vmess', 'trojan', 'shadowsocks',
	'hysteria2', 'anytls', 'tuic', 'naive', 'socks', 'http', 'ssh', 'tor'
];

var GROUP_TYPES = [ 'selector', 'urltest' ];

var DNS_SERVER_TYPES = [
	'udp', 'tcp', 'tls', 'https', 'h3', 'quic',
	'fakeip', 'hosts', 'local', 'dhcp', 'resolved', 'tailscale'
];

var DNS_RULE_ACTIONS = [
	'route', 'evaluate', 'respond', 'route-options', 'reject', 'predefined'
];

var ROUTE_RULE_ACTIONS = [
	'route', 'route-options', 'bypass', 'reject', 'hijack-dns', 'sniff', 'resolve'
];

var RULE_SET_TYPES = [ 'remote', 'local', 'inline' ];

var RULE_SET_FORMATS = [ 'binary', 'source' ];

var DNS_STRATEGIES = [ '', 'prefer_ipv4', 'prefer_ipv6', 'ipv4_only', 'ipv6_only' ];

var INBOUND_SNIPPETS = [
	{
		id: 'mixed',
		label: _('mixed (LAN Mixed Proxy)'),
		type: 'mixed',
		tag: 'mixed-in',
		remark: _('LAN Mixed Proxy'),
		config: {
			listen: '::',
			listen_port: 7890
		}
	},
	{
		id: 'socks',
		label: _('socks (SOCKS5 Proxy)'),
		type: 'socks',
		tag: 'socks-in',
		remark: _('LAN SOCKS5 Proxy'),
		config: {
			listen: '::',
			listen_port: 1080
		}
	},
	{
		id: 'redirect',
		label: _('redirect (TCP Transparent)'),
		type: 'redirect',
		tag: 'redirect-in',
		remark: _('Custom TCP Redirect'),
		config: {
			listen: '::',
			listen_port: 7891
		}
	},
	{
		id: 'tproxy',
		label: _('tproxy (UDP Transparent)'),
		type: 'tproxy',
		tag: 'tproxy-in',
		remark: _('Custom UDP TPROXY'),
		config: {
			listen: '::',
			listen_port: 7892,
			network: 'udp'
		}
	}
];

var OUTBOUND_SNIPPETS = [
	{
		id: 'direct',
		label: _('direct'),
		type: 'direct',
		tag: 'direct',
		remark: _('Direct'),
		config: {}
	},
	{
		id: 'hysteria2',
		label: _('hysteria2'),
		type: 'hysteria2',
		tag: 'hy2-node',
		remark: _('Hysteria2 Node'),
		config: {
			server: 'example.com',
			server_port: 443,
			password: 'your-password',
			up_mbps: 100,
			down_mbps: 100,
			tls: {
				enabled: true,
				server_name: 'example.com'
			}
		}
	},
	{
		id: 'vless_tls',
		label: _('vless+tls'),
		type: 'vless',
		tag: 'vless-node',
		remark: _('VLESS + TLS'),
		config: {
			server: 'example.com',
			server_port: 443,
			uuid: '00000000-0000-0000-0000-000000000000',
			flow: 'xtls-rprx-vision',
			tls: {
				enabled: true,
				server_name: 'example.com',
				utls: {
					enabled: true,
					fingerprint: 'chrome'
				}
			}
		}
	},
	{
		id: 'anytls',
		label: _('anytls'),
		type: 'anytls',
		tag: 'anytls-node',
		remark: _('AnyTLS Node'),
		config: {
			server: 'example.com',
			server_port: 443,
			password: 'your-password',
			idle_session_check_interval: '30s',
			idle_session_timeout: '30s',
			min_idle_session: 5,
			tls: {
				enabled: true,
				server_name: 'example.com'
			}
		}
	},
	{
		id: 'shadowsocks',
		label: _('shadowsocks'),
		type: 'shadowsocks',
		tag: 'ss-node',
		remark: _('Shadowsocks Node'),
		config: {
			server: 'example.com',
			server_port: 8388,
			method: '2022-blake3-aes-128-gcm',
			password: 'your-base64-password'
		}
	}
];

var GROUP_SNIPPETS = [
	{
		id: 'selector',
		label: _('selector (Manual Select)'),
		type: 'selector',
		tag: 'Proxy',
		remark: _('Manual Select'),
		outbounds: [ 'Auto', 'direct' ],
		fallback_outbound: 'direct',
		config: {
			default: 'Auto',
			interrupt_exist_connections: false
		}
	},
	{
		id: 'urltest',
		label: _('urltest (Auto Best)'),
		type: 'urltest',
		tag: 'Auto',
		remark: _('Auto Best'),
		outbounds: [],
		fallback_outbound: 'direct',
		config: {
			url: 'https://www.gstatic.com/generate_204',
			interval: '5m',
			tolerance: 50,
			idle_timeout: '30m',
			interrupt_exist_connections: false
		}
	}
];

var DNS_SERVER_SNIPPETS = [
	{
		id: 'udp_223',
		label: _('udp (223.5.5.5)'),
		type: 'udp',
		tag: 'dns-cn',
		remark: _('China Direct DNS'),
		config: {
			server: '223.5.5.5'
		}
	},
	{
		id: 'https_1111',
		label: _('https (1.1.1.1 DoH)'),
		type: 'https',
		tag: 'dns-proxy',
		remark: _('Proxy DoH'),
		config: {
			server: '1.1.1.1',
			detour: 'Proxy'
		}
	},
	{
		id: 'tls_dot',
		label: _('tls (DoT)'),
		type: 'tls',
		tag: 'dns-dot',
		remark: _('DNS over TLS'),
		config: {
			server: '8.8.8.8',
			server_port: 853,
			detour: 'Proxy'
		}
	},
	{
		id: 'fakeip_114',
		label: _('fakeip (1.14)'),
		type: 'fakeip',
		tag: 'dns-fakeip',
		remark: _('Fake-IP Pool'),
		config: {
			inet4_range: '198.18.0.0/15',
			inet6_range: 'fc00::/18'
		}
	}
];

var DNS_RULE_SNIPPETS = [
	{
		id: 'cn_ruleset',
		label: _('China Rule Set -> dns-cn'),
		action: 'route',
		server: 'dns-cn',
		remark: _('China domains direct'),
		config: {
			rule_set: [ 'geosite-cn' ]
		}
	},
	{
		id: 'fakeip_aaaa',
		label: _('A/AAAA -> dns-fakeip'),
		action: 'route',
		server: 'dns-fakeip',
		remark: _('Fake-IP A/AAAA'),
		config: {
			query_type: [ 'A', 'AAAA' ]
		}
	},
	{
		id: 'reject_https',
		label: _('Reject HTTPS/SVCB'),
		action: 'reject',
		server: '',
		remark: _('Reject HTTPS/SVCB queries'),
		config: {
			query_type: [ 'HTTPS', 'SVCB' ]
		}
	},
	{
		id: 'logical_dns',
		label: _('Logical Rule'),
		action: 'route',
		server: 'dns-cn',
		remark: _('Logical DNS Rule'),
		config: {
			type: 'logical',
			mode: 'and',
			rules: [
				{ domain_suffix: [ '.cn' ] },
				{ query_type: [ 'A', 'AAAA' ] }
			]
		}
	}
];

var ROUTE_RULE_SNIPPETS = [
	{
		id: 'sniff',
		label: _('sniff'),
		action: 'sniff',
		outbound: '',
		remark: _('Protocol Sniff'),
		config: {}
	},
	{
		id: 'hijack_dns',
		label: _('hijack-dns'),
		action: 'hijack-dns',
		outbound: '',
		remark: _('Hijack DNS'),
		config: {
			protocol: 'dns'
		}
	},
	{
		id: 'private_direct',
		label: _('Private IP -> direct'),
		action: 'route',
		outbound: 'direct',
		remark: _('Private IP Direct'),
		config: {
			ip_is_private: true
		}
	},
	{
		id: 'ruleset_direct',
		label: _('Rule Set -> direct'),
		action: 'route',
		outbound: 'direct',
		remark: _('China Traffic Direct'),
		config: {
			rule_set: [ 'geosite-cn', 'geoip-cn' ]
		}
	},
	{
		id: 'reject_quic',
		label: _('Reject QUIC'),
		action: 'reject',
		outbound: '',
		remark: _('Reject QUIC'),
		config: {
			protocol: 'quic'
		}
	},
	{
		id: 'logical_route',
		label: _('Logical Rule'),
		action: 'route',
		outbound: 'direct',
		remark: _('Logical Route Rule'),
		config: {
			type: 'logical',
			mode: 'and',
			rules: [
				{ ip_is_private: false },
				{ rule_set: [ 'geosite-cn' ] }
			]
		}
	}
];

var RULE_SET_SNIPPETS = [
	{
		id: 'remote_geosite_cn',
		label: _('remote (geosite-cn, http_client)'),
		type: 'remote',
		tag: 'geosite-cn',
		format: 'binary',
		remark: _('China Domain Rule Set'),
		config: {
			url: 'https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs',
			http_client: {
				detour: 'Proxy'
			},
			update_interval: '1d'
		}
	},
	{
		id: 'remote_geoip_cn',
		label: _('remote (geoip-cn, http_client)'),
		type: 'remote',
		tag: 'geoip-cn',
		format: 'binary',
		remark: _('China IP Rule Set'),
		config: {
			url: 'https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs',
			http_client: {
				detour: 'Proxy'
			},
			update_interval: '1d'
		}
	},
	{
		id: 'local_srs',
		label: _('local (.srs)'),
		type: 'local',
		tag: 'local-rules',
		format: 'binary',
		remark: _('Local Binary Rule Set'),
		config: {
			path: '/etc/nimbus/rule-sets/custom.srs'
		}
	},
	{
		id: 'inline_rules',
		label: _('inline'),
		type: 'inline',
		tag: 'inline-rules',
		format: '',
		remark: _('Inline Domain Rules'),
		config: {
			rules: [
				{ domain_suffix: [ '.example.com' ] }
			]
		}
	}
];

var OVERRIDE_SNIPPETS = [
	{
		id: 'native_api',
		label: _('Native sing-box API + Dashboard'),
		patch: {
			services: [
				{
					type: 'api',
					tag: 'api',
					listen: '::',
					listen_port: 9091,
					secret: 'change-me',
					dashboard: true
				}
			]
		}
	},
	{
		id: 'cache_file',
		label: _('Cache File + Fake-IP Store'),
		patch: {
			experimental: {
				cache_file: {
					enabled: true,
					store_fakeip: true
				}
			}
		}
	},
	{
		id: 'hysteria_realm',
		label: _('Hysteria Realm Service'),
		patch: {
			services: [
				{
					type: 'hysteria-realm',
					tag: 'hy-realm',
					listen: '::',
					listen_port: 8443,
					users: [
						{
							name: 'user1',
							token: 'secret',
							max_realms: 4
						}
					]
				}
			]
		}
	},
	{
		id: 'clash_api',
		label: _('Clash API'),
		patch: {
			experimental: {
				clash_api: {
					external_controller: '0.0.0.0:9090',
					secret: 'change-me',
					external_ui: 'dashboard'
				}
			}
		}
	},
	{
		id: 'http_clients',
		label: _('HTTP Clients'),
		patch: {
			http_clients: [
				{
					tag: 'proxy-client',
					detour: 'Proxy'
				}
			]
		}
	}
];

function deepClone(v) {
	if (v === null || typeof v !== 'object')
		return v;
	if (Array.isArray(v))
		return v.map(deepClone);
	var out = {};
	Object.keys(v).forEach(function(k) {
		out[k] = deepClone(v[k]);
	});
	return out;
}

function makeId(prefix) {
	idSeq++;
	return '%s_%s_%s'.format(prefix || 'item', Date.now().toString(36), idSeq.toString(36));
}

function prettyJson(obj) {
	return JSON.stringify(obj != null ? obj : {}, null, 2);
}

function parseJsonObject(str) {
	var text = str != null ? String(str).trim() : '';
	if (!text)
		return { ok: true, value: {} };
	try {
		var parsed = JSON.parse(text);
		if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed))
			return { ok: false, error: _('Value must be a JSON object.') };
		return { ok: true, value: parsed };
	} catch (e) {
		return { ok: false, error: _('Invalid JSON syntax: %s').format(e.message) };
	}
}

function createComboInput(value, suggestions, placeholder) {
	comboSeq++;
	var listId = 'nimbus-combo-%d'.format(comboSeq);
	var inputAttrs = {
		'type': 'text',
		'class': 'cbi-input-text',
		'list': listId,
		'value': value != null ? String(value) : '',
		'style': 'width:100%;'
	};
	if (placeholder)
		inputAttrs.placeholder = String(placeholder);

	var input = E('input', inputAttrs);
	var datalist = E('datalist', { 'id': listId });

	function setSuggestions(list) {
		while (datalist.firstChild)
			datalist.removeChild(datalist.firstChild);
		var seen = {};
		(Array.isArray(list) ? list : []).forEach(function(item) {
			var v = '';
			var lbl = '';
			if (item && typeof item === 'object') {
				v = item.value != null ? String(item.value) : '';
				lbl = item.label != null ? String(item.label) : '';
			} else if (item != null) {
				v = String(item);
			}
			if (!v || seen[v])
				return;
			seen[v] = true;
			var optAttrs = { 'value': v };
			if (lbl && lbl !== v)
				optAttrs.label = lbl;
			datalist.appendChild(E('option', optAttrs));
		});
	}

	setSuggestions(suggestions);

	var container = E('span', {
		'style': 'display:inline-block;width:100%;max-width:340px;'
	}, [ input, datalist ]);

	return {
		container: container,
		input: input,
		setSuggestions: setSuggestions
	};
}

function createBlankPreset() {
	return {
		schema_version: 1,
		sources: {},
		inbounds: [],
		outbound_groups: [
			{
				id: 'grp_proxy',
				enabled: true,
				type: 'selector',
				tag: 'Proxy',
				remark: 'Main Proxy',
				outbounds: [ 'direct' ],
				providers: [
					{
						profile_id: '*',
						include_regex: '',
						exclude_regex: ''
					}
				],
				fallback_outbound: 'direct',
				config: {}
			}
		],
		outbounds: [
			{
				id: 'out_direct',
				enabled: true,
				type: 'direct',
				tag: 'direct',
				remark: 'Direct',
				config: {}
			}
		],
		dns: {
			final: 'dns-direct',
			strategy: '',
			extra: {},
			servers: [
				{
					id: 'dns_direct',
					enabled: true,
					type: 'udp',
					tag: 'dns-direct',
					remark: 'Direct DNS',
					config: {
						server: '223.5.5.5'
					}
				}
			],
			rules: []
		},
		rule_sets: [],
		route: {
			final: 'Proxy',
			default_domain_resolver: 'dns-direct',
			extra: {},
			rules: []
		},
		override: {}
	};
}

function createStandard114Preset() {
	return {
		schema_version: 1,
		sources: {},
		inbounds: [
			{
				id: 'in_mixed',
				enabled: true,
				type: 'mixed',
				tag: 'mixed-in',
				remark: 'LAN Mixed Proxy',
				config: {
					listen: '::',
					listen_port: 7890
				}
			}
		],
		outbound_groups: [
			{
				id: 'grp_proxy',
				enabled: true,
				type: 'selector',
				tag: 'Proxy',
				remark: 'Manual Select',
				outbounds: [ 'Auto', 'direct' ],
				providers: [
					{
						profile_id: '*',
						include_regex: '',
						exclude_regex: ''
					}
				],
				fallback_outbound: 'direct',
				config: {
					default: 'Auto'
				}
			},
			{
				id: 'grp_auto',
				enabled: true,
				type: 'urltest',
				tag: 'Auto',
				remark: 'Auto Best',
				outbounds: [],
				providers: [
					{
						profile_id: '*',
						include_regex: '',
						exclude_regex: ''
					}
				],
				fallback_outbound: 'direct',
				config: {
					url: 'https://www.gstatic.com/generate_204',
					interval: '5m',
					tolerance: 50
				}
			}
		],
		outbounds: [
			{
				id: 'out_direct',
				enabled: true,
				type: 'direct',
				tag: 'direct',
				remark: 'Direct',
				config: {}
			}
		],
		dns: {
			final: 'dns-proxy',
			strategy: '',
			extra: {},
			servers: [
				{
					id: 'dns_cn',
					enabled: true,
					type: 'udp',
					tag: 'dns-cn',
					remark: 'China Direct DNS',
					config: {
						server: '223.5.5.5'
					}
				},
				{
					id: 'dns_proxy',
					enabled: true,
					type: 'https',
					tag: 'dns-proxy',
					remark: 'Proxy DoH',
					config: {
						server: '1.1.1.1',
						detour: 'Proxy'
					}
				},
				{
					id: 'dns_fakeip',
					enabled: true,
					type: 'fakeip',
					tag: 'dns-fakeip',
					remark: 'Fake-IP Pool',
					config: {
						inet4_range: '198.18.0.0/15',
						inet6_range: 'fc00::/18'
					}
				}
			],
			rules: [
				{
					id: 'dr_cn',
					enabled: true,
					remark: 'China domains direct',
					action: 'route',
					server: 'dns-cn',
					config: {
						rule_set: [ 'geosite-cn' ]
					}
				},
				{
					id: 'dr_fakeip',
					enabled: true,
					remark: 'Fake-IP A/AAAA',
					action: 'route',
					server: 'dns-fakeip',
					config: {
						query_type: [ 'A', 'AAAA' ]
					}
				}
			]
		},
		rule_sets: [
			{
				id: 'rs_geosite_cn',
				enabled: true,
				type: 'remote',
				tag: 'geosite-cn',
				format: 'binary',
				remark: 'China Domain Rule Set',
				config: {
					url: 'https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs',
					http_client: {
						detour: 'Proxy'
					},
					update_interval: '1d'
				}
			},
			{
				id: 'rs_geoip_cn',
				enabled: true,
				type: 'remote',
				tag: 'geoip-cn',
				format: 'binary',
				remark: 'China IP Rule Set',
				config: {
					url: 'https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs',
					http_client: {
						detour: 'Proxy'
					},
					update_interval: '1d'
				}
			}
		],
		route: {
			final: 'Proxy',
			default_domain_resolver: 'dns-cn',
			extra: {},
			rules: [
				{
					id: 'rr_sniff',
					enabled: true,
					remark: 'Protocol Sniff',
					action: 'sniff',
					outbound: '',
					config: {}
				},
				{
					id: 'rr_dns',
					enabled: true,
					remark: 'Hijack DNS',
					action: 'hijack-dns',
					outbound: '',
					config: {
						protocol: 'dns'
					}
				},
				{
					id: 'rr_private',
					enabled: true,
					remark: 'Private IP Direct',
					action: 'route',
					outbound: 'direct',
					config: {
						ip_is_private: true
					}
				},
				{
					id: 'rr_cn',
					enabled: true,
					remark: 'China Traffic Direct',
					action: 'route',
					outbound: 'direct',
					config: {
						rule_set: [ 'geosite-cn', 'geoip-cn' ]
					}
				}
			]
		},
		override: {
			services: [
				{
					type: 'api',
					tag: 'api',
					listen: '::',
					listen_port: 9091,
					dashboard: true
				}
			],
			experimental: {
				cache_file: {
					enabled: true,
					store_fakeip: true
				}
			}
		}
	};
}

function formatHostPort(host, port) {
	var h = host != null ? String(host) : '';
	var p = port != null && port !== '' ? String(port) : '';
	if (h && p) {
		if (h.indexOf(':') >= 0 && h.charAt(0) !== '[')
			return '[%s]:%s'.format(h, p);
		return '%s:%s'.format(h, p);
	}
	if (h)
		return h;
	if (p)
		return ':%s'.format(p);
	return '';
}

function formatCompactVal(val) {
	if (Array.isArray(val)) {
		if (val.length <= 3)
			return val.join(', ');
		return '%s (+%d)'.format(val.slice(0, 3).join(', '), val.length - 3);
	}
	if (val && typeof val === 'object')
		return '{...}';
	return String(val);
}

function summarizeInbound(item) {
	var c = (item && item.config && typeof item.config === 'object') ? item.config : {};
	var parts = [];
	var ep = formatHostPort(c.listen, c.listen_port);
	if (ep)
		parts.push(ep);
	else if (c.interface_name)
		parts.push(String(c.interface_name));
	if (c.network)
		parts.push('(%s)'.format(Array.isArray(c.network) ? c.network.join(',') : String(c.network)));
	if (c.address != null)
		parts.push(formatCompactVal(c.address));
	if (parts.length === 0) {
		var keys = Object.keys(c);
		if (keys.length === 0)
			return '-';
		return keys.slice(0, 3).map(function(k) { return '%s=%s'.format(k, formatCompactVal(c[k])); }).join(' · ');
	}
	return parts.join(' ');
}

function summarizeOutbound(item) {
	var c = (item && item.config && typeof item.config === 'object') ? item.config : {};
	var parts = [];
	var ep = formatHostPort(c.server, c.server_port);
	if (ep)
		parts.push(ep);
	if (c.detour)
		parts.push(_('via %s').format(c.detour));
	if (c.bind_interface)
		parts.push(_('dev:%s').format(c.bind_interface));
	if (parts.length === 0) {
		var keys = Object.keys(c);
		if (keys.length === 0)
			return '-';
		return keys.slice(0, 3).map(function(k) { return '%s=%s'.format(k, formatCompactVal(c[k])); }).join(' · ');
	}
	return parts.join(' · ');
}

function summarizeDnsServer(item) {
	var c = (item && item.config && typeof item.config === 'object') ? item.config : {};
	if (item && item.type === 'fakeip') {
		var ranges = [ c.inet4_range, c.inet6_range ].filter(Boolean);
		return ranges.length ? ranges.join(', ') : '-';
	}
	var parts = [];
	var ep = formatHostPort(c.server, c.server_port);
	if (ep)
		parts.push(ep + (c.path ? String(c.path) : ''));
	if (c.detour)
		parts.push(_('via %s').format(c.detour));
	if (c.interface)
		parts.push(_('dev:%s').format(c.interface));
	if (parts.length === 0) {
		var keys = Object.keys(c);
		if (keys.length === 0)
			return '-';
		return keys.slice(0, 3).map(function(k) { return '%s=%s'.format(k, formatCompactVal(c[k])); }).join(' · ');
	}
	return parts.join(' · ');
}

function summarizeRule(rule) {
	var c = (rule && rule.config && typeof rule.config === 'object') ? rule.config : {};
	if (c.type === 'logical') {
		var subCount = Array.isArray(c.rules) ? c.rules.length : 0;
		return _('logical (%s, %d sub-rules)').format(c.mode || 'and', subCount);
	}
	var keys = Object.keys(c);
	if (keys.length === 0)
		return _('All');
	var preferred = [
		'inbound', 'protocol', 'network', 'query_type', 'rule_set',
		'domain', 'domain_suffix', 'domain_keyword', 'domain_regex',
		'ip_cidr', 'ip_is_private', 'port', 'port_range', 'source_ip_cidr'
	];
	var ordered = [];
	preferred.forEach(function(k) {
		if (Object.prototype.hasOwnProperty.call(c, k))
			ordered.push(k);
	});
	keys.forEach(function(k) {
		if (ordered.indexOf(k) < 0)
			ordered.push(k);
	});
	var shown = ordered.slice(0, 3).map(function(k) {
		return '%s: %s'.format(k, formatCompactVal(c[k]));
	});
	if (ordered.length > 3)
		shown.push('+%d'.format(ordered.length - 3));
	return shown.join(' · ');
}

function summarizeRuleSet(item) {
	var c = (item && item.config && typeof item.config === 'object') ? item.config : {};
	if (item && item.type === 'inline') {
		var count = Array.isArray(c.rules) ? c.rules.length : 0;
		return _('%d inline rules').format(count);
	}
	if (item && item.type === 'local')
		return c.path || '-';
	var parts = [];
	if (c.url)
		parts.push(String(c.url));
	if (c.http_client && c.http_client.detour)
		parts.push(_('via %s').format(c.http_client.detour));
	if (c.update_interval)
		parts.push(String(c.update_interval));
	return parts.length ? parts.join(' · ') : '-';
}

return baseclass.extend({
	INBOUND_TYPES: INBOUND_TYPES,
	OUTBOUND_TYPES: OUTBOUND_TYPES,
	GROUP_TYPES: GROUP_TYPES,
	DNS_SERVER_TYPES: DNS_SERVER_TYPES,
	DNS_RULE_ACTIONS: DNS_RULE_ACTIONS,
	ROUTE_RULE_ACTIONS: ROUTE_RULE_ACTIONS,
	RULE_SET_TYPES: RULE_SET_TYPES,
	RULE_SET_FORMATS: RULE_SET_FORMATS,
	DNS_STRATEGIES: DNS_STRATEGIES,

	INBOUND_SNIPPETS: INBOUND_SNIPPETS,
	OUTBOUND_SNIPPETS: OUTBOUND_SNIPPETS,
	GROUP_SNIPPETS: GROUP_SNIPPETS,
	DNS_SERVER_SNIPPETS: DNS_SERVER_SNIPPETS,
	DNS_RULE_SNIPPETS: DNS_RULE_SNIPPETS,
	ROUTE_RULE_SNIPPETS: ROUTE_RULE_SNIPPETS,
	RULE_SET_SNIPPETS: RULE_SET_SNIPPETS,
	OVERRIDE_SNIPPETS: OVERRIDE_SNIPPETS,

	createBlankPreset: createBlankPreset,
	createStandard114Preset: createStandard114Preset,
	createComboInput: createComboInput,
	prettyJson: prettyJson,
	parseJsonObject: parseJsonObject,
	summarizeInbound: summarizeInbound,
	summarizeOutbound: summarizeOutbound,
	summarizeDnsServer: summarizeDnsServer,
	summarizeRule: summarizeRule,
	summarizeRuleSet: summarizeRuleSet,
	makeId: makeId,
	deepClone: deepClone
});
