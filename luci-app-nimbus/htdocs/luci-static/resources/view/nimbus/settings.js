'use strict';
'require view';
'require form';
'require uci';
'require nimbus.api as nimbusApi';

function parseHexU32(val) {
	if (typeof val !== 'string')
		return null;
	var s = val.trim();
	if (!/^(0[xX])?[0-9a-fA-F]+$/.test(s))
		return null;
	var n = parseInt(s, 16);
	if (isNaN(n) || n < 1 || n > 0xffffffff)
		return null;
	return n;
}

function isValidPortRange(val) {
	if (typeof val !== 'string')
		return false;
	var m = val.trim().match(/^([0-9]{1,5})(?:-([0-9]{1,5}))?$/);
	if (!m)
		return false;
	var p1 = parseInt(m[1], 10);
	var p2 = m[2] ? parseInt(m[2], 10) : p1;
	return (p1 >= 1 && p1 <= 65535 && p2 >= 1 && p2 <= 65535 && p1 <= p2);
}

function reloadWithRetry(attemptsLeft) {
	return nimbusApi.serviceAction('reload').then(function(res) {
		if (res && res.ok === false && res.code === 'E_LOCKED' && attemptsLeft > 0) {
			return new Promise(function(resolve) {
				setTimeout(resolve, 800);
			}).then(function() {
				return reloadWithRetry(attemptsLeft - 1);
			});
		}
		if (!res || res.ok === false)
			nimbusApi.notifyError(res);
		else
			nimbusApi.notifySuccess(_('Configuration applied and data plane reloaded.'));
	}).catch(function(err) {
		nimbusApi.notifyError(err);
	});
}

return view.extend({
	load: function() {
		return Promise.all([
			uci.load('nimbus'),
			nimbusApi.getNetworkInterfaces().catch(function() { return []; }),
			nimbusApi.getHostHints().catch(function() { return {}; })
		]);
	},

	render: function(data) {
		var ifaces = Array.isArray(data[1]) ? data[1] : [];
		var hints = (data[2] && typeof data[2] === 'object') ? data[2] : {};

		var ifaceNames = [];
		ifaces.forEach(function(item) {
			if (item && item.interface && ifaceNames.indexOf(item.interface) < 0)
				ifaceNames.push(item.interface);
		});
		if (ifaceNames.indexOf('lan') < 0)
			ifaceNames.push('lan');

		var m = new form.Map(
			'nimbus',
			_('Nimbus Settings'),
			_('Configure global routing topology, transparent proxy ports, DNS takeover, and per-device rules.')
		);

		// 1. Global Settings
		var sGlobal = m.section(form.NamedSection, 'global', 'main', _('Global Settings'));
		sGlobal.anonymous = true;
		sGlobal.addremove = false;

		var o;
		o = sGlobal.option(form.Flag, 'enabled', _('Enable Service'));
		o.default = '0';
		o.rmempty = false;

		o = sGlobal.option(form.ListValue, 'config_mode', _('Configuration Mode'));
		o.value('composer', _('Composer Mode'));
		o.value('profile', _('Raw Profile Mode'));
		o.default = 'composer';
		o.rmempty = false;

		var oActiveProfile = sGlobal.option(form.ListValue, 'active_profile', _('Active Profile'));
		oActiveProfile.depends('config_mode', 'profile');
		oActiveProfile.value('', _('-- Select Profile --'));
		uci.sections('nimbus', 'profile', function(sec) {
			var label = sec.name ? '%s (%s)'.format(sec.name, sec['.name']) : sec['.name'];
			oActiveProfile.value(sec['.name'], label);
		});

		o = sGlobal.option(form.ListValue, 'topology', _('Network Topology'));
		o.value('main', _('Main Router'));
		o.value('side', _('Side Router (Bypass Gateway)'));
		o.default = 'main';

		o = sGlobal.option(form.ListValue, 'proxy_mode', _('Proxy Mode'));
		o.value('tproxy_redirect', _('TPROXY + Redirect (TCP REDIRECT + UDP TPROXY)'));
		o.default = 'tproxy_redirect';

		o = sGlobal.option(form.Flag, 'fail_open', _('Fail-Open on Error'),
			_('When disabled (default), service failure switches to Fail-Closed Lockdown blocking non-whitelist LAN forwarding while keeping router SSH/LuCI reachable.'));
		o.default = '0';
		o.rmempty = false;

		var validateIfaceList = function(section_id, value) {
			if (value == null || value === '')
				return true;
			var items = Array.isArray(value) ? value : [ value ];
			for (var i = 0; i < items.length; i++) {
				var item = String(items[i] || '').trim();
				if (!item)
					continue;
				if (item === '.' || item === '..' || item.length > 64 || !/^[A-Za-z0-9_.+-]+$/.test(item))
					return _('Invalid interface name "%s": must be 1–64 characters matching [A-Za-z0-9_.+-].').format(item);
			}
			return true;
		};

		o = sGlobal.option(form.DynamicList, 'lan_interfaces', _('LAN Interfaces'),
			_('Logical OpenWrt network interfaces whose client traffic is intercepted.'));
		o.default = 'lan';
		o.validate = validateIfaceList;
		ifaceNames.forEach(function(name) {
			if (name !== 'loopback')
				o.value(name);
		});

		o = sGlobal.option(form.DynamicList, 'wan_interfaces', _('WAN Interfaces'),
			_('Logical WAN interfaces whose public IPv4/IPv6 prefixes are automatically bypassed in Main Router topology.'));
		o.depends('topology', 'main');
		o.validate = validateIfaceList;
		ifaceNames.forEach(function(name) {
			if (name !== 'loopback' && name !== 'lan')
				o.value(name);
		});

		var oIpv4 = sGlobal.option(form.Flag, 'ipv4_enable', _('Enable IPv4 Proxy'));
		oIpv4.default = '1';
		oIpv4.rmempty = false;

		var oIpv6 = sGlobal.option(form.Flag, 'ipv6_enable', _('Enable IPv6 Proxy'));
		oIpv6.default = '1';
		oIpv6.rmempty = false;
		oIpv6.validate = function(section_id, value) {
			if (value === '0' && oIpv4.formvalue(section_id) === '0')
				return _('IPv4 and IPv6 proxy cannot both be disabled.');
			return true;
		};

		var oProxyLocal = sGlobal.option(form.Flag, 'proxy_local', _('Proxy Router Outbound Traffic'),
			_('Intercept TCP/UDP connections initiated by the router itself.'));
		oProxyLocal.default = '0';
		oProxyLocal.rmempty = false;

		o = sGlobal.option(form.ListValue, 'log_level', _('Log Level'));
		[ 'trace', 'debug', 'info', 'warn', 'error', 'fatal', 'panic' ].forEach(function(lvl) {
			o.value(lvl, lvl);
		});
		o.default = 'warn';

		o = sGlobal.option(form.Value, 'gomemlimit', _('Go Memory Limit (GOMEMLIMIT)'),
			_('Use "auto" (40% of MemTotal, clamped 32MiB–256MiB) or an explicit binary value using B, KiB, MiB, GiB, or TiB (e.g. 128MiB).'));
		o.default = 'auto';
		o.rmempty = false;
		o.validate = function(section_id, value) {
			var v = String(value || '').trim();
			if (v === 'auto' || /^[0-9]+(B|KiB|MiB|GiB|TiB)$/.test(v))
				return true;
			return _('Must be "auto" or a binary Go memory limit using B, KiB, MiB, GiB, or TiB (e.g. 128MiB).');
		};

		// 2. Data Plane & Traffic Filtering
		var sProxy = m.section(form.NamedSection, 'proxy', 'proxy', _('Data Plane & Traffic Filtering'));
		sProxy.anonymous = true;
		sProxy.addremove = false;

		var oRedirPort = sProxy.option(form.Value, 'redirect_port', _('TCP Redirect Port'),
			_('Used when the active profile does not define a redirect inbound.'));
		oRedirPort.datatype = 'range(1024,65535)';
		oRedirPort.default = '7891';
		oRedirPort.rmempty = false;

		var oTproxyPort = sProxy.option(form.Value, 'tproxy_port', _('UDP TPROXY Port'),
			_('Used when the active profile does not define a UDP tproxy inbound.'));
		oTproxyPort.datatype = 'range(1024,65535)';
		oTproxyPort.default = '7892';
		oTproxyPort.rmempty = false;
		oTproxyPort.validate = function(section_id, value) {
			if (String(value).trim() === String(oRedirPort.formvalue(section_id)).trim())
				return _('TPROXY port must differ from TCP Redirect port.');
			return true;
		};

		var oOutMark = sProxy.option(form.Value, 'outbound_mark', _('Outbound Anti-Loop Mark'));
		oOutMark.default = '0xff';
		oOutMark.rmempty = false;
		oOutMark.validate = function(section_id, value) {
			if (parseHexU32(value) == null)
				return _('Must be a non-zero 32-bit hexadecimal mark (e.g. 0xff).');
			return true;
		};

		var oProxyMark = sProxy.option(form.Value, 'proxy_mark', _('UDP TPROXY Routing Mark'));
		oProxyMark.default = '0x1';
		oProxyMark.rmempty = false;
		oProxyMark.validate = function(section_id, value) {
			var pm = parseHexU32(value);
			if (pm == null)
				return _('Must be a non-zero 32-bit hexadecimal mark (e.g. 0x1).');
			var om = parseHexU32(oOutMark.formvalue(section_id));
			if (om != null && pm === om)
				return _('TPROXY routing mark must differ from outbound anti-loop mark.');
			return true;
		};

		o = sProxy.option(form.Value, 'route_table', _('Policy Route Table ID'));
		o.datatype = 'range(1,252)';
		o.default = '100';
		o.rmempty = false;

		o = sProxy.option(form.ListValue, 'port_filter_mode', _('Port Filter Mode'));
		o.value('all', _('Proxy All Ports'));
		o.value('include', _('Proxy Only Listed Ports'));
		o.value('exclude', _('Bypass Listed Ports'));
		o.default = 'all';

		o = sProxy.option(form.DynamicList, 'proxy_tcp_ports', _('TCP Ports / Ranges'),
			_('Examples: 80, 443, 8000-8999.'));
		o.depends('port_filter_mode', 'include');
		o.depends('port_filter_mode', 'exclude');
		o.validate = function(section_id, value) {
			var items = Array.isArray(value) ? value : (value != null && value !== '' ? [ value ] : []);
			for (var i = 0; i < items.length; i++) {
				if (!isValidPortRange(String(items[i] || '')))
					return _('Invalid port or range (expected 1-65535 or start-end).');
			}
			return true;
		};

		o = sProxy.option(form.DynamicList, 'proxy_udp_ports', _('UDP Ports / Ranges'),
			_('Examples: 53, 443, 10000-10100.'));
		o.depends('port_filter_mode', 'include');
		o.depends('port_filter_mode', 'exclude');
		o.validate = function(section_id, value) {
			var items = Array.isArray(value) ? value : (value != null && value !== '' ? [ value ] : []);
			for (var i = 0; i < items.length; i++) {
				if (!isValidPortRange(String(items[i] || '')))
					return _('Invalid port or range (expected 1-65535 or start-end).');
			}
			return true;
		};

		o = sProxy.option(form.ListValue, 'lan_device_mode', _('Default LAN Device Policy'),
			_('Fallback policy for LAN devices not matched by any enabled rule in LAN Device Rules below. Device rules take priority in top-to-bottom order.'));
		o.value('default_proxy', _('Proxy Unmatched Devices (Default)'));
		o.value('default_bypass', _('Bypass Unmatched Devices (Direct)'));
		o.default = 'default_proxy';
		o.rmempty = false;
		o.load = function(section_id) {
			var val = form.ListValue.prototype.load.call(this, section_id);
			var v = String(val != null ? val : 'default_proxy').trim();
			if (v === 'proxy_listed' || v === 'default_bypass')
				return 'default_bypass';
			return 'default_proxy';
		};

		o = sProxy.option(form.Flag, 'sniff', _('Inject Route Sniff Rule'),
			_('Ensure a modern route sniff action rule covers the active transparent inbounds.'));
		o.default = '0';
		o.rmempty = false;

		o = sProxy.option(form.Flag, 'block_quic', _('Block QUIC (UDP 443)'),
			_('Inject a route rule rejecting QUIC protocol traffic so browsers fall back to TCP.'));
		o.default = '0';
		o.rmempty = false;

		// 3. DNS Takeover (dnsmasq)
		var sDns = m.section(form.NamedSection, 'dns', 'dns', _('DNS Takeover (dnsmasq)'));
		sDns.anonymous = true;
		sDns.addremove = false;

		var oDnsMode = sDns.option(form.ListValue, 'mode', _('DNS Mode'));
		oDnsMode.value('none', _('Do Not Manage (Keep Existing dnsmasq)'));
		oDnsMode.value('singbox', _('Forward to Local sing-box DNS'));
		oDnsMode.value('custom', _('Forward to Custom Upstreams'));
		oDnsMode.default = 'none';

		var oDnsPort = sDns.option(form.Value, 'singbox_dns_port', _('sing-box DNS Listen Port'),
			_('Used when mode is "singbox" and the profile lacks a local direct DNS inbound.'));
		oDnsPort.datatype = 'range(1024,65535)';
		oDnsPort.default = '5353';
		oDnsPort.depends('mode', 'singbox');
		oDnsPort.validate = function(section_id, value) {
			if (oDnsMode.formvalue(section_id) !== 'singbox')
				return true;
			var p = String(value || '').trim();
			if (!p)
				return _('DNS listen port is required.');
			var rp = String(oRedirPort.formvalue('proxy') || uci.get('nimbus', 'proxy', 'redirect_port') || '7891').trim();
			var tp = String(oTproxyPort.formvalue('proxy') || uci.get('nimbus', 'proxy', 'tproxy_port') || '7892').trim();
			if (p === rp || p === tp) {
				return _('DNS port must not collide with TCP Redirect or UDP TPROXY port.');
			}
			return true;
		};

		o = sDns.option(form.DynamicList, 'custom_servers', _('Custom Upstream Servers'),
			_('dnsmasq upstream format, e.g. 127.0.0.1#5335 or 192.168.1.2#5353.'));
		o.depends('mode', 'custom');
		o.validate = function(section_id, value) {
			if (oDnsMode.formvalue(section_id) !== 'custom')
				return true;
			var items = Array.isArray(value)
				? value
				: (value != null && String(value).trim() !== '' ? [ String(value).trim() ] : []);
			if (items.length === 0)
				return _('At least one custom DNS upstream server is required.');
			for (var i = 0; i < items.length; i++) {
				var entry = String(items[i] || '').trim();
				if (!entry || /\s/.test(entry))
					return _('DNS upstream entry cannot be empty or contain spaces.');
			}
			return true;
		};

		var oLocalPolicy = sDns.option(form.ListValue, 'local_dns_policy', _('Local DNS ("local") Handling'),
			_('How to rewrite sing-box DNS servers of type "local" when dnsmasq forwards to sing-box or Router Outbound Proxy is enabled, preventing DNS loops.'));
		oLocalPolicy.value('auto', _('Auto-detect WAN DNS (Fallback to Direct DNS)'));
		oLocalPolicy.value('fallback', _('Always Use Configured Direct DNS'));
		oLocalPolicy.value('reject', _('Strict Reject ("local" Not Allowed)'));
		oLocalPolicy.default = 'auto';
		oLocalPolicy.depends('mode', 'singbox');
		oLocalPolicy.depends('nimbus.global.proxy_local', '1');

		var oLocalFallback = sDns.option(form.Value, 'local_fallback_server', _('Manual / Fallback Direct DNS'),
			_('Non-loopback direct DNS IP used when policy is "fallback", or when no safe WAN DNS is available yet. Leave empty to require WAN DNS.'));
		oLocalFallback.datatype = 'ipaddr';
		oLocalFallback.placeholder = '223.5.5.5';
		oLocalFallback.rmempty = true;
		oLocalFallback.depends({ mode: 'singbox', local_dns_policy: 'auto' });
		oLocalFallback.depends({ mode: 'singbox', local_dns_policy: 'fallback' });
		oLocalFallback.depends({ 'nimbus.global.proxy_local': '1', local_dns_policy: 'auto' });
		oLocalFallback.depends({ 'nimbus.global.proxy_local': '1', local_dns_policy: 'fallback' });
		oLocalFallback.validate = function(section_id, value) {
			var isSingboxDns = (oDnsMode.formvalue(section_id) === 'singbox');
			var rawProxyLocal = oProxyLocal.formvalue('global');
			var isProxyLocal = (String(rawProxyLocal != null ? rawProxyLocal : (uci.get('nimbus', 'global', 'proxy_local') || '0')) === '1');
			if (!isSingboxDns && !isProxyLocal)
				return true;
			var pol = oLocalPolicy.formvalue(section_id) || 'auto';
			if (pol === 'reject')
				return true;
			var v = String(value || '').trim();
			if (!v) {
				if (pol === 'fallback')
					return _('Direct DNS server IP is required when policy is set to always use fallback.');
				return true;
			}
			if (/^(127\.|0\.0\.0\.0$|::1$|::$)/.test(v))
				return _('Direct DNS server IP must not be a loopback or unspecified address.');
			return true;
		};

		o = sDns.option(form.Flag, 'hijack_lan_dns', _('Hijack LAN External DNS (Port 53)'),
			_('Redirect external TCP/UDP port 53 queries from proxied LAN devices back to router port 53 (devices bypassed by LAN Device Rules or Default LAN Device Policy are excluded).'));
		o.default = '0';
		o.rmempty = false;

		// 4. LAN Device Rules
		var sDev = m.section(form.GridSection, 'lan_device', _('LAN Device Rules'),
			_('Matched top-to-bottom (first match wins) before applying Default LAN Device Policy above. Disabled rows are ignored.'));
		sDev.anonymous = true;
		sDev.addremove = true;
		sDev.sortable = true;
		sDev.nodescriptions = true;

		o = sDev.option(form.Flag, 'enabled', _('Enabled'));
		o.default = '1';
		o.editable = true;
		o.rmempty = false;

		o = sDev.option(form.Value, 'name', _('Description'));
		o.rmempty = true;

		var oDevMac = sDev.option(form.Value, 'mac', _('MAC Address'));
		oDevMac.datatype = 'macaddr';
		oDevMac.rmempty = true;

		var oDevIp = sDev.option(form.Value, 'ip', _('IP / CIDR'));
		oDevIp.datatype = 'or(ip4addr,ip6addr,cidr4,cidr6)';
		oDevIp.rmempty = true;

		Object.keys(hints).sort().forEach(function(mac) {
			var info = hints[mac] || {};
			var labelParts = [ mac ];
			if (info.name)
				labelParts.push(info.name);
			if (Array.isArray(info.ipaddrs) && info.ipaddrs.length > 0)
				labelParts.push(info.ipaddrs[0]);
			oDevMac.value(mac, labelParts.join(' - '));

			(info.ipaddrs || []).forEach(function(ip4) {
				oDevIp.value(ip4, info.name ? '%s (%s)'.format(ip4, info.name) : ip4);
			});
			(info.ip6addrs || []).forEach(function(ip6) {
				oDevIp.value(ip6, info.name ? '%s (%s)'.format(ip6, info.name) : ip6);
			});
		});

		oDevMac.validate = function(section_id, value) {
			var macVal = String(value || '').trim();
			var ipVal = String(oDevIp.formvalue(section_id) || '').trim();
			if (!macVal && !ipVal)
				return _('Specify at least a MAC address or an IP/CIDR.');
			return true;
		};

		oDevIp.validate = function(section_id, value) {
			var ipVal = String(value || '').trim();
			var macVal = String(oDevMac.formvalue(section_id) || '').trim();
			if (!macVal && !ipVal)
				return _('Specify at least a MAC address or an IP/CIDR.');
			return true;
		};

		o = sDev.option(form.ListValue, 'policy', _('Policy'));
		o.value('bypass', _('Bypass (Direct)'));
		o.value('proxy', _('Proxy'));
		o.default = 'bypass';
		o.editable = true;
		o.rmempty = false;

		return m.render();
	},

	handleSaveApply: function(ev, mode) {
		return this.super('handleSaveApply', [ ev, mode ]).then(function() {
			return reloadWithRetry(2);
		});
	}
});
