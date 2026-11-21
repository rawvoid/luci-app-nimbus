include $(TOPDIR)/rules.mk

PKG_NAME:=nimbus
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

PKG_LICENSE:=GPL-3.0-or-later
PKG_MAINTAINER:=nimbus

include $(INCLUDE_DIR)/package.mk

define Package/nimbus
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Transparent proxy management core for sing-box
  PKGARCH:=all
  DEPENDS:=+ucode +ucode-mod-fs +ucode-mod-uci +ucode-mod-ubus +ucode-mod-uloop +rpcd-mod-ucode +nftables-json +ip-full +ca-bundle +curl +kmod-nft-core +kmod-nft-fib +kmod-nft-nat +kmod-nft-tproxy
endef

define Package/nimbus/description
  Modular transparent proxy controller for sing-box using native ucode,
  isolated inet nftables rules, dual-stack policy routing, and rpcd ubus APIs.
endef

define Package/nimbus/conffiles
/etc/config/nimbus
endef

define Package/nimbus/prerm
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] && exit 0

is_upgrade=0
if [ "$${PKG_UPGRADE:-0}" = "1" ] || [ "$$1" = "upgrade" ]; then
	is_upgrade=1
fi

if [ -x /etc/init.d/nimbus ]; then
	/etc/init.d/nimbus stop >/dev/null 2>&1 || true
	if [ "$$is_upgrade" -eq 0 ]; then
		/etc/init.d/nimbus disable >/dev/null 2>&1 || true
	fi
fi

nft delete table inet nimbus >/dev/null 2>&1 || true

rtable=$$(uci -q get nimbus.proxy.route_table 2>/dev/null || echo 100)
case "$$rtable" in
	*[!0-9]*|'') rtable=100 ;;
esac
if [ "$${#rtable}" -gt 3 ] || [ "$$rtable" -lt 1 ] || [ "$$rtable" -gt 252 ]; then
	rtable=100
fi
while ip -4 rule del lookup "$$rtable" >/dev/null 2>&1; do :; done
while ip -6 rule del lookup "$$rtable" >/dev/null 2>&1; do :; done
ip -4 route flush table "$$rtable" >/dev/null 2>&1 || true
ip -6 route flush table "$$rtable" >/dev/null 2>&1 || true

if [ -f /etc/nimbus/dns_backup.json ] && [ -f /usr/share/nimbus/dns_manager.uc ]; then
	ucode -S -L /usr/share/nimbus -e "import * as dns from 'dns_manager'; dns.restore_dns();" >/dev/null 2>&1 || true
fi

if [ "$$is_upgrade" -eq 0 ] && [ -f /etc/crontabs/root ] && grep -q '# nimbus-' /etc/crontabs/root 2>/dev/null; then
	tmp_cron=$$(mktemp /tmp/nimbus-prerm-cron.XXXXXX 2>/dev/null) || tmp_cron=""
	if [ -n "$$tmp_cron" ]; then
		chmod 0600 "$$tmp_cron"
		rc=0
		grep -v '# nimbus-' /etc/crontabs/root > "$$tmp_cron" || rc=$$?
		if [ "$$rc" -le 1 ] && mv -f "$$tmp_cron" /etc/crontabs/root; then
			[ -x /etc/init.d/cron ] && /etc/init.d/cron reload >/dev/null 2>&1 || true
		else
			rm -f "$$tmp_cron"
		fi
	fi
fi

exit 0
endef

define Build/Compile
endef

define Package/nimbus/install
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/etc/config/nimbus $(1)/etc/config/nimbus

	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/etc/uci-defaults/99-nimbus $(1)/etc/uci-defaults/99-nimbus

	$(INSTALL_DIR) $(1)/lib/upgrade/keep.d
	$(INSTALL_DATA) ./files/lib/upgrade/keep.d/nimbus $(1)/lib/upgrade/keep.d/nimbus

	$(INSTALL_DIR) $(1)/usr/share/nimbus
	$(INSTALL_DATA) ./files/usr/share/nimbus/common.uc $(1)/usr/share/nimbus/common.uc
	$(INSTALL_DATA) ./files/usr/share/nimbus/config_builder.uc $(1)/usr/share/nimbus/config_builder.uc
endef

$(eval $(call BuildPackage,nimbus))
