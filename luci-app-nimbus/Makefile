include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-nimbus
PKG_VERSION:=$(if $(NIMBUS_PKG_VERSION),$(NIMBUS_PKG_VERSION),0.1.0)
PKG_RELEASE:=$(if $(NIMBUS_PKG_RELEASE),$(NIMBUS_PKG_RELEASE),1)
PKG_PO_VERSION:=$(PKG_VERSION)-r$(PKG_RELEASE)
PKG_LICENSE:=GPL-3.0-or-later
PKG_MAINTAINER:=nimbus
PKGARCH:=all

LUCI_TITLE:=LuCI support for Nimbus transparent proxy
LUCI_DEPENDS:=+nimbus +luci-base
LUCI_PKGARCH:=all

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
