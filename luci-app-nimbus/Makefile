include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-nimbus
PKG_VERSION:=0.1.0
PKG_RELEASE:=1
PKG_LICENSE:=GPL-3.0-or-later
PKG_MAINTAINER:=nimbus
PKGARCH:=all

LUCI_TITLE:=LuCI support for Nimbus transparent proxy
LUCI_DEPENDS:=+nimbus +luci-base
LUCI_PKGARCH:=all

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
