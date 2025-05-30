# openwisp.org
#
# This is free software, licensed under the GNU General Public License v3.
# See /LICENSE for more information.

include $(TOPDIR)/rules.mk

PKG_NAME:=nexapp-monitoring
PKG_VERSION:=$(shell cat ../VERSION)
PKG_RELEASE:=1
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)/$(PKG_SOURCE_SUBDIR)
PKG_MAINTAINER:=Federico Capoano <f.capoano@openwisp.io>
PKG_LICENSE:=GPL-3.0-or-later

include $(INCLUDE_DIR)/package.mk

define Package/nexapp-monitoring
	TITLE:=Nexapp Monitoring agent
	CATEGORY:=Administration
	SECTION:=admin
	SUBMENU:=openwisp
	DEPENDS:=+netjson-monitoring +openwisp-config
	PKGARCH:=all
	URL:=http://openwisp.org
endef

define Package/netjson-monitoring
	TITLE:=NetJSON Monitoring
	CATEGORY:=Administration
	SECTION:=admin
	SUBMENU:=openwisp
	DEPENDS:=+libubus-lua +lua-cjson +rpcd
	DEPENDS+=+NETJSON_MONITORING_IWINFO:rpcd-mod-iwinfo
	PKGARCH:=all
	URL:=http://openwisp.org
endef

define Package/netjson-monitoring/config
	source "$(SOURCE)/Config.in"
endef

define Build/Compile
endef

define Package/nexapp-monitoring/conffiles
/etc/config/nexapp-monitoring
endef

define Package/netjson-monitoring/install
	$(INSTALL_DIR) \
		$(1)/usr/sbin \
		$(1)/usr/libexec \
		$(1)/usr/lib/lua/nexapp-monitoring \
		$(1)/usr/lib/nexapp-monitoring

	$(INSTALL_BIN) \
		files/sbin/netjson-monitoring.lua \
		$(1)/usr/libexec/netjson-monitoring

	$(INSTALL_BIN) \
		files/netjson-monitoring \
		$(1)/usr/sbin/netjson-monitoring

	$(INSTALL_DATA) \
		files/lib/nexapp-monitoring/dhcp.lua \
		$(1)/usr/lib/lua/nexapp-monitoring/dhcp.lua

	$(INSTALL_DATA) \
		files/lib/nexapp-monitoring/interfaces.lua \
		$(1)/usr/lib/lua/nexapp-monitoring/interfaces.lua

	$(INSTALL_DATA) \
		files/lib/nexapp-monitoring/monitoring.lua \
		$(1)/usr/lib/lua/nexapp-monitoring/monitoring.lua

	$(INSTALL_DATA) \
		files/lib/nexapp-monitoring/utils.lua \
		$(1)/usr/lib/lua/nexapp-monitoring/utils.lua

	$(INSTALL_DATA) \
		files/lib/nexapp-monitoring/neighbors.lua \
		$(1)/usr/lib/lua/nexapp-monitoring/neighbors.lua

	$(INSTALL_DATA) \
		files/lib/nexapp-monitoring/resources.lua \
		$(1)/usr/lib/lua/nexapp-monitoring/resources.lua

	$(INSTALL_DATA) \
		files/lib/nexapp-monitoring/wifi.lua \
		$(1)/usr/lib/lua/nexapp-monitoring/wifi.lua

# Iwinfo is enabled by default unless specified otherwise
ifeq ($(CONFIG_NETJSON_MONITORING_IWINFO), y)
	$(CP) files/lib/nexapp-monitoring/iwinfo.lua $(1)/usr/lib/lua/nexapp-monitoring/iwinfo.lua
endif

	$(CP) ../VERSION $(1)/usr/lib/nexapp-monitoring/
endef

define Package/nexapp-monitoring/install
	$(INSTALL_DIR) \
		$(1)/usr/sbin \
		$(1)/etc/init.d \
		$(1)/etc/config \
		$(1)/usr/lib/nexapp-monitoring \
		$(1)/etc/hotplug.d/nexapp

	$(INSTALL_BIN) \
		files/monitoring.agent \
		$(1)/usr/sbin/nexapp-monitoring

	$(INSTALL_BIN) \
		files/monitoring.init \
		$(1)/etc/init.d/nexapp-monitoring

	$(INSTALL_BIN) \
		files/nexapp-monitoring.hotplug \
		$(1)/etc/hotplug.d/nexapp/nexapp-monitoring

	$(INSTALL_CONF) \
		files/monitoring.config \
		$(1)/etc/config/nexapp-monitoring

endef

$(eval $(call BuildPackage,nexapp-monitoring))
$(eval $(call BuildPackage,netjson-monitoring))
