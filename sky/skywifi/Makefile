include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/target.mk

PKG_NAME:=skywifi
PKG_VERSION:=1.0.5
PKG_RELEASE:=3
PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
include $(INCLUDE_DIR)/package.mk


define Package/skywifi
	SECTION:=utils
	CATEGORY:=Utilities
	TITLE:=skywifi
	DEPENDS:=+boost +libstdcpp +libopenssl +boost-system +boost-thread +libatomic
endef

define Package/skywifi/description
 Skywifi.pro client for cloud management
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/skywifi/install
	$(INSTALL_DIR) $(1)/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/skywifi $(1)/bin/
	mkdir -p $(1)/etc/init.d
	$(CP) $(PKG_BUILD_DIR)/config.json $(1)/etc/
	$(CP) $(PKG_BUILD_DIR)/initd.sh $(1)/etc/init.d/skywifi
endef

$(eval $(call BuildPackage,skywifi,libopenssl boost-system boost-thread libatomic))
