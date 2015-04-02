include $(TOPDIR)/rules.mk

PKG_NAME:=xsocks
PKG_VERSION:=0.1.0
PKG_RELEASE=$(PKG_SOURCE_VERSION)

PKG_SOURCE_URL:=https://github.com/lparam/xsocks/archive
PKG_SOURCE:=v$(PKG_VERSION).tar.gz
PKG_MAINTAINER:=Ken <ken.i18n@gmail.com>

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)/$(PKG_NAME)-$(PKG_VERSION)

PKG_INSTALL:=1
PKG_USE_MIPS16:=0
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk

define Package/xsocks/Default
  SECTION:=net
  CATEGORY:=Network
  TITLE:=A secure and fast proxy for protect your network traffic
  URL:=https://github.com/lparam/xsocks
endef

define Package/xsocks
  $(call Package/xsocks/Default)
  DEPENDS:=+libpthread +librt
endef

define Package/xsocks/description
xsocks is a secure and fast proxy for protect your network traffic
endef

define Package/xsocks/install
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/xsocks.init $(1)/etc/init.d/xsocks
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/x{socks,tproxy,forwarder,tunnel} $(1)/usr/bin
endef

$(eval $(call BuildPackage,xsocks))
