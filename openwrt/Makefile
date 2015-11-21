include $(TOPDIR)/rules.mk

PKG_NAME:=xSocks
PKG_VERSION:=0.4.4
PKG_RELEASE=

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/lparam/xSocks.git
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_VERSION:=v$(PKG_VERSION)

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

PKG_MAINTAINER:=lparam

PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/xSocks/Default
  SECTION:=net
  CATEGORY:=Network
  TITLE:=A secure and fast proxy for protect your network traffic
  URL:=https://github.com/lparam/xSocks
endef

define Package/xSocks
  $(call Package/xSocks/Default)
  DEPENDS:=+libpthread +librt
endef

define Package/xSocks/description
  xSocks is a secure and fast proxy for protect your network traffic
endef

define Package/xSocks/install
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/xSocks.init $(1)/etc/init.d/xSocks
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/x{Socks,Tproxy,Forwarder,Tunnel} $(1)/usr/bin
endef

$(eval $(call BuildPackage,xSocks))
