
TARGET := iphone:clang:latest:16.5
INSTALL_TARGET_PROCESSES = xpcsploit

include $(THEOS)/makefiles/common.mk

APPLICATION_NAME = xpcsploit

xpcsploit_FILES = main.m XPCAppDelegate.m XPCRootViewController.m XPCSploit.c
xpcsploit_FRAMEWORKS = UIKit CoreGraphics CoreFoundation
xpcsploit_CFLAGS = -fobjc-arc -Wno-unused-function
xpcsploit_CODESIGN_FLAGS=-Sentitlements.xml
include $(THEOS_MAKE_PATH)/application.mk
