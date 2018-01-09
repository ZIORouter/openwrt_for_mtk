#
# Copyright (C) 2009 OpenWrt.org
#

SUBTARGET:=mt7620
BOARDNAME:=MT7620 based boards
ARCH_PACKAGES:=ramips_24kec
FEATURES+=usb
CPU_TYPE:=24kec
CPU_SUBTYPE:=dsp

DEFAULT_PACKAGES += 

define Target/Description
	Build firmware images for Ralink MT7620 based boards.
endef

