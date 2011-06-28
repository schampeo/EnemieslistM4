divert(-1)dnl
#
# Copyright (c) 2004-2011 hesketh.com/inc. All rights reserved.

# See the file LICENSE in the distribution for details.

#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_Offwhitelist.m4,v 1.15 2011/05/13 21:09:21 schampeo Exp $')
divert(-1)dnl

define(`_EL_OFFWHITELIST', `1')

LOCAL_CONFIG
# enemieslist.com host "offwhitelist"
#
# flexible keywords-based tainted server lookup. 
# Keywords:
#  O or OFFWHITE	- has relayed spam or viruses
#  T or BADRECD  	- probable webmail system with insufficient tracking in Recd header
#  L or LEGIT    	- legitimate host we have not yet received spam or viruses from
#  P or PHISH    	- compromised host we have received phish scams from
#  V or VIRUS    	- host we have received viruses from and want to block
#  C or CR       	- Challenge/response host
#  R                - known open relay
# 
# file format: 
# fully.qualified.host.name    tab   KEYWORD

KEL_Offwhitelist ifdef(`confEL_OFFWHITELIST_FILE', `confEL_DB_MAP_TYPE' `confEL_OFFWHITELIST_FILE')
