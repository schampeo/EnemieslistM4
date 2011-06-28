divert(-1)dnl
#
# Copyright (c) 2004-2011 hesketh.com/inc. All rights reserved.
#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_Whitelist.m4,v 1.15 2011/05/13 21:03:16 schampeo Exp $')
divert(-1)dnl

define(`_EL_WHITELIST', `1')

LOCAL_CONFIG
# enemieslist.com IP whitelist
# 
# file format: 
# dot.ted.qu.ad    tab   OK
KEL_Whitelist ifdef(`confEL_WHITELIST_FILE', `confEL_DB_MAP_TYPE' `confEL_WHITELIST_FILE')



