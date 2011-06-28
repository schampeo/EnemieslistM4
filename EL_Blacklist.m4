divert(-1)dnl
#
# Copyright (c) 2004-2011 hesketh.com/inc. All rights reserved.
#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_Blacklist.m4,v 1.7 2011/05/17 19:47:15 schampeo Exp $')
divert(-1)dnl

define(`_EL_BLACKLIST', `1')

LOCAL_CONFIG
# enemieslist.com IP blacklist
# 
# file format: 
# dot.ted.qu.ad    tab   FOAD
KEL_Blacklist ifdef(`confEL_BLACKLIST_FILE', `confEL_DB_MAP_TYPE' `confEL_BLACKLIST_FILE')

