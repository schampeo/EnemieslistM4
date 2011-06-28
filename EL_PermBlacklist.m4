divert(-1)dnl
#
# Copyright (c) 2004-2011 hesketh.com/inc. All rights reserved.

# See the file LICENSE in the distribution for details.

#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_PermBlacklist.m4,v 1.10 2011/05/13 21:07:51 schampeo Exp $')
divert(-1)dnl

define(`_EL_PERMBLACKLIST', `1')

LOCAL_CONFIG
# enemieslist.com permanent IP blacklist (for abuse of role accounts, etc.)
# 
# file format: 
# dot.ted.qu.ad    tab   DIEDIEDIE
# dot.ted.qu.ad    tab   P
KEL_PermBlacklist ifdef(`confEL_PERMANENTBLACKLIST_FILE', `confEL_DB_MAP_TYPE' `confEL_PERMANENTBLACKLIST_FILE')

