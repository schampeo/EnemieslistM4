divert(-1)dnl
#
# Copyright (c) 2004-2011 hesketh.com/inc. All rights reserved.

# See the file LICENSE in the distribution for details.

#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_DomainsBlacklist.m4,v 1.7 2011/05/13 22:12:06 schampeo Exp $')dnl
divert(-1)dnl

define(`_EL_DOMAIN_BLACKLIST', `1')

LOCAL_CONFIG
# enemieslist.com domain blacklist
# 
# file format: 
# domain    tab   SPAMMER
# domain    tab   S
KEL_DomainBlacklist ifdef(`confEL_DOMAIN_BLACKLIST_FILE', `confEL_DB_MAP_TYPE' `confEL_DOMAIN_BLACKLIST_FILE')


