divert(-1)dnl
#
# Copyright (c) 2004-2011 hesketh.com/inc. All rights reserved.

# See the file LICENSE in the distribution for details.

#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_Spamtrap.m4,v 1.13 2011/05/13 21:04:31 schampeo Exp $')
divert(-1)dnl

define(`_EL_SPAMTRAP', `1')

LOCAL_CONFIG
# enemieslist.com spamtrap blacklist
# 
# file format: 
# spamtrap@address    tab   T
# dormant@domain      tab   D
# keyword@            tab   T
#
# T is for trap - these addresses should never receive mail
# D is for dormant - these are old retired addresses that may get mail

KEL_Spamtrap ifdef(`confEL_SPAMTRAPS_FILE', `confEL_DB_MAP_TYPE' `confEL_SPAMTRAPS_FILE')
