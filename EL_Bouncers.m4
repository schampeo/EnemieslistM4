divert(-1)dnl
#
# Copyright (c) 2004-2011 hesketh.com/inc. All rights reserved.

# See the file LICENSE in the distribution for details.

#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_Bouncers.m4,v 1.8 2011/05/17 19:46:46 schampeo Exp $')dnl
divert(-1)dnl

define(`_EL_BOUNCERS', `1')

LOCAL_CONFIG
# enemieslist.com accept-then-bounce virus/spam/joe-job sources
# 
# file format:
# host   tab   BOUNCER
# host   tab   B
KEL_Bouncer ifdef(`confEL_BOUNCER_FILE', `confEL_DB_MAP_TYPE' `confEL_BOUNCER_FILE')


