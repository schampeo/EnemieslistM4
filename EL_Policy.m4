divert(-1)dnl
#
# Copyright (c) 2004-2011 hesketh.com/inc. All rights reserved.

# See the file LICENSE in the distribution for details.

#
# questions? <support@enemieslist.com>
#
# original version contributed by Bruce Gingery

divert(0)dnl
VERSIONID(`$Id: EL_Policy.m4,v 1.8 2011/05/13 21:06:41 schampeo Exp $')
divert(-1)dnl

define(`_EL_POLICY', `1')dnl

LOCAL_CONFIG
#------------------------------------------------------------------------
# enemieslist.com per-user policy manager
#
# only argument is account/alias for user ($&u)
# returns string of keywords separated by commas; each keyword is an 'on'
# switch for a given test or set of tests.
#------------------------------------------------------------------------
KEL_Policy ifdef(`confEL_POLICY_FILE', `confEL_DB_MAP_TYPE' -a<OK> `confEL_POLICY_FILE')

