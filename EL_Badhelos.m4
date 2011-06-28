divert(-1)dnl
#
# Copyright (c) 2004-2011 hesketh.com/inc. All rights reserved.
#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_Badhelos.m4,v 1.10 2011/05/17 19:48:21 schampeo Exp $')
divert(-1)dnl

define(`_EL_BADHELOS', `1')

LOCAL_CONFIG
# enemieslist.com bad HELO/EHLO blacklist
#
# file format:
# helostring    tab   BYE
KEL_Badhelos ifdef(`confEL_BADHELOS_FILE', `confEL_DB_MAP_TYPE' `confEL_BADHELOS_FILE')

