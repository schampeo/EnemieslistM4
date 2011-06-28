divert(-1)dnl
#
# Copyright (c) 2007-2011 hesketh.com/inc. All rights reserved.
#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_Outscatter.m4,v 1.3 2011/05/13 21:08:43 schampeo Exp $')dnl
divert(-1)dnl

define(`_EL_OUTSCATTER', `1')

LOCAL_CONFIG
# enemieslist.com accept-then-bounce virus/spam/joe-job sources
# 
# file format:
#
# host   tab   Bn
#
# where n is an indicator of a subclass of env sender localpart
#
KEL_Outscatter ifdef(`confEL_OUTSCATTER_FILE', `confEL_DB_MAP_TYPE' `confEL_OUTSCATTER_FILE')


