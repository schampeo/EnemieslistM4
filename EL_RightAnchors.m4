divert(-1)dnl
#
# Copyright (c) 2006-2011 hesketh.com/inc. All rights reserved.

# See the file LICENSE in the distribution for details.

#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_RightAnchors.m4,v 1.4 2011/05/13 21:05:17 schampeo Exp $')dnl
divert(-1)dnl

define(`_EL_RIGHTANCHOR', `1')

LOCAL_CONFIG
# enemieslist.com right anchor rDNS/hostname substring lookup
# 
# file format: 
# .dsl.bigisp.example.net [tab] RIGHT
KEL_RightAnchors ifdef(`confEL_RIGHTANCHOR_FILE', `confEL_DB_MAP_TYPE' `confEL_RIGHTANCHOR_FILE')

