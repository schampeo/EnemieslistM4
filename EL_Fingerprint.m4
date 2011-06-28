divert(-1)dnl
#
# Copyright (c) 2004-2011 hesketh.com/inc. All rights reserved.

# See the file LICENSE in the distribution for details.

#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_Fingerprint.m4,v 1.6 2011/05/13 22:07:52 schampeo Exp $')dnl
divert(-1)dnl

LOCAL_CONFIG
KEL_Fingerprint program ifdef(`confEL_P0FQEL', `confEL_P0FQEL', `/usr/sbin/p0fqel')
