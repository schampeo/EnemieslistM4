divert(-1)dnl
#
# Copyright (c) 2004-2011 hesketh.com/inc. All rights reserved.
#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_ReportAbuse.m4,v 1.9 2011/05/13 21:06:06 schampeo Exp $')
divert(-1)dnl

define(`_EL_REPORT_ABUSE', `1')

LOCAL_CONFIG
# enemieslist.com abuse reporting db
#
# file format:
# Report:domain		tab	   YES/NO
# Contact:domain	tab	   abuse-address
KEL_AbuseContacts ifdef(`confEL_ABUSE_CONTACTS_FILE', `confEL_DB_MAP_TYPE' `confEL_ABUSE_CONTACTS_FILE')


