divert(-1)dnl
#
# Copyright (c) 2004-2011 hesketh.com/inc. All rights reserved.
#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_Wordlist.m4,v 1.11 2011/05/13 21:01:31 schampeo Exp $')
divert(-1)dnl

define(`_EL_WORDLIST', `1')

LOCAL_CONFIG
#
# enemieslist.com wordlist for dictionary word lookups
#
# file format: 
# word    tab    WORD (or W)
# name    tab    NAME (or N)
# both    tab    BOTH (or B)
KEL_Wordlist ifdef(`confEL_WORDLIST_FILE', `confEL_DB_MAP_TYPE' `confEL_WORDLIST_FILE')

