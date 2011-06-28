divert(-1)dnl
#
# Copyright (c) 2004-2011 hesketh.com/inc. All rights reserved.
#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_Check_Header_DateWarning.m4,v 1.15 2011/05/17 19:09:59 schampeo Exp $')
divert(-1)dnl

LOCAL_RULESETS
#------------------------------------------------------------------------
# enemieslist.com Date-Warning header checks
#------------------------------------------------------------------------
HDate-warning: $>EL_Check_Header_DateWarning
SEL_Check_Header_DateWarning
ifdef(`_EL_TRACE', `dnl
R$*					$: $1 $(EL_Log "DateWarning w/ " $1 "; score: " $&{ELSuspiciousCount} "." $)
')dnl

ifdef(`_EL_SKIPLOCAL', `dnl
R$*					$: $1 $| $&{client_addr}
R$* $| 127.0.0.1	$@
')dnl

# skip whitelisted hosts
R$*				$: $&{ELWhitelisted}
R$+:$+			$@

R$*					$#error $@ 5.7.1 $: ifdef(`confEL_ErrDateWarning', `confEL_ErrDateWarning', `"554 BADDATW Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam (invalid Date header)."')

