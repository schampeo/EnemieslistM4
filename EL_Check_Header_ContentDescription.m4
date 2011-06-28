divert(-1)dnl
#
# Copyright (c) 2004-2011 hesketh.com/inc. All rights reserved.

# See the file LICENSE in the distribution for details.

#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_Check_Header_ContentDescription.m4,v 1.15 2011/05/17 19:18:58 schampeo Exp $')
divert(-1)dnl

LOCAL_CONFIG
#------------------------------------------------------------------------
# enemieslist.com Content-Description: header check patterns and call
#------------------------------------------------------------------------
HContent-Description: $>EL_Check_Header_ContentDescription

KEL_BogusContentDesc regex -f -aMATCH ^ [a-z]+ [a-z]+ [a-z]+$

KEL_ContentDescriptionChecks sequence EL_BogusContentDesc

LOCAL_RULESETS
#------------------------------------------------------------------------
# enemieslist.com Content-Description header checks
#------------------------------------------------------------------------
SEL_Check_Header_ContentDescription
ifdef(`_EL_TRACE', `dnl
R$*					$: $1 $(EL_Log "ContentDescription w/ " $1 "; score: " $&{ELSuspiciousCount} "." $)
')dnl

ifdef(`_EL_SKIPLOCAL', `dnl
R$*					$: $1 $| $&{client_addr}
R$* $| 127.0.0.1	$@
')dnl

# skip whitelisted hosts
R$*					$: $&{ELWhitelisted}
R$+:$+				$@

R$*					$: $(EL_ContentDescriptionChecks $&{currHeader} $)
RMATCH				$#error $@ 5.7.1 $: ifdef(`confEL_ErrContentDescription', `confEL_ErrContentDescription', `"554 BADHDCD Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as a possible virus; it contains a suspicious header (Content-Description)."')
