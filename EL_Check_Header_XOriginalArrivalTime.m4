divert(-1)dnl
#
# Copyright (c) 2004-2011 hesketh.com/inc. All rights reserved.
#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_Check_Header_XOriginalArrivalTime.m4,v 1.13 2011/05/17 17:54:46 schampeo Exp $')
divert(-1)dnl

LOCAL_CONFIG
#------------------------------------------------------------------------
# enemieslist.com X-OriginalArrivalTime: header check pattern and call
#------------------------------------------------------------------------
HX-OriginalArrivalTime: $>EL_Check_Header_XOriginalArrivalTime

LOCAL_RULESETS
#------------------------------------------------------------------------
# enemieslist.com X-OriginalArrivalTime header checks
#------------------------------------------------------------------------
SEL_Check_Header_XOriginalArrivalTime
ifdef(`_EL_TRACE', `dnl
R$*					$: $1 $(EL_Log "XOriginalArrivalTime w/ " $1 "; score: " $&{ELSuspiciousCount} "." $)
')dnl

ifdef(`_EL_SKIPLOCAL', `dnl
R$*					$: $1 $| $&{client_addr}
R$* $| 127.0.0.1	$@
')dnl

# skip whitelisted hosts
R$*					$: $&{ELWhitelisted}
R$+:$+				$@

ifdef(`_EL_B0RKEN', `dnl
R$*					$: $(EL_B0rkenRatware $&{currHeader} $)
R@SPAM				$#error $@ 5.7.1 $: ifdef(`confEL_ErrB0rkenRatware', `confEL_ErrB0rkenRatware', `"554 B0RKENR Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it appears to have been sent by laughably broken spam software."')
')dnl

R$*					$: $&{ELSpamsignFrom}
R1					$#error $@ 5.7.1 $: ifdef(`confEL_ErrToFromCialis', `confEL_ErrToFromCialis', `"554 TO_FROM Contact "$&{ELContactEmail}" if this is in error, but your message was rejected; it seems to be spam (To/From)"')


