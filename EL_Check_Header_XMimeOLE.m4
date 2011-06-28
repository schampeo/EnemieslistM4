divert(-1)dnl
#
# Copyright (c) 2004-2011 hesketh.com/inc. All rights reserved.
#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_Check_Header_XMimeOLE.m4,v 1.16 2011/05/17 17:58:10 schampeo Exp $')
divert(-1)dnl

LOCAL_CONFIG
#------------------------------------------------------------------------
# enemieslist.com X-MimeOLE: header check patterns and call
#------------------------------------------------------------------------
HX-MimeOLE: $>EL_Check_Header_XMimeOLE

LOCAL_RULESETS
#------------------------------------------------------------------------
# enemieslist.com X-MimeOLE header checks
#------------------------------------------------------------------------
SEL_Check_Header_XMimeOLE
ifdef(`_EL_TRACE', `dnl
R$*					$: $1 $(EL_Log "XMimeOLE w/ " $1 "; score: " $&{ELSuspiciousCount} "." $)
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

