divert(-1)dnl
#
# Copyright (c) 2004-2011 hesketh.com/inc. All rights reserved.
#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_Check_Header_XApparentlyFrom.m4,v 1.12 2011/05/17 18:12:59 schampeo Exp $')
divert(-1)dnl

LOCAL_CONFIG
#------------------------------------------------------------------------
# enemieslist.com X-Apparently-From: header check pattern and call
#------------------------------------------------------------------------
HX-Apparently-From: $>EL_Check_Header_XApparentlyFrom

KEL_XApparentlyFrom regex -a@SPAM ERR_USER_NULL

LOCAL_RULESETS
#------------------------------------------------------------------------
# enemieslist.com X-Apparently-From: header checks
#------------------------------------------------------------------------
SEL_Check_Header_XApparentlyFrom
ifdef(`_EL_TRACE', `dnl
R$*					$: $1 $(EL_Log "XApparentlyFrom w/ " $1 "; score: " $&{ELSuspiciousCount} "." $)
')dnl

ifdef(`_EL_SKIPLOCAL', `dnl
R$*					$: $1 $| $&{client_addr}
R$* $| 127.0.0.1	$@
')dnl

# skip whitelisted hosts
R$*				$: $&{ELWhitelisted}
R$+:$+			$@

ifdef(`_EL_B0RKEN', `dnl
R$*					$: $(EL_B0rkenRatware $&{currHeader} $)
R@SPAM				$#error $@ 5.7.1 $: ifdef(`confEL_ErrB0rkenRatware', `confEL_ErrB0rkenRatware', `"554 B0RKENR Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it appears to have been sent by laughably broken spam software."')
')dnl

R$*					$: $(EL_XApparentlyFrom $&{currHeader} $) $| $&{INHEADERS}
R@SPAM $| YES		$#error $@ 5.7.1 $: ifdef(`confEL_ErrXApparentlyFrom', `confEL_ErrXApparentlyFrom', `"554 BDHDXAF Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it contains a suspicious header. (X-Apparently-From)"')
