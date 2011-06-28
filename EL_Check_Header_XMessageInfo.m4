divert(-1)dnl
#
# Copyright (c) 2004-2011 hesketh.com/inc. All rights reserved.
#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_Check_Header_XMessageInfo.m4,v 1.16 2011/05/17 17:59:03 schampeo Exp $')
divert(-1)dnl

LOCAL_CONFIG
#------------------------------------------------------------------------
# enemieslist.com X-Message-Info: header check pattern and call
#------------------------------------------------------------------------
HX-Message-Info: $>EL_Check_Header_XMessageInfo

KEL_XMessageInfoGibberish regex -a@SPAM [0-z/]+

LOCAL_RULESETS
#------------------------------------------------------------------------
# enemieslist.com X-Message-Info: header checks
#------------------------------------------------------------------------
SEL_Check_Header_XMessageInfo
ifdef(`_EL_TRACE', `dnl
R$*					$: $1 $(EL_Log "XMessageInfo w/ " $1 "; score: " $&{ELSuspiciousCount} "." $)
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

R$*					$: $(EL_XMessageInfoGibberish $&{currHeader} $) $| $&{INHEADERS}
R@SPAM $| YES		$#error $@ 5.7.1 $: ifdef(`confEL_ErrXMessageInfo', `confEL_ErrXMessageInfo', `"554 BDHDXMI Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it contains a suspicious header. (X-Message-Info)"')
