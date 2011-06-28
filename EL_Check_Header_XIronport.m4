divert(-1)dnl
#
# Copyright (c) 2006-2011 hesketh.com/inc. All rights reserved.
#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_Check_Header_XIronport.m4,v 1.8 2011/05/17 18:07:17 schampeo Exp $')dnl
divert(-1)dnl

LOCAL_CONFIG
#------------------------------------------------------------------------
# enemieslist.com X-IronPort-Anti-Spam-Filtered: header check pattern and call
#------------------------------------------------------------------------
HX-IronPort-Anti-Spam-Filtered: $>EL_Check_Header_XIronport

KEL_XIronportTrue regex -a@SPAM true

LOCAL_RULESETS
#------------------------------------------------------------------------
# enemieslist.com X-IronPort-Anti-Spam-Filtered: header checks
#------------------------------------------------------------------------
SEL_Check_Header_XIronport
ifdef(`_EL_TRACE', `dnl
R$*					$: $1 $(EL_Log "XIronport w/ " $1 "; score: " $&{ELSuspiciousCount} "." $)
')dnl

ifdef(`_EL_SKIPLOCAL', `dnl
R$*					$: $1 $| $&{client_addr}
R$* $| 127.0.0.1	$@
')dnl

# skip whitelisted hosts
R$*				$: $&{ELWhitelisted}
R$+:$+			$@

R$*					$: $(EL_XIronportTrue $&{currHeader} $) $| $&{INHEADERS}
R@SPAM $| YES		$#error $@ 5.7.1 $: ifdef(`confEL_ErrXIronport', `confEL_ErrXIronport', `"554 BDHDXIP Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; if Ironport thinks it is spam, so do we."')
