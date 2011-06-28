divert(-1)dnl
#
# Copyright (c) 2005-2011 hesketh.com/inc. All rights reserved.
#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_Check_Header_XAntiAbuse.m4,v 1.12 2011/05/17 18:15:54 schampeo Exp $')
divert(-1)dnl

LOCAL_CONFIG
#------------------------------------------------------------------------
# enemieslist.com X-AntiAbuse: header ruleset call (phishing test)
#------------------------------------------------------------------------
HX-AntiAbuse: $>EL_Check_Header_XAntiAbuse

LOCAL_RULESETS
#------------------------------------------------------------------------
# enemieslist.com X-AntiAbuse: header checks
#------------------------------------------------------------------------
SEL_Check_Header_XAntiAbuse
ifdef(`_EL_TRACE', `dnl
R$*					$: $1 $(EL_Log "XAntiAbuse w/ " $1 "; score: " $&{ELSuspiciousCount} "." $)
')dnl

ifdef(`_EL_SKIPLOCAL', `dnl
R$*					$: $1 $| $&{client_addr}
R$* $| 127.0.0.1	$@
')dnl

# skip whitelisted hosts
R$*					$: $&{ELWhitelisted}
R$+:$+				$@

ifdef(`_EL_PHISH', `dnl
R$*					$: $(EL_PhishFromDomains $&{mail_addr} $) 
RPHISH				$>EL_TagSuspicious <ifdef(`confEL_TagErrMsgLikelyPhish', `confEL_TagErrMsgLikelyPhish', `"probable phish attempt"')> $| 3

# ??? quick hack to test the concept. if it works we will need to add all
# the NOBANK checks and so forth.
R$*					$: $(EL_PhishMailFromLocalparts $&{mail_addr} $) $| $(EL_Math & $@ 64 $@ $&{ELSpamsign} $) 
RPHISH $| 64		$>EL_TagSuspicious <ifdef(`confEL_TagErrMsgLikelyPhish', `confEL_TagErrMsgLikelyPhish', `"probable phish attempt"')> $| 3

')dnl

