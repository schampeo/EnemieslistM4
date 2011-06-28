divert(-1)dnl
#
# Copyright (c) 2004-2011 hesketh.com/inc. All rights reserved.

# See the file LICENSE in the distribution for details.

#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_Check_Header_ContentID.m4,v 1.17 2011/05/17 19:15:49 schampeo Exp $')
divert(-1)dnl

LOCAL_CONFIG
#------------------------------------------------------------------------
# enemieslist.com Content-Id: header check patterns and call
#------------------------------------------------------------------------
HContent-Id: $>EL_Check_Header_ContentID

KEL_ContentIdVirus regex -a@VIRUS ^.*<[a-z]+>$

KEL_ContentIdPillPushers regex -a<MATCH> ^\ ?[a-z]{19}$

KEL_ContentIdChecks sequence EL_ContentIdVirus

LOCAL_RULESETS
#------------------------------------------------------------------------
# enemieslist.com Content-ID header checks
#------------------------------------------------------------------------
SEL_Check_Header_ContentID
ifdef(`_EL_TRACE', `dnl
R$*					$: $1 $(EL_Log "ContentID w/ " $1 "; score: " $&{ELSuspiciousCount} "." $)
')dnl

ifdef(`_EL_SKIPLOCAL', `dnl
R$*					$: $1 $| $&{client_addr}
R$* $| 127.0.0.1	$@
')dnl

# skip whitelisted hosts
R$*					$: $&{ELWhitelisted}
R$+:$+				$@

R$*					$: $(EL_ContentIdChecks $&{currHeader} $)
R@VIRUS				$#error $@ 5.7.1 $: ifdef(`confEL_ErrContentID', `confEL_ErrContentID', `"554 BDHDCID Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as a possible virus; it contains a suspicious header (Content-Id)."')

R$*					$: $(EL_ContentIdPillPushers $&{currHeader} $) $| $&{INHEADERS}
R<MATCH> $| NO		$#error $@ 5.7.1 $: ifdef(`confEL_ErrContentIDSpam', `confEL_ErrContentIDSpam', `"554 BHDCIDS Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as a probable spam; it contains a suspicious header."')
