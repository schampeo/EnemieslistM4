divert(-1)dnl
#
# Copyright (c) 2005-2011 hesketh.com/inc. All rights reserved.

# See the file LICENSE in the distribution for details.

#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_Check_Header_XSpamDetect.m4,v 1.10 2011/05/17 17:48:57 schampeo Exp $')
divert(-1)dnl

LOCAL_CONFIG
#------------------------------------------------------------------------
# enemieslist.com X-Spam-Detect header check regexes
#------------------------------------------------------------------------
# check for a certain value in X-Spam-Detect: header to reject probable
# spam not otherwise rejected by intermediate relay.
KEL_XSpamDetect regex -a<YES> -s1 :.([0-9]+\.[0-9]+)\ .*

LOCAL_RULESETS
#------------------------------------------------------------------------
# enemieslist.com X-Spam-Detect header check ruleset
#------------------------------------------------------------------------
HX-Spam-Detect: $>EL_Check_Header_XSpamDetect
SEL_Check_Header_XSpamDetect
ifdef(`_EL_TRACE', `dnl
R$*					$: $1 $(EL_Log "XSpamDetect w/ " $1 "; score: " $&{ELSuspiciousCount} "." $)
')dnl

ifdef(`_EL_SKIPLOCAL', `dnl
R$*					$: $1 $| $&{client_addr}
R$* $| 127.0.0.1	$@
')dnl

# skip whitelisted hosts
R$*					$: $&{ELWhitelisted}
R$+:$+				$@

ifdef(`_EL_POLICY', `dnl
R$*							$: $(EL_XSpamDetect $&{currHeader} $) $| $&{ELPolicyUser}
R$+<YES> $| $*TRUSTSD:$-$*	$: $(EL_Math l $@ $1 $@ $3 $) $(EL_Log "X-Spam-Detect check: "$1"/"$3 $)

# if no match try default policy
R$* $| $* 					$: $1 $| $(EL_Policy default $)
R$+<YES> $| $*TRUSTSD:$-$*	$: $(EL_Math l $@ $1 $@ $3 $) $(EL_Log "X-Spam-Detect check: "$1"/"$3 $)

RFALSE						$#error $@ 5.7.1 $: ifdef(`confEL_ErrXSpamDetect', `confEL_ErrXSpamDetect', `"554 XSPMDTC Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam (should have been rejected by relay)."')
')dnl
