divert(-1)dnl
#
# Copyright (c) 2007-2011 hesketh.com/inc. All rights reserved.
#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_Check_Header_XNAISpamFlag.m4,v 1.7 2011/05/17 17:56:12 schampeo Exp $')
divert(-1)dnl

LOCAL_CONFIG
#------------------------------------------------------------------------
# enemieslist.com X-NAI-Spam-Flag header check regexes
#------------------------------------------------------------------------
# check for a certain value in X-NAI-Spam-Flag: header to reject probable
# spam not otherwise rejected by intermediate relay.
KEL_XNAISpamFlag regex -a<YES> YES

LOCAL_RULESETS
#------------------------------------------------------------------------
# enemieslist.com X-NAI-Spam-Flag header check ruleset
#------------------------------------------------------------------------
HX-NAI-Spam-Flag: $>EL_Check_Header_XNAISpamFlag
SEL_Check_Header_XNAISpamFlag
ifdef(`_EL_TRACE', `dnl
R$*					$: $1 $(EL_Log "XNAISpamFlag w/ " $1 "; score: " $&{ELSuspiciousCount} "." $)
')dnl

ifdef(`_EL_SKIPLOCAL', `dnl
R$*					$: $1 $| $&{client_addr}
R$* $| 127.0.0.1	$@
')dnl

# skip whitelisted hosts
R$*					$: $&{ELWhitelisted}
R$+:$+				$@

ifdef(`_EL_POLICY', `dnl
R$*							$: $(EL_XNAISpamFlag $&{currHeader} $)
R$+<YES> 					$#error $@ 5.7.1 $: ifdef(`confEL_ErrXNAISpamFlag', `confEL_ErrXNAISpamFlag', `"554 XNAISPM Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam (should have been rejected by relay)."')
')dnl
