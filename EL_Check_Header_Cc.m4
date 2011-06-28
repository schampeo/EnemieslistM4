divert(-1)dnl
#
# Copyright (c) 2004-2011 hesketh.com/inc. All rights reserved.

# See the file LICENSE in the distribution for details.

#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_Check_Header_Cc.m4,v 1.22 2011/05/17 19:21:11 schampeo Exp $')
divert(-1)dnl

LOCAL_CONFIG
#------------------------------------------------------------------------
# enemieslist.com Cc: header check patterns and call
#------------------------------------------------------------------------
HCc: $>EL_Check_Header_Cc

ifdef(`_EL_SAMEADDRTWICE', `dnl
KEL_CcSameAddressTwice regex -f -a@SPAM ^.*ifdef(`confEL_SameAddressTwice', `confEL_SameAddressTwice', `(steve@champeon.com,\ steve@champeon.com|solutions@hesketh.com,\ solutions@hesketh.com)')

KEL_CcChecks sequence EL_CcSameAddressTwice
')dnl

LOCAL_RULESETS
#------------------------------------------------------------------------
# enemieslist.com Cc header checks
#------------------------------------------------------------------------
SEL_Check_Header_Cc        
ifdef(`_EL_TRACE', `dnl
R$*					$: $1 $(EL_Log "Cc w/ " $1 "; score: " $&{ELSuspiciousCount} "." $)
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

ifdef(`_EL_SAMEADDRTWICE', `dnl
R$*					$: $(EL_CcChecks $&{currHeader} $)
R@SPAM				$#error $@ 5.7.1 $: ifdef(`confEL_ErrCc', `confEL_ErrCc', `"554 BADHDCC Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it contains a suspicious header (Cc:)"')
')dnl

ifdef(`_EL_TOOMANYCCS', `dnl
R$*					$: $(arith + $@ 1 $@ $&{ELCcHeaderCount} $)
R$*					$: $(EL_SetVar {ELCcHeaderCount} $@ $1 $)
ifdef(`_EL_DEBUG', `dnl
R$*					$: $(EL_Log "EL Cc cnt: " $&{ELCcHeaderCount} $)
')dnl
R$*					$: $&{ELCcHeaderCount}
R5					$#error $@ 5.7.1 $: ifdef(`confEL_ErrCcCount', `confEL_ErrCcCount', `"554 FIVECCS Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. Surely, five Cc: headers are enough."')
')dnl

ifdef(`_EL_SPAMTRAP', `dnl
R$*					$: $(EL_GetEmailAddress $&{currHeader} $)
R<$*@$*><ADDR>		$: $>canonify <$1@$2>
R$*@$*<ADDR>		$: $>canonify <$1@$2>
R$*<@$*.>			$: $(EL_Spamtrap $1@$2 $)
ifelse(_EL_POLICY, 1, `dnl
# go ahead and tag the message here so other non-spamtrap recipients know too
R$* 									$: $1 $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
RSPAMTRAP $| $*SPAMTRAP$* $| $+			$: <TAGTRAP>
RSPAMTRAP $| $*SPAMTRAP$* $| TAG		$: <TAGTRAP>
RSPAMTRAP $| $*SPAMTRAP$* $| BLOCK		$: <REJTRAP>
RSPAMTRAP $| $* +SPAMTRAP$* $| ASK		$: <TAGTRAP>
RSPAMTRAP $| $* !SPAMTRAP$* $| ASK		$: <REJTRAP>

RT $| $*SPAMTRAP$* $| $+				$: <TAGTRAP>
RT $| $*SPAMTRAP$* $| TAG				$: <TAGTRAP>
RT $| $*SPAMTRAP$* $| BLOCK				$: <REJTRAP>
RT $| $* +SPAMTRAP$* $| ASK				$: <TAGTRAP>
RT $| $* !SPAMTRAP$* $| ASK				$: <REJTRAP>

RD $| $*SPAMTRAP$* $| TAG				$: <TAGDORM>
RD $| $*SPAMTRAP$* $| BLOCK				$: <REJDORM> 
RD $| $* +SPAMTRAP$* $| ASK				$: <TAGDORM>
RD $| $* !SPAMTRAP$* $| ASK				$: <REJDORM> 

# if no match try default policy
R$* $| $* $| $* 						$: $1 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
RSPAMTRAP $| $*SPAMTRAP$* $| $+			$: <TAGTRAP>
RSPAMTRAP $| $*SPAMTRAP$* $| TAG		$: <TAGTRAP>
RSPAMTRAP $| $*SPAMTRAP$* $| BLOCK		$: <REJTRAP>
RSPAMTRAP $| $* +SPAMTRAP$* $| ASK		$: <TAGTRAP>
RSPAMTRAP $| $* !SPAMTRAP$* $| ASK		$: <REJTRAP>

RT $| $*SPAMTRAP$* $| $+				$: <TAGTRAP>
RT $| $*SPAMTRAP$* $| TAG				$: <TAGTRAP>
RT $| $*SPAMTRAP$* $| BLOCK				$: <REJTRAP>
RT $| $* +SPAMTRAP$* $| ASK				$: <TAGTRAP>
RT $| $* !SPAMTRAP$* $| ASK				$: <REJTRAP>

RD $| $*SPAMTRAP$* $| TAG				$: <TAGDORM>
RD $| $*SPAMTRAP$* $| BLOCK				$: <REJDORM> 
RD $| $* +SPAMTRAP$* $| ASK				$: <TAGDORM>
RD $| $* !SPAMTRAP$* $| ASK				$: <REJDORM> 
', `
RSPAMTRAP								$: <REJTRAP>
RT										$: <REJTRAP>
RD										$: <REJDORM>
')dnl
R<TAGTRAP>				$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgSpamtrap', `confEL_TagErrMsgSpamtrap', `"Message addressed to a known spamtrap"')> $| 5
R<REJTRAP>				$#error $@ 5.7.1 $: ifdef(`confEL_ErrCc', `confEL_ErrCc', `"554 GO_AWAY Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as unsolicited bulk/commercial mail. (Cc)"')
R<REJDORM>				$#error $@ 5.7.1 $: ifdef(`confEL_ErrSpamtrapDormant', `confEL_ErrSpamtrapDormant', `"550 DORMANT Old unused account / will soon go away for good / you smell bad, spammer"')
')dnl


