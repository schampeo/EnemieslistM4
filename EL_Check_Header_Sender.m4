divert(-1)dnl
#
# Copyright (c) 2004-2011 hesketh.com/inc. All rights reserved.

# See the file LICENSE in the distribution for details.

#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_Check_Header_Sender.m4,v 1.23 2011/05/17 18:29:35 schampeo Exp $')
divert(-1)dnl

LOCAL_CONFIG
#------------------------------------------------------------------------
# enemieslist.com Sender: header check patterns
#------------------------------------------------------------------------
KEL_SenderBogusISO regex -a@SPAM ^.*=\?UNKNOWN\?

KEL_SenderHibit regex -m -b -f -a<HIBIT> ^.*[€-ÿ].*

KEL_SenderStormUser regex -a<STORM> -f ^\"?User\ [a-z]{3,15}\"?\s\<

KEL_SenderChecks sequence EL_SenderBogusISO EL_SenderHibit

LOCAL_RULESETS
#------------------------------------------------------------------------
# enemieslist.com Sender: header checks
#------------------------------------------------------------------------
HSender: $>EL_Check_Header_Sender
SEL_Check_Header_Sender
ifdef(`_EL_TRACE', `dnl
R$*					$: $1 $(EL_Log "Sender w/ " $1 "; score: " $&{ELSuspiciousCount} "." $)
')dnl

ifdef(`_EL_SKIPLOCAL', `dnl
R$*					$: $1 $| $&{client_addr}
R$* $| 127.0.0.1	$@
')dnl

# skip whitelisted hosts
R$*				$: $&{ELWhitelisted}
R$+:$+			$@

# catch one Storm variant
R$*					$: $(EL_SenderStormUser $&{currHeader} $)
R<STORM>			$#error $@ 5.7.1 $: ifdef(`confEL_ErrStormVirus', `confEL_ErrStormVirus', `"554 STVIRUS Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it appears to have been sent by the Storm virus."')

ifdef(`_EL_B0RKEN', `dnl
R$*					$: $(EL_B0rkenRatware $&{currHeader} $)
R@SPAM				$#error $@ 5.7.1 $: ifdef(`confEL_ErrB0rkenRatware', `confEL_ErrB0rkenRatware', `"554 B0RKENR Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it appears to have been sent by laughably broken spam software."')
')dnl

R$*					$: $(EL_SenderChecks $&{currHeader} $)
R@SPAM				$#error $@ 5.7.1 $: ifdef(`confEL_ErrSender', `confEL_ErrSender', `"554 BADSEND Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it contains a suspicious header (Sender:)"')

R<HIBIT>			$#error $@ 5.7.1 $: ifdef(`confEL_ErrSenderHibit', `confEL_ErrSenderHibit', `"554 SENDHIB Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it contains a suspicious header (Sender:) (hibit)"')

ifdef(`_EL_DOMAIN_BLACKLIST', `dnl
R$*					$: $(EL_GetEmailAddress $&{currHeader} $)
R<$*@$*><ADDR>		$: $>canonify <$1@$2>
R$*@$*<ADDR>		$: $>canonify <$1@$2>
R$*<@$*.$-.$-.$-.>	$: $(EL_DomainBlacklist $3.$4.$5 $)
R$*<@$*.$-.$-.$->	$: $(EL_DomainBlacklist $3.$4.$5 $)
R$*<@$*.$-.$-.>		$: $(EL_DomainBlacklist $3.$4 $)
R$*<@$*.$-.$->		$: $(EL_DomainBlacklist $3.$4 $)
R$*<@$*.$-.>		$: $(EL_DomainBlacklist $2.$3 $)
R$*<@$*.$->			$: $(EL_DomainBlacklist $2.$3 $)
R$*<@$*.>			$: $(EL_DomainBlacklist $2 $)
R$*<@$*>			$: $(EL_DomainBlacklist $2 $)

ifelse(_EL_POLICY, 1, `dnl
R$-					$: $1 $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
RSPAMMER $| $*DOMAINSBL$* $| TAG			$: <TAGDOMAINSBL>
RSPAMMER $| $*DOMAINSBL$* $| BLOCK			$: <REJDOMAINSBL>
RSPAMMER $| $* +DOMAINSBL$* $| ASK			$: <TAGDOMAINSBL>
RSPAMMER $| $* -DOMAINSBL$* $| ASK			$: <REJDOMAINSBL>
RS $| $*DOMAINSBL$* $| TAG					$: <TAGDOMAINSBL>
RS $| $*DOMAINSBL$* $| BLOCK				$: <REJDOMAINSBL>
RS $| $* +DOMAINSBL$* $| ASK				$: <TAGDOMAINSBL>
RS $| $* -DOMAINSBL$* $| ASK				$: <REJDOMAINSBL>

# if no match try default policy
R$* $| $* $| $* 							$: $1 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
RSPAMMER $| $*DOMAINSBL$* $| TAG			$: <TAGDOMAINSBL>
RSPAMMER $| $*DOMAINSBL$* $| BLOCK			$: <REJDOMAINSBL>
RSPAMMER $| $* +DOMAINSBL$* $| ASK			$: <TAGDOMAINSBL>
RSPAMMER $| $* -DOMAINSBL$* $| ASK			$: <REJDOMAINSBL>
RS $| $*DOMAINSBL$* $| TAG					$: <TAGDOMAINSBL>
RS $| $*DOMAINSBL$* $| BLOCK				$: <REJDOMAINSBL>
RS $| $* +DOMAINSBL$* $| ASK				$: <TAGDOMAINSBL>
RS $| $* -DOMAINSBL$* $| ASK				$: <REJDOMAINSBL>

R<TAGDOMAINSBL>								$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgSenderBL', `confEL_TagErrMsgSenderBL', `"message sender from domain in local blacklist"')> $| 4
R<REJDOMAINSBL>								$#error $@ 5.7.1 $: ifdef(`confEL_ErrSenderSpammerDomain', `confEL_ErrSenderSpammerDomain', `"554 SENDSPM Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. We do not accept mail sent from your domain."')
', `dnl
RSPAMMER			$#error $@ 5.7.1 $: ifdef(`confEL_ErrSenderSpammerDomain', `confEL_ErrSenderSpammerDomain', `"554 SENDSPM Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. We do not accept mail sent from your domain."')
RS					$#error $@ 5.7.1 $: ifdef(`confEL_ErrSenderSpammerDomain', `confEL_ErrSenderSpammerDomain', `"554 SENDSPM Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. We do not accept mail sent from your domain."')
')dnl
')dnl
