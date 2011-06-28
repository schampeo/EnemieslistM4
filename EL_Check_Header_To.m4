divert(-1)dnl
#
# Copyright (c) 2004-2011 hesketh.com/inc. All rights reserved.

# See the file LICENSE in the distribution for details.

#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_Check_Header_To.m4,v 1.30 2011/05/26 13:28:28 schampeo Exp $')
divert(-1)dnl

define(`_EL_CHECK_TO', `1')

LOCAL_CONFIG
#------------------------------------------------------------------------
# enemieslist.com To: header check patterns and call
#------------------------------------------------------------------------
HTo: $>EL_Check_Header_To

# currently disabled
KEL_ToBlank regex -f -a@SPAM ^$
KEL_ToNullSender regex -f -a@SPAM ^.*<>

KEL_ToUSResidents regex -f -a@SPAM ^.*U\.S\.\ Residents

KEL_ToAPineMessageID regex -a@SPAM ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[0-9]+\.[0-f]+@

KEL_ToASendmailMessageID regex -f -a@SPAM ^[0-9]{11,}\.[a-z]{3}[0-9]{5}

KEL_ToVariousCommonSpamAddresses regex -f -a@SPAM ^\ <(DirectTraffic|Friends|InvestorAwareness|Online\.Trades|Online\ Trades|Subscribed)@

ifdef(`_EL_SAMEADDRTWICE', `dnl
KEL_ToSameAddressTwice regex -f -a@SPAM ^.*ifdef(`confEL_SameAddressTwice', `confEL_SameAddressTwice', `(steve@champeon.com,\ steve@champeon.com|solutions@hesketh.com,\ solutions@hesketh.com)')
')dnl

# stop cialis/viagra spammers - they never put brackets around their To:
# addresses, and lack a space between the quoted part and localpart in From:
KEL_UnbracketedTo regex -f -a_SPAMSIGN_ ^\ *[a-z]+@[a-z]+

# certain phishing scams have been seen with "\r" (not the character, just
# the escaped r) in the To: 
KEL_ToCarriageReturn regex -f -a@SPAM \\r\"

KEL_ToUndisclosedRecipients regex -f -a<NO> Undisclosed\-Recipients?

KEL_ToChecks sequence EL_ToUSResidents EL_ToAPineMessageID EL_ToASendmailMessageID EL_ToVariousCommonSpamAddresses ifdef(`_EL_SAMEADDRTWICE', `EL_ToSameAddressTwice') ifdef(`_EL_MILLIONSFORGERY', `EL_ToMillionsCD') EL_ToCarriageReturn

LOCAL_RULESETS
#------------------------------------------------------------------------
# enemieslist.com To header checks
#------------------------------------------------------------------------
SEL_Check_Header_To
ifdef(`_EL_TRACE', `dnl
R$*					$: $1 $(EL_Log "To w/ " $1 "; score: " $&{ELSuspiciousCount} "." $)
')dnl

# set our header-tracker
R$*					$: $(EL_Math + $@ 8 $@ $&{ELHasHeader} $)
R$*					$: $(EL_SetVar {ELHasHeader} $@ $1 $)
R$*					$: $(EL_Log "ELHasHeader (to): " $&{ELHasHeader} $)

ifdef(`_EL_SKIPLOCAL', `dnl
R$*					$: $1 $| $&{client_addr}
R$* $| 127.0.0.1	$@
')dnl

# skip whitelisted hosts
R$*					$: $&{ELWhitelisted}
R$+:$+				$@

# ??? should also check to see if we are archiving spamtraps here before
# ??? we start rejecting recognizable message-ids, others.

# check against our known spam signatures
R$*					$: $(EL_ToChecks $&{currHeader} $)
R@SPAM				$#error $@ 5.7.1 $: ifdef(`confEL_ErrTo', `confEL_ErrTo', `"554 BADHDTO Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it contains a suspicious header (To:)"')

# check for cialis/viagra spammers
R$*							$: $(EL_UnbracketedTo $&{currHeader} $) $| $(EL_FromCialis $&{ELHeaderFrom} $)
R_SPAMSIGN_ $| _SPAMSIGN_	$#error $@ 5.7.1 $: ifdef(`confEL_ErrToFromCialis', `confEL_ErrToFromCialis', `"554 TO_FROM Contact "$&{ELContactEmail}" if this is in error, but your message was rejected; it seems to be spam (To/From)"')

# check for persistent and annoying managementchile.cl seminar spammers
# they send to "Undisclosed-Recipient" via gmail.
R$*						$: $(EL_ToUndisclosedRecipients $&{currHeader} $) $| $&{client_name}
R<NO> $| $+.gmail.com	$: $>EL_TagSuspicious <"probably managementchile.cl spammers"> $| 2


# temporary rule to catch pump and dump scammers; CS4 defined in EL_CH_From
R$*					$: $(EL_CommonSubstrings4 $&{currHeader} $)
R@SPAM				$#error $@ 5.7.1 $: ifdef(`confEL_ErrTo', `confEL_ErrTo', `"554 BADHDTO Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it contains a suspicious header (To:)"')

ifdef(`_EL_B0RKEN', `dnl
R$*					$: $(EL_B0rkenRatware $&{currHeader} $)
R@SPAM				$#error $@ 5.7.1 $: ifdef(`confEL_ErrB0rkenRatware', `confEL_ErrB0rkenRatware', `"554 B0RKENR Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it appears to have been sent by laughably broken spam software."')
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
R<TAGTRAP>								$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgSpamtrap', `confEL_TagErrMsgSpamtrap', `"Message addressed to a known spamtrap"')> $| 5
R<REJTRAP>				$#error $@ 5.7.1 $: ifdef(`confEL_ErrToSpamtrap', `confEL_ErrToSpamtrap', `"554 GO_AWAY Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as unsolicited bulk/commercial mail. (To)"')
R<REJDORM>				$#error $@ 5.7.1 $: ifdef(`confEL_ErrSpamtrapDormant', `confEL_ErrSpamtrapDormant', `"550 DORMANT Old unused account / will soon go away for good / you smell bad, spammer"')
')dnl

ifdef(`_EL_DOMAIN_BLACKLIST', `dnl
# reject all blacklisted hosts
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
RSPAMMER $| $* !DOMAINSBL$* $| ASK			$: <REJDOMAINSBL>

RS $| $*DOMAINSBL$* $| TAG					$: <TAGDOMAINSBL>
RS $| $*DOMAINSBL$* $| BLOCK				$: <REJDOMAINSBL>
RS $| $* +DOMAINSBL$* $| ASK				$: <TAGDOMAINSBL>
RS $| $* !DOMAINSBL$* $| ASK				$: <REJDOMAINSBL>

# if no match try default policy
R$* $| $* $| $* 							$: $1 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
RSPAMMER $| $*DOMAINSBL$* $| TAG			$: <TAGDOMAINSBL>
RSPAMMER $| $*DOMAINSBL$* $| BLOCK			$: <REJDOMAINSBL>
RSPAMMER $| $* +DOMAINSBL$* $| ASK			$: <TAGDOMAINSBL>
RSPAMMER $| $* !DOMAINSBL$* $| ASK			$: <REJDOMAINSBL>

RS $| $*DOMAINSBL$* $| TAG					$: <TAGDOMAINSBL>
RS $| $*DOMAINSBL$* $| BLOCK				$: <REJDOMAINSBL>
RS $| $* +DOMAINSBL$* $| ASK				$: <TAGDOMAINSBL>
RS $| $* !DOMAINSBL$* $| ASK				$: <REJDOMAINSBL>
',`dnl
RSPAMMER									$: <REJDOMAINSBL>
RS											$: <REJDOMAINSBL>
')dnl
R<TAGDOMAINSBL>								$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgToBL', `confEL_TagErrMsgToBL', `"message sent to domain in local blacklist"')> $| 4
R<REJDOMAINSBL>								$#error $@ 5.7.1 $: ifdef(`confEL_ErrToDomainBlacklist', `confEL_ErrToDomainBlacklist', `"550 TDOMAIN Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail sent to users in your domain."')
')dnl
