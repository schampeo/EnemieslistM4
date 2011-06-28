divert(-1)dnl
#
# Copyright (c) 2004-2011 hesketh.com/inc. All rights reserved.
#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_Check_Header_ErrorsTo.m4,v 1.25 2011/05/17 19:07:07 schampeo Exp $')
divert(-1)dnl

LOCAL_CONFIG
#------------------------------------------------------------------------
# enemieslist.com Errors-To: header check patterns
# note: this is to block specific virus-infected morons; edit to suit
# n.b. #2: the address shown is not the address of the infected moron.
# n.b. #3: removed 6/2/2004 as it appears to have been fixed.
#------------------------------------------------------------------------
#KEL_BadErrorsTo regex -a@VIRUS ^.*lpalmeri@conceptscdpap\.org

LOCAL_RULESETS
#------------------------------------------------------------------------
# enemieslist.com Errors-To: header check patterns
#------------------------------------------------------------------------
HErrors-To: $>EL_Check_Header_ErrorsTo
SEL_Check_Header_ErrorsTo
ifdef(`_EL_TRACE', `dnl
R$*					$: $1 $(EL_Log "ErrorsTo w/ " $1 "; score: " $&{ELSuspiciousCount} "." $)
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
', `dnl
RSPAMMER									$: <REJDOMAINSBL>
RS											$: <REJDOMAINSBL>
')dnl
R<TAGDOMAINSBL>								$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgErrorsToBL', `confEL_TagErrMsgErrorsToBL', `"message errors-to header contains domain in local blacklist"')> $| 4
R<REJDOMAINSBL>								$#error $@ 5.7.1 $: ifdef(`confEL_ErrErrorsToSpammerDomain', `confEL_ErrErrorsToSpammerDomain', `"554 ERSTOBL Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. We do not accept mail with a Errors-To: header containing your domain."')
')dnl
