divert(-1)dnl
#
# Copyright (c) 2004-2011 hesketh.com/inc. All rights reserved.
#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_Check_Header_ReplyTo.m4,v 1.27 2011/05/17 18:32:15 schampeo Exp $')
divert(-1)dnl

LOCAL_CONFIG
#------------------------------------------------------------------------
# enemieslist.com Reply-To: header check patterns
# note: edit this to check for locally originating mail that never has a
# Reply-To: header set.
#------------------------------------------------------------------------
KEL_ReplyToBlank1 regex -aMATCH ^$
KEL_ReplyToAlmostEmpty regex -aMATCH ^\.$
KEL_ReplyToBlank sequence EL_ReplyToBlank1 EL_ReplyToAlmostEmpty

KEL_ReplyToNull regex -aMATCH ^\ ?\<\>$

# ??? bug: needs to be m4-configurable
KEL_ReplyToForged regex -aMATCH ^.*\"\"\ <schampeo@hesketh.com

KEL_ReplyToChecks sequence EL_ReplyToBlank EL_ReplyToForged EL_ReplyToNull

LOCAL_RULESETS
#------------------------------------------------------------------------
# enemieslist.com Reply-To: header checks
#------------------------------------------------------------------------
HReply-To: $>EL_Check_Header_ReplyTo
SEL_Check_Header_ReplyTo
ifdef(`_EL_TRACE', `dnl
R$*					$: $1 $(EL_Log "ReplyTo w/ " $1 "; score: " $&{ELSuspiciousCount} "." $)
')dnl

ifdef(`_EL_SKIPLOCAL', `dnl
R$*					$: $1 $| $&{client_addr}
R$* $| 127.0.0.1	$@
')dnl

# skip whitelisted hosts
R$*				$: $&{ELWhitelisted}
R$+:$+			$@

ifdef(`_EL_SETTECLTD', `dnl
# settecltd / link.net conference spammers
# this comes before domain blacklist check because we really do not want
# their mail, ever.
R$*						$: $&{currHeader} 
R$*@settecltd.com		$#error $@ 5.7.1 $: ifdef(`confEL_ErrReplyToSpammerDomain', `confEL_ErrReplyToSpammerDomain', `"554 RTOSPAM Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. We do not accept mail containing a Reply-To: from your domain."')
')dnl

R$*						$: $(EL_ReplyToChecks $&{currHeader} $)
RMATCH					$#error $@ 5.7.1 $: ifdef(`confEL_ErrReplyTo', `confEL_ErrReplyTo', `"554 REPLYTO Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it contains a suspicious header (Reply-To:)"')

ifdef(`_EL_B0RKEN', `dnl
R$*					$: $(EL_B0rkenRatware $&{currHeader} $)
R@SPAM				$#error $@ 5.7.1 $: ifdef(`confEL_ErrB0rkenRatware', `confEL_ErrB0rkenRatware', `"554 B0RKENR Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it appears to have been sent by laughably broken spam software."')
')dnl

ifdef(`_EL_GENERIC_419', `dnl
R$*							$: $(EL_Generic419Sender $&{currHeader} $) $| $(EL_Offwhitelist $&{client_name} $) $| $&{INHEADERS}
ifelse(_EL_POLICY, 1, `dnl
R<AFF> $| 419 $| YES		$: $&{ELPolicyUser} $| $&{ELPolicySwitch}
R<AFF> $| O $| YES			$: $&{ELPolicyUser} $| $&{ELPolicySwitch}
R$* GEN419 $* $| TAG		$: <TAGGEN419>
R$* GEN419 $* $| BLOCK		$: <REJGEN419>
R$* +GEN419 $* $| ASK		$: <TAGGEN419>
R$* !GEN419 $* $| ASK		$: <REJGEN419>

# if no match try default policy
R$*							$: $(EL_Generic419Sender $&{currHeader} $) $| $(EL_Offwhitelist $&{client_name} $) $| $&{INHEADERS}
R<AFF> $| 419 $| YES		$: $(EL_Policy default $) $| $&{ELPolicySwitch}
R<AFF> $| O $| YES			$: $(EL_Policy default $) $| $&{ELPolicySwitch}
R$* GEN419 $* $| TAG		$: <TAGGEN419>
R$* GEN419 $* $| BLOCK		$: <REJGEN419>
R$* +GEN419 $* $| ASK		$: <TAGGEN419>
R$* !GEN419 $* $| ASK		$: <REJGEN419>
',`
R<AFF> $| 419 $| YES		$: <TAGGEN419>
')dnl

R<TAGGEN419>				$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgGeneric419', `confEL_TagErrMsgGeneric419', `"probably 419/advanced fee fraud scam mail"')> $| 0
R<REJGEN419>				$#error $@ 5.7.1 $: ifdef(`confEL_ErrGeneric419', `confEL_ErrGeneric419', `"554 GEN419 Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as a likely advance fee fraud."')
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
R$-											$: $1 $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
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

R<TAGDOMAINSBL>								$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgReplyToBL', `confEL_TagErrMsgReplyToBL', `"message reply-to header contains domain in local blacklist"')> $| 4
R<REJDOMAINSSBL>							$#error $@ 5.7.1 $: ifdef(`confEL_ErrReplyToSpammerDomain', `confEL_ErrReplyToSpammerDomain', `"554 RTOSPAM Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. We do not accept mail containing a Reply-To: from your domain."')
', `dnl
RSPAMMER			$#error $@ 5.7.1 $: ifdef(`confEL_ErrReplyToSpammerDomain', `confEL_ErrReplyToSpammerDomain', `"554 RTOSPAM Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. We do not accept mail containing a Reply-To: from your domain."')
RS					$#error $@ 5.7.1 $: ifdef(`confEL_ErrReplyToSpammerDomain', `confEL_ErrReplyToSpammerDomain', `"554 RTOSPAM Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. We do not accept mail containing a Reply-To: from your domain."')
')dnl
')dnl

ifdef(`_EL_CHECK_URIBL_DOMAIN', `dnl
R$*					$: $(EL_GetEmailAddress $&{currHeader} $)
R<$*@$*><ADDR>		$: $>canonify <$1@$2>
R$*@$*<ADDR>		$: $>canonify <$1@$2>
R$*<@$*.$-.$-.$-.>	$: <?> $(dnsbl $3.$4.$5.black.uribl.com. $: OK $)
R$*<@$*.$-.$-.$->	$: <?> $(dnsbl $3.$4.$5.black.uribl.com. $: OK $)
R$*<@$*.$-.$-.>		$: <?> $(dnsbl $3.$4.black.uribl.com. $: OK $)
R$*<@$*.$-.$->		$: <?> $(dnsbl $3.$4.black.uribl.com. $: OK $)
R$*<@$*.$-.>		$: <?> $(dnsbl $2.$3.black.uribl.com. $: OK $)
R$*<@$*.$->			$: <?> $(dnsbl $2.$3.black.uribl.com. $: OK $)
R$*<@$*.>			$: <?> $(dnsbl $2.black.uribl.com. $: OK $)
R$*<@$*>			$: <?> $(dnsbl $2.black.uribl.com. $: OK $)

ifelse(_EL_POLICY, 1, `dnl
# need to check for DNS lookup failures here
R<?>OK				$: OKSOFAR
R<?>$+<TMP>			$: TMPOK
R<?>$+				$: $1 $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
R$+ $| $*URIBL$* $| TAG			$: <TAGURIBL>
R$+ $| $*URIBL$* $| BLOCK		$: <REJURIBL>
R$+ $| $* +URIBL$* $| ASK		$: <TAGURIBL>
R$+ $| $* !URIBL$* $| ASK		$: <REJURIBL>

# if no match try default policy
R$* $| $* $| $* 				$: $1 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
R$+ $| $*URIBL$* $| TAG			$: <TAGURIBL>
R$+ $| $*URIBL$* $| BLOCK		$: <REJURIBL>
R$+ $| $* +URIBL$* $| ASK		$: <TAGURIBL>
R$+ $| $* !URIBL$* $| ASK		$: <REJURIBL>

R<TAGURIBL>						$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgReplyToURIBL', `confEL_TagErrMsgReplyToURIBL', `"message reply-to header contains domain in uribl.com blacklist"')> $| 4
R<REJURIBL>						$#error $@ 5.7.1 $: ifdef(`confEL_ErrReplyToURIBL', `confEL_ErrReplyToURIBL', `"554 URIBLRT Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. We do not accept mail containing a Reply-To: from your domain as it is listed by uribl.com."')
')dnl
')dnl

ifdef(`_EL_CHECK_SURBL_DOMAIN', `dnl
R$*					$: $(EL_GetEmailAddress $&{currHeader} $)
R<$*@$*><ADDR>		$: $>canonify <$1@$2>
R$*@$*<ADDR>		$: $>canonify <$1@$2>
R$*<@$*.$-.$-.$-.>	$: <?> $(dnsbl $3.$4.$5.multi.surbl.org. $: OK $)
R$*<@$*.$-.$-.$->	$: <?> $(dnsbl $3.$4.$5.multi.surbl.org. $: OK $)
R$*<@$*.$-.$-.>		$: <?> $(dnsbl $3.$4.multi.surbl.org. $: OK $)
R$*<@$*.$-.$->		$: <?> $(dnsbl $3.$4.multi.surbl.org. $: OK $)
R$*<@$*.$-.>		$: <?> $(dnsbl $2.$3.multi.surbl.org. $: OK $)
R$*<@$*.$->			$: <?> $(dnsbl $2.$3.multi.surbl.org. $: OK $)
R$*<@$*.>			$: <?> $(dnsbl $2.multi.surbl.org. $: OK $)
R$*<@$*>			$: <?> $(dnsbl $2.multi.surbl.org. $: OK $)

ifelse(_EL_POLICY, 1, `dnl
# need to check for DNS lookup failures here
R<?>OK				$: OKSOFAR
R<?>$+<TMP>			$: TMPOK
R<?>$+				$: $1 $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
R$+ $| $*SURBL$* $| TAG			$: <TAGSURBL>
R$+ $| $*SURBL$* $| BLOCK		$: <REJSURBL>
R$+ $| $* +SURBL$* $| ASK		$: <TAGSURBL>
R$+ $| $* !SURBL$* $| ASK		$: <REJSURBL>

# if no match try default
R$* $| $* $| $* 				$: $1 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
R$+ $| $*SURBL$* $| TAG			$: <TAGSURBL>
R$+ $| $*SURBL$* $| BLOCK		$: <REJSURBL>
R$+ $| $* +SURBL$* $| ASK		$: <TAGSURBL>
R$+ $| $* !SURBL$* $| ASK		$: <REJSURBL>

R<TAGSURBL>						$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgReplyToSURBL', `confEL_TagErrMsgReplyToSURBL', `"message reply-to header contains domain in surbl.org blacklist"')> $| 4
R<REJSURBL>						$#error $@ 5.7.1 $: ifdef(`confEL_ErrReplyToSURBL', `confEL_ErrReplyToSURBL', `"554 SURBLRT Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. We do not accept mail containing a Reply-To: from your domain as it is listed by surbl.org."')
')dnl
')dnl
