divert(-1)dnl
#
# Copyright (c) 2004-2011 hesketh.com/inc. All rights reserved.
#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_LocalCheckRcptConfig.m4,v 1.47 2011/05/20 19:59:28 schampeo Exp $')
divert(-1)dnl

LOCAL_CONFIG
#------------------------------------------------------------------------
# enemieslist.com local user policy
#------------------------------------------------------------------------
H?${ELPolicySwitch}?X-EL-User-Policy: ${ELPolicySwitch}
C{persistentMacros} {ELPolicySwitch}

LOCAL_RULESETS
#------------------------------------------------------------------------
# enemieslist.com Local_check_rcpt
# perform various checks on common forgeries, etc.
#------------------------------------------------------------------------
SLocal_check_rcpt
ifdef(`_EL_TRACE', `dnl
R$*					$: $1 $(EL_Log "in Local_check_rcpt w/ " $1 $)
')dnl

R$*					$: $(EL_SetVar {EL_CurrRcpt} $@ $1 $)

# check for deferred delivery mode
R$*					$: < ${deliveryMode} >
R< d >				$@ deferred
R< $* >				$: $&{EL_CurrRcpt}

ifdef(`_EL_WHITELIST', `dnl
# this needs to come before the auth check
H?${ELWhitelisted}?X-EL-Whitelist: sent via whitelisted host ${ELWhitelisted}
C{persistentMacros} {ELWhitelisted}

# check for whitelisted hosts; tag them if they are whitelisted
R$*					$: $&{client_addr}
R$-.$-.$-.$-		$: $(EL_Whitelist $1.$2.$3.$4 $)
R$-.$-.$-.$-		$: $(EL_Whitelist $1.$2.$3 $)
R$-.$-.$-.$-		$: $(EL_Whitelist $1.$2 $)
R$-.$-.$-.$-		$: $(EL_Whitelist $1 $)
ROK					$: $(EL_SetVar {ELWhitelisted} $@ <$&{client_name}:$&{client_addr}> $) 

# accept all whitelisted mail
R$*					$: $&{client_addr}
R$-.$-.$-.$-		$: $(EL_Whitelist $1.$2.$3.$4 $)
R$-.$-.$-.$-		$: $(EL_Whitelist $1.$2.$3 $)
R$-.$-.$-.$-		$: $(EL_Whitelist $1.$2 $)
R$-.$-.$-.$-		$: $(EL_Whitelist $1 $)
ROK					$#OK
R$*					$: $&{EL_CurrRcpt}
')dnl

# do not check authenticated submissions
# was the sender authenticated?
R$*					$: $>RelayTLS

# authenticated by a trusted mechanism?
R$*							$: $1 $| $&{auth_type}
R$* $|						$: $1
R$* $| $={TrustAuthMech}	$@ $(EL_SetVar {hc_switch} $@ ? $)
R$* $| $*					$: $&{EL_CurrRcpt}

# need to initialize our bitwise/numeric macros before we get to header checks
R$*					$: $1 $| $(EL_SetVar {ELCcHeaderCount}   $@ 0 $)
R$* $| $*			$: $1 $| $(EL_SetVar {ELHasHeader}       $@ 0 $)
R$* $| $*			$: $1 $| $(EL_SetVar {ELRecdHeaderCount} $@ 0 $)
R$* $| $*			$: $1 $| $(EL_SetVar {ELSpamsign}        $@ 0 $)

# technically, we are not quite in headers, but it does not matter
R$* $| $*			$: $1 $(EL_SetVar {INHEADERS} $@ YES $)

ifdef(_EL_POLICY, 1, `dnl
# set default policy from policy file
R$*					$: $(EL_Policy default $)
R$+<OK>				$: $1 $(EL_SetVar {ELPolicyUser} $@ $1 $)

R$*TAG				$: $1 $(EL_SetVar {ELPolicySwitch} $@ TAG $)
R$*BLOCK			$: $1 $(EL_SetVar {ELPolicySwitch} $@ BLOCK $)
R$*ASK				$: $1 $(EL_SetVar {ELPolicySwitch} $@ ASK $)
R$*					$: $&{EL_CurrRcpt}

ifdef(`_EL_REPORT_ABUSE', `dnl
# clear abuse contact
R$*					$: $(EL_SetVar {ELAbuseContact} $@ NONE $)
R$*					$: $&{client_name}

# lookup and set abuse contact 
R$*.$-.$-			$: $(EL_AbuseContacts Report:$2.$3 $) $| $2.$3
RYES $| $*			$: YES $| $(EL_AbuseContacts Contact:$1 $)
RYES $| $+			$: $(EL_SetVar {ELAbuseContact} $@ $1 $)

R$*.$-.$-.$-		$: $(EL_AbuseContacts Report:$2.$3.$4 $) $| $2.$3.$4
RYES $| $*			$: YES $| $(EL_AbuseContacts Contact:$1 $)
RYES $| $+			$: $(EL_SetVar {ELAbuseContact} $@ $1 $)
R$*					$: $&{EL_CurrRcpt}
')dnl

# check for @domain form
R$*<$*@$*>$*		$: $2@$3
R$*@$*				$: @$2

# set user policy (override default if user found)
R$*					$: $(EL_Policy $1 $)
R$+<OK>				$: $1 $(EL_SetVar {ELPolicyUser} $@ $1 $)
R$*TAG				$: $1 $(EL_SetVar {ELPolicySwitch} $@ TAG $)
R$*BLOCK			$: $1 $(EL_SetVar {ELPolicySwitch} $@ BLOCK $)
R$*ASK				$: $1 $(EL_SetVar {ELPolicySwitch} $@ ASK $)
R$*					$: $&{EL_CurrRcpt}

# get current user in user@host form
R$*<$*@$*>$*		$: $2@$3
R$*@$*				$: $1@$2

# set user policy (override default if user found)
R$*					$: $(EL_Policy $1 $)
R$+<OK>				$: $1 $(EL_SetVar {ELPolicyUser} $@ $1 $)
R$*TAG				$: $1 $(EL_SetVar {ELPolicySwitch} $@ TAG $)
R$*BLOCK			$: $1 $(EL_SetVar {ELPolicySwitch} $@ BLOCK $)
R$*ASK				$: $1 $(EL_SetVar {ELPolicySwitch} $@ ASK $)
R$*					$: $&{EL_CurrRcpt}
')dnl

ifdef(`_EL_SPAMTRAP', `dnl
# reject all mail whose recipient is a spamtrap address
# this will likely only work if your access.db does not already contain
# a list of these spamtrap addresses.
R$*					$: $&{EL_CurrRcpt}
R<$*>				$: $1
R$*					$: $(EL_Spamtrap $1 $)

ifdef(`_EL_REPORT_ABUSE', `dnl
RSPAMTRAP			$: SPAMTRAP $| $&{ELAbuseContact}
RSPAMTRAP $| NONE	$: SPAMTRAP
RSPAMTRAP $| $+		$: SPAMTRAP $(EL_Log "EL Report to "$1": claimed to be "$&{s}"; from "$&{mail_addr}" to "$&{rcpt_addr}" from "$&{client_name}" ["$&{client_addr}"]" $)
RT					$: T $| $&{ELAbuseContact}
RT $| NONE			$: T
RT $| $+			$: T $(EL_Log "EL Report to "$1": claimed to be "$&{s}"; from "$&{mail_addr}" to "$&{rcpt_addr}" from "$&{client_name}" ["$&{client_addr}"]" $)
')dnl

ifelse(_EL_POLICY, 1, `dnl
# go ahead and tag the message here so other non-spamtrap recipients know too
R$* 									$: $1 $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
RSPAMTRAP $| $*SPAMTRAP$* $| $+			$: <TAGTRAP>
RT $| $*SPAMTRAP$* $| $+				$: <TAGTRAP>

RSPAMTRAP $| $*SPAMTRAP$* $| TAG		$: <TAGTRAP>
RSPAMTRAP $| $*SPAMTRAP$* $| BLOCK		$: <REJTRAP> 
RSPAMTRAP $| $* +SPAMTRAP$* $| ASK		$: <TAGTRAP>
RSPAMTRAP $| $* !SPAMTRAP$* $| ASK		$: <REJTRAP> 

RT $| $*SPAMTRAP$* $| TAG				$: <TAGTRAP>
RT $| $*SPAMTRAP$* $| BLOCK				$: <REJTRAP> 
RT $| $* +SPAMTRAP$* $| ASK				$: <TAGTRAP>
RT $| $* !SPAMTRAP$* $| ASK				$: <REJTRAP> 

RD $| $*SPAMTRAP$* $| TAG				$: <TAGDORM>
RD $| $*SPAMTRAP$* $| BLOCK				$: <REJDORM> 
RD $| $* +SPAMTRAP$* $| ASK				$: <TAGDORM>
RD $| $* !SPAMTRAP$* $| ASK				$: <REJDORM> 

# if no match, check default policy
R$* $| $* $| $*							$: $1 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
RSPAMTRAP $| $*SPAMTRAP$* $| $+			$: <TAGTRAP>
RT $| $*SPAMTRAP$* $| $+				$: <TAGTRAP>

RSPAMTRAP $| $*SPAMTRAP$* $| TAG		$: <TAGTRAP>
RSPAMTRAP $| $*SPAMTRAP$* $| BLOCK		$: <REJTRAP> 
RSPAMTRAP $| $* +SPAMTRAP$* $| ASK		$: <TAGTRAP>
RSPAMTRAP $| $* !SPAMTRAP$* $| ASK		$: <REJTRAP> 

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
R<REJTRAP>				$#error $@ 5.7.1 $: ifdef(`confEL_ErrSpamtrap', `confEL_ErrSpamtrap', `"550 GO_AWAY Spammer tries again / nice people do not spam us! / will you never stop?"')
R<TAGDORM>				$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgSpamtrapDormant', `confEL_TagErrMsgSpamtrapDormant', `"Message addressed to a known dormant address"')> $| 3
R<REJDORM>				$#error $@ 5.7.1 $: ifdef(`confEL_ErrSpamtrapDormant', `confEL_ErrSpamtrapDormant', `"550 DORMANT Old unused account / will soon go away for good / you smell bad, spammer"')

# reject all mail whose recipient localpart is a spamtrap address
# this will likely only work if your access.db does not already contain
# a list of these spamtrap address localparts.
R$*					$: $&{EL_CurrRcpt}
R<$*@$*>			$: $1@
R$*					$: $(EL_Spamtrap $1 $)
ifdef(`_EL_REPORT_ABUSE', `dnl
RSPAMTRAP			$: SPAMTRAP $| $&{ELAbuseContact}
RSPAMTRAP $| NONE	$: SPAMTRAP
RSPAMTRAP $| $+		$: SPAMTRAP $(EL_Log "EL Report to "$1": claimed to be "$&{s}"; from "$&{mail_addr}" to "$&{rcpt_addr}" from "$&{client_name}" ["$&{client_addr}"]" $)
RT					$: T $| $&{ELAbuseContact}
RT $| NONE			$: T
RT $| $+			$: T $(EL_Log "EL Report to "$1": claimed to be "$&{s}"; from "$&{mail_addr}" to "$&{rcpt_addr}" from "$&{client_name}" ["$&{client_addr}"]" $)
')dnl

ifelse(_EL_POLICY, 1, `dnl
# go ahead and tag the message here so other non-spamtrap recipients know too
R$* 									$: $1 $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
RSPAMTRAP $| $*SPAMTRAP$* $| $+			$: <TAGTRAP>
RT $| $*SPAMTRAP$* $| $+				$: <TAGTRAP>

RSPAMTRAP $| $*SPAMTRAP$* $| TAG		$: <TAGTRAP>
RSPAMTRAP $| $*SPAMTRAP$* $| BLOCK		$: <REJTRAP>
RSPAMTRAP $| $* +SPAMTRAP$* $| ASK		$: <TAGTRAP>
RSPAMTRAP $| $* !SPAMTRAP$* $| ASK		$: <REJTRAP>

RT $| $*SPAMTRAP$* $| TAG				$: <TAGTRAP>
RT $| $*SPAMTRAP$* $| BLOCK				$: <REJTRAP>
RT $| $* +SPAMTRAP$* $| ASK				$: <TAGTRAP>
RT $| $* !SPAMTRAP$* $| ASK				$: <REJTRAP>

RD $| $*SPAMTRAP$* $| TAG				$: <TAGDORM>
RD $| $*SPAMTRAP$* $| BLOCK				$: <REJDORM>
RD $| $* +SPAMTRAP$* $| ASK				$: <TAGDORM>
RD $| $* !SPAMTRAP$* $| ASK				$: <REJDORM>

# if no match, check default policy
R$* $| $* $| $*							$: $1 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
RSPAMTRAP $| $*SPAMTRAP$* $| $+			$: <TAGTRAP>
RT $| $*SPAMTRAP$* $| $+				$: <TAGTRAP>

RSPAMTRAP $| $*SPAMTRAP$* $| TAG		$: <TAGTRAP>
RSPAMTRAP $| $*SPAMTRAP$* $| BLOCK		$: <REJTRAP> 
RSPAMTRAP $| $* +SPAMTRAP$* $| ASK		$: <TAGTRAP>
RSPAMTRAP $| $* !SPAMTRAP$* $| ASK		$: <REJTRAP> 

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
R<REJTRAP> 				$#error $@ 5.7.1 $: ifdef(`confEL_ErrSpamtrap', `confEL_ErrSpamtrap', `"550 GO_AWAY Spammer tries again / nice people do not spam us! / will you never stop?"')
R<TAGDORM>				$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgSpamtrapDormant', `confEL_TagErrMsgSpamtrapDormant', `"Message addressed to a known dormant address"')> $| 3
R<REJDORM> 				$#error $@ 5.7.1 $: ifdef(`confEL_ErrSpamtrapDormant', `confEL_ErrSpamtrapDormant', `"550 DORMANT Old unused account / will soon go away for good / you smell bad, spammer"')
')dnl

ifdef(`_EL_PERMBLACKLIST', `dnl
# reject all permanently blacklisted hosts (for abuse of role accounts)
R$*							$: $(EL_PermBlacklist $&{client_addr} $) $| $(EL_CheckForRoleAccount $&{EL_CurrRcpt} $)
RDIEDIEDIE $| <ROLE>		$#error $@ 5.7.1 $: ifdef(`confEL_ErrPermBlacklist', `confEL_ErrPermBlacklist', `"550 ROLEACT Contact "$&{ELContactPhone}" if this is in error, but we do not accept mail from your IP address, (" $&{client_addr} "), which has a history of spamming/abusing role accounts, e.g., abuse or postmaster."')
RP $| <ROLE>				$#error $@ 5.7.1 $: ifdef(`confEL_ErrPermBlacklist', `confEL_ErrPermBlacklist', `"550 ROLEACT Contact "$&{ELContactPhone}" if this is in error, but we do not accept mail from your IP address, (" $&{client_addr} "), which has a history of spamming/abusing role accounts, e.g., abuse or postmaster."')
')dnl

ifdef(`_EL_NOFCRDNS', `dnl
# isolate mail from hosts with non-FCrDNS according to TLD
R$*									$: $&{client_resolve} $| $&{client_ptr} ifdef(`_EL_DEBUG', `$(EL_Log "EL FCrDNS: " $&{client_resolve} "/" $&{client_ptr} $)')
ifelse(_EL_POLICY, 1, `dnl
RFORGED $| $+ 						$: $(EL_GetTLD $1 $) $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
R$+<TLD> $| $*NOFCRDNS$* $| TAG		$: <TAGFORGED>
R$+<TLD> $| $*NOFCRDNS$* $| BLOCK	$: <REJFORGED>
R$+<TLD> $| $* +NOFCRDNS $* $| ASK	$: <TAGFORGED>
R$+<TLD> $| $* !NOFCRDNS $* $| ASK	$: <REJFORGED>

# if no match, try default policy
R$* $| $* $| $* 					$: $1 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
R$+<TLD> $| $*NOFCRDNS$* $| TAG		$: <TAGFORGED>
R$+<TLD> $| $*NOFCRDNS$* $| BLOCK	$: <REJFORGED>
R$+<TLD> $| $* +NOFCRDNS $* $| ASK	$: <TAGFORGED>
R$+<TLD> $| $* !NOFCRDNS $* $| ASK	$: <REJFORGED>
',`
RFORGED $| $+.$-					$: $(EL_GetTLD $2 $)
')dnl

R<TAGFORGED>						$: $>EL_TagSuspicious <"remote host may be forged"> $| 2
R<REJFORGED>						$#error $@ 5.7.1 $: ifdef(`confEL_ErrNoFCrDNS', `confEL_ErrNoFCrDNS', `"550 NOFCRDNS Contact "$&{ELContactPhone}" if this is in error, but we do not accept mail from your IP address, (" $&{client_addr} "), which appears to lack forward-compatible reverse DNS."')
')dnl

ifdef(`_EL_BLOCKDOTASRDNS', `dnl
# isolate mail from hosts with a single dot as rDNS
R$*									$: $&{client_resolve} $| <$&{client_ptr}> ifdef(`_EL_DEBUG', `$(EL_Log "EL DotAsrDNS: <" $&{client_ptr} ">" $)')
ROK $| <$@>							$#error $@ 5.7.1 $: ifdef(`confEL_ErrDotAsrDNS', `confEL_ErrDotAsrDNS', `"550 DOTASRDNS Contact "$&{ELContactPhone}" if this is in error, but we do not accept mail from your IP address, (" $&{client_addr} "), which appears to have a single dot as reverse DNS."')
ROK $| <.>							$#error $@ 5.7.1 $: ifdef(`confEL_ErrDotAsrDNS', `confEL_ErrDotAsrDNS', `"550 DOTASRDNS Contact "$&{ELContactPhone}" if this is in error, but we do not accept mail from your IP address, (" $&{client_addr} "), which appears to have a single dot as reverse DNS."')
')dnl

ifdef(`_EL_CUSTOM_DNSBLS', `dnl
# ??? bug: should make these configurable
# DNS based IP address spam list zen.spamhaus.org
R$*				$: $&{client_addr}
ifelse(_EL_POLICY, 1, `dnl
R$-.$-.$-.$- 						$: <?> $(dnsbl $4.$3.$2.$1.zen.spamhaus.org. $: OK $) $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
R<?>OK $| $* $| $*					$: OKSOFAR $| $1 $| $2
R<?>$+<TMP> $| $* $| $*				$: TMPOK $| $2 $| $3
R<?>$+ $| $*SPAMHAUS$* $| TAG 		$: <TAGSH>
R<?>$+ $| $*SPAMHAUS$* $| BLOCK 	$: <REJSH>
R<?>$+ $| $* +SPAMHAUS$* $| ASK 	$: <TAGSH>
R<?>$+ $| $* !SPAMHAUS$* $| ASK 	$: <REJSH>

# if no match, try default policy
R$* $| $* $| $* 					$: $1 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
R<?>OK $| $* $| $*					$: OKSOFAR $| $1 $| $2
R<?>$+<TMP> $| $* $| $*				$: TMPOK $| $2 $| $3
R<?>$+ $| $*SPAMHAUS$* $| TAG 		$: <TAGSH>
R<?>$+ $| $*SPAMHAUS$* $| BLOCK 	$: <REJSH>
R<?>$+ $| $* +SPAMHAUS$* $| ASK 	$: <TAGSH>
R<?>$+ $| $* !SPAMHAUS$* $| ASK 	$: <REJSH>
', `
R$-.$-.$-.$-					$: <?> $(dnsbl $4.$3.$2.$1.zen.spamhaus.org. $: OK $)
R<?>OK							$: OKSOFAR
R<?>$+<TMP>						$: TMPOK
R<?>$+							$: <REJSBL>
')dnl
R<TAGSH>						$: $>EL_TagSuspicious <"remote IP listed in ZEN"> $| 3
R<REJSH>						$#error $@ 5.7.1 $: "SPAMHAUS Sorry <"$&f">, your mail server appears to be an ongoing spam source as listed by zen.spamhaus.org. Contact "$&{ELContactEmail}" for more information. http://www.spamhaus.org/query/bl?ip="$&{client_addr}

# DNS based IP address spam list dnsbl.ahbl.org
R$*			$: $&{client_addr}
ifelse(_EL_POLICY, 1, `dnl
R$-.$-.$-.$-					$: <?> $(dnsbl $4.$3.$2.$1.dnsbl.ahbl.org. $: OK $) $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
R<?>OK $| $* $| $*				$: OKSOFAR $| $1 $| $2
R<?>$+<TMP> $| $* $| $*			$: TMPOK $| $2 $| $3
R<?>$+ $| $*AHBL$* $| TAG		$: <TAGAHBL>
R<?>$+ $| $*AHBL$* $| BLOCK		$: <REJAHBL>
R<?>$+ $| $* +AHBL$* $| ASK		$: <TAGAHBL>
R<?>$+ $| $* !AHBL$* $| ASK		$: <REJAHBL>

# if no match try default policy
R$* $| $* $| $* 				$: $1 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
R<?>OK $| $* $| $*				$: OKSOFAR $| $1 $| $2
R<?>$+<TMP> $| $* $| $*			$: TMPOK $| $2 $| $3
R<?>$+ $| $*AHBL$* $| TAG		$: <TAGAHBL>
R<?>$+ $| $*AHBL$* $| BLOCK		$: <REJAHBL>
R<?>$+ $| $* +AHBL$* $| ASK		$: <TAGAHBL>
R<?>$+ $| $* !AHBL$* $| ASK		$: <REJAHBL>
',`
R$-.$-.$-.$-					$: <?> $(dnsbl $4.$3.$2.$1.dnsbl.ahbl.org. $: OK $)
R<?>OK							$: OKSOFAR
R<?>$+<TMP>						$: TMPOK
R<?>$+							$: <REJAHBL>
')dnl
R<TAGAHBL>						$: $>EL_TagSuspicious <"remote IP listed in AHBL"> $| 2
R<REJAHBL>						$#error $@ 5.7.1 $: "AHBL Sorry, <"$&f">, your mail was rejected because your IP is listed by ahbl.org. Contact "$&{ELContactEmail}" for more information. See http://www.ahbl.org/tools/lookup.php?ip="$&{client_addr}
')dnl

ifdef(`_EL_CHECK_URIBL_DOMAIN_HELO', `dnl
R$*					$: $&{s}
R$-.$-.$-.$-		$: <?> $(dnsbl $1.$2.$3.$4.black.uribl.com. $: OK $) ifdef(`_EL_DEBUG', `$(EL_Log "EL uribl: " $1.$2.$3.$4 $)')
R$-.$-.$-			$: <?> $(dnsbl $1.$2.$3.black.uribl.com. $: OK $) ifdef(`_EL_DEBUG', `$(EL_Log "EL uribl: " $1.$2.$3 $)')
R$-.$-				$: <?> $(dnsbl $1.$2.black.uribl.com. $: OK $) ifdef(`_EL_DEBUG', `$(EL_Log "EL uribl: " $1.$2 $)')

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
R$* $| $* $| $*					$: $1 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
R$+ $| $*URIBL$* $| TAG			$: <TAGURIBL>
R$+ $| $*URIBL$* $| BLOCK		$: <REJURIBL>
R$+ $| $* +URIBL$* $| ASK		$: <TAGURIBL>
R$+ $| $* !URIBL$* $| ASK		$: <REJURIBL>

R<TAGURIBL>						$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgHELOURIBL', `confEL_TagErrMsgHELOURIBL', `"message from header contains domain in uribl.com blacklist"')> $| 2
R<REJURIBL>						$#error $@ 5.7.1 $: ifdef(`confEL_ErrHELOURIBL', `confEL_ErrHELOURIBL', `"550 URIBLHL Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. We do not accept mail sent from your domain as it is listed by uribl.com."')
')dnl
')dnl

ifdef(`_EL_CHECK_SURBL_DOMAIN_HELO', `dnl
R$*					$: $&{s}
R$-.$-.$-.$-		$: <?> $(dnsbl $1.$2.$3.$4.multi.surbl.org. $: OK $) ifdef(`_EL_DEBUG', `$(EL_Log "EL surbl: " $1.$2.$3.$4 $)')
R$-.$-.$-			$: <?> $(dnsbl $1.$2.$3.multi.surbl.org. $: OK $) ifdef(`_EL_DEBUG', `$(EL_Log "EL surbl: " $1.$2.$3 $)')
R$-.$-				$: <?> $(dnsbl $1.$2..multi.surbl.org. $: OK $) ifdef(`_EL_DEBUG', `$(EL_Log "EL surbl: " $1.$2 $)')

ifelse(_EL_POLICY, 1, `dnl
# need to check for DNS lookup failures here
R<?>OK				$: OKSOFAR
R<?>$+<TMP>			$: TMPOK
R<?>$+				$: $1 $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
R$+ $| $*SURBL$* $| TAG			$: <TAGSURBL>
R$+ $| $*SURBL$* $| BLOCK		$: <REJSURBL>
R$+ $| $* +SURBL$* $| ASK		$: <TAGSURBL>
R$+ $| $* !SURBL$* $| ASK		$: <REJSURBL>

# if no match try default policy
R$* $| $* $| $*					$: $1 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
R$+ $| $*SURBL$* $| TAG			$: <TAGSURBL>
R$+ $| $*SURBL$* $| BLOCK		$: <REJSURBL>
R$+ $| $* +SURBL$* $| ASK		$: <TAGSURBL>
R$+ $| $* !SURBL$* $| ASK		$: <REJSURBL>

R<TAGSURBL>						$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgHELOSURBL', `confEL_TagErrMsgHELOSURBL', `"HELO contains domain in surbl.org blacklist"')> $| 2
R<REJSURBL>						$#error $@ 5.7.1 $: ifdef(`confEL_ErrHELOSURBL', `confEL_ErrHELOSURBL', `"550 SURBLHL Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. We do not accept mail sent from your domain as it is listed by surbl.org."')
')dnl
')dnl

ifdef(`_EL_BOGUS_QUOTED_SENDER', `dnl
KEL_BogusQuotedSender regex -a<BOGUS> \".*\"
R$*							$: $(EL_BogusQuotedSender $&{mail_from} $)
R<BOGUS>					$#error $@ 5.7.1 $: ifdef(`confEL_ErrBogusQuotedSender', `confEL_ErrBogusQuotedSender', `"550 BOGUSQS Contact "$&{ELContactPhone}" if this is in error, but your mail was refused because your sender address is bogus."')
')dnl

ifdef(`_EL_CHECK_SCHIZO', `dnl
# check to see if the connecting host claims to be us.
KEL_Check_SchizoLocalIP regex -a<MATCH> ^ifdef(`confEL_LOCAL_IP', `confEL_LOCAL_IP')$
R$*							$: $(EL_Check_SchizoLocalIP $&{s} $)

ifdef(`_EL_REPORT_ABUSE', `dnl
R<MATCH>					$: <MATCH> $| $&{ELAbuseContact}
R<MATCH> $| NONE			$: <MATCH>
R<MATCH> $| $+				$: <MATCH> $(EL_Log "EL Report to "$1": claimed to be "$&{s}"; from "$&{mail_addr}" to "$&{rcpt_addr}" from "$&{client_name}" ["$&{client_addr}"]" $)
')dnl
R<MATCH>					$#error $@ 5.7.1 $: ifdef(`confEL_ErrSchizoLocalIP', `confEL_ErrSchizoLocalIP', `"550 LOCALIP Contact "$&{ELContactPhone}" if this is in error, but your mail was refused because you are forging your HELO string. I am " $&{s} ", not you."')

KEL_Check_SchizoLocalHostname regex -a<MATCH> ^ifdef(`confEL_LOCAL_HOSTNAME', `confEL_LOCAL_HOSTNAME')$
R$*							$: $(EL_Check_SchizoLocalHostname $&{s} $)
ifdef(`_EL_REPORT_ABUSE', `dnl
# ??? bug: should only emit log info if abuse contact found; is "" == $@?
R<MATCH>					$: <MATCH> $| $&{ELAbuseContact}
R<MATCH> $| NONE			$: <MATCH>
R<MATCH> $| $+				$: <MATCH> $(EL_Log "EL Report to "$1": claimed to be "$&{s}"; from "$&{mail_addr}" to "$&{rcpt_addr}" from "$&{client_name}" ["$&{client_addr}"]" $)
')dnl
R<MATCH>					$#error $@ 5.7.1 $: ifdef(`confEL_ErrSchizoLocalHostname', `confEL_ErrSchizoLocalHostname', `"550 LOCALHN Contact "$&{ELContactPhone}" if this is in error, but your mail was refused because you are forging your HELO string. I am " $&{s} ", not you."')

KEL_Check_SchizoLocalDomains regex -a<MATCH> ^ifdef(`confEL_LOCAL_DOMAINS', `confEL_LOCAL_DOMAINS')$
R$*							$: $(EL_Check_SchizoLocalDomains $&{s} $)
ifdef(`_EL_REPORT_ABUSE', `dnl
# ??? bug: should only emit log info if abuse contact found; is "" == $@?
R<MATCH>					$: <MATCH> $| $&{ELAbuseContact}
R<MATCH> $| NONE			$: <MATCH>
R<MATCH> $| $+				$: <MATCH> $(EL_Log "EL Report to "$1": claimed to be "$&{s}"; from "$&{mail_addr}" to "$&{rcpt_addr}" from "$&{client_name}" ["$&{client_addr}"]" $)
')dnl
R<MATCH>					$#error $@ 5.7.1 $: ifdef(`confEL_ErrSchizoLocalDomains', `confEL_ErrSchizoLocalDomains', `"550 LOCLDOM Contact "$&{ELContactPhone}" if this is in error, but your mail was refused because you are forging your HELO string. I am " $&{s} ", not you."')

KEL_Check_SchizoMaildotLocalDomains regex -a<MATCH> ^mail\.ifdef(`confEL_LOCAL_DOMAINS', `confEL_LOCAL_DOMAINS')$
R$*							$: $(EL_Check_SchizoMaildotLocalDomains $&{s} $)
ifdef(`_EL_REPORT_ABUSE', `dnl
# ??? bug: should only emit log info if abuse contact found; is "" == $@?
R<MATCH>					$: <MATCH> $| $&{ELAbuseContact}
R<MATCH> $| NONE			$: <MATCH>
R<MATCH> $| $+				$: <MATCH> $(EL_Log "EL Report to "$1": claimed to be "$&{s}"; from "$&{mail_addr}" to "$&{rcpt_addr}" from "$&{client_name}" ["$&{client_addr}"]" $)
')dnl
R<MATCH>					$#error $@ 5.7.1 $: ifdef(`confEL_ErrSchizoMailDotLocalDomains', `confEL_ErrSchizoMailDotLocalDomains', `"550 LOCMDOM Contact "$&{ELContactPhone}" if this is in error, but your mail was refused because you are forging your HELO string. I am " $&{s} ", not you."')
R$*							$: $&{EL_CurrRcpt}
')dnl

ifdef(`_EL_CHECK_SCHIZO_CLASSW', `dnl
# check for schizoid HELO against $=w
R$*							$: $&{s}
R$=w						$: <SCHIZOHELO>
R$*.$=w						$: <SCHIZOHELO>

R<SCHIZOHELO>				$: <MATCH>

ifdef(`_EL_REPORT_ABUSE', `dnl
# ??? bug: should only emit log info if abuse contact found; is "" == $@?
R<MATCH>					$: <MATCH> $| $&{ELAbuseContact}
R<MATCH> $| NONE			$: <MATCH>
R<MATCH> $| $+				$: <MATCH> $(EL_Log "EL Report to "$1": claimed to be "$&{s}"; from "$&{mail_addr}" to "$&{rcpt_addr}" from "$&{client_name}" ["$&{client_addr}"]" $)
')
R<MATCH>					$#error $@ 5.7.1 $: ifdef(`confEL_ErrSchizoLocalHostname', `confEL_ErrSchizoLocalHostname', `"550 LOCALHN Contact "$&{ELContactPhone}" if this is in error, but your mail was refused because you are forging your HELO string. I am " $&{s} ", not you."')
')dnl

ifdef(`_EL_CHECK_MSGID_AS_ADDR', `dnl
# maps to match common (sendmail/pine) Message-ID formats
KEL_Check_MessageIDAsAddr1 regex -a<MATCH> [0-9]{12,14}\.[a-z]{1,3}[0-9]{4,5}\@ifdef(`confEL_LOCAL_DOMAINS', `confEL_LOCAL_DOMAINS')
KEL_Check_MessageIDAsAddr2 regex -a<MATCH> [0-9]\.[0-9]\.[0-9]\.[0-9]\.[0-9]\.[0-9]{14}.[0-z]{8}\@ifdef(`confEL_LOCAL_DOMAINS', `confEL_LOCAL_DOMAINS')
KEL_Check_MessageIDAsAddr3 regex -a<MATCH> [a-z]{2}[0-9]{5}\@ifdef(`confEL_LOCAL_DOMAINS', `confEL_LOCAL_DOMAINS')
ifdef(`_EL_CHECK_5DIGITMSGID_AS_ADDR', `dnl
KEL_Check_5DigitMessageIDAsAddr regex -a<MATCH> ^\ ?<?[0-9]{4,5}@ifdef(`confEL_LOCAL_DOMAINS', `confEL_LOCAL_DOMAINS')
KEL_Check_MessageIDAsAddr3 regex -a<MATCH> ^\ ?<?[a-z]{3}[0-9]{4,5}@ifdef(`confEL_LOCAL_DOMAINS', `confEL_LOCAL_DOMAINS')
')dnl
KEL_Check_MessageIDAsAddr sequence EL_Check_MessageIDAsAddr1 EL_Check_MessageIDAsAddr2 EL_Check_MessageIDAsAddr3 ifdef(`_EL_CHECK_5DIGITMSGID_AS_ADDR', `EL_Check_5DigitMessageIDAsAddr') ifdef(`_EL_CHECK_5DIGITMSGID_AS_ADDR', `EL_Check_MessageIDAsAddr3')

R$*							$: $(EL_Check_MessageIDAsAddr $&{EL_CurrRcpt} $)
ifdef(`_EL_REPORT_ABUSE', `dnl
R<MATCH>					$: <MATCH> $| $&{ELAbuseContact}
R<MATCH> $| NONE			$: <MATCH>
R<MATCH> $| $+				$: <MATCH> $(EL_Log "EL Report to "$1": claimed to be "$&{s}"; from "$&{mail_addr}" to "$&{rcpt_addr}" from "$&{client_name}" ["$&{client_addr}"]" $)
')dnl

ifdef(_EL_POLICY, 1, `dnl
# check for policy
R$*					$: $1 $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
R<MATCH> $| $*MIDADDY$* $| TAG		$: <TAGMIDADDY>
R<MATCH> $| $*MIDADDY$* $| BLOCK	$: <REJMIDADDY>
R<MATCH> $| $* +MIDADDY$* $| ASK	$: <TAGMIDADDY>
R<MATCH> $| $* !MIDADDY$* $| ASK	$: <REJMIDADDY>

# if no match try default policy
R$* $| $* $| $* 					$: $1 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
R<MATCH> $| $*MIDADDY$* $| TAG		$: <TAGMIDADDY>
R<MATCH> $| $*MIDADDY$* $| BLOCK	$: <REJMIDADDY>
R<MATCH> $| $* +MIDADDY$* $| ASK	$: <TAGMIDADDY>
R<MATCH> $| $* !MIDADDY$* $| ASK	$: <REJMIDADDY>

R<TAGMIDADDY>					$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgMidAddy', `confEL_TagErrMsgMidAddy', `"Recipient is a Message-ID"')> $| 5
R<REJMIDADDY>					$#error $@ 5.7.1 $: ifdef(`confEL_ErrMsgidAsAddr', `confEL_ErrMsgidAsAddr', `"550 SCRAPED Contact "$&{ELContactPhone}" if this is in error, but your mail was refused because you sent it to a bogus address; it is a Message-ID, not an email address; probably scraped from an online list archive."')
')dnl
')dnl

ifdef(`_EL_CHECK_MSGID_AS_ADDR_CLASSW', `dnl
# maps to match common (sendmail/pine) Message-ID formats
KEL_Check_MessageIDAsAddr1 regex -a<MSGID> -s1 [0-9]{12,14}\.[a-z]{1,3}[0-9]{4,5}\@(.+)>?$
KEL_Check_MessageIDAsAddr2 regex -a<MSGID> -s1 [0-9]\.[0-9]\.[0-9]\.[0-9]\.[0-9]\.[0-9]{14}.[0-z]{8}\@(.+)>?$
KEL_Check_MessageIDAsAddr3 regex -a<MSGID> -s1 [a-z]{2}[0-9]{5}\@(.+)>?$
ifdef(`_EL_CHECK_5DIGITMSGID_AS_ADDR', `dnl
KEL_Check_5DigitMessageIDAsAddr regex -a<MSGID> -s1 ^\ ?<?[0-9]{4,5}@(.+)>?$
KEL_Check_MessageIDAsAddr3 regex -a<MSGID> -s1 ^\ ?<?[a-z]{3}[0-9]{4,5}@(.+)>?$
')dnl
KEL_Check_MessageIDAsAddr sequence EL_Check_MessageIDAsAddr1 EL_Check_MessageIDAsAddr2 EL_Check_MessageIDAsAddr3 ifdef(`_EL_CHECK_5DIGITMSGID_AS_ADDR', `EL_Check_5DigitMessageIDAsAddr') ifdef(`_EL_CHECK_5DIGITMSGID_AS_ADDR', `EL_Check_MessageIDAsAddr3')

R$*							$: $(EL_Check_MessageIDAsAddr $&{EL_CurrRcpt} $)
ifdef(`_EL_REPORT_ABUSE', `dnl
R<MSGID>$*					$: <MSGID> $| $1 $| $&{ELAbuseContact}
R<MSGID> $| $* $| NONE		$: <MSGID>
R<MSGID> $| $* $| $+		$: <MSGID> $| $1 $(EL_Log "EL Report to "$1": claimed to be "$&{s}"; from "$&{mail_addr}" to "$&{rcpt_addr}" from "$&{client_name}" ["$&{client_addr}"]" $)
')dnl
R<MSGID> $| $=w				$: <MATCH>
R<MSGID> $| $*.$=w			$: <MATCH>

ifdef(_EL_POLICY, 1, `dnl
# check for policy
R$*					$: $1 $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
R<MATCH> $| $*MIDADDY$* $| TAG		$: <TAGMIDADDY>
R<MATCH> $| $*MIDADDY$* $| BLOCK	$: <REJMIDADDY>
R<MATCH> $| $* +MIDADDY$* $| ASK	$: <TAGMIDADDY>
R<MATCH> $| $* !MIDADDY$* $| ASK	$: <REJMIDADDY>

# if no match try default policy
R$* $| $* $| $* 					$: $1 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
R<MATCH> $| $*MIDADDY$* $| TAG		$: <TAGMIDADDY>
R<MATCH> $| $*MIDADDY$* $| BLOCK	$: <REJMIDADDY>
R<MATCH> $| $* +MIDADDY$* $| ASK	$: <TAGMIDADDY>
R<MATCH> $| $* !MIDADDY$* $| ASK	$: <REJMIDADDY>

R<TAGMIDADDY>					$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgMidAddy', `confEL_TagErrMsgMidAddy', `"Recipient is a Message-ID"')> $| 5
R<REJMIDADDY>					$#error $@ 5.7.1 $: ifdef(`confEL_ErrMsgidAsAddr', `confEL_ErrMsgidAsAddr', `"550 SCRAPED Contact "$&{ELContactPhone}" if this is in error, but your mail was refused because you sent it to a bogus address; it is a Message-ID, not an email address; probably scraped from an online list archive."')
')dnl
')dnl

ifdef(`_EL_PHISH', `dnl
ifdef(_EL_POLICY, 1, `dnl
# check for no-bank policies for this recipient
R$*					$: $(EL_PhishFromDomains $&{mail_addr} $) $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
RPHISH $| $*NOBANK$* $| TAG		$: <TAGPH>
RPHISH $| $*NOBANK$* $| BLOCK	$: <REJPH>
RPHISH $| $* +NOBANK$* $| ASK 	$: <TAGPH>
RPHISH $| $* !NOBANK$* $| ASK 	$: <REJPH>

# if no match try default policy
R$* $| $* $| $* 				$: $1 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
RPHISH $| $*NOBANK$* $| TAG		$: <TAGPH>
RPHISH $| $*NOBANK$* $| BLOCK	$: <REJPH>
RPHISH $| $* +NOBANK$* $| ASK 	$: <TAGPH>
RPHISH $| $* !NOBANK$* $| ASK 	$: <REJPH>

R<TAGPH>						$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgNobank', `confEL_TagErrMsgNobank', `"Banking message sent to address that has no finances"')> $| 4
R<REJPH>						$#error $@ 5.7.1 $: ifdef(`confEL_ErrPhishNoBankAccount', `confEL_ErrPhishNoBankAccount', `"550 NOBANK Contact "$&{ELContactEmail}" if this is in error, but you are sending phishing scams to an account that has no finances at all."')
')dnl
')dnl

ifdef(`_EL_FOAD_FirstMLastdictionary', `dnl
# "spokeez.com" spammers using distinctive ratware
# this is more for forged blowback spam where the blowback 
# host has not yet lowercased the recipient
KEL_FirstMLastdictionary regex -aSPOKEEZ -f ^ *<?[A-Z][a-z]+[A-Z][A-Z][a-z]+@ifdef(`confEL_LOCAL_DOMAINS', `confEL_LOCAL_DOMAINS', `(example\.com|example\.net)')
R$*						$: (EL_FirstMLastdictionary $&{mail_addr} $)
RSPOKEEZ				$#error $@ 5.7.1 $: ifdef(`confEL_ErrFirstMLastdictionary', `confEL_ErrFirstMLastdictionary', `550 FIRSTMLD Contact "$&{ELContactPhone}" if this is a legitimate email, but odds are it is blowback from a forged spam run."')
')dnl

ifdef(`_EL_FOAD_WENBZR', `dnl
# "virility pro" spammers (Ralsky)
KEL_Wenbzr regex -aWENBZR -f ^ *<?[A-Z][a-z]+_[0-9]{1,2}_[A-Z][a-z]+@?(hotmail|msn|yahoo)?(\.com)?>?$
R$*						$: $(EL_Wenbzr $&{mail_addr} $) $| $&{EL_CurrRcpt}
RWENBZR $| $*abuse$*	$#error $@ 5.7.1 $: ifdef(`confEL_ErrWenbzr', `confEL_ErrWenbzr', `"550 WENBZRS Contact "$&{ELContactPhone}" if this is in error, but your mail was refused as suspected spam. If this was a legitimate abuse report, call us instead."')
')dnl

ifdef(`_EL_FOAD_BTP', `dnl
# two word domain spammers (BTP)
KEL_BTP regex -aBTP ^ *<?info\-[0-9a-f]{20,22}@
R$*						$: $(EL_BTP $&{mail_addr} $)
RBTP					$#error $@ 5.7.1 $: ifdef(`confEL_ErrBTP', `confEL_ErrBTP', `"550 BTPGRUP Contact "$&{ELContactPhone}" if this is in error, but your mail was refused as suspected spam. It looks rather a lot like the sort of trash the BTP Group likes to send us."')
')dnl

ifdef(`_EL_FOAD_GLOWING_EDGE', `dnl
# dealbrick.com et al. (Glowing Edge)
KEL_GlowingEdge regex -aGLOWING ^ *<?a[a-z0-9]{29}@
R$*						$: $(EL_GlowingEdge $&{mail_addr} $)
RGLOWING				$#error $@ 5.7.1 $: ifdef(`confEL_ErrGlowingEdge', `confEL_ErrGlowingEdge', `"550 GLWEDGE Contact "$&{ELContactPhone}" if this is in error, but your mail was refused as suspected spam. It looks rather a lot like the sort of trash Glowing Edge likes to send us."')
')dnl

ifdef(`_EL_CAPDOTWORDNUMNUM', `dnl
# still trying to identify this spamware
KEL_CapDotWordNumNum regex -a<MATCH> -s1 ^[A-Z]\.([a-z]+)[0-9]{2}@
R$*						$: $(EL_CapDotWordNumNum $&{mail_addr} $)
R$+<MATCH>				$: $(EL_Wordlist $1 $) 
RWORD					$#error $@ 5.7.1 $: ifdef(`confEL_ErrCapDotWordNumNum', `confEL_ErrCapDotWordNumNum', `"550 CAPDWNN Contact "$&{ELContactPhone}" if this is in error, but your mail was refused as suspected spam."')
RW						$#error $@ 5.7.1 $: ifdef(`confEL_ErrCapDotWordNumNum', `confEL_ErrCapDotWordNumNum', `"550 CAPDWNN Contact "$&{ELContactPhone}" if this is in error, but your mail was refused as suspected spam."')
')dnl

ifdef(`_EL_WORDWORDCAPNUMLETTERCAPLETTER', `dnl
# still trying to identify this spamware
KEL_WordwordCapNumletterCapletter regex -f -aSPAM [A-Z][a-z]+[A-Za-z]+[A-Z][0-9][a-z][A-Z][a-z]@
R$*						$: $(EL_WordwordCapNumletterCapletter $&{mail_addr} $)
RSPAM					$#error $@ 5.7.1 $: ifdef(`confEL_ErrWordwordCapNumletterCapletter', `confEL_ErrWordwordCapNumletterCapletter', `"550 WWCNLCL Contact "$&{ELContactPhone}" if this is in error, but your mail was refused as suspected spam."')
')dnl

ifdef(`_EL_MXNUMBERBIZUS_HELO', `dnl
# SBL ROKSO spammer Steve Goudreault
KEL_MXNumberBizUS regex -aGOUDREAULT ^mx[0-9]+\.[0-9a-z]+\.(biz|us)$
R$*						$: $(EL_MXNumberBizUS $&{s} $)
RGOUDREAULT				$#error $@ 5.7.1 $: ifdef(`confEL_ErrMXNumberBizUS', `confEL_ErrMXNumberBizUS', `"550 MXNUMBZ Contact "$&{ELContactPhone}" if this is in error, but your mail was refused as suspected spam. We have never received any legitimate mail from any host with a name like yours."')
')dnl

ifdef(`_EL_CHECK_BOGUS_HELO', `dnl
# look for "helimore" spamware (uses random numerics after a set of known
# or possibly configurable strings, so needs to be a regex)
# 02/21/07 - removed "test" due to false positive
KEL_Check_BogusHELO419 regex -a<MATCH> ^(123|2mails|ab[0-9]+c|abc|adplist|afzhg|ameinfo|azhg|bol|caramail|cookbe|coolde|coolgoose|coolre|coxlde|csiitb|cta|di\-ve|dontbleftout|dontmissthis|emailwinnersclub|emarketmail|emzitd|emztd|eurosom|fastermail|fe[0-9]+son|fredrickanderson|fsmail|fubared|gawab|galmail|healthinsurance|helimore|hellrimore|heloimoex|heloimore|heythere|hotmail|imel|indxi|internationallotto|joininonit|juno|justice|laposte|latinmail|lawyer|lchost|libero|localhst|loclhst|lottery|lycos|madrid|madridspain|mail2world|mmail|mrson|msn|mxcson|netsape|netscae|netscpe|netscape|n2now|navar|nst2now|nut2now|ok|okey|okgy|okzy|omonmail|onemails|once|onmo|onmp|personal|phatomemail|qfgf|rdxx|rediffmail|rmk|sender|simbamail|sina|slickwebs|softice|somyingdd|spain|spinfinder|survey-pay|taylorsfamily|tellx|telstra|thaiservice|tiscali|tom|totalmail|twomails|visitmail|voila|vtomo|web\-mail|whipmail|winning|wwinf|yahoo|yehey|z6|zwallet)[0-9]+\.(biz|com)
R$*						$: $(EL_Check_BogusHELO419 $&{s} $)
R<MATCH>				$#error $@ 5.7.1 $: ifdef(`confEL_ErrBogusHelo419', `confEL_ErrBogusHelo419', `"550 AFFSPAM Contact "$&{ELContactPhone}" if this is in error, but your message from bogus HELO ("$&{s}") was not accepted. It is a known spam signature."')

# match Atriks.com naming conventions
KEL_Check_BogusHELOAtriks regex -a<MATCH> ^(host|mail|smtp|srvr)[adfikmpqsv]{8,10}[0-9][0-9][a-z]\.[a-z0-9\-]+\.[a-z]+
R$*						$: $(EL_Check_BogusHELOAtriks $&{s} $)
R<MATCH>				$#error $@ 5.7.1 $: ifdef(`confEL_ErrBogusHeloAtriks', `confEL_ErrBogusHeloAtriks', `"550 FOOSPAM Contact "$&{ELContactPhone}" if this is in error, but your message from bogus HELO ("$&{s}") was not accepted. It is a known spam signature."')

KEL_Check_BogusHELOAtriks2 regex -a<MATCH> ^[0-9a-z]{6}\-[0-9a-z]{1}\-[0-9a-z]{7}\-[0-9a-z]{5}\.[0-9a-z]+\.(com|net|org)
R$*						$: $(EL_Check_BogusHELOAtriks2 $&{s} $)
R<MATCH>				$#error $@ 5.7.1 $: ifdef(`confEL_ErrBogusHeloAtriks', `confEL_ErrBogusHeloAtriks', `"550 FOOSPAM Contact "$&{ELContactPhone}" if this is in error, but your message from bogus HELO ("$&{s}") was not accepted. It is a known spam signature."')
')dnl

ifdef(`_EL_CHECK_RFCBOGUS_HELO', `dnl
# still trying to identify this spamware
KEL_Check_BogusHELOWordDotNumDotNum regex -a<MATCH> ^[a-z]+\.[0-9]+\.[0-9]+$
R$*					$: $(EL_Check_BogusHELOWordDotNumDotNum $&{s} $)
ifelse(_EL_POLICY, 1, `dnl
R<$->								$: <$1> $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
R<MATCH> $| $*BOGUSHELO$* $| TAG	$: <TAGBADHELO>
R<MATCH> $| $*BOGUSHELO$* $| BLOCK	$: <REJBADHELO>
R<MATCH> $| $* +BOGUSHELO$* $| ASK	$: <TAGBADHELO>
R<MATCH> $| $* !BOGUSHELO$* $| ASK	$: <REJBADHELO>

# if no match try default policy
R$* $| $* $| $* 					$: $1 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
R<MATCH> $| $*BOGUSHELO$* $| TAG	$: <TAGBADHELO>
R<MATCH> $| $*BOGUSHELO$* $| BLOCK	$: <REJBADHELO>
R<MATCH> $| $* +BOGUSHELO$* $| ASK	$: <TAGBADHELO>
R<MATCH> $| $* !BOGUSHELO$* $| ASK	$: <REJBADHELO>
', `dnl
R<MATCH>							$: <REJBADHELO>
')dnl
R<TAGBADHELO>				$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgBogusHELO', `confEL_TagErrMsgBogusHELO', `"remote host used bogus HELO "$&{s}"."')> $| 4
R<REJBADHELO>				$#error $@ 5.7.1 $: ifdef(`confEL_ErrBogusHeloWordDotNumDotNum', `confEL_ErrBogusHeloWordDotNumDotNum', `"550 WORDNUM Contact "$&{ELContactPhone}" if this is in error, but your mail was refused because you have a misconfigured mail server (tip: fix your HELO string per RFC 2821, section 4.1.1.1)."')

KEL_Check_BogusHELONumDotNum regex -a<MATCH> ^[0-9]+\.[0-9]+$
R$*					$: $(EL_Check_BogusHELONumDotNum $&{s} $)
ifelse(_EL_POLICY, 1, `dnl
R<$->					$: <$1> $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
R<MATCH> $| $*BOGUSHELO$* $| TAG	$: <TAGBADHELO>
R<MATCH> $| $*BOGUSHELO$* $| BLOCK	$: <REJBADHELO>
R<MATCH> $| $* +BOGUSHELO$* $| ASK	$: <TAGBADHELO>
R<MATCH> $| $* !BOGUSHELO$* $| ASK	$: <REJBADHELO>

# if no match try default policy
R$* $| $* $| $* 					$: $1 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
R<MATCH> $| $*BOGUSHELO$* $| TAG	$: <TAGBADHELO>
R<MATCH> $| $*BOGUSHELO$* $| BLOCK	$: <REJBADHELO>
R<MATCH> $| $* +BOGUSHELO$* $| ASK	$: <TAGBADHELO>
R<MATCH> $| $* !BOGUSHELO$* $| ASK	$: <REJBADHELO>
', `dnl
R<MATCH>							$: <REJBADHELO>
')dnl
R<TAGBADHELO>				$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgBogusHELO', `confEL_TagErrMsgBogusHELO', `"remote host used bogus HELO "$&{s}"."')> $| 4
R<REJBADHELO>				$#error $@ 5.7.1 $: ifdef(`confEL_ErrBogusHeloNumDotNum', `confEL_ErrBogusHeloNumDotNum', `"550 NUM.NUM Contact "$&{ELContactPhone}" if this is in error, but your mail was refused because you have a misconfigured mail server (tip: fix your HELO string per RFC 2821, section 4.1.1.1)."')

ifdef(`_EL_BOGUSHELO_INTERNAL_LOCAL', `dnl
KEL_Check_BogusHELOdotInternal regex -a<MATCH> \.internal*$
R$*					$: $(EL_Check_BogusHELOdotInternal $&{s} $)
ifelse(_EL_POLICY, 1, `dnl
R<$->					$: <$1> $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
R<MATCH> $| $*BOGUSHELO$* $| TAG		$: <TAGBADHELO>
R<MATCH> $| $*BOGUSHELO$* $| BLOCK		$: <REJBADHELO>
R<MATCH> $| $* +BOGUSHELO$* $| ASK		$: <TAGBADHELO>
R<MATCH> $| $* !BOGUSHELO$* $| ASK		$: <REJBADHELO>

# if no match try default policy
R$* $| $* $| $*							$: $1 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
R<MATCH> $| $*BOGUSHELO$* $| TAG		$: <TAGBADHELO>
R<MATCH> $| $*BOGUSHELO$* $| BLOCK		$: <REJBADHELO>
R<MATCH> $| $* +BOGUSHELO$* $| ASK		$: <TAGBADHELO>
R<MATCH> $| $* !BOGUSHELO$* $| ASK		$: <REJBADHELO>
', `dnl
R<MATCH>								$: <REJBADHELO>
')dnl

R<TAGBADHELO>				$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgBogusHELO', `confEL_TagErrMsgBogusHELO', `"remote host used bogus HELO "$&{s}"."')> $| 3
R<REJBADHELO>				$#error $@ 5.7.1 $: ifdef(`confEL_ErrBogusHeloDotInternal', `confEL_ErrBogusHeloDotInternal', `"550 INTERNL Contact "$&{ELContactPhone}" if this is in error, but your mail was refused because you have a misconfigured mail server (tip: fix your HELO string per RFC 2821, section 4.1.1.1)."')

KEL_Check_BogusHELOdotLocal regex -a<MATCH> \.local[e]*$
R$*					$: $(EL_Check_BogusHELOdotLocal $&{s} $)
ifelse(_EL_POLICY, 1, `dnl
R<$->					$: <$1> $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
R<MATCH> $| $*BOGUSHELO$* $| TAG		$: <TAGBADHELO>
R<MATCH> $| $*BOGUSHELO$* $| BLOCK		$: <REJBADHELO>
R<MATCH> $| $* +BOGUSHELO$* $| ASK		$: <TAGBADHELO>
R<MATCH> $| $* !BOGUSHELO$* $| ASK		$: <REJBADHELO>

# if no match try default policy
R$* $| $* $| $*							$: $1 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
R<MATCH> $| $*BOGUSHELO$* $| TAG		$: <TAGBADHELO>
R<MATCH> $| $*BOGUSHELO$* $| BLOCK		$: <REJBADHELO>
R<MATCH> $| $* +BOGUSHELO$* $| ASK		$: <TAGBADHELO>
R<MATCH> $| $* !BOGUSHELO$* $| ASK		$: <REJBADHELO>
', `dnl
R<MATCH>								$: <REJBADHELO>
')dnl
R<TAGBADHELO>				$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgBogusHELO', `confEL_TagErrMsgBogusHELO', `"remote host used bogus HELO "$&{s}"."')> $| 3
R<REJBADHELO>				$#error $@ 5.7.1 $: ifdef(`confEL_ErrBogusHeloDotLocal', `confEL_ErrBogusHeloDotLocal', `"550 DOTLOCL Contact "$&{ELContactPhone}" if this is in error, but your mail was refused because you have a misconfigured mail server (tip: fix your HELO string per RFC 2821, section 4.1.1.1)."')
')dnl

KEL_Check_BogusHELODottedIP regex -a<MATCH> ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$
R$*					$: $(EL_Check_BogusHELODottedIP $&{s} $)
ifdef(`_EL_REPORT_ABUSE', `dnl
R<MATCH>			$: <MATCH> $| $&{ELAbuseContact}
R<MATCH> $| NONE	$: <MATCH>
R<MATCH> $| $+		$: <MATCH> $(EL_Log "EL Report to "$1": claimed to be "$&{s}"; from "$&{mail_addr}" to "$&{rcpt_addr}" from "$&{client_name}" ["$&{client_addr}"]" $)
')dnl
ifelse(_EL_POLICY, 1, `dnl
R<$->					$: <$1> $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
R<MATCH> $| $*BOGUSHELO$* $| TAG	$: <TAGBADHELO>
R<MATCH> $| $*BOGUSHELO$* $| BLOCK	$: <REJBADHELO>
R<MATCH> $| $* +BOGUSHELO$* $| ASK	$: <TAGBADHELO>
R<MATCH> $| $* !BOGUSHELO$* $| ASK	$: <REJBADHELO>

# if no match try default policy
R$* $| $* $| $*						$: $1 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
R<MATCH> $| $*BOGUSHELO$* $| TAG	$: <TAGBADHELO>
R<MATCH> $| $*BOGUSHELO$* $| BLOCK	$: <REJBADHELO>
R<MATCH> $| $* +BOGUSHELO$* $| ASK	$: <TAGBADHELO>
R<MATCH> $| $* !BOGUSHELO$* $| ASK	$: <REJBADHELO>
', `dnl
R<MATCH>							$: <REJBADHELO>
')dnl

R<TAGBADHELO>				$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgBogusHELO', `confEL_TagErrMsgBogusHELO', `"remote host used bogus HELO "$&{s}"."')> $| 3
R<REJBADHELO>				$#error $@ 5.7.1 $: ifdef(`confEL_ErrBogusHeloDottedIP', `confEL_ErrBogusHeloDottedIP', `"550 DOTQUAD Contact "$&{ELContactPhone}" if this is in error, but we do not accept mail from servers that use bogus HELO strings like " $&{s} " (see RFC 2821, section 4.1.1.1)."')

# sony and HP apparently ship with "your-0xdeadbeef" default names 
# (your- followed by ten hex digits) ??? maybe need a specific check
# for those? they still fall under this check anyway.
KEL_Check_BogusHELONetBIOS regex -a<MATCH> ^\.*[-0-_]+\.*$
R$*					$: $(EL_Check_BogusHELONetBIOS $&{s} $)
ifdef(`_EL_REPORT_ABUSE', `dnl
R<MATCH>			$: <MATCH> $| $&{ELAbuseContact}
R<MATCH> $| NONE	$: <MATCH>
R<MATCH> $| $+		$: <MATCH> $(EL_Log "EL Report to "$1": claimed to be "$&{s}"; from "$&{mail_addr}" to "$&{rcpt_addr}" from "$&{client_name}" ["$&{client_addr}"]" $)
')dnl
ifelse(_EL_POLICY, 1, `dnl
R<$->					$: <$1> $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
R<MATCH> $| $*BOGUSHELO$* $| TAG	$: <TAGBADHELO>
R<MATCH> $| $*BOGUSHELO$* $| BLOCK	$: <REJBADHELO>
R<MATCH> $| $* +BOGUSHELO$* $| ASK	$: <TAGBADHELO>
R<MATCH> $| $* !BOGUSHELO$* $| ASK	$: <REJBADHELO>

# if no match try default policy
R$* $| $* $| $* 					$: $1 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
R<MATCH> $| $*BOGUSHELO$* $| TAG	$: <TAGBADHELO>
R<MATCH> $| $*BOGUSHELO$* $| BLOCK	$: <REJBADHELO>
R<MATCH> $| $* +BOGUSHELO$* $| ASK	$: <TAGBADHELO>
R<MATCH> $| $* !BOGUSHELO$* $| ASK	$: <REJBADHELO>
', `dnl
R<MATCH>							$: <REJBADHELO>
')dnl
R<TAGBADHELO>				$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgBogusHELO', `confEL_TagErrMsgBogusHELO', `"remote host used bogus HELO "$&{s}"."')> $| 3
R<REJBADHELO>				$#error $@ 5.7.1 $: ifdef(`confEL_ErrBogusHeloNetbios', `confEL_ErrBogusHeloNetbios', `"550 NETBIOS Contact "$&{ELContactPhone}" if this is in error, but we do not accept mail from servers that use bogus HELO strings like " $&{s} " (see RFC 2821, section 4.1.1.1)."')
')dnl

ifdef(`_EL_TAG_HELO_BRACKETED_IP', `dnl
R$*									$: $(EL_IsAnIP $&{s} $)
R<IP>								$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgBracketedIPHELO', `confEL_TagErrMsgBracketedIPHELO', `"remote host used bracketed IP as HELO"')> $| 1
')dnl

ifdef(`_EL_ACCEPT_ALL_LOCAL_ROLE_ACCTS', `dnl
R$*									$: $&{EL_CurrRcpt}
# accept all abuse|postmaster-addressed mail to local domains
R$*									$: $>canonify $1
ifdef(`_EL_TENTATIVE_ROLEACCTS', `dnl
# ??? bug: should be configurable via m4
# but here we only accept abuse if it does not fail any other checks
Rabuse <@ $=w . >					$: OKSOFAR
Rpostmaster <@ $=w . >				$#OK
', `dnl
Rabuse <@ $=w . >					$#OK
Rpostmaster <@ $=w . >				$#OK
')dnl
')dnl

ifdef(`_EL_BOGUS_BIGISP_HELO', `dnl
# 
# bogus HELOs used by recent spamware (DMS?) e.g.
#
# aupeqjh.uaie.optonline.net
# j5bgaucc.uuzo.verizon.net
# eql24fo.8e8u02.adelphia.net
# qzvfa71.ueaoxov0.rr.com
# slquqabi.e9aeuio.comcast.net
# pov1eir.om4a008.cox.net
# v6dzm9k.umfkzmu.ameritech.net
# iv3hz6a.nfiffo.adelphia.net
# m4ueeic.eqwen5o.ameritech.net
# 3oatjs7.a50i.verizon.net
# 1ielaaf.cia9ot.optonline.net
# oomw0gi6.u3ok.optonline.net
# dhvvk0.nxoqaas.rr.com
# csii4.xh3ne3l.comcast.net
# 2oa4l.8iau3q.aol.com
# a6ee44i.109i.cox.net
# iboe7.iutumi.adelphia.net

# FP potential:
# mailhost.chi1.ameritech.net (mailhost1-chcgil.chcgil.ameritech.net [206.141.192.67])
# mailhost.bcv1.ameritech.net (mailhost1-bcvloh.bcvloh.ameritech.net [66.73.20.42])
# mailout5.nyroc.rr.com (mailout5-1.nyroc.rr.com [24.92.226.169])
#
# So we have to compare the domains - if they match it is 
# likely okay or at least rare enough to let it go for now
KEL_Check_BogusHELOBigISP regex -a<HELO> -s1 ^[a-z0-9]{5,8}\.[a-z0-9]{4,8}\.(adelphia\.net|ameritech\.net|aol\.com|comcast\.net|cox\.net|optonline\.net|rr\.com|verizon\.net)$
KEL_GetSenderDomain regex -a<DOM> -s1 \.([a-z0-9\-]+\.([a-z]{2}|com\.[a-z]{2}|net\.[a-z]{2}|com|net))

# ??? bug here. when the client_name is not present due to lack of RCrDNS
# the GetSenderDomain fails and so the comparison also fails
# need to check client_rdns?

R$*					$: $(EL_Check_BogusHELOBigISP $&{s} $) $| $(EL_GetSenderDomain $&{client_name} $) $(EL_Log "EL helocheck " $&{s} " / " $&{client_name} $)
# returns e.g.         adelphia.net<HELO>                     adelphia.net<DOM>
#  or
#                      adelphia.net<HELO>                     notadelphia.net<DOM>

R$-.$-<HELO> $| [$-.$-.$-.$-]		$: $(EL_Check_BogusHELOBigISP $&{s} $) $| $(EL_GetSenderDomain $&{client_ptr} $) $(EL_Log "EL helocheck non-FCrDNS " $&{s} " / " $&{client_ptr} $)

ifelse(_EL_POLICY, 1, `dnl
# /- adelphia.net ------------------------------------\
# |           /- adelphia.net<DOM> OR not<DOM> --\    |
# |           |                                  |    |
# |           |                                  |    |
R$-.$-<HELO> $| $-.$+<DOM>			$: <HELO> $| $3.$4<CHECK> $| $1.$2<CHECK>

# so we swap them and set a macro to compare them
#          H     D                     D     H   and set the macro to H, which is $1 now
R<HELO> $| $+ $| $+					$: $2 $| $1 $(EL_SetVar {ELhelodom} $@ $1 $) $(EL_Log "EL helocheck " $1 "/" $2 " from " $&{s} $)

# if real domain D matches HELO domain H we need to skip NOT reject
R$&{ELhelodom} $| $+				$: <MATCH>

R$-.$+<CHECK> $| $-.$+<CHECK>		$: <NOMATCH> $| $&{ELPolicyUser} $| $&{ELPolicySwitch}

R<NOMATCH> $| $*BOGUSHELO$* $| TAG		$: <TAGBADHELO>
R<NOMATCH> $| $*BOGUSHELO$* $| BLOCK	$: <REJBADHELO>
R<NOMATCH> $| $* +BOGUSHELO$* $| ASK	$: <TAGBADHELO>
R<NOMATCH> $| $* !BOGUSHELO$* $| ASK	$: <REJBADHELO>

# if no match try default policy
R$* $| $* $| $* 						$: $1 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
R<NOMATCH> $| $*BOGUSHELO$* $| TAG		$: <TAGBADHELO>
R<NOMATCH> $| $*BOGUSHELO$* $| BLOCK	$: <REJBADHELO>
R<NOMATCH> $| $* +BOGUSHELO$* $| ASK	$: <TAGBADHELO>
R<NOMATCH> $| $* !BOGUSHELO$* $| ASK	$: <REJBADHELO>
', `dnl
R<NOMATCH>								$: <REJBADHELO>
')dnl
R<TAGBADHELO>				$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgBogusHELO', `confEL_TagErrMsgBogusHELO', `"remote host used bogus HELO "$&{s}"."')> $| 4
R<REJBADHELO>				$#error $@ 5.7.1 $: ifdef(`confEL_ErrBogusHeloBigISP', `confEL_ErrBogusHeloBigISP', `"550 ISPHELO Contact "$&{ELContactPhone}" if this is in error, but we do not accept mail from servers that forge their HELO like " $&{s}')

R<MATCH>					$: $&{EL_CurrRcpt} $(EL_SetVar {ELhelodom} $@ "<>" $)
')dnl

ifdef(`_EL_BOUNCERS', `dnl
# reject all mail whose sender is the null sender IFF it is from one of these
# servers or domains, which are accepting-then-bouncing forged mail
KEL_BouncerSenderAddys1 regex -aFROMBOUNCER -f ^(Admin(istrator)?|Auto\-Mai\ler|postmaster|mailerdaemon|mmdf|nobody|mailadmin|webmaster|administrator|root|virus_alert|responder|spamdefender|BCM_SMTP_Gateways|contentsecurity|responder|MAI\L\ER-IMP|email_admin|Mailer-Daemon|MAI\LER-DAEMON|mmdf|no\-reply|autoresponse\-bounce|Customer_Service|no-reply-necessary|PageUp_Virus_Gateway|AntiVirus\-System|Krieger_Worldwide_E_Mail_Filter|InternetAdmin|Postmaster|nondelivery|badmail|theremail|attention\-nospam|MDaemon|eSafe|undeliverable|.?Mail\ Monitoring.?|mailmarshal|devnull|null|spampostmaster|No\.Sender|spammgr|admin|spamwatch)@
KEL_BouncerSenderAddys2 regex -aFROMBOUNCER -f (confirm-return|InterscanVirusWall|JCT_AntiVirus_System|Network.*Associates.*Webshield|Symantec_AntiVirus_for_SMTP_Gateway|MAILE\R\-DAEMON|noreply|Antivirus/SPAM_Alert|DrWeb|antivirus|dontreply|DO_NOT_REPLY|spamblocker-challenge|interner-SMTP-Backbone-Service|Antivirus_Mail_Administrator|eSafe|IMCEAGWISE|SMTP_Mail_Service|AntiVirus_Gateway|AV_Gateway|mailto|securiQ\.Watchdog|Antigen|(av|mail|AntiVirus|Mail|SMTP)[-_][gG]ateway).*@

KEL_BouncerSenderAddysSeq sequence EL_BouncerSenderAddys1 EL_BouncerSenderAddys2
')dnl

ifdef(`_EL_OUTSCATTER', `dnl
KEL_OutscatterSenderAddys_1  regex -a<SCAT> ^<?>?$
KEL_OutscatterSenderAddys_2  regex -a<SCAT> postmaster
KEL_OutscatterSenderAddys_3  regex -a<SCAT> notify 
KEL_OutscatterSenderAddys_4  regex -a<SCAT> mailman\-bounces
KEL_OutscatterSenderAddys_5  regex -a<SCAT> root
KEL_OutscatterSenderAddys_6  regex -a<SCAT> admin
KEL_OutscatterSenderAddys_7  regex -a<SCAT> spam
KEL_OutscatterSenderAddys_8  regex -a<SCAT> reply
KEL_OutscatterSenderAddys_9  regex -a<SCAT> (norton|notes|symantec)
KEL_OutscatterSenderAddys_10 regex -a<SCAT> devnull
KEL_OutscatterSenderAddys_11 regex -a<SCAT> admin

KEL_OutscatterSenderAddysSeq sequence EL_OutscatterSenderAddys_1 EL_OutscatterSenderAddys_2 EL_OutscatterSenderAddys_3 EL_OutscatterSenderAddys_4 EL_OutscatterSenderAddys_5 EL_OutscatterSenderAddys_6 EL_OutscatterSenderAddys_7 EL_OutscatterSenderAddys_8 EL_OutscatterSenderAddys_9 EL_OutscatterSenderAddys_10 EL_OutscatterSenderAddys_11
')dnl

ifdef(`_EL_BLOCK_BARRACUDA', `dnl
# ??? may need to disable for now due to use of BSAs as outbound relays
KEL_CheckBarracuda regex -a<MATCH> ^barracuda\.
R$*					$: $(EL_CheckBarracuda $&{s} $)
ifdef(`_EL_REPORT_ABUSE', `dnl
R<MATCH> 			$: <MATCH> $| $&{ELAbuseContact}
R<MATCH> $| NONE	$: <MATCH>
R<MATCH> $| $+		$: <MATCH> $(EL_Log "EL Report to "$1": claimed to be "$&{s}"; from "$&{mail_addr}" to "$&{rcpt_addr}" from "$&{client_name}" ["$&{client_addr}"]" $)
')dnl

ifelse(_EL_POLICY, 1, `dnl
ifelse(_EL_BOUNCERS, 1, `dnl
R<$->					$: <$1> $| $(EL_BouncerSenderAddysSeq $&{mail_addr} $) $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
R<MATCH> $| BOUNCER $| $*BRACUDA$* $| TAG		$: <TAGBRCDA>
R<MATCH> $| BOUNCER $| $*BRACUDA$* $| BLOCK		$: <REJBRCDA>
R<MATCH> $| BOUNCER $| $* +BRACUDA$* $| ASK		$: <TAGBRCDA>
R<MATCH> $| BOUNCER $| $* !BRACUDA$* $| ASK		$: <REJBRCDA>

# if no match try default policy
R$* $| $* $| $* $| $* 							$: $1 $| $2 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
R<MATCH> $| BOUNCER $| $*BRACUDA$* $| TAG		$: <TAGBRCDA>
R<MATCH> $| BOUNCER $| $*BRACUDA$* $| BLOCK		$: <REJBRCDA>
R<MATCH> $| BOUNCER $| $* +BRACUDA$* $| ASK		$: <TAGBRCDA>
R<MATCH> $| BOUNCER $| $* !BRACUDA$* $| ASK		$: <REJBRCDA>
', _EL_OUTSCATTER, 1, `dnl
R<$->					$: <$1> $| $(EL_OutscatterSenderAddysSeq $&{mail_addr} $) $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
R<MATCH> $| <SCAT> $| $* +BRACUDA$* $| ASK		$: <TAGBRCDA>
R<MATCH> $| <SCAT> $| $* !BRACUDA$* $| ASK		$: <REJBRCDA>

# if no match try default policy
R$* $| $* $| $* $| $* 							$: $1 $| $2 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
R<MATCH> $| <SCAT> $| $* +BRACUDA$* $| ASK		$: <TAGBRCDA>
R<MATCH> $| <SCAT> $| $* !BRACUDA$* $| ASK		$: <REJBRCDA>
', `dnl
R<$->					$: <$1> $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
R<MATCH> $| $*BRACUDA$* $| TAG					$: <TAGBRCDA>
R<MATCH> $| $*BRACUDA$* $| BLOCK				$: <REJBRCDA>
R<MATCH> $| $* +BRACUDA$* $| ASK				$: <TAGBRCDA>
R<MATCH> $| $* !BRACUDA$* $| ASK				$: <REJBRCDA>

# if no match try default policy
R$* $| $* $| $* 		$: $1 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
R<MATCH> $| $*BRACUDA$* $| TAG					$: <TAGBRCDA>
R<MATCH> $| $*BRACUDA$* $| BLOCK				$: <REJBRCDA>
R<MATCH> $| $* +BRACUDA$* $| ASK				$: <TAGBRCDA>
R<MATCH> $| $* !BRACUDA$* $| ASK				$: <REJBRCDA>
')
', `dnl
R<MATCH>										$: <REJBRCDA>
')dnl
R<TAGBRCDA>				$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgBarracuda', `confEL_TagErrMsgBarracuda', `"remote host may be running a barracuda spam appliance."')> $| 1
R<REJBRCDA>				$#error $@ 5.7.1 $: ifdef(`confEL_ErrBarracuda', `confEL_ErrBarracuda', `"550 BRACUDA Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail from servers running Barracuda spam appliances. When we do it is always outscatter."')
')dnl

# ??? was bogus rdns check - now in EL_Check_Eoh

ifdef(`_EL_PHISH', `dnl
R$*				$: $(EL_IsAnIP $&{client_name} $) $| $(EL_IsAnIP $&{client_ptr} $)
R<IP> $| <IP>	$: $(EL_SetVar {ELPhishProperOrigin} $@ NO $) 
R<IP> $| $-		$: $(EL_PhishProperOriginDomains $&{client_ptr} $) 
R$- $| <IP>		$: $(EL_PhishProperOriginDomains $&{client_name} $) 
R$+ $| $+		$: $(EL_PhishProperOriginDomains $&{client_ptr} $) 
R$+ $| $+		$: $(EL_PhishProperOriginDomains $&{client_name} $) 
RYES			$: $(EL_SetVar {ELPhishProperOrigin} $@ YES $) $(EL_Log "EL ELPhishProperOrigin (YES)" $)
R$+				$: $(EL_SetVar {ELPhishProperOrigin} $@ NO $) $(EL_Log "EL ELPhishProperOrigin (NO)" $)
')dnl

ifdef(`_EL_BOUNCERS', `dnl
# NOTE: EL_BouncerSenderAddysSeq K map definition is found earlier in the file
ifdef(`_EL_POLICY', `dnl
# check sender against list of outscatter senders and hosts and reject
R$*						$: $(EL_Bouncer $&{client_name} $) $| $(EL_BouncerSenderAddysSeq $&{mail_addr} $) $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
RB$* $| $@ $| $*BOUNCER$* $| TAG					$: <TAGBOUNCER>
RB$* $| $@ $| $*BOUNCER$* | BLOCK					$: <REJBOUNCER>
RB$* $| $@ $| $* +BOUNCER $* $| ASK					$: <TAGBOUNCER>
RB$* $| $@ $| $* !BOUNCER $* $| ASK					$: <REJBOUNCER>
RB$* $| FROMBOUNCER $| $*BOUNCER$* $| TAG			$: <TAGBOUNCER>
RB$* $| FROMBOUNCER $| $*BOUNCER$* | BLOCK			$: <REJBOUNCER>
RB$* $| FROMBOUNCER $| $* +BOUNCER $* $| ASK		$: <TAGBOUNCER>
RB$* $| FROMBOUNCER $| $* !BOUNCER $* $| ASK		$: <REJBOUNCER>

# if no match try default policy
R$* $| $* $| $* $| $* 								$: $1 $| $2 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
RB$* $| $@ $| $*BOUNCER$* $| TAG					$: <TAGBOUNCER>
RB$* $| $@ $| $*BOUNCER$* | BLOCK					$: <REJBOUNCER>
RB$* $| $@ $| $* +BOUNCER $* $| ASK					$: <TAGBOUNCER>
RB$* $| $@ $| $* !BOUNCER $* $| ASK					$: <REJBOUNCER>
RB$* $| FROMBOUNCER $| $*BOUNCER$* $| TAG			$: <TAGBOUNCER>
RB$* $| FROMBOUNCER $| $*BOUNCER$* | BLOCK			$: <REJBOUNCER>
RB$* $| FROMBOUNCER $| $* +BOUNCER $* $| ASK		$: <TAGBOUNCER>
RB$* $| FROMBOUNCER $| $* !BOUNCER $* $| ASK		$: <REJBOUNCER>

R<TAGBOUNCER>				$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgBouncer', `confEL_TagErrMsgBouncer', `"Possible outscatter message from known insecure host"')> $| 3
R<REJBOUNCER>				$#error $@ 5.7.1 $: ifdef(`confEL_ErrBouncerName', `confEL_ErrBouncerName', `"550 BOUNCER Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail from your null sender; your system is broken and sending us bounces from forged mail we didnt send."') 

# now check for just the domain (assume domain.tld for now)
R$*						$: $&{client_name}
R$*.$+.$+				$: $(EL_Bouncer $2.$3 $) $| $(EL_BouncerSenderAddysSeq $&{mail_addr} $) $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
RB$* $| $@ $| $*BOUNCER$* $| TAG					$: <TAGBOUNCER>
RB$* $| $@ $| $*BOUNCER$* | BLOCK					$: <REJBOUNCER>
RB$* $| $@ $| $* +BOUNCER $* $| ASK					$: <TAGBOUNCER>
RB$* $| $@ $| $* !BOUNCER $* $| ASK					$: <REJBOUNCER>
RB$* $| FROMBOUNCER $| $*BOUNCER$* $| TAG			$: <TAGBOUNCER>
RB$* $| FROMBOUNCER $| $*BOUNCER$* | BLOCK			$: <REJBOUNCER>
RB$* $| FROMBOUNCER $| $* +BOUNCER $* $| ASK		$: <TAGBOUNCER>
RB$* $| FROMBOUNCER $| $* !BOUNCER $* $| ASK		$: <REJBOUNCER>

# if no match try default policy
R$* $| $* $| $* $| $* 								$: $1 $| $2 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
RB$* $| $@ $| $*BOUNCER$* $| TAG					$: <TAGBOUNCER>
RB$* $| $@ $| $*BOUNCER$* | BLOCK					$: <REJBOUNCER>
RB$* $| $@ $| $* +BOUNCER $* $| ASK					$: <TAGBOUNCER>
RB$* $| $@ $| $* !BOUNCER $* $| ASK					$: <REJBOUNCER>
RB$* $| FROMBOUNCER $| $*BOUNCER$* $| TAG			$: <TAGBOUNCER>
RB$* $| FROMBOUNCER $| $*BOUNCER$* | BLOCK			$: <REJBOUNCER>
RB$* $| FROMBOUNCER $| $* +BOUNCER $* $| ASK		$: <TAGBOUNCER>
RB$* $| FROMBOUNCER $| $* !BOUNCER $* $| ASK		$: <REJBOUNCER>

R<TAGBOUNCER>				$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgBouncer', `confEL_TagErrMsgBouncer', `"Possible outscatter message from known insecure host"')> $| 3
R<REJBOUNCER>				$#error $@ 5.7.1 $: ifdef(`confEL_ErrBouncerName', `confEL_ErrBouncerName', `"550 BOUNCER Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail from your null sender; your system is broken and sending us bounces from forged mail we didnt send."') 

# now check for just the domain (assume domain.co.tld for now)
R$*						$: $&{client_name}
R$*.$+.$+.$+			$: $(EL_Bouncer $2.$3.$4 $) $| $(EL_BouncerSenderAddysSeq $&{mail_addr} $) $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
RB$* $| $@ $| $*BOUNCER$* $| TAG					$: <TAGBOUNCER>
RB$* $| $@ $| $*BOUNCER$* | BLOCK					$: <REJBOUNCER>
RB$* $| $@ $| $* +BOUNCER $* $| ASK					$: <TAGBOUNCER>
RB$* $| $@ $| $* !BOUNCER $* $| ASK					$: <REJBOUNCER>
RB$* $| FROMBOUNCER $| $*BOUNCER$* $| TAG			$: <TAGBOUNCER>
RB$* $| FROMBOUNCER $| $*BOUNCER$* | BLOCK			$: <REJBOUNCER>
RB$* $| FROMBOUNCER $| $* +BOUNCER $* $| ASK		$: <TAGBOUNCER>
RB$* $| FROMBOUNCER $| $* !BOUNCER $* $| ASK		$: <REJBOUNCER>

# if no match try default policy
R$* $| $* $| $* $| $* 								$: $1 $| $2 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
RB$* $| $@ $| $*BOUNCER$* $| TAG					$: <TAGBOUNCER>
RB$* $| $@ $| $*BOUNCER$* | BLOCK					$: <REJBOUNCER>
RB$* $| $@ $| $* +BOUNCER $* $| ASK					$: <TAGBOUNCER>
RB$* $| $@ $| $* !BOUNCER $* $| ASK					$: <REJBOUNCER>
RB$* $| FROMBOUNCER $| $*BOUNCER$* $| TAG			$: <TAGBOUNCER>
RB$* $| FROMBOUNCER $| $*BOUNCER$* | BLOCK			$: <REJBOUNCER>
RB$* $| FROMBOUNCER $| $* +BOUNCER $* $| ASK		$: <TAGBOUNCER>
RB$* $| FROMBOUNCER $| $* !BOUNCER $* $| ASK		$: <REJBOUNCER>

R<TAGBOUNCER>				$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgBouncer', `confEL_TagErrMsgBouncer', `"Possible outscatter message from known insecure host"')> $| 3
R<REJBOUNCER>				$#error $@ 5.7.1 $: ifdef(`confEL_ErrBouncerName', `confEL_ErrBouncerName', `"550 BOUNCER Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail from your null sender; your system is broken and sending us bounces from forged mail we didnt send."') 

# now check for HELO

R$*						$: $(EL_Bouncer $&{s} $) $| $(EL_BouncerSenderAddysSeq $&{mail_addr} $) $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
RB$* $| $@ $| $*BOUNCER$* $| TAG					$: <TAGBOUNCER>
RB$* $| $@ $| $*BOUNCER$* | BLOCK					$: <REJBOUNCER>
RB$* $| $@ $| $* +BOUNCER $* $| ASK					$: <TAGBOUNCER>
RB$* $| $@ $| $* !BOUNCER $* $| ASK					$: <REJBOUNCER>
RB$* $| FROMBOUNCER $| $*BOUNCER$* $| TAG			$: <TAGBOUNCER>
RB$* $| FROMBOUNCER $| $*BOUNCER$* | BLOCK			$: <REJBOUNCER>
RB$* $| FROMBOUNCER $| $* +BOUNCER $* $| ASK		$: <TAGBOUNCER>
RB$* $| FROMBOUNCER $| $* !BOUNCER $* $| ASK		$: <REJBOUNCER>

# if no match try default policy
R$* $| $* $| $* $| $* 								$: $1 $| $2 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
RB$* $| $@ $| $*BOUNCER$* $| TAG					$: <TAGBOUNCER>
RB$* $| $@ $| $*BOUNCER$* | BLOCK					$: <REJBOUNCER>
RB$* $| $@ $| $* +BOUNCER $* $| ASK					$: <TAGBOUNCER>
RB$* $| $@ $| $* !BOUNCER $* $| ASK					$: <REJBOUNCER>
RB$* $| FROMBOUNCER $| $*BOUNCER$* $| TAG			$: <TAGBOUNCER>
RB$* $| FROMBOUNCER $| $*BOUNCER$* | BLOCK			$: <REJBOUNCER>
RB$* $| FROMBOUNCER $| $* +BOUNCER $* $| ASK		$: <TAGBOUNCER>
RB$* $| FROMBOUNCER $| $* !BOUNCER $* $| ASK		$: <REJBOUNCER>

R<TAGBOUNCER>				$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgBouncer', `confEL_TagErrMsgBouncer', `"Possible outscatter message from known insecure host"')> $| 3
R<REJBOUNCER>				$#error $@ 5.7.1 $: ifdef(`confEL_ErrBouncerHelo', `confEL_ErrBouncerHelo', `"550 BNCHELO Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail from your null sender; your system is broken and sending us bounces from forged mail we didnt send."')

# now check whether this address should be getting bounces at all
R$*										$: $(EL_BouncerSenderAddysSeq $&{mail_addr} $) $| $&{ELPolicyUser} $| $&{ELPolicySwitch}

RFROMBOUNCER $| $*NOBOUNCE$* $| TAG		$: <TAGBOUNCER> 
RFROMBOUNCER $| $*NOBOUNCE$* $| BLOCK	$: <REJBOUNCER>
RFROMBOUNCER $| $* +NOBOUNCE$* $| ASK 	$: <TAGBOUNCER>
RFROMBOUNCER $| $* !NOBOUNCE$* $| ASK 	$: <REJBOUNCER>

# and check for null sender
R$@ $| $*NOBOUNCE$* $| TAG				$: <TAGBOUNCER>
R$@ $| $*NOBOUNCE$* $| BLOCK			$: <REJBOUNCER>
R$@ $| $* +NOBOUNCE$* $| ASK 			$: <TAGBOUNCER>
R$@ $| $* !NOBOUNCE$* $| ASK 			$: <REJBOUNCER>

# if no match try default policy
R$* $| $* $| $* 						$: $1 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
RFROMBOUNCER $| $*NOBOUNCE$* $| TAG		$: <TAGBOUNCER> 
RFROMBOUNCER $| $*NOBOUNCE$* $| BLOCK	$: <REJBOUNCER>
RFROMBOUNCER $| $* +NOBOUNCE$* $| ASK 	$: <TAGBOUNCER>
RFROMBOUNCER $| $* !NOBOUNCE$* $| ASK 	$: <REJBOUNCER>

# and check for null sender
R$@ $| $*NOBOUNCE$* $| TAG				$: <TAGBOUNCER>
R$@ $| $*NOBOUNCE$* $| BLOCK			$: <REJBOUNCER>
R$@ $| $* +NOBOUNCE$* $| ASK 			$: <TAGBOUNCER>
R$@ $| $* !NOBOUNCE$* $| ASK 			$: <REJBOUNCER>

R<TAGBOUNCER>					$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgNobounce', `confEL_TagErrMsgNobounce', `"Bounce message sent to address that sends no mail"')> $| 4
R<REJBOUNCER>					$#error $@ 5.7.1 $: ifdef(`confEL_ErrNoBounce', `confEL_ErrNoBounce', `"550 NOBOUNCE Contact "$&{ELContactEmail}" if this is in error, but you are sending bounces to an address that sends no mail."')
')dnl
')dnl

ifdef(`_EL_OUTSCATTER', `dnl
# NOTE: EL_OutscatterSenderAddysSeq K map definition is found earlier in the file
ifdef(`_EL_POLICY', `dnl
# check sender against list of outscatter senders and hosts and reject
# do them one at a time here so as to avoid rejection by entire class of
# outscatter senders on all known outscatter hosts
R$*			$: $1 $| $(EL_Outscatter $&{client_name} $) $| $(EL_OutscatterSenderAddysSeq $&{mail_addr} $) 
R$* $| $* $| $*		$: $1 $| $(EL_Log "EL outscatter: " $&{client_name} " / " $&{mail_addr} " / " $2 " / " $3  "." $)
R$* $| $*		$: $1

R$* 					$: <O> $| $(EL_Outscatter $&{client_name} $) $| $(EL_OutscatterSenderAddys_1 $&{mail_addr} $) $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
R<O> $| O1$* $| $@ $| $* +BOUNCER $* $| ASK			$: <TAGBOUNCER>
R<O> $| O1$* $| $@ $| $* !BOUNCER $* $| ASK			$: <REJBOUNCER>
R<O> $| O1$* $| <SCAT> $| $* +BOUNCER $* $| ASK		$: <TAGBOUNCER>
R<O> $| O1$* $| <SCAT> $| $* !BOUNCER $* $| ASK		$: <REJBOUNCER>

R<O> $| $*				$: <O> $| $(EL_Outscatter $&{client_name} $) $| $(EL_OutscatterSenderAddys_2 $&{mail_addr} $) $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
R<O> $| $*O2$* $| <SCAT> $| $* +BOUNCER $* $| ASK		$: <TAGBOUNCER>
R<O> $| $*O2$* $| <SCAT> $| $* !BOUNCER $* $| ASK		$: <REJBOUNCER>

R<O> $| $*				$: <O> $| $(EL_Outscatter $&{client_name} $) $| $(EL_OutscatterSenderAddys_3 $&{mail_addr} $) $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
R<O> $| $*O3$* $| <SCAT> $| $* +BOUNCER $* $| ASK		$: <TAGBOUNCER>
R<O> $| $*O3$* $| <SCAT> $| $* !BOUNCER $* $| ASK		$: <REJBOUNCER>

R<O> $| $*				$: <O> $| $(EL_Outscatter $&{client_name} $) $| $(EL_OutscatterSenderAddys_4 $&{mail_addr} $) $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
R<O> $| $*O4$* $| <SCAT> $| $* +BOUNCER $* $| ASK		$: <TAGBOUNCER>
R<O> $| $*O4$* $| <SCAT> $| $* !BOUNCER $* $| ASK		$: <REJBOUNCER>

R<O> $| $*				$: <O> $| $(EL_Outscatter $&{client_name} $) $| $(EL_OutscatterSenderAddys_5 $&{mail_addr} $) $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
R<O> $| $*O5$* $| <SCAT> $| $* +BOUNCER $* $| ASK		$: <TAGBOUNCER>
R<O> $| $*O5$* $| <SCAT> $| $* !BOUNCER $* $| ASK		$: <REJBOUNCER>

R<O> $| $*				$: <O> $| $(EL_Outscatter $&{client_name} $) $| $(EL_OutscatterSenderAddys_6 $&{mail_addr} $) $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
R<O> $| $*O6$* $| <SCAT> $| $* +BOUNCER $* $| ASK		$: <TAGBOUNCER>
R<O> $| $*O6$* $| <SCAT> $| $* !BOUNCER $* $| ASK		$: <REJBOUNCER>

R<O> $| $*				$: <O> $| $(EL_Outscatter $&{client_name} $) $| $(EL_OutscatterSenderAddys_7 $&{mail_addr} $) $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
R<O> $| $*O7$* $| <SCAT> $| $* +BOUNCER $* $| ASK		$: <TAGBOUNCER>
R<O> $| $*O7$* $| <SCAT> $| $* !BOUNCER $* $| ASK		$: <REJBOUNCER>

R<O> $| $*				$: <O> $| $(EL_Outscatter $&{client_name} $) $| $(EL_OutscatterSenderAddys_8 $&{mail_addr} $) $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
R<O> $| $*O8$* $| <SCAT> $| $* +BOUNCER $* $| ASK		$: <TAGBOUNCER>
R<O> $| $*O8$* $| <SCAT> $| $* !BOUNCER $* $| ASK		$: <REJBOUNCER>

R<O> $| $*				$: <O> $| $(EL_Outscatter $&{client_name} $) $| $(EL_OutscatterSenderAddys_9 $&{mail_addr} $) $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
R<O> $| $*O9$* $| <SCAT> $| $* +BOUNCER $* $| ASK		$: <TAGBOUNCER>
R<O> $| $*O9$* $| <SCAT> $| $* !BOUNCER $* $| ASK		$: <REJBOUNCER>

R<O> $| $*				$: <O> $| $(EL_Outscatter $&{client_name} $) $| $(EL_OutscatterSenderAddys_10 $&{mail_addr} $) $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
R<O> $| $*O10$* $| <SCAT> $| $* +BOUNCER $* $| ASK		$: <TAGBOUNCER>
R<O> $| $*O10$* $| <SCAT> $| $* !BOUNCER $* $| ASK		$: <REJBOUNCER>

R<O> $| $*				$: <O> $| $(EL_Outscatter $&{client_name} $) $| $(EL_OutscatterSenderAddys_11 $&{mail_addr} $) $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
R<O> $| $*O11$* $| <SCAT> $| $* +BOUNCER $* $| ASK		$: <TAGBOUNCER>
R<O> $| $*O11$* $| <SCAT> $| $* !BOUNCER $* $| ASK		$: <REJBOUNCER>

# if no match try default policy
R<O> $| $*  	$: <O> $| $(EL_Outscatter $&{client_name} $) $| $(EL_OutscatterSenderAddys_1 $&{mail_addr} $) $| $(EL_Policy default $) $| $&{ELPolicySwitch}
R<O> $| O1$* $| $@ $| $* +BOUNCER $* $| ASK			$: <TAGBOUNCER>
R<O> $| O1$* $| $@ $| $* !BOUNCER $* $| ASK			$: <REJBOUNCER>
R<O> $| O1$* $| <SCAT> $| $* +BOUNCER $* $| ASK		$: <TAGBOUNCER>
R<O> $| O1$* $| <SCAT> $| $* !BOUNCER $* $| ASK		$: <REJBOUNCER>

R<O> $| $*		$: <O> $| $(EL_Outscatter $&{client_name} $) $| $(EL_OutscatterSenderAddys_2 $&{mail_addr} $) $| $(EL_Policy default $) $| $&{ELPolicySwitch}
R<O> $| $*O2$* $| <SCAT> $| $* +BOUNCER $* $| ASK		$: <TAGBOUNCER>
R<O> $| $*O2$* $| <SCAT> $| $* !BOUNCER $* $| ASK		$: <REJBOUNCER>

R<O> $| $*		$: <O> $| $(EL_Outscatter $&{client_name} $) $| $(EL_OutscatterSenderAddys_3 $&{mail_addr} $) $| $(EL_Policy default $) $| $&{ELPolicySwitch}
R<O> $| $*O3$* $| <SCAT> $| $* +BOUNCER $* $| ASK		$: <TAGBOUNCER>
R<O> $| $*O3$* $| <SCAT> $| $* !BOUNCER $* $| ASK		$: <REJBOUNCER>

R<O> $| $*		$: <O> $| $(EL_Outscatter $&{client_name} $) $| $(EL_OutscatterSenderAddys_4 $&{mail_addr} $) $| $(EL_Policy default $) $| $&{ELPolicySwitch}
R<O> $| $*O4$* $| <SCAT> $| $* +BOUNCER $* $| ASK		$: <TAGBOUNCER>
R<O> $| $*O4$* $| <SCAT> $| $* !BOUNCER $* $| ASK		$: <REJBOUNCER>

R<O> $| $*		$: <O> $| $(EL_Outscatter $&{client_name} $) $| $(EL_OutscatterSenderAddys_5 $&{mail_addr} $) $| $(EL_Policy default $) $| $&{ELPolicySwitch}
R<O> $| $*O5$* $| <SCAT> $| $* +BOUNCER $* $| ASK		$: <TAGBOUNCER>
R<O> $| $*O5$* $| <SCAT> $| $* !BOUNCER $* $| ASK		$: <REJBOUNCER>

R<O> $| $*		$: <O> $| $(EL_Outscatter $&{client_name} $) $| $(EL_OutscatterSenderAddys_6 $&{mail_addr} $) $| $(EL_Policy default $) $| $&{ELPolicySwitch}
R<O> $| $*O6$* $| <SCAT> $| $* +BOUNCER $* $| ASK		$: <TAGBOUNCER>
R<O> $| $*O6$* $| <SCAT> $| $* !BOUNCER $* $| ASK		$: <REJBOUNCER>

R<O> $| $*		$: <O> $| $(EL_Outscatter $&{client_name} $) $| $(EL_OutscatterSenderAddys_7 $&{mail_addr} $) $| $(EL_Policy default $) $| $&{ELPolicySwitch}
R<O> $| $*O7$* $| <SCAT> $| $* +BOUNCER $* $| ASK		$: <TAGBOUNCER>
R<O> $| $*O7$* $| <SCAT> $| $* !BOUNCER $* $| ASK		$: <REJBOUNCER>

R<O> $| $*		$: <O> $| $(EL_Outscatter $&{client_name} $) $| $(EL_OutscatterSenderAddys_8 $&{mail_addr} $) $| $(EL_Policy default $) $| $&{ELPolicySwitch}
R<O> $| $*O8$* $| <SCAT> $| $* +BOUNCER $* $| ASK		$: <TAGBOUNCER>
R<O> $| $*O8$* $| <SCAT> $| $* !BOUNCER $* $| ASK		$: <REJBOUNCER>

R<O> $| $*		$: <O> $| $(EL_Outscatter $&{client_name} $) $| $(EL_OutscatterSenderAddys_9 $&{mail_addr} $) $| $(EL_Policy default $) $| $&{ELPolicySwitch}
R<O> $| $*O9$* $| <SCAT> $| $* +BOUNCER $* $| ASK		$: <TAGBOUNCER>
R<O> $| $*O9$* $| <SCAT> $| $* !BOUNCER $* $| ASK		$: <REJBOUNCER>

R<O> $| $*		$: <O> $| $(EL_Outscatter $&{client_name} $) $| $(EL_OutscatterSenderAddys_10 $&{mail_addr} $) $| $(EL_Policy default $) $| $&{ELPolicySwitch}
R<O> $| $*O10$* $| <SCAT> $| $* +BOUNCER $* $| ASK		$: <TAGBOUNCER>
R<O> $| $*O10$* $| <SCAT> $| $* !BOUNCER $* $| ASK		$: <REJBOUNCER>

R<O> $| $*		$: <O> $| $(EL_Outscatter $&{client_name} $) $| $(EL_OutscatterSenderAddys_11 $&{mail_addr} $) $| $(EL_Policy default $) $| $&{ELPolicySwitch}
R<O> $| $*O11$* $| <SCAT> $| $* +BOUNCER $* $| ASK		$: <TAGBOUNCER>
R<O> $| $*O11$* $| <SCAT> $| $* !BOUNCER $* $| ASK		$: <REJBOUNCER>

R<TAGBOUNCER>				$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgBouncer', `confEL_TagErrMsgBouncer', `"Possible outscatter message from known insecure host"')> $| 3
ifdef(`_EL_RETURN_OUTSCATTER', `
R<REJBOUNCER>				$#error $@ 5.7.1 $: ifdef(`confEL_ErrReturnOutscatter', `confEL_ErrReturnOutscatter', `"551 User not local; please try <postmaster@["$&{client_addr}"]>"')
',`
R<REJBOUNCER>				$#error $@ 5.7.1 $: ifdef(`confEL_ErrBouncerName', `confEL_ErrBouncerName', `"550 BOUNCER Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail from your null sender; your system is broken and sending us bounces from forged mail we didnt send."') 
')dnl

# now check whether this address should be getting bounces at all
R$*										$: $(EL_OutscatterSenderAddysSeq $&{mail_addr} $) $| $&{ELPolicyUser} $| $&{ELPolicySwitch}

R<SCAT> $| $*NOBOUNCE$* $| TAG		$: <TAGBOUNCER> 
R<SCAT> $| $*NOBOUNCE$* $| BLOCK	$: <REJBOUNCER>
R<SCAT> $| $* +NOBOUNCE$* $| ASK 	$: <TAGBOUNCER>
R<SCAT> $| $* !NOBOUNCE$* $| ASK 	$: <REJBOUNCER>

# and check for null sender
R$@ $| $*NOBOUNCE$* $| TAG			$: <TAGBOUNCER>
R$@ $| $*NOBOUNCE$* $| BLOCK		$: <REJBOUNCER>
R$@ $| $* +NOBOUNCE$* $| ASK 		$: <TAGBOUNCER>
R$@ $| $* !NOBOUNCE$* $| ASK 		$: <REJBOUNCER>

# if no match try default policy
R$* $| $* $| $* 					$: $1 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
R<SCAT> $| $*NOBOUNCE$* $| TAG		$: <TAGBOUNCER> 
R<SCAT> $| $*NOBOUNCE$* $| BLOCK	$: <REJBOUNCER>
R<SCAT> $| $* +NOBOUNCE$* $| ASK 	$: <TAGBOUNCER>
R<SCAT> $| $* !NOBOUNCE$* $| ASK 	$: <REJBOUNCER>

# and check for null sender
R$@ $| $*NOBOUNCE$* $| TAG			$: <TAGBOUNCER>
R$@ $| $*NOBOUNCE$* $| BLOCK		$: <REJBOUNCER>
R$@ $| $* +NOBOUNCE$* $| ASK 		$: <TAGBOUNCER>
R$@ $| $* !NOBOUNCE$* $| ASK 		$: <REJBOUNCER>

R<TAGBOUNCER>					$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgNobounce', `confEL_TagErrMsgNobounce', `"Bounce message sent to address that sends no mail"')> $| 4
R<REJBOUNCER>					$#error $@ 5.7.1 $: ifdef(`confEL_ErrNoBounce', `confEL_ErrNoBounce', `"550 NOBOUNCE Contact "$&{ELContactEmail}" if this is in error, but you are sending bounces to an address that sends no mail."')
')dnl
')dnl

ifdef(`_EL_BADHELOS', `dnl
# do not accept mail from folks with known bad helos
R$*								$: $(EL_Badhelos $&{s} $)

ifelse(_EL_POLICY, 1, `dnl
R$-								$: $1 $| $&{ELPolicyUser} $| $&{ELPolicySwitch}

RBYE $| $*BADHELO$* $| TAG		$: <TAGBADHELO> 
RBYE $| $*BADHELO$* $| BLOCK	$: <REJBADHELO>
RBYE $| $* +BADHELO$* $| ASK	$: <TAGBADHELO>
RBYE $| $* !BADHELO$* $| ASK	$: <REJBADHELO>

# if no match try default policy
R$* $| $* $| $* 				$: $1 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
RBYE $| $*BADHELO$* $| TAG		$: <TAGBADHELO> 
RBYE $| $*BADHELO$* $| BLOCK	$: <REJBADHELO>
RBYE $| $* +BADHELO$* $| ASK	$: <TAGBADHELO>
RBYE $| $* !BADHELO$* $| ASK	$: <REJBADHELO>
', `dnl
RBYE							$: <REJBADHELO>
')dnl
R<TAGBADHELO>				$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgBogusHELO', `confEL_TagErrMsgBogusHELO', `"remote host used bogus HELO "$&{s}"."')> $| 3
R<REJBADHELO>				$#error $@ 5.7.1 $: ifdef(`confEL_ErrBadHelos', `confEL_ErrBadHelos', `"550 BADHELO Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail from hosts that announce themselves via HELO/EHLO as " $&s ", as when we do it is always spam."')
')dnl

ifdef(`_EL_NOCACHEFLOW', `dnl
# do not accept outscatter from CacheFlow servers
KEL_Check_BogusHELOSubstring regex -a<MATCH> CacheFlowServer
R$*							$: $(EL_Check_BogusHELOSubstring $&{s} $)
R<MATCH>					$#error $@ 5.7.1 $: ifdef(`confEL_ErrCacheFlowServer', `confEL_ErrCacheFlowServer', `"550 CACHFLO Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail sent via CacheFlow Servers."')
')dnl

ifdef(`_EL_HIBIT_HELO', `dnl
# check for illegal characters in HELO
KEL_CheckBogusHibitHELO regex -m -b -f -a<HIBIT> ^.*[€-þ].*
R$*							$: $(EL_CheckBogusHibitHELO $&{s} $)
R<HIBIT>					$#error $@ 5.7.1 $: ifdef(`confEL_ErrHibitHelo', `confEL_ErrHibitHelo', `"550 HI_BITS Contact "$&{ELContactEmail}" if this is in error, but your HELO string is bogus (contains hibit characters)."')
')dnl
