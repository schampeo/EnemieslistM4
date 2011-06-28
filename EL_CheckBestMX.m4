divert(-1)dnl
#
# Copyright (c) 2004-2011 hesketh.com/inc. All rights reserved.
#
# questions? <support@enemieslist.com>
#
# original version contributed by Bruce Gingery

divert(0)dnl
VERSIONID(`$Id: EL_CheckBestMX.m4,v 1.18 2011/05/17 19:45:59 schampeo Exp $')
divert(-1)dnl

define(`_EL_CHECK_BESTMX', `1')dnl

LOCAL_CONFIG
#
# enemieslist.com MX checks map definition
#
KEL_bestmx bestmx -TTEMP
KEL_BannedMX ifdef(`confEL_BADMX_FILE', `confEL_DB_MAP_TYPE' `confEL_BADMX_FILE')
KEL_SpaceInAddr regex -a@SPAM ^\ ?.*\ .*$
# see also EL_SubjectLobits; this is backspace, tab, newline, vertical tab, carriage return and escape
KEL_Unprintables regex -a<MATCH> [	]

LOCAL_RULESETS
#------------------------------------------------------------------------
# enemieslist.com bestmx checks
#
# only argument is HELO string or domain of MAIL FROM: sender
#------------------------------------------------------------------------
SEL_CheckBMXOutblaze
# Is it a mail.com domain?
R$*						$: $1 $| $(EL_bestmx $1 $: $1 $)   
R$* $| $* outblaze.com.	$: $1

# No?  Return empty
R$* $| $*				$@

# Is the client named in the outblaze.com domain?
R$*						$: $1 $| $&{client_name}

# If so, return empty   
R$* $| $* outblaze.com	$@

# If not, return <FRAUD> indicator
R$* $| $*				$@ <FRAUD>

# And as an indicator of normal return, empty (never gets done).
R$*						$@

SEL_CheckBMXHotmail
# is it hotmail.com?
R$*						$: $1 $| $(EL_bestmx $1 $: $1 $)
R$* $| $* hotmail.com.	$: $1

# No? return empty
R$* $| $*				$@

# Is the client named in the hotmail.com domain?
R$*						$: $1 $| $&{client_name}

# If so, return empty
R$* $| $* hotmail.com	$@

# If not, return <FRAUD> indicator
R$* $| $*				$@ <FRAUD>

# and as indicator of normal return, empty (never gets done).
R$*						$@

SEL_CheckBMXYahoo
# is it yahoo.com?
R$*						$: $1 $| $(EL_bestmx $1 $: $1 $)
R$* $| $* yahoo.com.	$: $1

# No? return empty
R$* $| $*				$@

# Is the client named in the yahoo.com domain?
R$*						$: $1 $| $&{client_name}

# If so, return empty
R$* $| $* yahoo.com	$@

# If not, return <FRAUD> indicator
R$* $| $*				$@ <FRAUD>

# and as indicator of normal return, empty (never gets done).
R$*						$@

SEL_CheckBMXSeznam
# is it seznam.cz?
R$*						$: $1 $| $(EL_bestmx $1 $: $1 $)
R$* $| $* seznam.cz.	$: $1

# No? return empty
R$* $| $*				$@

# Is the client named in the seznam.cz domain?
R$*						$: $1 $| $&{client_name}

# If so, return empty
R$* $| $* seznam.cz		$@

# If not, return <FRAUD> indicator
R$* $| $*				$@ <FRAUD>

# and as indicator of normal return, empty (never gets done).
R$*						$@

# Hotmail, prserv.net and some others HELO as their bare domain    
# but have FCrDNS (else reject) for the host _within_that domain.
# Note that Hotmail.com and prserv.net don't necessarily restrict
# sending to their own outgoing mailservers...wouldn't do an SPF.
# So some people wouldn't want the R lines above the #####      
SEL_CheckBMXDumbHELO
R$*								$: $&{client_name} $| $1     

# Do the 2LDs match?
R$*hotmail.com $| $*hotmail.com	$@
R$*prserv.net  $| $*prserv.net	$@
R$*yahoo.com   $| $*yahoo.com	$@

# If not, and it's one we're checking, return <FRAUD> flag
R$* $| $*hotmail.com			$@ <FRAUD>
R$* $| $*prserv.net				$@ <FRAUD>
R$* $| $*yahoo.com				$@ <FRAUD>

#####
R$*								$: $&{client_name} $| $&{s}

# Do the 2LDs match?
R$*hotmail.com $| $*hotmail.com	$@
R$*prserv.net  $| $*prserv.net	$@
R$*yahoo.com   $| $*yahoo.com	$@

# If not, and it's one we're checking, return <FRAUD> flag
R$* $| $*hotmail.com			$@ <FRAUD>
R$* $| $*prserv.net				$@ <FRAUD>
R$* $| $*yahoo.com				$@ <FRAUD>

# Else, it is not something we are looking for...
R$*								$@

SEL_CheckBannedMX
# check mx against known banned MXen db
R$*						$: $&{mail_addr}
R<$*@$*>				$: <$1@$2> $| $(EL_bestmx $2 $: $2 $)

R$* $| $*				$: $1 $| $[ $2 $]
ifdef(`_EL_DEBUG', `dnl
R$* $| $*				$: $1 $| $2 $(EL_Log "EL mx lookup: " $2 $)
')dnl

R$* $| $-.$-.$-.$-.		$: $1 $| $2.$3.$4.$5
R$* $| $-.$-.$-.$-		$: $1 $| $(EL_BannedMX $2.$3.$4.$5 $)
R$* $| $-.$-.$-.$-		$: $1 $| $(EL_BannedMX $2.$3.$4 $)
R$* $| $-.$-.$-.$-		$: $1 $| $(EL_BannedMX $2.$3 $)
R$* $| $-.$-.$-.$-		$: $1 $| $(EL_BannedMX $2 $)
R$* $| BANNED			$@ <BANNED>
R$* $| B				$@ <BANNED>
R$*						$@

SLocal_check_mail
R$*					$: $1 $(EL_SetVar {INHEADERS} $@ YES $)
ifdef(`_EL_DEBUG', `dnl
R$* 				$: $1 $(EL_Log "Local_check_mail w/ " $1 $)
')dnl

ifdef(`_EL_SKIPLOCAL', `dnl
R$*					$: $1 $| $&{client_addr}
R$* $| 127.0.0.1	$@
ifdef(`confEL_LOCAL_IP_UNESCAPED', `dnl
R$* $| confEL_LOCAL_IP_UNESCAPED		$@
')dnl
R$* $| $*			$: $1
')dnl

ifdef(`_EL_QUICK_REFUSE_NORDNS', `dnl
# check for whether the host has any rDNS, if not, reject immediately
ifdef(`_EL_ACCEPT_NORDNS_FORTRAPS', `dnl
# except for spamtraps
R$*					$: $&{client_resolve} $| $(EL_Spamtrap $&{EL_CurrRcpt} $) $| $1
RFAIL $| T $| $*	$: $1
RTEMP $| T $| $*	$: $1
RFAIL $| D $| $*	$: $1
RTEMP $| D $| $*	$: $1
RFAIL $| $* $| $*	$#error $@ 5.7.1 $: ifdef(`confEL_ErrNoRDNS', `confEL_ErrNoRDNS', `"421 NORDNS Contact "$&{ELContactEmail}" if this is in error, but as far as we can tell, your reverse DNS is missing."')
RTEMP $| $* $| $*	$#error $@ 5.7.1 $: ifdef(`confEL_ErrNoRDNS', `confEL_ErrNoRDNS', `"421 NORDNS Contact "$&{ELContactEmail}" if this is in error, but as far as we can tell, your reverse DNS is missing."')
R$* $| $* $| $*		$: $3
',`
R$*					$: $&{client_resolve} $| $1
RFAIL $| $* 		$#error $@ 5.7.1 $: ifdef(`confEL_ErrNoRDNS', `confEL_ErrNoRDNS', `"421 NORDNS Contact "$&{ELContactEmail}" if this is in error, but as far as we can tell, your reverse DNS is missing."')
RTEMP $| $*			$#error $@ 5.7.1 $: ifdef(`confEL_ErrNoRDNS', `confEL_ErrNoRDNS', `"421 NORDNS Contact "$&{ELContactEmail}" if this is in error, but as far as we can tell, your reverse DNS is missing."')
R$* $| $*			$: $2
')dnl
')dnl

ifdef(`_EL_BLOCK1CHARADDYS', `dnl
R<!>				$#error $@ 5.7.1 $: ifdef(`confEL_Err1CharAddys', `confEL_Err1CharAddys', `"550 1CHRADD Contact "$&{ELContactPhone}" if this is in error, but your mail was refused because your address is bogus."')
R<.>				$#error $@ 5.7.1 $: ifdef(`confEL_Err1CharAddys', `confEL_Err1CharAddys', `"550 1CHRADD Contact "$&{ELContactPhone}" if this is in error, but your mail was refused because your address is bogus."')
R<%>				$#error $@ 5.7.1 $: ifdef(`confEL_Err1CharAddys', `confEL_Err1CharAddys', `"550 1CHRADD Contact "$&{ELContactPhone}" if this is in error, but your mail was refused because your address is bogus."')
R<*>				$#error $@ 5.7.1 $: ifdef(`confEL_Err1CharAddys', `confEL_Err1CharAddys', `"550 1CHRADD Contact "$&{ELContactPhone}" if this is in error, but your mail was refused because your address is bogus."')
R<+>				$#error $@ 5.7.1 $: ifdef(`confEL_Err1CharAddys', `confEL_Err1CharAddys', `"550 1CHRADD Contact "$&{ELContactPhone}" if this is in error, but your mail was refused because your address is bogus."')
R<->				$#error $@ 5.7.1 $: ifdef(`confEL_Err1CharAddys', `confEL_Err1CharAddys', `"550 1CHRADD Contact "$&{ELContactPhone}" if this is in error, but your mail was refused because your address is bogus."')
R</>				$#error $@ 5.7.1 $: ifdef(`confEL_Err1CharAddys', `confEL_Err1CharAddys', `"550 1CHRADD Contact "$&{ELContactPhone}" if this is in error, but your mail was refused because your address is bogus."')
R<@>				$#error $@ 5.7.1 $: ifdef(`confEL_Err1CharAddys', `confEL_Err1CharAddys', `"550 1CHRADD Contact "$&{ELContactPhone}" if this is in error, but your mail was refused because your address is bogus."')
')dnl

# Strip to single fangs
R<$*>					$1
R$*						$: <$1>

# check for unprintable characters in mail from
R$*						$: $(EL_Unprintables $1 $)
R<MATCH>				$#error $@ 5.7.1 $: ifdef(`confEL_ErrUnprintableInAddr', `confEL_ErrUnprintableInAddr', `"550 ADDRUNP Contact "$&{ELContactPhone}" if this is in error, but your mail was refused because the sender address is bogus."')

# check for b0rken ratware
R$*						$: $(EL_B0rkenRatware $1 $)
R@SPAM					$#error $@ 5.7.1 $: ifdef(`confEL_ErrB0rkenRatware', `confEL_ErrB0rkenRatware', `"554 B0RKENR Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it appears to have been sent by laughably broken spam software."')

# Check for MX 0 .
# indicator that domain owner has repudiated email
R<$*@$*>				$: <$1@$2> $| $(EL_bestmx $2 $: $2 $)
ifdef(`_EL_DEBUG', `dnl
R$* $| $*				$: $1 $| $2 $(EL_Log "EL bestmx for " $1 ": " $2 $)
')dnl

R<$*@$*> $| .			$#error $@ 5.7.1 $: ifdef(`confEL_ErrBestMXDot', `confEL_ErrBestMXDot', `"550 MXISDOT Contact "$&{ELContactPhone}" if this is in error, but your mail was refused because your domain has repudiated mail."')

R$* $| TEMP				$#error $@ 4.7.1 $: ifdef(`confEL_ErrBestMXNoMXTemp', `confEL_ErrBestMXNoMXTemp', `"450 NOMXTMP Contact "$&{ELContactPhone}" if this is in error, but your mail was refused because your domain seems to lack an MX record. We do not accept mail from anyone we can not complain about it to."')

ifdef(`_EL_CHECK_BOGUS_HOTMAIL', `dnl
# check for forged hotmail HELO/EHLO
R$* $|					$: $1 $| $>EL_CheckBMXHotmail $&s
R$* $| <FRAUD>			$#error $@ 5.7.1 $: ifdef(`confEL_ErrBestMXHotmail', `confEL_ErrBestMXHotmail', `"550 HOTMAIL Contact "$&{ELContactPhone}" if this is in error, but your mail was refused because it was believed to be forged. Use your providers outbound servers."')
')

ifdef(`_EL_CHECK_BOGUS_YAHOO', `dnl
# check for forged yahoo HELO/EHLO
R$* $|					$: $1 $| $>EL_CheckBMXYahoo $&s
R$* $| <FRAUD>			$#error $@ 5.7.1 $: ifdef(`confEL_ErrBestMXYahoo', `confEL_ErrBestMXYahoo', `"550 YAHOOFG Contact "$&{ELContactPhone}" if this is in error, but your mail was refused because it was believed to be forged. Use your providers outbound servers."')
')

ifdef(`_EL_CHECK_BOGUS_SEZNAM', `dnl
# check for forged seznam.cz HELO/EHLO
R$* $|					$: $1 $| $>EL_CheckBMXSeznam $&s
R$* $| <FRAUD>			$#error $@ 5.7.1 $: ifdef(`confEL_ErrBestMXSeznam', `confEL_ErrBestMXSeznam', `"550 FSEZNAM Contact "$&{ELContactPhone}" if this is in error, but your mail was refused because it was believed to be forged. Use your providers outbound servers."')
')

ifdef(`_EL_CHECK_BANNED_MX', `dnl
# check for banned mx
R<$*@$*> $| $*			$: <$1@$2> $| $>EL_CheckBannedMX $2
R$* $| <BANNED>			$#error $@ 5.7.1 $: ifdef(`confEL_ErrBestMXBanned', `confEL_ErrBestMXBanned', `"550 BANNDMX Contact "$&{ELContactPhone}" if this is in error, but your mail was refused because your domain shares an MX record with a spammer. Clean up your network."')

R<$*@$*> $| $*			$: <$1@$2> $| $(EL_bestmx $2 $: $2 $)
R$* $| $*				$: $1 $| $(EL_HostIP $2 $@ FAIL $)

R$* $| FAIL				$#error $@ 5.7.1 $: ifdef(`confEL_ErrBestMXNoMXFail', `confEL_ErrBestMXNoMXFail', `"550 NOMXFAL Contact "$&{ELContactPhone}" if this is in error, but your mail was refused because your domain lacks an MX record. We do not accept mail from anyone we can not complain about it to."')

R$* $| TEMP				$#error $@ 4.7.1 $: ifdef(`confEL_ErrBestMXNoMXTemp', `confEL_ErrBestMXNoMXTemp', `"450 NOMXTMP Contact "$&{ELContactPhone}" if this is in error, but your mail was refused because your domain seems to lack an MX record. We do not accept mail from anyone we can not complain about it to."')
')

ifdef(`_EL_CHECK_BANNED_NS', `dnl
# check for banned NS
R<$*@$*> $| $*			$: <$1@$2> $| $>EL_CheckBannedNS $2
#R$* $| <BANNED>		$#error $@ 5.7.1 $: ifdef(`confEL_ErrBannedNS', `confEL_ErrBannedNS', `"550 BANNDNS Contact "$&{ELContactPhone}" if this is in error, but your mail was refused because your domain shares an NS record with a spammer. Clean up your network."')
R$* $| <BANNED>			$>EL_TagSuspicious <ifdef(`confEL_TagErrMsgTaintedNS', `confEL_TagErrMsgTaintedNS', `"domain shares a DNS server with a spammer"')> $| 3
')dnl
