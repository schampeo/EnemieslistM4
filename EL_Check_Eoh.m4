divert(-1)dnl
#
# Copyright (c) 2004-2011 hesketh.com/inc. All rights reserved.
#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_Check_Eoh.m4,v 1.43 2011/05/20 19:45:13 schampeo Exp $')
divert(-1)dnl

LOCAL_CONFIG
ifdef(`_EL_FINGERPRINT', `dnl
#------------------------------------------------------------------------
# enemieslist.com Fingerprinting checks
#------------------------------------------------------------------------
KEL_FingerprintMatchWin95      regex -s1 -a<WIN95>    ^(.*Windows:95.*)$
KEL_FingerprintMatchWin98      regex -s1 -a<WIN98>    ^(.*Windows:98.*)$
KEL_FingerprintMatchWinME      regex -s1 -a<WINME>    ^(.*Windows:ME.*)$
KEL_FingerprintMatchWin2000SP2 regex -s1 -a<WIN2KSP2> ^(.*Windows.+2000\ SP2.*)$
KEL_FingerprintMatchWin2000SP3 regex -s1 -a<WIN2KSP3> ^(.*Windows.+2000\ SP3.*)$
KEL_FingerprintMatchWin2000SP4 regex -s1 -a<WIN2KSP4> ^(.*Windows.+2000\ SP4.*)$
KEL_FingerprintMatchWinXP2000  regex -s1 -a<WINXP2K>  ^(.*Windows:(XP|2000).*)$
KEL_FingerprintMatchWinXP      regex -s1 -a<WINXP>    ^(.*Windows:XP\ SP.\+[^,].*)$
KEL_FingerprintMatchWin2003    regex -s1 -a<WIN2K3>   ^(.*Windows:2003.*)$

KEL_FingerprintMatch sequence EL_FingerprintMatchWin95 EL_FingerprintMatchWin98 EL_FingerprintMatchWinME EL_FingerprintMatchWin2000SP2 EL_FingerprintMatchWin2000SP3 EL_FingerprintMatchWin2000SP4 EL_FingerprintMatchWinXP2000 EL_FingerprintMatchWinXP EL_FingerprintMatchWin2003
')

LOCAL_RULESETS
#------------------------------------------------------------------------
# enemieslist.com check_eoh dropin
#------------------------------------------------------------------------
Scheck_eoh
ifdef(`_EL_TRACE', `dnl
R$*					$: $1 $| $(EL_Log "check_eoh w/ " $1 "; score: " $&{ELSuspiciousCount} "." $)
R$* $| $*			$: $(EL_SetVar {currHeader} $1 $)
')dnl

ifdef(`_EL_SKIPLOCAL', `dnl
R$*					$: $&{client_addr}
R127.0.0.1			$@
')dnl

# skip whitelisted hosts
R$*					$: $&{ELWhitelisted}
R$+:$+				$@ $(EL_Log "EL skipping whitelisted host " $&{ELWhitelisted} $)

# do not check authenticated submissions
# was the sender authenticated?
R$*					$: $>RelayTLS

# authenticated by a trusted mechanism?
R$*							$: $1 $| $&{auth_type}
R$* $|						$: $1
R$* $| $={TrustAuthMech}	$@ $(EL_SetVar {hc_switch} $@ ? $)
R$* $| $*					$: $&{EL_CurrRcpt}

ifdef(`_EL_FINGERPRINT', `dnl
R$*						$: $(EL_Fingerprint ifdef(`confEL_P0FSOCK', `confEL_P0FSOCK')":"$&{client_addr}":"$&{client_port}":"ifdef(`confEL_LOCAL_IP_UNESCAPED', `confEL_LOCAL_IP_UNESCAPED')":25" $)
R$*						$: $(EL_FingerprintMatch $1 $) $| $(EL_Log "EL fingerprint: " $&{client_addr} ":" $&{client_port} "; " $1 $)
R$+<WIN95> $| $*		$: $>EL_TagSuspicious <"Remote host is running Windows 95 OS: " $1> $| ifdef(`confEL_ScoreWin95', `confEL_ScoreWin95', `5')
R$+<WIN98> $| $*		$: $>EL_TagSuspicious <"Remote host is running Windows 98 OS: " $1> $| ifdef(`confEL_ScoreWin98', `confEL_ScoreWin98', `4')
R$+<WINME> $| $*		$: $>EL_TagSuspicious <"Remote host is running Windows ME OS: " $1> $| ifdef(`confEL_ScoreWinME', `confEL_ScoreWinME', `4')
# 2000 check comes first as fingerprints are similar for Win2k and WinXP
R$+<WIN2KSP2> $| $*		$: $>EL_TagSuspicious <"Remote host is running Windows 2000 OS: " $1> $| ifdef(`confEL_ScoreWin2000SP2', `confEL_ScoreWin2000SP2', `3')
R$+<WIN2KSP3> $| $*		$: $>EL_TagSuspicious <"Remote host is running Windows 2000 OS: " $1> $| ifdef(`confEL_ScoreWin2000SP3', `confEL_ScoreWin2000SP3', `2')
R$+<WIN2KSP4> $| $*		$: $>EL_TagSuspicious <"Remote host is running Windows 2000 OS: " $1> $| ifdef(`confEL_ScoreWin2000SP4', `confEL_ScoreWin2000SP4', `1')
R$+<WINXP2K> $| $*		$: $>EL_TagSuspicious <"Remote host is running Windows XP/2000 OS: " $1> $| ifdef(`confEL_ScoreWinXP2000', `confEL_ScoreWinXP2000', `1')
R$+<WINXP> $| $*		$: $>EL_TagSuspicious <"Remote host is running Windows XP OS: " $1> $| ifdef(`confEL_ScoreWinXP', `confEL_ScoreWinXP', `2')
R$+<WIN2K3> $| $*		$: $>EL_TagSuspicious <"Remote host is running Windows 2003 OS: " $1> $| ifdef(`confEL_ScoreWin2003', `confEL_ScoreWin2003', `1')
')dnl

ifdef(`_EL_BLANK_SUBJ_ROLEACCT', `dnl
# final check before setting INHEADERS to NO
R$*						$: $(EL_Math & $@ 4 $@ $&{ELHasHeader} $) $| $(EL_CheckForRoleAccount $&{EL_CurrRcpt} $) $| $&{INHEADERS}
R0 $| <ROLE> $| YES		$#error $@ 5.7.1 $: ifdef(`confEL_ErrRoleAcctNoSubj', `confEL_ErrRoleAcctNoSubj', `"554 BLSBJRA Contact "$&{ELContactPhone}" if this is in error, or resend with a Subject: header. We do not accept blank mail to role accounts due to massive ongoing abuse."')
')dnl

R$*					$: $(EL_SetVar {INHEADERS} $@ NO $)

# always skip this check for local mail
R$*					$: $&{client_addr}
R127.0.0.1			$@

R$*					$: $&{mail_addr}

# always skip this check if from null sender?
# 06/24/09 - disabled due to ongoing abuse of null sender
#R$@					$@

ifdef(`_EL_TAG_DIRECTTOMX', `dnl
R$*					$: $&{ELRecdHeaderCount}
R0					$: <YES> $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgDirecttoMX', `confEL_TagErrMsgDirecttoMX', `"Message sent direct-to-MX"')> $| 1
R$@					$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgDirecttoMX', `confEL_TagErrMsgDirecttoMX', `"Message sent direct-to-MX"')> $| 1
')dnl

# all checks from here down are for Message-Id and some other condition
# except where Outlook override is in effect.

ifdef(`_EL_REJECT_NOMSGID', `dnl
# need to check for null sender here
R$*					$: $(EL_Math & $@ 1 $@ $&{ELHasHeader} $) $| $&{mail_addr}
R0 $| $+			$#error $@ 5.7.1 $: ifdef(`confEL_ErrNoMsgID', `confEL_ErrNoMsgID', `"554 NOMSGID Contact "$&{ELContactEmail}" if this is in error; your message was rejected as it lacks a Message-ID header and is therefore invalid."')
')dnl

ifdef(`_EL_TAG_NOMSGID', `dnl
# need to check for null sender here
R$*					$: $(EL_Math & $@ 1 $@ $&{ELHasHeader} $) $| $&{mail_addr}
R$* $| $*			$: $1 $| $2 ifdef(`_EL_DEBUG', `$(EL_Log "EL msgid: " $1 " / " $&{ELHasHeader} $)')
R0 $| $+			$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgNomsgid', `confEL_TagErrMsgNomsgid', `"Message has no Message-ID header"')> $| 2
')dnl

ifdef(`_EL_REJECT_NOMSGID_OR_SUBJECT', `dnl
R$*					$: $(EL_Math & $@ 1 $@ $&{ELHasHeader} $) $| $(EL_Math & $@ 4 $@ $&{ELHasHeader} $)
R$* $| $*			$: $1 $| $2 ifdef(`_EL_DEBUG', `$(EL_Log "EL msgid/subj: " $1 "/" $2 "/" $&{ELHasHeader} $)')
R0 $| 0				$#error $@ 5.7.1 $: ifdef(`confEL_ErrNoMsgIDSubject', `confEL_ErrNoMsgIDSubject', `"554 NOMIDSB Contact "$&{ELContactEmail}" if this is in error; your message was rejected as it lacks a Message-ID header and and a Subject header."')
')dnl

ifdef(`_EL_TAG_NOMSGID_OR_SUBJECT', `dnl
R$*					$: $(EL_Math & $@ 1 $@ $&{ELHasHeader} $) $| $(EL_Math & $@ 4 $@ $&{ELHasHeader} $)
R$* $| $*			$: $1 $| $2 ifdef(`_EL_DEBUG', `$(EL_Log "EL msgid/subj: " $1 "/" $2 "/" $&{ELHasHeader} $)')
R0 $| 0				$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgNomsgidSubj', `confEL_TagErrMsgNomsgidSubj', `"Message has no Message-ID or Subject header"')> $| 3
')dnl

ifdef(`_EL_REJECT_NOMSGID_OR_RDNS', `dnl
R$*					$: $(EL_Math & $@ 1 $@ $&{ELHasHeader} $) $| $&{client_resolve}
R0 $| FAIL			$#error $@ 5.7.1 $: ifdef(`confEL_ErrNoMsgIDorRDNS', `confEL_ErrNoMsgIDorRDNS', `"554 NOMIDDF Contact "$&{ELContactEmail}" if this is in error; your message was rejected as it lacks a Message-ID header and your host lacks reverse DNS."')
')dnl

ifdef(`_EL_TAG_NOMSGID_OR_RDNS', `dnl
R$*					$: $(EL_Math & $@ 1 $@ $&{ELHasHeader} $) $| $&{client_resolve}
R0 $| FAIL			$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgNomsgidNorDNS', `confEL_TagErrMsgNomsgidNorDNS', `"Message lacks Message-ID header and host has no reverse DNS"')> $| 3
')dnl

ifdef(`_EL_REJECT_NOMSGID_AND_GENRDNS', `dnl
# need to check here to see which set of rules they are using. this assumes
# they are using either the old config rDNS workaround or the default rules
ifdef(`_EL_DNSBL', `dnl
# no sense checking if the host does not resolve
R$*						$: $&{client_resolve} $| $(EL_Math & $@ 1 $@ $&{ELHasHeader} $) $| $(EL_HostIP $&{client_name}.g.enemieslist.com. $)
ROK $| 0 $| $+.1		$#error $@ 5.7.1 $: ifdef(`confEL_ErrNoMsgIDandGenericRDNS', `confEL_ErrNoMsgIDandGenericRDNS', `"554 NOMIDGR Contact "$&{ELContactEmail}" if this is in error; your message was rejected as it lacks a Message-ID header and your host has generic reverse DNS."')
ROK $| 0 $| $+.2		$#error $@ 5.7.1 $: ifdef(`confEL_ErrNoMsgIDandGenericRDNS', `confEL_ErrNoMsgIDandGenericRDNS', `"554 NOMIDGR Contact "$&{ELContactEmail}" if this is in error; your message was rejected as it lacks a Message-ID header and your host has generic reverse DNS."')
ROK $| 0 $| $+.3		$#error $@ 5.7.1 $: ifdef(`confEL_ErrNoMsgIDandGenericRDNS', `confEL_ErrNoMsgIDandGenericRDNS', `"554 NOMIDGR Contact "$&{ELContactEmail}" if this is in error; your message was rejected as it lacks a Message-ID header and your host has generic reverse DNS."')
ROK $| 0 $| $+.10		$#error $@ 5.7.1 $: ifdef(`confEL_ErrNoMsgIDandGenericRDNS', `confEL_ErrNoMsgIDandGenericRDNS', `"554 NOMIDGR Contact "$&{ELContactEmail}" if this is in error; your message was rejected as it lacks a Message-ID header and your host has generic reverse DNS."')
# but worth checking even if non-FCrDNS
RFORGED $| $* $| $*		$: $&{client_resolve} $| $(EL_Math & $@ 1 $@ $&{ELHasHeader} $) $| $(EL_HostIP $&{client_ptr}.g.enemieslist.com. $)
RFORGED $| 0 $| $+.1	$#error $@ 5.7.1 $: ifdef(`confEL_ErrNoMsgIDandGenericRDNS', `confEL_ErrNoMsgIDandGenericRDNS', `"554 NOMIDGR Contact "$&{ELContactEmail}" if this is in error; your message was rejected as it lacks a Message-ID header and your host has generic reverse DNS."')
RFORGED $| 0 $| $+.2	$#error $@ 5.7.1 $: ifdef(`confEL_ErrNoMsgIDandGenericRDNS', `confEL_ErrNoMsgIDandGenericRDNS', `"554 NOMIDGR Contact "$&{ELContactEmail}" if this is in error; your message was rejected as it lacks a Message-ID header and your host has generic reverse DNS."')
RFORGED $| 0 $| $+.3	$#error $@ 5.7.1 $: ifdef(`confEL_ErrNoMsgIDandGenericRDNS', `confEL_ErrNoMsgIDandGenericRDNS', `"554 NOMIDGR Contact "$&{ELContactEmail}" if this is in error; your message was rejected as it lacks a Message-ID header and your host has generic reverse DNS."')
RFORGED $| 0 $| $+.10	$#error $@ 5.7.1 $: ifdef(`confEL_ErrNoMsgIDandGenericRDNS', `confEL_ErrNoMsgIDandGenericRDNS', `"554 NOMIDGR Contact "$&{ELContactEmail}" if this is in error; your message was rejected as it lacks a Message-ID header and your host has generic reverse DNS."')
')dnl

ifelse(_EL_CONFIG_WORKAROUND, 1, `dnl
R$*					$: $(EL_Math & $@ 1 $@ $&{ELHasHeader} $) $| $>EL_Check_GenericRDNSConfig <$&{client_addr}>
`,'
R$*					$: $(EL_Math & $@ 1 $@ $&{ELHasHeader} $) $| $>EL_Check_GenericRDNS <$&{client_addr}>
')dnl
R0 $| $#error$*			$#error $@ 5.7.1 $: ifdef(`confEL_ErrNoMsgIDandGenericRDNS', `confEL_ErrNoMsgIDandGenericRDNS', `"554 NOMIDGR Contact "$&{ELContactEmail}" if this is in error; your message was rejected as it lacks a Message-ID header and your host has generic reverse DNS."')
')dnl

ifdef(`_EL_POLICY', `dnl
ifdef(`_EL_PHISH', `dnl
# this check has to come in check_eoh in order to guarantee that the ELSpamsign
# macro is set - doing it in check_rcpt will not work.
R$*					$: $(EL_PhishMailFromLocalparts $&{mail_addr} $) $| $(EL_Math & $@ 64 $@ $&{ELSpamsign} $) $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
RPHISH $| 64 $| $*NOBANK$* $| TAG		$: <TAGNOBANK>
RPHISH $| 64 $| $*NOBANK$* $| BLOCK		$: <REJNOBANK>
RPHISH $| 64 $| $* +NOBANK$* $| ASK 	$: <TAGNOBANK>
RPHISH $| 64 $| $* !NOBANK$* $| ASK 	$: <REJNOBANK>

# if no match try default policy
R$* $| $* $| $* $| $*					$: $1 $| $2 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
RPHISH $| 64 $| $*NOBANK$* $| TAG		$: <TAGNOBANK>
RPHISH $| 64 $| $*NOBANK$* $| BLOCK		$: <REJNOBANK>
RPHISH $| 64 $| $* +NOBANK$* $| ASK 	$: <TAGNOBANK>
RPHISH $| 64 $| $* !NOBANK$* $| ASK 	$: <REJNOBANK>

R<TAGNOBANK>					$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgNobank', `confEL_TagErrMsgNobank', `"Banking message sent to address that has no finances"')> $| 4
R<REJNOBANK>					$#error $@ 5.7.1 $: ifdef(`confEL_ErrPhishNoBankAccount', `confEL_ErrPhishNoBankAccount', `"554 NOBANK Contact "$&{ELContactEmail}" if this is in error, but you are sending phishing scams to an account that has no finances at all."')
')dnl

ifdef(`_EL_OFFWHITELIST', `dnl
# tag/reject anything listed in our offwhitelist
H?${ELOffwhitelisted}?X-EL-Offwhitelist: sent via ${ELOffwhitelisted}, occasional spam source
C{persistentMacros} {ELOffwhitelisted}

# check to see if either host or helo is "offwhite" for all quarantine/scoring conditions
# this is here to avoid cascading scores on a per-recipient basis in a multiple rcpt session
R$*					$: $(EL_Offwhitelist $&{client_name} $) $| $(EL_Offwhitelist $&{s} $)
ROFFWHITE $| $*		$: $(EL_SetVar {ELOffwhitelisted} $@ <$&{client_name}> $) $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgOffwhite', `confEL_TagErrMsgOffwhite', `"common source of spam"')> $| 1
RO $| $*			$: $(EL_SetVar {ELOffwhitelisted} $@ <$&{client_name}> $) $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgOffwhite', `confEL_TagErrMsgOffwhite', `"common source of spam"')> $| 1
R419 $| $*			$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsg419AFFSource', `confEL_TagErrMsg419AFFSource', `"common source of Nigerian 419 spam"')> $| 1

R$* $| OFFWHITE		$: $(EL_SetVar {ELOffwhitelisted} $@ <$&{client_name}> $) $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgOffwhite', `confEL_TagErrMsgOffwhite', `"common source of spam"')> $| 1
R$* $| O			$: $(EL_SetVar {ELOffwhitelisted} $@ <$&{client_name}> $) $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgOffwhite', `confEL_TagErrMsgOffwhite', `"common source of spam"')> $| 1
R$* $| 419			$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsg419AFFSource', `confEL_TagErrMsg419AFFSource', `"common source of Nigerian 419 spam"')> $| 1

# ??? bug here if client_name is [dot.ted.qu.ad] - need to test for forged
# and then use client_ptr instead?

R$*					$: $(EL_Offwhitelist $&{client_name} $)
RBADRECD			$#error $@ 5.7.1 $: ifdef(`confEL_ErrBadReceived', `confEL_ErrBadReceived', `"554 NOTRACK Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail from your server as it does not provide adequate tracking of point of injection and is therefore heavily abused."')
RT					$#error $@ 5.7.1 $: ifdef(`confEL_ErrBadReceived', `confEL_ErrBadReceived', `"554 NOTRACK Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail from your server as it does not provide adequate tracking of point of injection and is therefore heavily abused."')

RR					$#error $@ 5.7.1 $: ifdef(`confEL_ErrOpenRelay', `confEL_ErrOpenRelay', `"554 LOLORLY Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail from your server as it appears to be an open relay and is therefore heavily abused."')

RC$*				$#error $@ 5.7.1 $: ifdef(`confEL_ErrCR', `confEL_ErrCR', `"554 BOGUSCR Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail from your host, which issues bogus challenge/response messages in response to spam/virus traffic."')

RPHISH				$#error $@ 5.7.1 $: ifdef(`confEL_ErrPhish', `confEL_ErrPhish', `"554 PHISHES Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail from your host, which is a source of annoyingly large amounts of phish attempts."')
RP					$#error $@ 5.7.1 $: ifdef(`confEL_ErrPhish', `confEL_ErrPhish', `"554 PHISHES Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail from your host, which is a source of annoyingly large amounts of phish attempts."')

RVIRUS				$#error $@ 5.7.1 $: ifdef(`confEL_ErrVirus', `confEL_ErrVirus', `"554 VIRUS Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail from your host, which is sending us viruses."')
RV					$#error $@ 5.7.1 $: ifdef(`confEL_ErrVirus', `confEL_ErrVirus', `"554 VIRUS Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail from your host, which is sending us viruses."')

RSV					$#error $@ 5.7.1 $: ifdef(`confEL_ErrSenderVerification', `confEL_ErrSenderVerification', `"554 NOVRFY Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail from your host, which is emitting sender verification abuse."')

R$*					$: $(EL_Offwhitelist $&{s} $)
RBADRECD			$#error $@ 5.7.1 $: ifdef(`confEL_ErrBadReceived', `confEL_ErrBadReceived', `"554 NOTRACK Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail from your server as it does not provide adequate tracking of point of injection and is therefore heavily abused."')
RT					$#error $@ 5.7.1 $: ifdef(`confEL_ErrBadReceived', `confEL_ErrBadReceived', `"554 NOTRACK Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail from your server as it does not provide adequate tracking of point of injection and is therefore heavily abused."')

RR					$#error $@ 5.7.1 $: ifdef(`confEL_ErrOpenRelay', `confEL_ErrOpenRelay', `"554 LOLORLY Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail from your server as it appears to be an open relay and is therefore heavily abused."')

RC$*				$#error $@ 5.7.1 $: ifdef(`confEL_ErrCR', `confEL_ErrCR', `"554 BOGUSCR Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail from your host, which issues bogus challenge/response messages in response to spam/virus traffic."')

RPHISH				$#error $@ 5.7.1 $: ifdef(`confEL_ErrPhish', `confEL_ErrPhish', `"554 PHISHES Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail from your host, which is a source of annoyingly large amounts of phish attempts."')
RP					$#error $@ 5.7.1 $: ifdef(`confEL_ErrPhish', `confEL_ErrPhish', `"554 PHISHES Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail from your host, which is a source of annoyingly large amounts of phish attempts."')

RVIRUS				$#error $@ 5.7.1 $: ifdef(`confEL_ErrVirus', `confEL_ErrVirus', `"554 VIRUS Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail from your host, which is sending us viruses."')
RV					$#error $@ 5.7.1 $: ifdef(`confEL_ErrVirus', `confEL_ErrVirus', `"554 VIRUS Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail from your host, which is sending us viruses."')

# catch the handbag scammers
R$*						$: $(EL_Offwhitelist $&{client_name} $) $| $&{mail_addr}
R419 $| $*@handbag.com	$#error $@ 5.7.1 $: ifdef(`confEL_ErrFrom419', `confEL_ErrFrom419', `"554 FROM419 Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as a variant of a Nigerian 419 scam."')
R$* $| $*				$: $1
')dnl

R$*						$: $&{client_ptr}
R$+.in-addr.arpa		$#error $@ 5.7.1 $: ifdef(`confEL_ErrInAddrArpa', `confEL_ErrInAddrArpa', `"554 INADDR Contact "$&{ELContactEmail}" if this is in error, but your message was rejected - your reverse DNS is bungled."')

R$*						$: $&{s}
R$+.in-addr.arpa		$#error $@ 5.7.1 $: ifdef(`confEL_ErrHELOInAddrArpa', `confEL_ErrHELOInAddrArpa', `"554 INADDR Contact "$&{ELContactEmail}" if this is in error, but your message was rejected - your HELO is bungled."')

ifdef(`_EL_RIGHTANCHOR', `dnl
# external non-access.db right anchor checks
#
# deal with hosts who have rDNS or hostname matching right anchor substrings
# e.g., given c-24-0-176-221.hsd1.tx.comcast.net
# test c-24-0-176-221.hsd1.tx.comcast.net
#                     hsd1.tx.comcast.net
#                          tx.comcast.net
#                             comcast.net
#
# ??? need to also avoid double jeopardy with patterns that also have a right anchor
R$*		$: $1 

# no sense checking the name if it does not resolve
R$*									$: $&{client_resolve} $| $&{client_name}

ROK $| $-.$-.$-.$-.$-.$-.$-.$-.$-	$: $&{client_resolve} $| $(EL_RightAnchors $2.$3.$4.$5.$6.$7.$8.$9 $)
ROK $| $-.$-.$-.$-.$-.$-.$-.$-		$: $&{client_resolve} $| $(EL_RightAnchors $2.$3.$4.$5.$6.$7.$8 $)
ROK $| $-.$-.$-.$-.$-.$-.$-			$: $&{client_resolve} $| $(EL_RightAnchors $2.$3.$4.$5.$6.$7 $)
ROK $| $-.$-.$-.$-.$-.$-			$: $&{client_resolve} $| $(EL_RightAnchors $2.$3.$4.$5.$6 $)
ROK $| $-.$-.$-.$-.$-				$: $&{client_resolve} $| $(EL_RightAnchors $2.$3.$4.$5 $)
ROK $| $-.$-.$-.$-					$: $&{client_resolve} $| $(EL_RightAnchors $2.$3.$4 $)
ROK $| $-.$-.$-						$: $&{client_resolve} $| $(EL_RightAnchors $2.$3 $)
ROK $| $-.$-						$: $&{client_resolve} $| $(EL_RightAnchors $2 $)
ROK $| $+							$: $&{client_resolve} $| $(EL_RightAnchors $1 $)

# but worth checking the name even if non-FCrDNS
RFORGED $| $*							$: $&{client_resolve} $| $&{client_ptr}

RFORGED $| $-.$-.$-.$-.$-.$-.$-.$-.$-	$: $&{client_resolve} $| $(EL_RightAnchors $2.$3.$4.$5.$6.$7.$8.$9 $)
RFORGED $| $-.$-.$-.$-.$-.$-.$-.$-		$: $&{client_resolve} $| $(EL_RightAnchors $2.$3.$4.$5.$6.$7.$8 $)
RFORGED $| $-.$-.$-.$-.$-.$-.$-			$: $&{client_resolve} $| $(EL_RightAnchors $2.$3.$4.$5.$6.$7 $)
RFORGED $| $-.$-.$-.$-.$-.$-			$: $&{client_resolve} $| $(EL_RightAnchors $2.$3.$4.$5.$6 $)
RFORGED $| $-.$-.$-.$-.$-				$: $&{client_resolve} $| $(EL_RightAnchors $2.$3.$4.$5 $)
RFORGED $| $-.$-.$-.$-					$: $&{client_resolve} $| $(EL_RightAnchors $2.$3.$4 $)
RFORGED $| $-.$-.$-						$: $&{client_resolve} $| $(EL_RightAnchors $2.$3 $)
RFORGED $| $-.$-						$: $&{client_resolve} $| $(EL_RightAnchors $2 $)
RFORGED $| $+							$: $&{client_resolve} $| $(EL_RightAnchors $1 $)

ifelse(_EL_POLICY, 1, `dnl
ROK $| $-							$: $1 $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
RFORGED $| $-						$: $1 $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
RRIGHT $| $*RTANCHR$* $| TAG		$: <TAGRIGHTANCHOR>
RRIGHT $| $*RTANCHR$* $| BLOCK		$: <REJRIGHTANCHOR>
RRIGHT $| $* +RTANCHR$* $| ASK		$: <TAGRIGHTANCHOR>
RRIGHT $| $* !RTANCHR$* $| ASK		$: <REJRIGHTANCHOR>

RSTATIC $| $*RTANCHR:static$* $| TAG			$: <TAGRIGHTANCHORS>
RSTATIC $| $*RTANCHR:static$* $| BLOCK			$: <REJRIGHTANCHORS>
RSTATIC $| $* +RTANCHR:static$* $| ASK			$: <TAGRIGHTANCHORS>
RSTATIC $| $* !RTANCHR:static$* $| ASK			$: <REJRIGHTANCHORS>

RMIXED $| $*RTANCHR:mixed$* $| TAG				$: <TAGRIGHTANCHORS>
RMIXED $| $*RTANCHR:mixed$* $| BLOCK			$: <REJRIGHTANCHORS>
RMIXED $| $* +RTANCHR:mixed$* $| ASK			$: <TAGRIGHTANCHORS>
RMIXED $| $* !RTANCHR:mixed$* $| ASK			$: <REJRIGHTANCHORS>

RDYNAMIC $| $*RTANCHR:dynamic$* $| TAG			$: <TAGRIGHTANCHORD>
RDYNAMIC $| $*RTANCHR:dynamic$* $| BLOCK		$: <REJRIGHTANCHORD>
RDYNAMIC $| $* +RTANCHR:dynamic$* $| ASK		$: <TAGRIGHTANCHORD>
RDYNAMIC $| $* !RTANCHR:dynamic$* $| ASK		$: <REJRIGHTANCHORD>

RGENERIC $| $*RTANCHR:generic$* $| TAG			$: <TAGRIGHTANCHOR>
RGENERIC $| $*RTANCHR:generic$* $| BLOCK		$: <REJRIGHTANCHOR>
RGENERIC $| $* +RTANCHR:generic$* $| ASK		$: <TAGRIGHTANCHOR>
RGENERIC $| $* !RTANCHR:generic$* $| ASK		$: <REJRIGHTANCHOR>

# if no match try default policy
R$* $| $* $| $* 					$: $1 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
RRIGHT $| $*RTANCHR$* $| TAG		$: <TAGRIGHTANCHOR>
RRIGHT $| $*RTANCHR$* $| BLOCK		$: <REJRIGHTANCHOR>
RRIGHT $| $* +RTANCHR$* $| ASK		$: <TAGRIGHTANCHOR>
RRIGHT $| $* !RTANCHR$* $| ASK		$: <REJRIGHTANCHOR>

RSTATIC $| $*RTANCHR:static$* $| TAG			$: <TAGRIGHTANCHORS>
RSTATIC $| $*RTANCHR:static$* $| BLOCK			$: <REJRIGHTANCHORS>
RSTATIC $| $* +RTANCHR:static$* $| ASK			$: <TAGRIGHTANCHORS>
RSTATIC $| $* !RTANCHR:static$* $| ASK			$: <REJRIGHTANCHORS>

RMIXED $| $*RTANCHR:mixed$* $| TAG				$: <TAGRIGHTANCHORS>
RMIXED $| $*RTANCHR:mixed$* $| BLOCK			$: <REJRIGHTANCHORS>
RMIXED $| $* +RTANCHR:mixed$* $| ASK			$: <TAGRIGHTANCHORS>
RMIXED $| $* !RTANCHR:mixed$* $| ASK			$: <REJRIGHTANCHORS>

RDYNAMIC $| $*RTANCHR:dynamic$* $| TAG			$: <TAGRIGHTANCHORD>
RDYNAMIC $| $*RTANCHR:dynamic$* $| BLOCK		$: <REJRIGHTANCHORD>
RDYNAMIC $| $* +RTANCHR:dynamic$* $| ASK		$: <TAGRIGHTANCHORD>
RDYNAMIC $| $* !RTANCHR:dynamic$* $| ASK		$: <REJRIGHTANCHORD>

RGENERIC $| $*RTANCHR:generic$* $| TAG			$: <TAGRIGHTANCHOR>
RGENERIC $| $*RTANCHR:generic$* $| BLOCK		$: <REJRIGHTANCHOR>
RGENERIC $| $* +RTANCHR:generic$* $| ASK		$: <TAGRIGHTANCHOR>
RGENERIC $| $* !RTANCHR:generic$* $| ASK		$: <REJRIGHTANCHOR>

R<TAGRIGHTANCHOR>					$: $(EL_SetVar {ELMatchedRightAnchor} $@ 1 $)  $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgRightAnchor', `confEL_TagErrMsgRightAnchor', `"remote host has generic name " $&{client_name} ')> $| ifdef(`confEL_ScoreRightGeneric', `confEL_ScoreRightGeneric', `3') 
R<REJRIGHTANCHOR>					$#error $@ 5.7.1 $: ifdef(`confEL_ErrRightAnchor', `confEL_ErrRightAnchor', `"554 RTANCHR Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail from hosts with generic hostnames, " $&{client_name} ", as they are nearly always zombies."')

R<TAGRIGHTANCHORS>					$: $(EL_SetVar {ELMatchedRightAnchor} $@ 1 $)$>EL_TagSuspicious <ifdef(`confEL_TagErrMsgRightAnchorStatic', `confEL_TagErrMsgRightAnchorStatic', `"remote host has static generic name " $&{client_name} ')> $| ifdef(`confEL_ScoreRightStatic', `confEL_ScoreRightStatic', `2')
R<REJRIGHTANCHORS>					$#error $@ 5.7.1 $: ifdef(`confEL_ErrRightAnchorStatic', `confEL_ErrRightAnchorStatic', `"554 RTANCHRS Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail from hosts with static generic hostnames, " $&{client_name} ", as they are often zombies."')

R<TAGRIGHTANCHORD>					$: $(EL_SetVar {ELMatchedRightAnchor} $@ 1 $)$>EL_TagSuspicious <ifdef(`confEL_TagErrMsgRightAnchorDynamic', `confEL_TagErrMsgRightAnchorDynamic', `"remote host has dynamic generic name " $&{client_name} ')> $| ifdef(`confEL_ScoreRightDynamic', `confEL_ScoreRightDynamic', `3')
R<REJRIGHTANCHORD>					$#error $@ 5.7.1 $: ifdef(`confEL_ErrRightAnchorDynamic', `confEL_ErrRightAnchorDynamic', `"554 RTANCHRD Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail from dynamic hosts with generic hostnames, " $&{client_name} ", as they are nearly always zombies."')
', `dnl
RRIGHT				$#error $@ 5.7.1 $: ifdef(`confEL_ErrRightAnchor', `confEL_ErrRightAnchor', `"554 RTANCHR Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail from hosts with generic hostnames, " $&{client_name} ", as they are nearly always zombies."')
RSTATIC				$#error $@ 5.7.1 $: ifdef(`confEL_ErrRightAnchorStatic', `confEL_ErrRightAnchorStatic', `"554 RTANCHRS Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail from hosts with static generic hostnames, " $&{client_name} ", as they are often zombies."')
RMIXED				$#error $@ 5.7.1 $: ifdef(`confEL_ErrRightAnchorMixed', `confEL_ErrRightAnchorMixed', `"554 RTANCHRM Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail from hosts with generic hostnames, " $&{client_name} ", as they are often zombies."')
RDYNAMIC			$#error $@ 5.7.1 $: ifdef(`confEL_ErrRightAnchorDynamic', `confEL_ErrRightAnchorDynamic', `"554 RTANCHRD Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail from dynamic hosts with generic hostnames, " $&{client_name} ", as they are nearly always zombies."')
RGENERIC			$#error $@ 5.7.1 $: ifdef(`confEL_ErrRightAnchor', `confEL_ErrRightAnchor', `"554 RTANCHR Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail from hosts with generic hostnames, " $&{client_name} ", as they are nearly always zombies."')
')dnl

# now check HELO
R$*								$: $&{s}
R$-.$-.$-.$-.$-.$-.$-.$-.$-		$: $(EL_RightAnchors $2.$3.$4.$5.$6.$7.$8.$9 $)
R$-.$-.$-.$-.$-.$-.$-.$-		$: $(EL_RightAnchors $2.$3.$4.$5.$6.$7.$8 $)
R$-.$-.$-.$-.$-.$-.$-			$: $(EL_RightAnchors $2.$3.$4.$5.$6.$7 $)
R$-.$-.$-.$-.$-.$-				$: $(EL_RightAnchors $2.$3.$4.$5.$6 $)
R$-.$-.$-.$-.$-					$: $(EL_RightAnchors $2.$3.$4.$5 $)
R$-.$-.$-.$-					$: $(EL_RightAnchors $2.$3.$4 $)
R$-.$-.$-						$: $(EL_RightAnchors $2.$3 $)
R$-.$-							$: $(EL_RightAnchors $2 $)
R$+								$: $(EL_RightAnchors $1 $)

ifelse(_EL_POLICY, 1, `dnl
R$-				$: $1 $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
RRIGHT $| $*RTANCHH$* $| TAG		$: <TAGHELORIGHTANCHOR>
RRIGHT $| $*RTANCHH$* $| BLOCK		$: <REJHELORIGHTANCHOR>
RRIGHT $| $* +RTANCHH$* $| ASK		$: <TAGHELORIGHTANCHOR>
RRIGHT $| $* !RTANCHH$* $| ASK		$: <REJHELORIGHTANCHOR>

RSTATIC $| $*RTANCHR:static$* $| TAG			$: <TAGHELORIGHTANCHORS>
RSTATIC $| $*RTANCHR:static$* $| BLOCK			$: <REJHELORIGHTANCHORS>
RSTATIC $| $* +RTANCHR:static$* $| ASK			$: <TAGHELORIGHTANCHORS>
RSTATIC $| $* !RTANCHR:static$* $| ASK			$: <REJHELORIGHTANCHORS>

RMIXED $| $*RTANCHR:mixed$* $| TAG				$: <TAGHELORIGHTANCHORS>
RMIXED $| $*RTANCHR:mixed$* $| BLOCK			$: <REJHELORIGHTANCHORS>
RMIXED $| $* +RTANCHR:mixed$* $| ASK			$: <TAGHELORIGHTANCHORS>
RMIXED $| $* !RTANCHR:mixed$* $| ASK			$: <REJHELORIGHTANCHORS>

RDYNAMIC $| $*RTANCHR:dynamic$* $| TAG			$: <TAGHELORIGHTANCHORD>
RDYNAMIC $| $*RTANCHR:dynamic$* $| BLOCK		$: <REJHELORIGHTANCHORD>
RDYNAMIC $| $* +RTANCHR:dynamic$* $| ASK		$: <TAGHELORIGHTANCHORD>
RDYNAMIC $| $* !RTANCHR:dynamic$* $| ASK		$: <REJHELORIGHTANCHORD>

RGENERIC $| $*RTANCHR:generic$* $| TAG			$: <TAGHELORIGHTANCHOR>
RGENERIC $| $*RTANCHR:generic$* $| BLOCK		$: <REJHELORIGHTANCHOR>
RGENERIC $| $* +RTANCHR:generic$* $| ASK		$: <TAGHELORIGHTANCHOR>
RGENERIC $| $* !RTANCHR:generic$* $| ASK		$: <REJHELORIGHTANCHOR>

# if no match try default policy
R$* $| $* $| $* 					$: $1 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
RRIGHT $| $*RTANCHH$* $| TAG		$: <TAGHELORIGHTANCHOR>
RRIGHT $| $*RTANCHH$* $| BLOCK		$: <REJHELORIGHTANCHOR>
RRIGHT $| $* +RTANCHH$* $| ASK		$: <TAGHELORIGHTANCHOR>
RRIGHT $| $* !RTANCHH$* $| ASK		$: <REJHELORIGHTANCHOR>

RSTATIC $| $*RTANCHR:static$* $| TAG			$: <TAGHELORIGHTANCHORS>
RSTATIC $| $*RTANCHR:static$* $| BLOCK			$: <REJHELORIGHTANCHORS>
RSTATIC $| $* +RTANCHR:static$* $| ASK			$: <TAGHELORIGHTANCHORS>
RSTATIC $| $* !RTANCHR:static$* $| ASK			$: <REJHELORIGHTANCHORS>

RMIXED $| $*RTANCHR:mixed$* $| TAG				$: <TAGHELORIGHTANCHORS>
RMIXED $| $*RTANCHR:mixed$* $| BLOCK			$: <REJHELORIGHTANCHORS>
RMIXED $| $* +RTANCHR:mixed$* $| ASK			$: <TAGHELORIGHTANCHORS>
RMIXED $| $* !RTANCHR:mixed$* $| ASK			$: <REJHELORIGHTANCHORS>

RDYNAMIC $| $*RTANCHR:dynamic$* $| TAG			$: <TAGHELORIGHTANCHORD>
RDYNAMIC $| $*RTANCHR:dynamic$* $| BLOCK		$: <REJHELORIGHTANCHORD>
RDYNAMIC $| $* +RTANCHR:dynamic$* $| ASK		$: <TAGHELORIGHTANCHORD>
RDYNAMIC $| $* !RTANCHR:dynamic$* $| ASK		$: <REJHELORIGHTANCHORD>

RGENERIC $| $*RTANCHR:generic$* $| TAG			$: <TAGHELORIGHTANCHOR>
RGENERIC $| $*RTANCHR:generic$* $| BLOCK		$: <REJHELORIGHTANCHOR>
RGENERIC $| $* +RTANCHR:generic$* $| ASK		$: <TAGHELORIGHTANCHOR>
RGENERIC $| $* !RTANCHR:generic$* $| ASK		$: <REJHELORIGHTANCHOR>

R<TAGHELORIGHTANCHOR>				$: $(EL_SetVar {ELMatchedRightAnchor} $@ 1 $) $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgRightAnchorHelo', `confEL_TagErrMsgRightAnchorHelo', `"remote host used generic HELO " $&{s} ')> $| ifdef(`confEL_ScoreRightHELOGeneric', `confEL_ScoreRightHELOGeneric', `3')
R<REJHELORIGHTANCHOR>				$#error $@ 5.7.1 $: ifdef(`confEL_ErrRightAnchorHelo', `confEL_ErrRightAnchorHelo', `"554 RTANCHH Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail from hosts that HELO with generic hostnames, " $&{s} ", as they are nearly always zombies."')

R<TAGHELORIGHTANCHORS>				$: $(EL_SetVar {ELMatchedRightAnchor} $@ 1 $) $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgRightAnchorHeloStatic', `confEL_TagErrMsgRightAnchorHeloStatic', `"remote host used static generic HELO " $&{s} ')> $| ifdef(`confEL_ScoreRightHELOStatic', `confEL_ScoreRightHELOStatic', `3')
R<REJHELORIGHTANCHORS>				$#error $@ 5.7.1 $: ifdef(`confEL_ErrRightAnchorHeloStatic', `confEL_ErrRightAnchorHeloStatic', `"554 RTANCHHS Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail from static hosts that HELO with generic hostnames, " $&{s} ", as they are nearly always zombies."')

R<TAGHELORIGHTANCHORD>				$: $(EL_SetVar {ELMatchedRightAnchor} $@ 1 $) $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgRightAnchorHeloDynamic', `confEL_TagErrMsgRightAnchorHeloDynamic', `"remote host used dynamic generic HELO " $&{s} ')> $| ifdef(`confEL_ScoreRightHELODynamic', `confEL_ScoreRightHELODynamic', `4')
R<REJHELORIGHTANCHORD>				$#error $@ 5.7.1 $: ifdef(`confEL_ErrRightAnchorHeloDynamic', `confEL_ErrRightAnchorHeloDynamic', `"554 RTANCHHD Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail from dynamic hosts that HELO with generic hostnames, " $&{s} ", as they are nearly always zombies."')
', `dnl
RRIGHT				$#error $@ 5.7.1 $: ifdef(`confEL_ErrRightAnchorHelo', `confEL_ErrRightAnchorHelo', `"554 RTANCHH Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail from hosts that HELO with generic hostnames, " $&{s} ", as they are nearly always zombies."')
RSTATIC				$#error $@ 5.7.1 $: ifdef(`confEL_ErrRightAnchorHeloStatic', `confEL_ErrRightAnchorHeloStatic', `"554 RTANCHHS Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail from static hosts that HELO with generic hostnames, " $&{s} ", as they are nearly always zombies."')
RMIXED				$#error $@ 5.7.1 $: ifdef(`confEL_ErrRightAnchorHeloMixed', `confEL_ErrRightAnchorHeloMixed', `"554 RTANCHHM Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail from hosts that HELO with generic hostnames, " $&{s} ", as they are nearly always zombies."')
RDYNAMIC			$#error $@ 5.7.1 $: ifdef(`confEL_ErrRightAnchorHeloDynamic', `confEL_ErrRightAnchorHeloDynamic', `"554 RTANCHHD Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail from dynamic hosts that HELO with generic hostnames, " $&{s} ", as they are nearly always zombies."')
RGENERIC			$#error $@ 5.7.1 $: ifdef(`confEL_ErrRightAnchorHelo', `confEL_ErrRightAnchorHelo', `"554 RTANCHH Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail from hosts that HELO with generic hostnames, " $&{s} ", as they are nearly always zombies."')
')dnl
')dnl

ifdef(`_EL_DNSBL', `dnl
# DNSBL lookup interface
# check HELO first
# ??? bug here of sorts when HELO is bracketed IP
R$*										$: $&{s}
ifelse(_EL_POLICY, 1, `dnl
R$+										$: <?> $(EL_HostIP $1.h.enemieslist.com.. $) $| $1 $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
R<?>OK $| $* $| $* $| $*				$: OKSOFAR $| $1 $| $2 $| $3
R<?>$+<TMP> $| $* $| $* $| $*			$: TMPOK $| $2 $| $3 $| $4
R<?>$+ $| $* $| $+ $| $+				$: <?>$1 $| $2 $| $3 $| $4 ifdef(`_EL_DEBUG', `$(EL_Log "EL dnsbl " $&{client_name} " is " $1 $)')

# or maybe we should return 222.173.190.239?
R<?>127.127.127.127 $| $* $| $+ $| $+	$@ $(EL_Log "EL: SYSERR: dnsbl has been discontinued - please stop using it." $)

R<?>$+.0.1 $| $* $| $*HELOGEN:generic$* $| TAG		$: <TAGGEN>
R<?>$+.0.1 $| $* $| $*HELOGEN:generic$* $| BLOCK	$: <REJGEN>
R<?>$+.0.1 $| $* $| $* +HELOGEN:generic$* $| ASK	$: <TAGGEN>
R<?>$+.0.1 $| $* $| $* !HELOGEN:generic$* $| ASK	$: <REJGEN>

# special case for handling webhosts
R<?>$+.2.2 $| $* $| $*HELOGEN:webhost$* $| TAG		$: <TAGWEB>
R<?>$+.2.2 $| $* $| $*HELOGEN:webhost$* $| BLOCK	$: <REJWEB>
R<?>$+.2.2 $| $* $| $* +HELOGEN:webhost$* $| ASK	$: <TAGWEB>
R<?>$+.2.2 $| $* $| $* !HELOGEN:webhost$* $| ASK	$: <REJWEB>

R<?>$+.0.2 $| $* $| $*HELOGEN:static$* $| TAG		$: <TAGSTA>
R<?>$+.0.2 $| $* $| $*HELOGEN:static$* $| BLOCK		$: <REJSTA>
R<?>$+.0.2 $| $* $| $* +HELOGEN:static$* $| ASK		$: <TAGSTA>
R<?>$+.0.2 $| $* $| $* !HELOGEN:static$* $| ASK		$: <REJSTA>

R<?>$+.0.3 $| $* $| $*HELOGEN:dynamic$* $| TAG		$: <TAGDYN>
R<?>$+.0.3 $| $* $| $*HELOGEN:dynamic$* $| BLOCK	$: <REJDYN>
R<?>$+.0.3 $| $* $| $* +HELOGEN:dynamic$* $| ASK	$: <TAGDYN>
R<?>$+.0.3 $| $* $| $* !HELOGEN:dynamic$* $| ASK	$: <REJDYN>

R<?>$+.0.4 $| $* $| $*DOMAINSBL$* $| TAG			$: <TAGSPM>
R<?>$+.0.4 $| $* $| $*DOMAINSBL$* $| BLOCK			$: <REJSPM>
R<?>$+.0.4 $| $* $| $* +DOMAINSBL$* $| ASK			$: <TAGSPM>
R<?>$+.0.4 $| $* $| $* !DOMAINSBL$* $| ASK			$: <REJSPM>

R<?>$+.0.10 $| $* $| $*HELOGEN:mixed$* $| TAG		$: <TAGMIX>
R<?>$+.0.10 $| $* $| $*HELOGEN:mixed$* $| BLOCK		$: <REJMIX>
R<?>$+.0.10 $| $* $| $* +HELOGEN:mixed$* $| ASK		$: <TAGMIX>
R<?>$+.0.10 $| $* $| $* !HELOGEN:mixed$* $| ASK		$: <REJMIX>

R<?>$+.0.11 $| $* $| $*HELOGEN:badrdns$* $| TAG		$: <TAGBAD>
R<?>$+.0.11 $| $* $| $*HELOGEN:badrdns$* $| BLOCK	$: <REJBAD>
R<?>$+.0.11 $| $* $| $* +HELOGEN:badrdns$* $| ASK	$: <TAGBAD>
R<?>$+.0.11 $| $* $| $* !HELOGEN:badrdns$* $| ASK	$: <REJBAD>

R<?>$+.0.12 $| $* $| $*HELOGEN:cloud$* $| TAG		$: <TAGCLD>
R<?>$+.0.12 $| $* $| $*HELOGEN:cloud$* $| BLOCK		$: <REJCLD>
R<?>$+.0.12 $| $* $| $* +HELOGEN:cloud$* $| ASK		$: <TAGCLD>
R<?>$+.0.12 $| $* $| $* !HELOGEN:cloud$* $| ASK		$: <REJCLD>


# compact and right anchor set octet 3 to "1" so we can 
# test here for that if local policy does not allow any
# blocking on non-fully-qualified patterns.
R<?>$+.1.5 $| $* $| $*HELOGEN:compact$* $| TAG		$: <TAGGEN>
R<?>$+.1.5 $| $* $| $*HELOGEN:compact$* $| BLOCK	$: <REJGEN>
R<?>$+.1.5 $| $* $| $* +HELOGEN:compact$* $| ASK	$: <TAGGEN>
R<?>$+.1.5 $| $* $| $* !HELOGEN:compact$* $| ASK	$: <REJGEN>

R<?>$+.1.6 $| $* $| $*HELOGEN:rightanch$* $| TAG	$: <TAGGEN>
R<?>$+.1.6 $| $* $| $*HELOGEN:rightanch$* $| BLOCK	$: <REJGEN>
R<?>$+.1.6 $| $* $| $* +HELOGEN:rightanch$* $| ASK	$: <TAGGEN>
R<?>$+.1.6 $| $* $| $* !HELOGEN:rightanch$* $| ASK	$: <REJGEN>

R<?>$+.0.7 $| $* $| $*HELOGEN:resnet$* $| TAG		$: <TAGRES>
R<?>$+.0.7 $| $* $| $*HELOGEN:resnet$* $| BLOCK		$: <REJRES>
R<?>$+.0.7 $| $* $| $* +HELOGEN:resnet$* $| ASK		$: <TAGRES>
R<?>$+.0.7 $| $* $| $* !HELOGEN:resnet$* $| ASK		$: <REJRES>

R<?>$+.0.8 $| $* $| $*HELOGEN:unassigned$* $| TAG	$: <TAGUNK>
R<?>$+.0.8 $| $* $| $*HELOGEN:unassigned$* $| BLOCK	$: <REJUNK>
R<?>$+.0.8 $| $* $| $* +HELOGEN:unassigned$* $| ASK	$: <TAGUNK>
R<?>$+.0.8 $| $* $| $* !HELOGEN:unassigned$* $| ASK	$: <REJUNK>

R<?>$+.0.9 $| $* $| $*HELOGEN:natproxy$* $| TAG	$: <TAGNAT>
R<?>$+.0.9 $| $* $| $*HELOGEN:natproxy$* $| BLOCK	$: <REJNAT>
R<?>$+.0.9 $| $* $| $* +HELOGEN:natproxy$* $| ASK	$: <TAGNAT>
R<?>$+.0.9 $| $* $| $* !HELOGEN:natproxy$* $| ASK	$: <REJNAT>

# if no match try default policy
R$* $| $* $| $* $| $* 								$: $1 $| $2 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
R<?>$+.0.1 $| $* $| $*HELOGEN:generic$* $| TAG		$: <TAGGEN>
R<?>$+.0.1 $| $* $| $*HELOGEN:generic$* $| BLOCK	$: <REJGEN>
R<?>$+.0.1 $| $* $| $* +HELOGEN:generic$* $| ASK	$: <TAGGEN>
R<?>$+.0.1 $| $* $| $* !HELOGEN:generic$* $| ASK	$: <REJGEN>

# special case for handling webhosts
R<?>$+.2.2 $| $* $| $*HELOGEN:webhost$* $| TAG		$: <TAGWEB>
R<?>$+.2.2 $| $* $| $*HELOGEN:webhost$* $| BLOCK	$: <REJWEB>
R<?>$+.2.2 $| $* $| $* +HELOGEN:webhost$* $| ASK	$: <TAGWEB>
R<?>$+.2.2 $| $* $| $* !HELOGEN:webhost$* $| ASK	$: <REJWEB>

R<?>$+.0.2 $| $* $| $*HELOGEN:static$* $| TAG		$: <TAGSTA>
R<?>$+.0.2 $| $* $| $*HELOGEN:static$* $| BLOCK		$: <REJSTA>
R<?>$+.0.2 $| $* $| $* +HELOGEN:static$* $| ASK		$: <TAGSTA>
R<?>$+.0.2 $| $* $| $* !HELOGEN:static$* $| ASK		$: <REJSTA>

R<?>$+.0.3 $| $* $| $*HELOGEN:dynamic$* $| TAG		$: <TAGDYN>
R<?>$+.0.3 $| $* $| $*HELOGEN:dynamic$* $| BLOCK	$: <REJDYN>
R<?>$+.0.3 $| $* $| $* +HELOGEN:dynamic$* $| ASK	$: <TAGDYN>
R<?>$+.0.3 $| $* $| $* !HELOGEN:dynamic$* $| ASK	$: <REJDYN>

R<?>$+.0.4 $| $* $| $*DOMAINSBL$* $| TAG			$: <TAGSPM>
R<?>$+.0.4 $| $* $| $*DOMAINSBL$* $| BLOCK			$: <REJSPM>
R<?>$+.0.4 $| $* $| $* +DOMAINSBL$* $| ASK			$: <TAGSPM>
R<?>$+.0.4 $| $* $| $* !DOMAINSBL$* $| ASK			$: <REJSPM>

R<?>$+.0.7 $| $* $| $*HELOGEN:resnet$* $| TAG		$: <TAGRES>
R<?>$+.0.7 $| $* $| $*HELOGEN:resnet$* $| BLOCK		$: <REJRES>
R<?>$+.0.7 $| $* $| $* +HELOGEN:resnet$* $| ASK		$: <TAGRES>
R<?>$+.0.7 $| $* $| $* !HELOGEN:resnet$* $| ASK		$: <REJRES>

R<?>$+.0.8 $| $* $| $*HELOGEN:unassigned$* $| TAG	$: <TAGUNK>
R<?>$+.0.8 $| $* $| $*HELOGEN:unassigned$* $| BLOCK	$: <REJUNK>
R<?>$+.0.8 $| $* $| $* +HELOGEN:unassigned$* $| ASK	$: <TAGUNK>
R<?>$+.0.8 $| $* $| $* !HELOGEN:unassigned$* $| ASK	$: <REJUNK>

R<?>$+.0.9 $| $* $| $*HELOGEN:natproxy$* $| TAG	$: <TAGNAT>
R<?>$+.0.9 $| $* $| $*HELOGEN:natproxy$* $| BLOCK	$: <REJNAT>
R<?>$+.0.9 $| $* $| $* +HELOGEN:natproxy$* $| ASK	$: <TAGNAT>
R<?>$+.0.9 $| $* $| $* !HELOGEN:natproxy$* $| ASK	$: <REJNAT>

R<?>$+.0.10 $| $* $| $*HELOGEN:mixed$* $| TAG		$: <TAGMIX>
R<?>$+.0.10 $| $* $| $*HELOGEN:mixed$* $| BLOCK		$: <REJMIX>
R<?>$+.0.10 $| $* $| $* +HELOGEN:mixed$* $| ASK		$: <TAGMIX>
R<?>$+.0.10 $| $* $| $* !HELOGEN:mixed$* $| ASK		$: <REJMIX>

R<?>$+.0.11 $| $* $| $*HELOGEN:badrdns$* $| TAG		$: <TAGBAD>
R<?>$+.0.11 $| $* $| $*HELOGEN:badrdns$* $| BLOCK	$: <REJBAD>
R<?>$+.0.11 $| $* $| $* +HELOGEN:badrdns$* $| ASK	$: <TAGBAD>
R<?>$+.0.11 $| $* $| $* !HELOGEN:badrdns$* $| ASK	$: <REJBAD>

R<?>$+.0.12 $| $* $| $*HELOGEN:cloud$* $| TAG		$: <TAGCLD>
R<?>$+.0.12 $| $* $| $*HELOGEN:cloud$* $| BLOCK		$: <REJCLD>
R<?>$+.0.12 $| $* $| $* +HELOGEN:cloud$* $| ASK		$: <TAGCLD>
R<?>$+.0.12 $| $* $| $* !HELOGEN:cloud$* $| ASK		$: <REJCLD>

# compact and right anchor set octet 3 to "1" so we can 
# test here for that if local policy does not allow any
# blocking on non-fully-qualified patterns.
R<?>$+.1.5 $| $* $| $*HELOGEN:compact$* $| TAG		$: <TAGGEN>
R<?>$+.1.5 $| $* $| $*HELOGEN:compact$* $| BLOCK	$: <REJGEN>
R<?>$+.1.5 $| $* $| $* +HELOGEN:compact$* $| ASK	$: <TAGGEN>
R<?>$+.1.5 $| $* $| $* !HELOGEN:compact$* $| ASK	$: <REJGEN>

R<?>$+.1.6 $| $* $| $*HELOGEN:rightanch$* $| TAG	$: <TAGGEN>
R<?>$+.1.6 $| $* $| $*HELOGEN:rightanch$* $| BLOCK	$: <REJGEN>
R<?>$+.1.6 $| $* $| $* +HELOGEN:rightanch$* $| ASK	$: <TAGGEN>
R<?>$+.1.6 $| $* $| $* !HELOGEN:rightanch$* $| ASK	$: <REJGEN>

# check for double jeopardy with right anchor matches
R$+ 					$: $1 $| $(EL_Math = $@ 1 $@ $&{ELMatchedRightAnchor} $)
R$+ $| TRUE				$: <SKIPCHECK>
R$+ $| $*				$: $1

R<TAGGEN>				$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgGenericrDNSHELO', `confEL_TagErrMsgGenericrDNSHELO', `"remote host has generic reverse DNS HELO"')> $| ifdef(`confEL_ScoreHELOGEN', `confEL_ScoreHELOGEN', `4')
R<REJGEN>				$#error $@ 5.7.1. $: ifdef(`confEL_ErrHeloGenrdns', `confEL_ErrHeloGenrdns', `"554 GENHELO Contact <"$&{ELContactEmail}"> if in error, <"$&f">, but we refuse mail directly from hosts that HELO with generic reverse DNS; please use another outbound mail server, "$&{client_name}"."') 

R<TAGSTA>				$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgStatGenericrDNSHELO', `confEL_TagErrMsgStatGenericrDNSHELO', `"remote host has generic static reverse DNS HELO"')> $| ifdef(`confEL_ScoreHELOGENStatic', `confEL_ScoreHELOGENStatic', `4')
R<REJSTA>				$#error $@ 5.7.1. $: ifdef(`confEL_ErrHeloStatGenrdns', `confEL_ErrHeloStatGenrdns', `"554 SGNHELO Contact <"$&{ELContactEmail}"> if in error, <"$&f">, but we refuse mail directly from hosts that HELO with generic static reverse DNS; please use another outbound mail server, "$&{client_name}"."')

R<TAGMIX>				$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgStatMixedrDNSHELO', `confEL_TagErrMsgStatMixedrDNSHELO', `"remote host has generic reverse DNS HELO"')> $| ifdef(`confEL_ScoreHELOGENMixed', `confEL_ScoreHELOGENMixed', `4')
R<REJMIX>				$#error $@ 5.7.1. $: ifdef(`confEL_ErrHeloMixedGenrdns', `confEL_ErrHeloMixedGenrdns', `"554 MGNHELO Contact <"$&{ELContactEmail}"> if in error, <"$&f">, but we refuse mail directly from hosts that HELO with generic reverse DNS; please use another outbound mail server, "$&{client_name}"."')

R<TAGDYN>				$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgDynGenericrDNSHELO', `confEL_TagErrMsgDynGenericrDNSHELO', `"remote host has generic dynamic reverse DNS HELO"')> $| ifdef(`confEL_ScoreHELOGENDynamic', `confEL_ScoreHELOGENDynamic', `4')
R<REJDYN>				$#error $@ 5.7.1. $: ifdef(`confEL_ErrHeloDynGenrdns', `confEL_ErrHeloDynGenrdns', `"554 DGNHELO Contact <"$&{ELContactEmail}"> if in error, <"$&f">, but we refuse mail directly from hosts that HELO with generic dynamic reverse DNS; please use another outbound mail server, "$&{client_name}"."') 

R<TAGSPM>				$: $>EL_TagSuspicious <"remote sender is a known spammer"> $| ifdef(`confEL_ScoreDOMAINSBL', `confEL_ScoreDOMAINSBL', `4')
R<REJSPM>				$#error $@ 5.7.1. $: "554 SPAMMER Contact <"$&{ELContactEmail}"> if in error, <"$&f">, but we refuse mail from spammers."

R<TAGWEB>				$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgGenericWebhostrDNSHELO', `confEL_TagErrMsgGenericWebhostrDNSHELO', `"remote host has generic reverse DNS HELO (webhost)"')> $| ifdef(`confEL_ScoreHELOGENWebhost', `confEL_ScoreHELOGENWebhost', `2')
R<REJWEB>				$#error $@ 5.7.1. $: ifdef(`confEL_ErrHeloGenrdnsWebhost', `confEL_ErrHeloGenrdnsWebhost', `"554 WEBHELO Contact <"$&{ELContactEmail}"> if in error, <"$&f">, but we refuse mail directly from hosts that HELO with generic Web hosting provider reverse DNS; please use another outbound mail server, "$&{client_name}"."') 

R<TAGRES>				$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgGenericResnetrDNSHELO', `confEL_TagErrMsgGenericResnetrDNSHELO', `"remote host has generic reverse DNS HELO (resnet)"')> $| ifdef(`confEL_ScoreHELOGENResnet', `confEL_ScoreHELOGENResnet', `4')
R<REJRES>				$#error $@ 5.7.1. $: ifdef(`confEL_ErrHeloGenrdnsResnet', `confEL_ErrHeloGenrdnsResnet', `"554 RSNHELO Contact <"$&{ELContactEmail}"> if in error, <"$&f">, but we refuse mail directly from hosts that HELO with generic residential network reverse DNS; please use another outbound mail server, "$&{client_name}"."') 

R<TAGUNK>				$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgGenericUnknownrDNSHELO', `confEL_TagErrMsgGenericUnknownrDNSHELO', `"remote host has unknown/unassigned generic reverse DNS HELO"')> $| ifdef(`confEL_ScoreHELOGENUnknown', `confEL_ScoreHELOGENUnknown', `4')
R<REJUNK>				$#error $@ 5.7.1. $: ifdef(`confEL_ErrHeloGenrdnsUnknown', `confEL_ErrHeloGenrdnsUnknown', `"554 UNKHELO Contact <"$&{ELContactEmail}"> if in error, <"$&f">, but we refuse mail directly from hosts that HELO with generic unknown/unassigned reverse DNS; please use another outbound mail server, "$&{client_name}"."') 

R<TAGNAT>				$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgGenericNatProxyrDNSHELO', `confEL_TagErrMsgGenericNatProxyrDNSHELO', `"remote host has generic NAT/Proxy reverse DNS HELO"')> $| ifdef(`confEL_ScoreHELOGENNatProxy', `confEL_ScoreHELOGENNatProxy', `4')
R<REJNAT>				$#error $@ 5.7.1. $: ifdef(`confEL_ErrHeloGenrdnsNatProxy', `confEL_ErrHeloGenrdnsNatProxy', `"554 NATHELO Contact <"$&{ELContactEmail}"> if in error, <"$&f">, but we refuse mail directly from hosts that HELO with generic NAT/Proxy reverse DNS; please use another outbound mail server, "$&{client_name}"."') 

R<TAGBAD>				$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgGenericBadrDNSHELO', `confEL_TagErrMsgGenericBadrDNSHELO', `"remote host has generic bad/mangled reverse DNS HELO"')> $| ifdef(`confEL_ScoreHELOGENBadrDNS', `confEL_ScoreHELOGENBadrDNS', `4')
R<REJBAD>				$#error $@ 5.7.1. $: ifdef(`confEL_ErrHeloGenBadrdns', `confEL_ErrHeloGenBadrdns', `"554 BRDNSHELO Contact <"$&{ELContactEmail}"> if in error, <"$&f">, but we refuse mail directly from hosts that HELO with bad/mangled reverse DNS; please use another outbound mail server, "$&{client_name}"."') 

R<TAGCLD>				$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgGenericCloudrDNSHELO', `confEL_TagErrMsgGenericCloudrDNSHELO', `"remote host has generic cloud computing reverse DNS HELO"')> $| ifdef(`confEL_ScoreHELOGENCloud', `confEL_ScoreHELOGENCloud', `4')
R<REJCLD>				$#error $@ 5.7.1. $: ifdef(`confEL_ErrHeloGenCloud', `confEL_ErrHeloGenCloud', `"554 CLOUDHELO Contact <"$&{ELContactEmail}"> if in error, <"$&f">, but we refuse mail directly from hosts that HELO with generic cloud computing reverse DNS; please use another outbound mail server, "$&{client_name}"."') 
', `
R$+									$: <?> $(EL_HostIP $&{s}.h.enemieslist.com.. $) $| $1
R<?>OK $| $* 						$: OKSOFAR
R<?>$+<TMP> $| $* 					$: TMPOK
R<?>$+ $| $*						$#error $@ 5.7.1. $: ifdef(`confEL_ErrHeloGenrdns', `confEL_ErrHeloGenrdns', `"554 GENHELO Contact <"$&{ELContactEmail}"> if in error, <"$&f">, but we refuse mail directly from hosts that HELO with generic reverse DNS; please use another outbound mail server, "$&{client_name}"."')
')dnl

R$*										$: $&{client_resolve} $| $&{client_name}
ifelse(_EL_POLICY, 1, `dnl
RFORGED $| $+							$: <WORKAROUND> $| $&{client_ptr}
R<WORKAROUND> $| $+						$: <?> $(EL_HostIP $1.g.enemieslist.com. $) $| $1 $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
ROK $| $+								$: <?> $(EL_HostIP $1.g.enemieslist.com. $) $| $1 $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
R<?>OK $| $* $| $* $| $*				$: OKSOFAR $| $1 $| $2 $| $3
R<?>$+<TMP> $| $* $| $* $| $*			$: TMPOK $| $2 $| $3 $| $4
R<?>$+ $| $* $| $+ $| $+				$: <?>$1 $| $2 $| $3 $| $4 ifdef(`_EL_DEBUG', `$(EL_Log "EL dnsbl for " $&{client_name} " is " $1 $)')

# or maybe we should return 222.173.190.239?
R<?>127.127.127.127 $| $* $| $+ $| $+	$@ $(EL_Log "EL: SYSERR: dnsbl has been discontinued - please stop using it." $)

R<?>$+.0.1 $| $* $| $*GENRDNS:generic$* $| TAG		$: <TAGGEN>
R<?>$+.0.1 $| $* $| $*GENRDNS:generic$* $| BLOCK	$: <REJGEN>
R<?>$+.0.1 $| $* $| $* +GENRDNS:generic$* $| ASK	$: <TAGGEN>
R<?>$+.0.1 $| $* $| $* !GENRDNS:generic$* $| ASK	$: <REJGEN>

# special case for handling webhosts
R<?>$+.2.2 $| $* $| $*GENRDNS:webhost$* $| TAG		$: <TAGWEB>
R<?>$+.2.2 $| $* $| $*GENRDNS:webhost$* $| BLOCK	$: <REJWEB>
R<?>$+.2.2 $| $* $| $* +GENRDNS:webhost$* $| ASK	$: <TAGWEB>
R<?>$+.2.2 $| $* $| $* !GENRDNS:webhost$* $| ASK	$: <REJWEB>

R<?>$+.0.2 $| $* $| $*GENRDNS:static$* $| TAG		$: <TAGSTA>
R<?>$+.0.2 $| $* $| $*GENRDNS:static$* $| BLOCK		$: <REJSTA>
R<?>$+.0.2 $| $* $| $* +GENRDNS:static$* $| ASK		$: <TAGSTA>
R<?>$+.0.2 $| $* $| $* !GENRDNS:static$* $| ASK		$: <REJSTA>

R<?>$+.0.3 $| $* $| $*GENRDNS:dynamic$* $| TAG		$: <TAGDYN>
R<?>$+.0.3 $| $* $| $*GENRDNS:dynamic$* $| BLOCK	$: <REJDYN>
R<?>$+.0.3 $| $* $| $* +GENRDNS:dynamic$* $| ASK	$: <TAGDYN>
R<?>$+.0.3 $| $* $| $* !GENRDNS:dynamic$* $| ASK	$: <REJDYN>

R<?>$+.0.4 $| $* $| $*DOMAINSBL$* $| TAG			$: <TAGSPM>
R<?>$+.0.4 $| $* $| $*DOMAINSBL$* $| BLOCK			$: <REJSPM>
R<?>$+.0.4 $| $* $| $* +DOMAINSBL$* $| ASK			$: <TAGSPM>
R<?>$+.0.4 $| $* $| $* !DOMAINSBL$* $| ASK			$: <REJSPM>

R<?>$+.0.7 $| $* $| $*GENRDNS:resnet$* $| TAG		$: <TAGRES>
R<?>$+.0.7 $| $* $| $*GENRDNS:resnet$* $| BLOCK		$: <REJRES>
R<?>$+.0.7 $| $* $| $* +GENRDNS:resnet$* $| ASK		$: <TAGRES>
R<?>$+.0.7 $| $* $| $* !GENRDNS:resnet$* $| ASK		$: <REJRES>

R<?>$+.0.8 $| $* $| $*GENRDNS:unassigned$* $| TAG	$: <TAGUNK>
R<?>$+.0.8 $| $* $| $*GENRDNS:unassigned$* $| BLOCK	$: <REJUNK>
R<?>$+.0.8 $| $* $| $* +GENRDNS:unassigned$* $| ASK	$: <TAGUNK>
R<?>$+.0.8 $| $* $| $* !GENRDNS:unassigned$* $| ASK	$: <REJUNK>

R<?>$+.0.9 $| $* $| $*GENRDNS:natproxy$* $| TAG		$: <TAGNAT>
R<?>$+.0.9 $| $* $| $*GENRDNS:natproxy$* $| BLOCK	$: <REJNAT>
R<?>$+.0.9 $| $* $| $* +GENRDNS:natproxy$* $| ASK	$: <TAGNAT>
R<?>$+.0.9 $| $* $| $* !GENRDNS:natproxy$* $| ASK	$: <REJNAT>

R<?>$+.0.10 $| $* $| $*GENRDNS:mixed$* $| TAG		$: <TAGMIX>
R<?>$+.0.10 $| $* $| $*GENRDNS:mixed$* $| BLOCK		$: <REJMIX>
R<?>$+.0.10 $| $* $| $* +GENRDNS:mixed$* $| ASK		$: <TAGMIX>
R<?>$+.0.10 $| $* $| $* !GENRDNS:mixed$* $| ASK		$: <REJMIX>

R<?>$+.0.11 $| $* $| $*GENRDNS:badrdns$* $| TAG		$: <TAGBAD>
R<?>$+.0.11 $| $* $| $*GENRDNS:badrdns$* $| BLOCK	$: <REJBAD>
R<?>$+.0.11 $| $* $| $* +GENRDNS:badrdns$* $| ASK	$: <TAGBAD>
R<?>$+.0.11 $| $* $| $* !GENRDNS:badrdns$* $| ASK	$: <REJBAD>

R<?>$+.0.12 $| $* $| $*GENRDNS:cloud$* $| TAG		$: <TAGCLD>
R<?>$+.0.12 $| $* $| $*GENRDNS:cloud$* $| BLOCK		$: <REJCLD>
R<?>$+.0.12 $| $* $| $* +GENRDNS:cloud$* $| ASK		$: <TAGCLD>
R<?>$+.0.12 $| $* $| $* !GENRDNS:cloud$* $| ASK		$: <REJCLD>


# compact and right anchor set octet 3 to "1" so we can 
# test here for that if local policy does not allow any
# blocking on non-fully-qualified patterns.
R<?>$+.1.5 $| $* $| $*GENRDNS:compact$* $| TAG		$: <TAGGEN>
R<?>$+.1.5 $| $* $| $*GENRDNS:compact$* $| BLOCK	$: <REJGEN>
R<?>$+.1.5 $| $* $| $* +GENRDNS:compact$* $| ASK	$: <TAGGEN>
R<?>$+.1.5 $| $* $| $* !GENRDNS:compact$* $| ASK	$: <REJGEN>

R<?>$+.1.6 $| $* $| $*GENRDNS:rightanch$* $| TAG	$: <TAGGEN>
R<?>$+.1.6 $| $* $| $*GENRDNS:rightanch$* $| BLOCK	$: <REJGEN>
R<?>$+.1.6 $| $* $| $* +GENRDNS:rightanch$* $| ASK	$: <TAGGEN>
R<?>$+.1.6 $| $* $| $* !GENRDNS:rightanch$* $| ASK	$: <REJGEN>


# if no match try default policy
R$* $| $* $| $* $| $* 								$: $1 $| $2 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
R<?>$+.0.1 $| $* $| $*GENRDNS:generic$* $| TAG		$: <TAGGEN>
R<?>$+.0.1 $| $* $| $*GENRDNS:generic$* $| BLOCK	$: <REJGEN>
R<?>$+.0.1 $| $* $| $* +GENRDNS:generic$* $| ASK	$: <TAGGEN>
R<?>$+.0.1 $| $* $| $* !GENRDNS:generic$* $| ASK	$: <REJGEN>

# special case for handling webhosts
R<?>$+.2.2 $| $* $| $*GENRDNS:webhost$* $| TAG		$: <TAGWEB>
R<?>$+.2.2 $| $* $| $*GENRDNS:webhost$* $| BLOCK	$: <REJWEB>
R<?>$+.2.2 $| $* $| $* +GENRDNS:webhost$* $| ASK	$: <TAGWEB>
R<?>$+.2.2 $| $* $| $* !GENRDNS:webhost$* $| ASK	$: <REJWEB>

R<?>$+.0.2 $| $* $| $*GENRDNS:static$* $| TAG		$: <TAGSTA>
R<?>$+.0.2 $| $* $| $*GENRDNS:static$* $| BLOCK		$: <REJSTA>
R<?>$+.0.2 $| $* $| $* +GENRDNS:static$* $| ASK		$: <TAGSTA>
R<?>$+.0.2 $| $* $| $* !GENRDNS:static$* $| ASK		$: <REJSTA>

R<?>$+.0.3 $| $* $| $*GENRDNS:dynamic$* $| TAG		$: <TAGDYN>
R<?>$+.0.3 $| $* $| $*GENRDNS:dynamic$* $| BLOCK	$: <REJDYN>
R<?>$+.0.3 $| $* $| $* +GENRDNS:dynamic$* $| ASK	$: <TAGDYN>
R<?>$+.0.3 $| $* $| $* !GENRDNS:dynamic$* $| ASK	$: <REJDYN>

R<?>$+.0.4 $| $* $| $*DOMAINSBL$* $| TAG			$: <TAGSPM>
R<?>$+.0.4 $| $* $| $*DOMAINSBL$* $| BLOCK			$: <REJSPM>
R<?>$+.0.4 $| $* $| $* +DOMAINSBL$* $| ASK			$: <TAGSPM>
R<?>$+.0.4 $| $* $| $* !DOMAINSBL$* $| ASK			$: <REJSPM>

R<?>$+.0.7 $| $* $| $*GENRDNS:resnet$* $| TAG		$: <TAGRES>
R<?>$+.0.7 $| $* $| $*GENRDNS:resnet$* $| BLOCK		$: <REJRES>
R<?>$+.0.7 $| $* $| $* +GENRDNS:resnet$* $| ASK		$: <TAGRES>
R<?>$+.0.7 $| $* $| $* !GENRDNS:resnet$* $| ASK		$: <REJRES>

R<?>$+.0.8 $| $* $| $*GENRDNS:unassigned$* $| TAG	$: <TAGUNK>
R<?>$+.0.8 $| $* $| $*GENRDNS:unassigned$* $| BLOCK	$: <REJUNK>
R<?>$+.0.8 $| $* $| $* +GENRDNS:unassigned$* $| ASK	$: <TAGUNK>
R<?>$+.0.8 $| $* $| $* !GENRDNS:unassigned$* $| ASK	$: <REJUNK>

R<?>$+.0.9 $| $* $| $*GENRDNS:natproxy$* $| TAG	$: <TAGNAT>
R<?>$+.0.9 $| $* $| $*GENRDNS:natproxy$* $| BLOCK	$: <REJNAT>
R<?>$+.0.9 $| $* $| $* +GENRDNS:natproxy$* $| ASK	$: <TAGNAT>
R<?>$+.0.9 $| $* $| $* !GENRDNS:natproxy$* $| ASK	$: <REJNAT>

R<?>$+.0.10 $| $* $| $*GENRDNS:mixed$* $| TAG		$: <TAGMIX>
R<?>$+.0.10 $| $* $| $*GENRDNS:mixed$* $| BLOCK		$: <REJMIX>
R<?>$+.0.10 $| $* $| $* +GENRDNS:mixed$* $| ASK		$: <TAGMIX>
R<?>$+.0.10 $| $* $| $* !GENRDNS:mixed$* $| ASK		$: <REJMIX>

R<?>$+.0.11 $| $* $| $*GENRDNS:badrdns$* $| TAG		$: <TAGBAD>
R<?>$+.0.11 $| $* $| $*GENRDNS:badrdns$* $| BLOCK	$: <REJBAD>
R<?>$+.0.11 $| $* $| $* +GENRDNS:badrdns$* $| ASK	$: <TAGBAD>
R<?>$+.0.11 $| $* $| $* !GENRDNS:badrdns$* $| ASK	$: <REJBAD>

R<?>$+.0.12 $| $* $| $*GENRDNS:cloud$* $| TAG		$: <TAGCLD>
R<?>$+.0.12 $| $* $| $*GENRDNS:cloud$* $| BLOCK		$: <REJCLD>
R<?>$+.0.12 $| $* $| $* +GENRDNS:cloud$* $| ASK		$: <TAGCLD>
R<?>$+.0.12 $| $* $| $* !GENRDNS:cloud$* $| ASK		$: <REJCLD>

# compact and right anchor set octet 3 to "1" so we can 
# test here for that if local policy does not allow any
# blocking on non-fully-qualified patterns.
R<?>$+.1.5 $| $* $| $*GENRDNS:compact$* $| TAG		$: <TAGGEN>
R<?>$+.1.5 $| $* $| $*GENRDNS:compact$* $| BLOCK	$: <REJGEN>
R<?>$+.1.5 $| $* $| $* +GENRDNS:compact$* $| ASK	$: <TAGGEN>
R<?>$+.1.5 $| $* $| $* !GENRDNS:compact$* $| ASK	$: <REJGEN>

R<?>$+.1.6 $| $* $| $*GENRDNS:rightanch$* $| TAG	$: <TAGGEN>
R<?>$+.1.6 $| $* $| $*GENRDNS:rightanch$* $| BLOCK	$: <REJGEN>
R<?>$+.1.6 $| $* $| $* +GENRDNS:rightanch$* $| ASK	$: <TAGGEN>
R<?>$+.1.6 $| $* $| $* !GENRDNS:rightanch$* $| ASK	$: <REJGEN>

# check for double jeopardy with right anchor matches
R$+ 					$: $1 $| $(EL_Math = $@ 1 $@ $&{ELMatchedRightAnchor} $)
R$+ $| TRUE				$: <SKIPCHECK>
R$+ $| $*				$: $1

R<TAGGEN>				$: $>EL_TagSuspicious <"remote IP has generic RDNS"> $| ifdef(`confEL_ScoreGENRDNS', `confEL_ScoreGENRDNS', `3')
R<REJGEN>				$#error $@ 5.7.1. $: ifdef(`confEL_ErrGenrdns', `confEL_ErrGenrdns', `"554 GENRDNS Contact <"$&{ELContactEmail}"> if in error, <"$&f">, but we refuse mail directly from hosts with generic reverse DNS; please use another outbound mail server, "$&{client_name}"."') 

R<TAGSTA>				$: $>EL_TagSuspicious <"remote IP has generic static RDNS"> $| ifdef(`confEL_ScoreGENRDNSStatic', `confEL_ScoreGENRDNSStatic', `2')
R<REJSTA>				$#error $@ 5.7.1. $: ifdef(`confEL_ErrStatGenrdns', `confEL_ErrStatGenrdns', `"554 SGNRDNS Contact <"$&{ELContactEmail}"> if in error, <"$&f">, but we refuse mail directly from hosts with generic static reverse DNS; please use another outbound mail server, "$&{client_name}"."') 

R<TAGMIX>				$: $>EL_TagSuspicious <"remote IP has mixed generic RDNS"> $| ifdef(`confEL_ScoreGENRDNSMixed', `confEL_ScoreGENRDNSMixed', `2')
R<REJMIX>				$#error $@ 5.7.1. $: ifdef(`confEL_ErrMixedGenrdns', `confEL_ErrMixedGenrdns', `"554 MGNRDNS Contact <"$&{ELContactEmail}"> if in error, <"$&f">, but we refuse mail directly from hosts with mixed generic reverse DNS; please use another outbound mail server, "$&{client_name}"."') 

R<TAGDYN>				$: $>EL_TagSuspicious <"remote IP has dynamic generic RDNS"> $| ifdef(`confEL_ScoreGENRDNSDynamic', `confEL_ScoreGENRDNSDynamic', `3')
R<REJDYN>				$#error $@ 5.7.1. $: ifdef(`confEL_ErrDynGenrdns', `confEL_ErrDynGenrdns', `"554 DGNRDNS Contact <"$&{ELContactEmail}"> if in error, <"$&f">, but we refuse mail directly from hosts with generic dynamic reverse DNS; please use another outbound mail server, "$&{client_name}"."') 

R<TAGSPM>				$: $>EL_TagSuspicious <"remote sender is a known spammer"> $| ifdef(`confEL_ScoreDOMAINSBL', `confEL_ScoreDOMAINSBL', `4')
R<REJSPM>				$#error $@ 5.7.1. $: "554 SPAMMER Contact <"$&{ELContactEmail}"> if in error, <"$&f">, but we refuse mail from spammers."

R<TAGWEB>				$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgGenericWebhostrDNS', `confEL_TagErrMsgGenericWebhostrDNS', `"remote host has generic reverse DNS (webhost)"')> $| ifdef(`confEL_ScoreGENRDNSWebhost', `confEL_ScoreGENRDNSWebhost', `2')
R<REJWEB>				$#error $@ 5.7.1. $: ifdef(`confEL_ErrGenrdnsWebhost', `confEL_ErrGenrdnsWebhost', `"554 WEBGENR Contact <"$&{ELContactEmail}"> if in error, <"$&f">, but we refuse mail directly from hosts with generic Web hosting provider reverse DNS; please use another outbound mail server, "$&{client_name}"."') 

R<TAGRES>				$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgGenericResnetrDNS', `confEL_TagErrMsgGenericResnetrDNS', `"remote host has generic reverse DNS (resnet)"')> $| ifdef(`confEL_ScoreGENRDNSResnet', `confEL_ScoreGENRDNSResnet', `4')
R<REJRES>				$#error $@ 5.7.1. $: ifdef(`confEL_ErrGenrdnsResnet', `confEL_ErrGenrdnsResnet', `"554 RSNGENR Contact <"$&{ELContactEmail}"> if in error, <"$&f">, but we refuse mail directly from hosts with generic residential network reverse DNS; please use another outbound mail server, "$&{client_name}"."') 

R<TAGUNK>				$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgGenericUnknownrDNS', `confEL_TagErrMsgGenericUnknownrDNS', `"remote host has unknown/unassigned generic reverse DNS"')> $| ifdef(`confEL_ScoreGENRDNSUnknown', `confEL_ScoreGENRDNSUnknown', `4')
R<REJUNK>				$#error $@ 5.7.1. $: ifdef(`confEL_ErrGenrdnsUnknown', `confEL_ErrGenrdnsUnknown', `"554 UNKGENR Contact <"$&{ELContactEmail}"> if in error, <"$&f">, but we refuse mail directly from hosts with generic unknown/unassigned reverse DNS; please use another outbound mail server, "$&{client_name}"."') 

R<TAGNAT>				$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgGenericNatProxyrDNS', `confEL_TagErrMsgGenericNatProxyrDNS', `"remote host has generic NAT/Proxy reverse DNS"')> $| ifdef(`confEL_ScoreGENRDNSNatProxy', `confEL_ScoreGENRDNSNatProxy', `4')
R<REJNAT>				$#error $@ 5.7.1. $: ifdef(`confEL_ErrGenrdnsNatProxy', `confEL_ErrGenrdnsNatProxy', `"554 NATPROX Contact <"$&{ELContactEmail}"> if in error, <"$&f">, but we refuse mail directly from hosts with generic NAT/Proxy reverse DNS; please use another outbound mail server, "$&{client_name}"."') 

R<TAGBAD>				$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgGenericBadrDNS', `confEL_TagErrMsgGenericBadrDNS', `"remote host has generic bad/mangled reverse DNS"')> $| ifdef(`confEL_ScoreGENRDNSBadrDNS', `confEL_ScoreGENRDNSBadrDNS', `4')
R<REJBAD>				$#error $@ 5.7.1. $: ifdef(`confEL_ErrHeloBadrdns', `confEL_ErrGenBadrdns', `"554 BADRDNS Contact <"$&{ELContactEmail}"> if in error, <"$&f">, but we refuse mail directly from hosts with bad/mangled reverse DNS; please use another outbound mail server, "$&{client_name}"."') 

R<TAGCLD>				$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgGenericCloudrDNS', `confEL_TagErrMsgGenericCloudrDNS', `"remote host has generic cloud computing reverse DNS"')> $| ifdef(`confEL_ScoreGENRDNSCloud', `confEL_ScoreGENRDNSCloud', `2')
R<REJCLD>				$#error $@ 5.7.1. $: ifdef(`confEL_ErrHeloGenCloud', `confEL_ErrHeloGenCloud', `"554 CLOUDHELO Contact <"$&{ELContactEmail}"> if in error, <"$&f">, but we refuse mail directly from hosts that HELO with generic cloud computing reverse DNS; please use another outbound mail server, "$&{client_name}"."') 
', `
ROK $| $+				$: <?> $(EL_HostIP $1.g.enemieslist.com.. $)
R<?>OK					$: OKSOFAR
R<?>$+<TMP>				$: TMPOK
R<?>$+					$#error $@ 5.7.1. $: ifdef(`confEL_ErrGenrdns', `confEL_ErrGenrdns', `"554 GENRDNS Contact <"$&{ELContactEmail}"> if in error, <"$&f">, but we refuse mail directly from hosts with generic reverse DNS; please use another outbound mail server, "$&{client_name}"."')
')dnl
')dnl

ifdef(`_EL_CONFIG_WORKAROUND', `dnl

sorry - enemieslist may no longer be used with the sendmail ruleset patterns 

')dnl

ifdef(`_EL_DEFAULT', `dnl

sorry - enemieslist may no longer be used with the sendmail ruleset patterns

')dnl

ifdef(`_EL_TAG_NORDNS', `dnl
# check for whether the host has any rDNS, if not, tag with a header
R$*					$: $&{client_resolve}
RFAIL				$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgNorDNS', `confEL_TagErrMsgNorDNS', `"remote host has no reverse DNS"')> $| 4
RTEMP				$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgNorDNS', `confEL_TagErrMsgNorDNS', `"remote host has no reverse DNS"')> $| 3
R$*					$: $&{EL_CurrRcpt}
')dnl

ifdef(`_EL_4XX_NORDNS', `dnl
# check for whether the host has any rDNS, if not, reject with a 421 
R$*					$: $&{client_resolve}
RFAIL				$#error $@ 5.7.1 $: ifdef(`confEL_ErrNoRDNS', `confEL_ErrNoRDNS', `"421 NORDNS Contact "$&{ELContactEmail}" if this is in error, but as far as we can tell, your reverse DNS is missing."')
')dnl

ifdef(`_EL_RDNSNOTFQDN', `dnl
# now check for and block hosts whose rDNS is not a FQDN

KEL_CheckBogusRDNS1 regex -a<MATCH> ^\.*[-0-_]+\.*$ 

KEL_CheckDotLocalRDNS regex -a<MATCH> \.local$

KEL_CheckLocalhostRDNS1 regex -a<MATCH> ^localhost$
KEL_CheckLocalhostRDNS2 regex -a<MATCH> ^localhost.localdomain$

KEL_CheckBogusRDNS sequence EL_CheckBogusRDNS1 EL_CheckDotLocalRDNS EL_CheckLocalhostRDNS1 EL_CheckLocalhostRDNS2

R$*					$: $(EL_CheckBogusRDNS $&{client_name} $)
ifdef(`_EL_REPORT_ABUSE', `dnl
R<MATCH>			$: <MATCH> $| $&{ELAbuseContact}
R<MATCH> $| NONE	$: <MATCH>
R<MATCH> $| $+		$: <MATCH> $(EL_Log "EL Report to "$1": claimed to be "$&{s}"; from "$&{mail_addr}" to "$&{rcpt_addr}" from "$&{client_name}" ["$&{client_addr}"]" $)
')dnl
ifelse(_EL_POLICY, 1, `dnl
R<$->					$: <$1> $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
R<MATCH> $| $*BOGUSRDNS$* $| TAG	$: <TAGBOGUSRDNS>
R<MATCH> $| $*BOGUSRDNS$* $| BLOCK	$: <REJBOGUSRDNS>
R<MATCH> $| $* +BOGUSRDNS$* $| ASK	$: <TAGBOGUSRDNS>
R<MATCH> $| $* !BOGUSRDNS$* $| ASK	$: <REJBOGUSRDNS>

# if no matches try default policy
R$* $| $* $| $*						$: $1 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
R<MATCH> $| $*BOGUSRDNS$* $| TAG	$: <TAGBOGUSRDNS>
R<MATCH> $| $*BOGUSRDNS$* $| BLOCK	$: <REJBOGUSRDNS>
R<MATCH> $| $* +BOGUSRDNS$* $| ASK	$: <TAGBOGUSRDNS>
R<MATCH> $| $* !BOGUSRDNS$* $| ASK	$: <REJBOGUSRDNS>

R<TAGBOGUSRDNS>				$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgBogusrDNS', `confEL_TagErrMsgBogusrDNS', `"remote host has bogus rDNS "$&{client_name}"."')> $| 2
R<REJBOGUSRDNS>				$#error $@ 5.7.1 $: ifdef(`confEL_ErrBogusRDNS', `confEL_ErrBogusRDNS', `"554 BADRDNS Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail from servers without fully-qualified rDNS."')
', `dnl
R<MATCH>				$#error $@ 5.7.1 $: ifdef(`confEL_ErrBogusRDNS', `confEL_ErrBogusRDNS', `"554 BADRDNS Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail from servers without fully-qualified rDNS."')
')dnl
')dnl

ifdef(`_EL_BLACKLIST', `dnl
# reject all blacklisted hosts
R$*					$: $&{client_addr}
R$-.$-.$-.$-		$: $(EL_Blacklist $1.$2.$3.$4 $)
R$-.$-.$-.$-		$: $(EL_Blacklist $1.$2.$3 $)
R$-.$-.$-			$: $(EL_Blacklist $1.$2 $)
R$-.$-				$: $(EL_Blacklist $1 $)
ifelse(_EL_POLICY, 1, `dnl
R$-					$: $1 $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
RFOAD $| $*BLACKLIST$* $| TAG			$: <TAGBLACKLIST>
RFOAD $| $*BLACKLIST$* $| BLOCK			$: <REJBLACKLIST>
RFOAD $| $* +BLACKLIST$* $| ASK			$: <TAGBLACKLIST>
RFOAD $| $* !BLACKLIST$* $| ASK			$: <REJBLACKLIST>
RY $| $*BLACKLIST$* $| TAG				$: <TAGBLACKLIST>
RY $| $*BLACKLIST$* $| BLOCK			$: <REJBLACKLIST>
RY $| $* +BLACKLIST$* $| ASK			$: <TAGBLACKLIST>
RY $| $* !BLACKLIST$* $| ASK			$: <REJBLACKLIST>

RSPAMMER $| $*BLACKLIST$* $| TAG		$: <TAGBADNEIGHBOR>
RSPAMMER $| $*BLACKLIST$* $| BLOCK		$: <REJBADNEIGHBOR>
RSPAMMER $| $* +BLACKLIST$* $| ASK		$: <TAGBADNEIGHBOR>
RSPAMMER $| $* !BLACKLIST$* $| ASK		$: <REJBADNEIGHBOR>
RS $| $*BLACKLIST$* $| TAG				$: <TAGBADNEIGHBOR>
RS $| $*BLACKLIST$* $| BLOCK			$: <REJBADNEIGHBOR>
RS $| $* +BLACKLIST$* $| ASK			$: <TAGBADNEIGHBOR>
RS $| $* !BLACKLIST$* $| ASK			$: <REJBADNEIGHBOR>

# if no match try default policy
R$* $| $* $| $* 						$: $1 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
RFOAD $| $*BLACKLIST$* $| TAG			$: <TAGBLACKLIST>
RFOAD $| $*BLACKLIST$* $| BLOCK			$: <REJBLACKLIST>
RFOAD $| $* +BLACKLIST$* $| ASK			$: <TAGBLACKLIST>
RFOAD $| $* !BLACKLIST$* $| ASK			$: <REJBLACKLIST>
RY $| $*BLACKLIST$* $| TAG				$: <TAGBLACKLIST>
RY $| $*BLACKLIST$* $| BLOCK			$: <REJBLACKLIST>
RY $| $* +BLACKLIST$* $| ASK			$: <TAGBLACKLIST>
RY $| $* !BLACKLIST$* $| ASK			$: <REJBLACKLIST>

RSPAMMER $| $*BLACKLIST$* $| TAG		$: <TAGBADNEIGHBOR>
RSPAMMER $| $*BLACKLIST$* $| BLOCK		$: <REJBADNEIGHBOR>
RSPAMMER $| $* +BLACKLIST$* $| ASK		$: <TAGBADNEIGHBOR>
RSPAMMER $| $* !BLACKLIST$* $| ASK		$: <REJBADNEIGHBOR>
RS $| $*BLACKLIST$* $| TAG				$: <TAGBADNEIGHBOR>
RS $| $*BLACKLIST$* $| BLOCK			$: <REJBADNEIGHBOR>
RS $| $* +BLACKLIST$* $| ASK			$: <TAGBADNEIGHBOR>
RS $| $* !BLACKLIST$* $| ASK			$: <REJBADNEIGHBOR>

R<TAGBLACKLIST>					$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgBlacklistIP', `confEL_TagErrMsgBlacklistIP', `"remote host IP "$&{client_addr}" listed in local blacklist"')> $| 4
R<REJBLACKLIST>					$#error $@ 5.7.1 $: ifdef(`confEL_ErrBlacklist', `confEL_ErrBlacklist', `"554 BLCKLST Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail from your IP address, " $&{client_addr} ", which has sent or tried to send us UCE/UBE or a virus recently."')

R<TAGBADNEIGHBOR>				$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgBadNeighborhood', `confEL_TagErrMsgBadNeighborhood', `"netblock of remote host IP "$&{client_addr}" listed in local blacklist"')> $| 4
R<REJBADNEIGHBOR>				$#error $@ 5.7.1 $: ifdef(`confEL_ErrBLSpammer', `confEL_ErrBLSpammer', `"554 SPMRBLK Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail from your IP address, " $&{client_addr} ", which is in a netblock assigned to a known spammer."') 
', `dnl
RFOAD					$#error $@ 5.7.1 $: ifdef(`confEL_ErrBlacklist', `confEL_ErrBlacklist', `"554 BLCKLST Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail from your IP address, " $&{client_addr} ", which has sent or tried to send us UCE/UBE or a virus recently."') 
RSPAMMER				$#error $@ 5.7.1 $: ifdef(`confEL_ErrBLSpammer', `confEL_ErrBLSpammer', `"554 SPMRBLK Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail from your IP address, " $&{client_addr} ", which is in a netblock assigned to a known spammer."')
RS						$#error $@ 5.7.1 $: ifdef(`confEL_ErrBLSpammer', `confEL_ErrBLSpammer', `"554 SPMRBLK Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail from your IP address, " $&{client_addr} ", which is in a netblock assigned to a known spammer."')
')dnl
')dnl

ifdef(`_EL_DOMAIN_BLACKLIST', `dnl
# reject all blacklisted hosts
R$*					$: <$&{client_name}>
R<$*>				$: <$(EL_DomainBlacklist $1 $)>
R<$*.$*>			$: <$(EL_DomainBlacklist $2 $)>
R<$*.$*.$*>			$: <$(EL_DomainBlacklist $3 $)>
R<$*.$*.$*.$*>		$: <$(EL_DomainBlacklist $4 $)>
R<$*>				$: $1
ifelse(_EL_POLICY, 1, `dnl
R$-					$: $1 $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
RSPAMMER $| $*DOMAINSBL$* $| TAG	$: <TAGSPAMMER>
RSPAMMER $| $*DOMAINSBL$* $| BLOCK	$: <REJSPAMMER>
RSPAMMER $| $* +DOMAINSBL$* $| ASK	$: <TAGSPAMMER>
RSPAMMER $| $* !DOMAINSBL$* $| ASK	$: <REJSPAMMER>
RS $| $*DOMAINSBL$* $| TAG			$: <TAGSPAMMER>
RS $| $*DOMAINSBL$* $| BLOCK		$: <REJSPAMMER>
RS $| $* +DOMAINSBL$* $| ASK		$: <TAGSPAMMER>
RS $| $* !DOMAINSBL$* $| ASK		$: <REJSPAMMER>

# if no match try default policy
R$* $| $* $| $*						$: $1 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
RSPAMMER $| $*DOMAINSBL$* $| TAG	$: <TAGSPAMMER>
RSPAMMER $| $*DOMAINSBL$* $| BLOCK	$: <REJSPAMMER>
RSPAMMER $| $* +DOMAINSBL$* $| ASK	$: <TAGSPAMMER>
RSPAMMER $| $* !DOMAINSBL$* $| ASK	$: <REJSPAMMER>
RS $| $*DOMAINSBL$* $| TAG			$: <TAGSPAMMER>
RS $| $*DOMAINSBL$* $| BLOCK		$: <REJSPAMMER>
RS $| $* +DOMAINSBL$* $| ASK		$: <TAGSPAMMER>
RS $| $* !DOMAINSBL$* $| ASK		$: <REJSPAMMER>

R<TAGSPAMMER>				$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgBlacklistDomain', `confEL_TagErrMsgBlacklistDomain', `"remote host "$&{client_name}" is in blacklisted domain."')> $| 4
R<REJSPAMMER>				$#error $@ 5.7.1 $: ifdef(`confEL_ErrDomainBlacklist', `confEL_ErrDomainBlacklist', `"554 SDOMAIN Contact "$&{ELContactPhone}" if this is in error, but we do not accept mail from your domain."')
', `dnl
RSPAMMER				$#error $@ 5.7.1 $: ifdef(`confEL_ErrDomainBlacklist', `confEL_ErrDomainBlacklist', `"554 SDOMAIN Contact "$&{ELContactPhone}" if this is in error, but we do not accept mail from your domain."')
RS						$#error $@ 5.7.1 $: ifdef(`confEL_ErrDomainBlacklist', `confEL_ErrDomainBlacklist', `"554 SDOMAIN Contact "$&{ELContactPhone}" if this is in error, but we do not accept mail from your domain."')
')dnl
')dnl

ifdef(`_EL_MATCH_HELO_TO_IP', `dnl
KEL_LookupHELO dns -RA -d5s -r2

# tag if the HELO used does not match the IP of the connecting host
R$*					$: $(EL_LookupHELO $&{s} $)
ifdef(`_EL_DEBUG', `dnl
R$*					$: $1 $| ifdef(`_EL_DEBUG', `$(EL_Log "EL HELO resolved to: " $1 $)')
R$* $| $*			$: $&{EL_CurrRcpt}
')dnl

# need to check for localhost HELOing as $j
R$j					$: <LOCAL>
R$={w}				$: <LOCAL>
R$&{client_addr}	$: <REMOTE>
R$&{client_name}	$: <REMOTE>
#R<REMOTE>			$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgFCrDNSHELO', `confEL_TagErrMsgFCrDNSHELO', `"HELO resolves to remote IP"')> $| 2
R$@					$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgnonFCrDNSHELO', `confEL_TagErrMsgnonFCrDNSHELO', `"HELO does not resolve to remote IP"')> $| 2
')dnl

ifdef(`_EL_SCORING', `dnl
#
# check to see if the user has a scoring threshold.
# if no threshold found, check default policy.
# if so, compare it to the spam score.
# if score equal to or higher, reject.
# if score lower, accept.
# 
R$*								$: $(EL_Policy default $) ifdef(`_EL_DEBUG_POLICY', `$(EL_Log "EL policy for user: " $&{ELPolicyUser} "; count: " $&{ELSuspiciousCount} $)')
R$*								$: ifdef(`_EL_DEBUG_POLICY', `$(EL_Log "EL policy default: " $1 $)')
#
#
#
R$*								$: <POLICY>$&{ELPolicyUser} $| $&{ELSuspiciousCount}
R<POLICY>$*HISCORE:$-$* $| $* 	$: <THRESHOLD>$2 $| <SCORE>$4 $| <USER>

# if it did not match HISCORE get it from default
R<POLICY>$* $| $+				$: $(EL_Policy default $) $| $&{ELSuspiciousCount}
R$*HISCORE:$-$* $| $* 			$: <THRESHOLD>$2 $| <SCORE>$4 $| <DEFAULT>

R<THRESHOLD>$- $| <SCORE>$- $| <$*>		$: $(EL_Math l $@ $2 $@ $1 $) $| $1 $| $2 $| ifdef(`_EL_DEBUG', `$(EL_Log "EL thresh: " $1 "; score: " $2 " ("$3")" $)')

# result thresh score junk
RFALSE $| $* $| $* $| $*		$: <REJECT> $| $1 $| $2 
R<REJECT> $| $* $| $* 			$#error $@ 5.7.1 $: ifdef(`confEL_ErrHiScore', `confEL_ErrHiScore', `"554 HISCORE Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it simply failed too many tests. (threshold: " $1 "; score: " $2 ") ') 

RTRUE $| $* $| $* $| $*			$: <OK> 
R<OK>							$: OKSOFAR
')dnl
')dnl
