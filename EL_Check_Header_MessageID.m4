divert(-1)dnl
#
# Copyright (c) 2004-2011 hesketh.com/inc. All rights reserved.
#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_Check_Header_MessageID.m4,v 1.38 2011/05/17 18:53:50 schampeo Exp $')
divert(-1)dnl

LOCAL_CONFIG
#------------------------------------------------------------------------
# enemieslist.com Message-ID: header check patterns and calls
#------------------------------------------------------------------------
HMessage-ID: $>EL_Check_Header_MessageID

# Srizbi botnet?
# e.g. <000801c8ab9a$059a7b40$35fa7998@epfjv>
KEL_MessageIDSrizbi regex -aMATCH <[0-9a-f]{12}.[0-9a-f]{8}.[0-9a-f]{8}@[a-z]{4,10}>

# seen in spam from netfirms.com
# Message-ID: <20050417104438.46DFDDAB2EA2CF4C@from.header.has.no.domain>
KEL_FromHeaderHasNoDomainMID regex -aMATCH @from\.header\.has\.no\.domain

# disabled for now as it seems to also be used by LISTSERV/LSMTP?
#KEL_MessageIDSpamwareSig regex -aMATCH (<[0-9]{10}\.[0-9]{4}|[0-9]{10}\-[0-9]{4})@

# this is the same ratware that uses foo.bar.ameritech.net
KEL_MessageID14dot10 regex -aMATCH <[0-9]{14}\.[0-9A-F]{10}@[0-9A-Z]+>

# ??? this matches a slew of Outlook mail so we do not use it
# for anything except quarantining image spam for now
KEL_MessageID12dollar8dollar8 regex -aMATCH <00[0-9a-f]{10}.[0-9a-f]{8}.[0-9a-f]{8}@

# this is to reject those foolish broken Message-ID headers:
# Message-ID: <X[20 (eof)
# we need to deliberately strip the first < because otherwise sendmail
# helpfully adds the missing one on the end!
KEL_BrokenMessageID regex -aMATCH ^.?<(.*[^>]+)$

# this is to reject messages with our IP in the message-ID
KEL_MidContainsLocalIP regex -aMATCH ifdef(`confEL_LOCAL_IP', `confEL_LOCAL_IP')$

# e.g. <SectionID-34137_HitID-1111657525000_SiteID-7282_EmailID-6472598_DB-0>
KEL_SectionHitSiteEmailID regex -aMATCH SectionID\-[0-9]+\_HitID\-[0-9]+\_SiteID\-[0-9]+\_EmailID\-[0-9]+\_

ifdef(`_EL_FINANCIALNETVENTURE', `dnl
# match e.g. <200408135435.kirzezex$jtizgkfizld.tfd@bdzpnt.inandoutnow.com>
KEL_FinancialNetVentureMid regex -f -aMATCH [0-9]{12}\.[a-z]+.[a-z]+\.(tfd|fix|evx)@[a-z]{6}\.
')dnl

ifdef(`_EL_GOTHSONLINE', `dnl
KEL_Gothsonline regex -f -aMATCH <ifdef(`confEL_Gothsonline', `confEL_Gothsonline')@
')dnl

ifdef(`_EL_TENDOTTENORTWELVEAT', `dnl
KEL_TenDotTenOrTwelveAt regex -aMATCH <[0-9]{10}\.[0-9]{10,12}@
')dnl

# Other possibles: 
# (added\ by.+)
# e.g. from Art.Barcelona.Dance.Festival.2005
# <41C050F800019F42@vsmtp2.tin.it> (added by postmaster@virgilio.it)

ifdef(`_EL_SETTECLTD', `dnl
# settecltd / link.net conference spammers
# e.g. Message-ID: <3845-22005141315206777@hotmail>
KEL_Settecltd regex -f -aMATCH <[0-9]{4}\-[0-9]{16,18}@(hotmail|Kandil)>
')

ifdef(`_EL_FOAD_DIRECTMEDS', `dnl
KEL_MidDirectmedsBiz regex -a<SPAM> ifdef(`confEL_DirectmedsBizMid', `confEL_DirectmedsBizMid', `(002b01c54b50.10e49590.de01a8c0|000a01c59d80.883b0070.0100a8c0|008101c5502b.b0ba1c90.6402a8c0|000601c5c1d8.46805780.bf6e81d4|000601c5e0b8.c128d490.f95bcf52|000601c618a5.4d0065e0.aa0fa8c0|000d01c62381.fd374910.0100a8c0|000001c62a4e.7b3c4180.0100007f|000601c628c0.d6ab72f0.aa0fa8c0|001601c6456b.34fe3510.aa0fa8c0|000801c64a92.2ff20a70.aa0fa8c0|001b01c65631.ada70bf0.aa0fa8c0|000a01c66e14.5b636640.aa0fa8c0)')
')dnl

KEL_MustToRead regex -a<SPAM> <[0-9a-f]{8}.[0-9a-f]{8}.6c822ecf@

KEL_MsgIDAllZeroes regex -aMATCH .00000000@

# disabled 07/18/08 due to FPs from Outlook
KEL_MsgIdStorm regex -a<STORM> <[0-9A-Za-z]{5,6}-[0-9A-Za-z]{6}-[0-9A-Za-z]{2}@

KEL_MidNoTrackingDevices sequence EL_SectionHitSiteEmailID EL_MessageID14dot10 ifdef(`_EL_FINANCIALNETVENTURE', `EL_FinancialNetVentureMid') ifdef(`_EL_GOTHSONLINE', `EL_Gothsonline') ifdef(`_EL_SETTECLTD', `EL_Settecltd')

KEL_MidSuspiciousHeader sequence EL_FromHeaderHasNoDomainMID EL_MsgIDAllZeroes


LOCAL_RULESETS
#------------------------------------------------------------------------
# enemieslist.com Message-ID header checks
#------------------------------------------------------------------------
SEL_Check_Header_MessageID
ifdef(`_EL_TRACE', `dnl
R$*					$: $1 $(EL_Log "MessageID w/ " $1 "; score: " $&{ELSuspiciousCount} "." $)
')dnl

# first add to our header counter but IFF we are not working around Outlook
# bug. seems that some mail servers will add a header even if Outlook left
# it off. so you cannot count on it being in a particular place in the message
# which means that it may be last. IOW after we have already encountered the
# Outlook X-Mailer header and worked around the bug.
ifelse(_EL_IGNORE_OUTLOOK_NOMSGID, 1, `dnl
# check to see if the Message-Id: flag has already been set. If so it was
# done by the Outlook workaround and the headers are in an odd order.
R$*					$: $1 $| $(EL_Math & $@ 1 $@ $&{ELHasHeader} $)
R$* $| 1			$: $1 $(EL_Log "mid flag already set." $)
R$* $| 0			$: $1 $| $(EL_Math + $@ 1 $@ $&{ELHasHeader} $)
R$* $| $*			$: $(EL_SetVar {ELHasHeader} $@ $2 $)
R$*					$: $(EL_Log "ELHasHeader (msgid): " $&{ELHasHeader} $)
',`dnl
R$*					$: $(EL_Math + $@ 1 $@ $&{ELHasHeader} $)
R$*					$: $(EL_SetVar {ELHasHeader} $@ $1 $)
R$*					$: $(EL_Log "ELHasHeader (msgid): " $&{ELHasHeader} $)
')dnl

ifdef(`_EL_SKIPLOCAL', `dnl
R$*					$: $1 $| $&{client_addr}
R$* $| 127.0.0.1	$@
')dnl

# skip whitelisted hosts
R$*					$: $&{ELWhitelisted}
R$+:$+				$@

R$*					$: $&{currHeader}
R$*					$: $(EL_BrokenMessageID $1 $)
ifelse(_EL_POLICY, 1, `dnl
R$+					$: $1 $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
R@SPAM $| $*BADHEAD$* $| TAG		$: <TAGBADHEAD>
R@SPAM $| $*BADHEAD$* $| BLOCK		$: <REJBADHEAD>
R@SPAM $| $* +BADHEAD$* $| ASK		$: <TAGBADHEAD>
R@SPAM $| $* !BADHEAD$* $| ASK		$: <REJBADHEAD>

# if no matches try default policy
R$* $| $* $| $* 					$: $1 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
R@SPAM $| $*BADHEAD$* $| TAG		$: <TAGBADHEAD>
R@SPAM $| $*BADHEAD$* $| BLOCK		$: <REJBADHEAD>
R@SPAM $| $* +BADHEAD$* $| ASK		$: <TAGBADHEAD>
R@SPAM $| $* !BADHEAD$* $| ASK		$: <REJBADHEAD>
', `dnl
R@SPAM				$: <REJBADHEAD>
')dnl

R<TAGBADHEAD>		$: $>EL_TagSuspicious <"broken message-id header"> $| 3
R<REJBADHEAD>		$#error $@ 5.7.1 $: ifdef(`confEL_ErrB0rkenRatware', `confEL_ErrB0rkenRatware', `"554 B0RKENR Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it appears to have been sent by laughably broken spam software."')

ifdef(`_EL_UNSAFE_STORMCHECK', `
# check for Storm
R$*					$: $(EL_MsgIdStorm $&{currHeader} $)
R<STORM>			$: $>EL_TagSuspicious <ifdef(`confEL_TagErrBadheader', `confEL_TagErrBadheader', `"message contains known bad header"')> $| ifdef(`confEL_ScoreStormMID', `confEL_ScoreStormMID', `4')

R$*					$: $&{currHeader}
R<$*@$*>			$: $(access $2 $)
ifelse(_EL_POLICY, 1, `dnl
R$+					$: $1 $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
RERROR:$* $| $*BADHEAD$* $| TAG		$: <TAGBADHEAD>
RERROR:$* $| $*BADHEAD$* $| BLOCK	$: <REJBADHEAD>
RERROR:$* $| $* +BADHEAD$* $| ASK	$: <TAGBADHEAD>
RERROR:$* $| $* !BADHEAD$* $| ASK	$: <REJBADHEAD>

# if no match try default policy
R$* $| $* $| $* 					$: $1 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
RERROR:$* $| $*BADHEAD$* $| TAG		$: <TAGBADHEAD>
RERROR:$* $| $*BADHEAD$* $| BLOCK	$: <REJBADHEAD>
RERROR:$* $| $* +BADHEAD$* $| ASK	$: <TAGBADHEAD>
RERROR:$* $| $* !BADHEAD$* $| ASK	$: <REJBADHEAD>
', `dnl
RERROR:$*			$: <REJBADHEAD>
')dnl
R<TAGBADHEAD>		$: $>EL_TagSuspicious <ifdef(`confEL_TagErrBadheader', `confEL_TagErrBadheader', `"message contains known bad header"')> $| ifdef(`confEL_ScoreStormMID', `confEL_ScoreStormMID', `4')
R<REJBADHEAD>		$#error $@ 5.7.1 $: ifdef(`confEL_ErrMessageIDSpammer', `confEL_ErrMessageIDSpammer', `"554 SPAMMID Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. It contains a suspicious header (Message-ID)."')
')dnl

ifdef(`_EL_TENDOTTENORTWELVEAT', `dnl
R$*					$: $(EL_TenDotTenOrTwelveAt $&{currHeader} $)
ifelse(_EL_POLICY, 1, `dnl
R$-					$: $1 $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
RMATCH $| $*BADHEAD$* $| TAG		$: <TAGBADHEAD>
RMATCH $| $*BADHEAD$* $| BLOCK		$: <REJBADHEAD>
RMATCH $| $* +BADHEAD$* $| ASK		$: <TAGBADHEAD>
RMATCH $| $* !BADHEAD$* $| ASK		$: <REJBADHEAD>

# if no match try default policy
R$* $| $* $| $* 					$: $1 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
RMATCH $| $*BADHEAD$* $| TAG		$: <TAGBADHEAD>
RMATCH $| $*BADHEAD$* $| BLOCK		$: <REJBADHEAD>
RMATCH $| $* +BADHEAD$* $| ASK		$: <TAGBADHEAD>
RMATCH $| $* !BADHEAD$* $| ASK		$: <REJBADHEAD>
', `dnl
RMATCH				$: <REJBADHEAD>
')dnl

R<TAGBADHEAD>		$: $>EL_TagSuspicious <ifdef(`confEL_TagErrBadheader', `confEL_TagErrBadheader', `"message contains known bad header"')> $| ifdef(`confEL_Score10or12atMID', `confEL_Score10or12atMID', `3')
R<REJBADHEAD>		$#error $@ 5.7.1 $: ifdef(`confEL_ErrTenDotTenOrTwelve', `confEL_ErrTenDotTenOrTwelve', `"554 TDTTMID Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. It contains a known spam signature."')
')dnl

ifdef(`_EL_SRIZBI_MID', `dnl
R$*					$: $(EL_MessageIDSrizbi $&{currHeader} $) $| $&{ELRecdHeaderCount}
ifelse(_EL_POLICY, 1, `dnl
R$- $| 0							$: $1 $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
RMATCH $| $*BADHEAD$* $| TAG		$: <TAGBADHEAD>
RMATCH $| $*BADHEAD$* $| BLOCK		$: <REJBADHEAD>
RMATCH $| $* +BADHEAD$* $| ASK		$: <TAGBADHEAD>
RMATCH $| $* !BADHEAD$* $| ASK		$: <REJBADHEAD>

# if no match try default policy
R$* $| $* $| $* 					$: $1 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
RMATCH $| $*BADHEAD$* $| TAG		$: <TAGBADHEAD>
RMATCH $| $*BADHEAD$* $| BLOCK		$: <REJBADHEAD>
RMATCH $| $* +BADHEAD$* $| ASK		$: <TAGBADHEAD>
RMATCH $| $* !BADHEAD$* $| ASK		$: <REJBADHEAD>
', `dnl
RMATCH				$: <REJBADHEAD>
')dnl

R<TAGBADHEAD>		$: $>EL_TagSuspicious <ifdef(`confEL_TagErrBadheaderSrizbi', `confEL_TagErrBadheaderSrizbi', `"message contains known bad header (srizbi)"')> $| ifdef(`confEL_ScoreSrizbiMID', `confEL_ScoreSrizbiMID', `4')
R<REJBADHEAD>		$#error $@ 5.7.1 $: ifdef(`confEL_ErrSrizbiMID', `confEL_ErrSrizbiMID', `"554 SRZBIMID Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. It contains a known spam signature."')
')dnl

ifdef(`_EL_FOAD_DIRECTMEDS', `dnl
R$*					$: $&{currHeader}
R$*<$*@$*>$*		$: $(EL_MidDirectmedsBiz $2 $)
ifelse(_EL_POLICY, 1, `dnl
R$+					$: $1 $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
R<SPAM> $| $*BADHEAD$* $| TAG		$: <TAGBADHEAD>
R<SPAM> $| $*BADHEAD$* $| BLOCK		$: <REJBADHEAD>
R<SPAM> $| $* +BADHEAD$* $| ASK		$: <TAGBADHEAD>
R<SPAM> $| $* !BADHEAD$* $| ASK		$: <REJBADHEAD>

# if no match try default policy
R$* $| $* $| $* 					$: $1 $| $(EL_Policy $) $| $&{ELPolicySwitch}
R<SPAM> $| $*BADHEAD$* $| TAG		$: <TAGBADHEAD>
R<SPAM> $| $*BADHEAD$* $| BLOCK		$: <REJBADHEAD>
R<SPAM> $| $* +BADHEAD$* $| ASK		$: <TAGBADHEAD>
R<SPAM> $| $* !BADHEAD$* $| ASK		$: <REJBADHEAD>
', `dnl
R<SPAM>				$: <REJBADHEAD>
')dnl

R<TAGBADHEAD>		$: $>EL_TagSuspicious <"directmeds.biz spam"> $| 3
R<REJBADHEAD>		$#error $@ 5.7.1 $: ifdef(`confEL_ErrDirectMedsBiz', `confEL_ErrDirectMedsBiz', `"554 DIRCTMD Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. It contains a laughably overused Message-Id: header."')
')dnl

R$*					$: $(EL_MustToRead $&{currHeader} $)
ifelse(_EL_POLICY, 1, `dnl
R$+					$: $1 $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
R<SPAM> $| $*BADHEAD$* $| TAG		$: <TAGBADHEAD>
R<SPAM> $| $*BADHEAD$* $| BLOCK		$: <REJBADHEAD>
R<SPAM> $| $* +BADHEAD$* $| ASK		$: <TAGBADHEAD>
R<SPAM> $| $* !BADHEAD$* $| ASK		$: <REJBADHEAD>

# if no match try default policy
R$* $| $* $| $* 					$: $1 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
R<SPAM> $| $*BADHEAD$* $| TAG		$: <TAGBADHEAD>
R<SPAM> $| $*BADHEAD$* $| BLOCK		$: <REJBADHEAD>
R<SPAM> $| $* +BADHEAD$* $| ASK		$: <TAGBADHEAD>
R<SPAM> $| $* !BADHEAD$* $| ASK		$: <REJBADHEAD>
', `dnl
R<SPAM>				$: <REJBADHEAD>
')dnl

R<TAGBADHEAD>		$: $>EL_TagSuspicious <"must-to-read pump and dump spammer"> $| 4
R<REJBADHEAD>		$#error $@ 5.7.1 $: ifdef(`confEL_ErrMustToRead', `confEL_ErrMustToRead', `"554 MTRPND Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as pump-and-dump spam."')

ifdef(`_EL_B0RKEN', `dnl
R$*					$: $(EL_B0rkenRatware $&{currHeader} $)
ifelse(_EL_POLICY, 1, `dnl
R$+					$: $1 $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
R@SPAM $| $*BADHEAD$* $| TAG		$: <TAGBADHEAD>
R@SPAM $| $*BADHEAD$* $| BLOCK		$: <REJBADHEAD>
R@SPAM $| $* +BADHEAD$* $| ASK		$: <TAGBADHEAD>
R@SPAM $| $* !BADHEAD$* $| ASK		$: <REJBADHEAD>

# if no match try default policy
R$* $| $* $| $* 					$: $1 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
R@SPAM $| $*BADHEAD$* $| TAG		$: <TAGBADHEAD>
R@SPAM $| $*BADHEAD$* $| BLOCK		$: <REJBADHEAD>
R@SPAM $| $* +BADHEAD$* $| ASK		$: <TAGBADHEAD>
R@SPAM $| $* !BADHEAD$* $| ASK		$: <REJBADHEAD>
', `dnl
R@SPAM				$: <REJBADHEAD>
')dnl

R<TAGBADHEAD>		$: $>EL_TagSuspicious <"broken message-id header"> $| 3
R<REJBADHEAD>		$#error $@ 5.7.1 $: ifdef(`confEL_ErrB0rkenRatware', `confEL_ErrB0rkenRatware', `"554 B0RKENR Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it appears to have been sent by laughably broken spam software."')
')dnl

R$*					$: $(EL_MidContainsLocalIP $&{currHeader} $)
ifelse(_EL_POLICY, 1, `dnl
R$+					$: $1 $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
RMATCH $| $*BADHEAD$* $| TAG		$: <TAGBADHEAD>
RMATCH $| $*BADHEAD$* $| BLOCK		$: <REJBADHEAD>
RMATCH $| $* +BADHEAD$* $| ASK		$: <TAGBADHEAD>
RMATCH $| $* !BADHEAD$* $| ASK		$: <REJBADHEAD>

# if no match try default policy
R$* $| $* $| $*						$: $1 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
RMATCH $| $*BADHEAD$* $| TAG		$: <TAGBADHEAD>
RMATCH $| $*BADHEAD$* $| BLOCK		$: <REJBADHEAD>
RMATCH $| $* +BADHEAD$* $| ASK		$: <TAGBADHEAD>
RMATCH $| $* !BADHEAD$* $| ASK		$: <REJBADHEAD>
', `dnl
RMATCH				$: <REJBADHEAD>
')dnl

R<TAGBADHEAD>		$: $>EL_TagSuspicious <"broken message-id header"> $| 3
R<REJBADHEAD>		$#error $@ 5.7.1 $: ifdef(`confEL_ErrMessageIDSpammer', `confEL_ErrMessageIDSpammer', `"554 SPAMMID Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. It contains a suspicious header (Message-ID)."')

ifdef(`_EL_DOMAIN_BLACKLIST', `dnl
R$*					$: $(EL_GetEmailAddress $&{currHeader} $)
R<$*@$*><ADDR>		$: $>canonify <$1@$2>
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
RSPAMMER			$: <REJDOMAINSBL>
RS					$: <REJDOMAINSBL>
')dnl
R<TAGDOMAINSBL>			$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgMidBL', `confEL_TagErrMsgMidBL', `"message-id header contains domain in local blacklist"')> $| 4
R<REJDOMAINSBL>			$#error $@ 5.7.1 $: ifdef(`confEL_ErrMessageIDSpammerDomain', `confEL_ErrMessageIDSpammerDomain', `"554 MIDSPAM Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. We do not accept mail with a Message-ID: from your domain."')
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

R<TAGURIBL>						$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgMidURIBL', `confEL_TagErrMsgMidURIBL', `"message-id header contains domain in uribl.com blacklist"')> $| 4
R<REJURIBL>						$#error $@ 5.7.1 $: ifdef(`confEL_ErrMidURIBL', `confEL_ErrMidURIBL', `"554 URIBLMID Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. We do not accept mail containing a Message-Id: from your domain as it is listed by uribl.com."')
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
R$* $| $* $| $* 				$: $1 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
R$+ $| $*SURBL$* $| TAG			$: <TAGSURBL>
R$+ $| $*SURBL$* $| BLOCK		$: <REJSURBL>
R$+ $| $* +SURBL$* $| ASK		$: <TAGSURBL>
R$+ $| $* !SURBL$* $| ASK		$: <REJSURBL>

R<TAGSURBL>						$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgMidSURBL', `confEL_TagErrMsgMidSURBL', `"message-id header contains domain in surbl.org blacklist"')> $| 4
R<REJSURBL>						$#error $@ 5.7.1 $: ifdef(`confEL_ErrMidSURBL', `confEL_ErrMidSURBL', `"554 SURBLMID Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. We do not accept mail containing a Message-Id: from your domain as it is listed by surbl.org."')
')dnl
')dnl

R$*					$: $(EL_MidNoTrackingDevices $&{currHeader} $)
ifelse(_EL_POLICY, 1, `dnl
R$+					$: $1 $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
RMATCH $| $*BADHEAD$* $| TAG		$: <TAGBADHEAD>
RMATCH $| $*BADHEAD$* $| BLOCK		$: <REJBADHEAD>
RMATCH $| $* +BADHEAD$* $| ASK		$: <TAGBADHEAD>
RMATCH $| $* !BADHEAD$* $| ASK		$: <REJBADHEAD>

# if no match try default policy
R$* $| $* $| $* 					$: $1 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
RMATCH $| $*BADHEAD$* $| TAG		$: <TAGBADHEAD>
RMATCH $| $*BADHEAD$* $| BLOCK		$: <REJBADHEAD>
RMATCH $| $* +BADHEAD$* $| ASK		$: <TAGBADHEAD>
RMATCH $| $* !BADHEAD$* $| ASK		$: <REJBADHEAD>
', `dnl
RMATCH				$: <REJBADHEAD>
')dnl

R<TAGBADHEAD>		$: $>EL_TagSuspicious <ifdef(`confEL_TagErrBadheader', `confEL_TagErrBadheader', `"message contains known bad header"')> $| ifdef(`confEL_ScoreTrackMID', `confEL_ScoreTrackMID', `3')
R<REJBADHEAD>		$#error $@ 5.7.1 $: ifdef(`confEL_ErrMessageIDTracker', `confEL_ErrMessageIDTracker', `"554 MIDTRCK Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. We do not accept messages containing tracking devices."')

R$*					$: $(EL_MidSuspiciousHeader $&{currHeader} $)
ifelse(_EL_POLICY, 1, `dnl
R$+					$: $1 $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
RMATCH $| $*BADHEAD$* $| TAG		$: <TAGBADHEAD>
RMATCH $| $*BADHEAD$* $| BLOCK		$: <REJBADHEAD>
RMATCH $| $* +BADHEAD$* $| ASK		$: <TAGBADHEAD>
RMATCH $| $* !BADHEAD$* $| ASK		$: <REJBADHEAD>

# if no match try default policy
R$* $| $* $| $*						$: $1 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
RMATCH $| $*BADHEAD$* $| TAG		$: <TAGBADHEAD>
RMATCH $| $*BADHEAD$* $| BLOCK		$: <REJBADHEAD>
RMATCH $| $* +BADHEAD$* $| ASK		$: <TAGBADHEAD>
RMATCH $| $* !BADHEAD$* $| ASK		$: <REJBADHEAD>
', `dnl
RMATCH				$: <REJBADHEAD>
')dnl

R<TAGBADHEAD>		$: $>EL_TagSuspicious <ifdef(`confEL_TagErrBadheader', `confEL_TagErrBadheader', `"message contains known bad header"')> $| ifdef(`confEL_ScoreSuspiciousMID', `confEL_ScoreSuspiciouskMID', `3')
R<REJBADHEAD>		$#error $@ 5.7.1 $: ifdef(`confEL_ErrMessageIDSpammer', `confEL_ErrMessageIDSpammer', `"554 SPAMMID Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. It contains a suspicious header (Message-ID)."')

ifdef(`_EL_PHISH', `dnl
ifelse(_EL_PHISH_LOOSE, 1, `dnl
R$*					$: $(EL_PhishFromDomains $&{currHeader} $) $| $&{ELPhishProperOrigin}
ifelse(_EL_POLICY, 1, `dnl
R$- $| $- 			$: $1 $| $2 $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
RPHISH $| NO $| $*NOPHISH$* $| TAG		$: <TAGPHISH>
RPHISH $| NO $*NOPHISH$* $| BLOCK		$: <REJPHISH>
RPHISH $| NO $| $* +NOPHISH$* $| ASK	$: <TAGPHISH>
RPHISH $| NO $| $* !NOPHISH$* $| ASK	$: <REJPHISH>

# if no match try default policy
R$* $| $* $| $*							$: $1 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
RPHISH $| NO $| $*NOPHISH$* $| TAG		$: <TAGPHISH>
RPHISH $| NO $*NOPHISH$* $| BLOCK		$: <REJPHISH>
RPHISH $| NO $| $* +NOPHISH$* $| ASK	$: <TAGPHISH>
RPHISH $| NO $| $* !NOPHISH$* $| ASK	$: <REJPHISH>

R<TAGPHISH>								$: $(EL_Math + $@ 64 $@ $&{ELSpamsign} $) $| $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgPhish', `confEL_TagErrMsgPhish', `"message is probably a phish scam"')> $| 3
R<REJPHISH>								$#error $@ 5.7.1 $: ifdef(`confEL_ErrFromPhish', `confEL_ErrFromPhish', `"554 PHISHFR Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as a phish scam."')
',`dnl
RPHISH $| NO 		$#error $@ 5.7.1 $: ifdef(`confEL_ErrFromPhish', `confEL_ErrFromPhish', `"554 PHISHFR Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as a phish scam."')
')
',`
R$*						$: $(EL_PhishFromDomains $&{currHeader} $) $| $&{ELPhishProperOrigin} $| $(EL_PhishMailFromLocalparts $&{mail_from} $)
ifelse(_EL_POLICY, 1, `dnl
R$- $| $- $| $-			$: $1 $| $2 $| $3 $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
RPHISH $| NO $| PHISH $| $*NOPHISH$* $| TAG		$: <TAGPHISH>
RPHISH $| NO $| PHISH $| $*NOPHISH$* $| BLOCK	$: <REJPHISH>
RPHISH $| NO $| PHISH $| $* +NOPHISH$* $| ASK	$: <TAGPHISH>
RPHISH $| NO $| PHISH $| $* !NOPHISH$* $| ASK	$: <REJPHISH>

# if no match try default policy
R$* $| $* $| $* $| $* $| $*						$: $1 $| $2 $| $3 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
RPHISH $| NO $| PHISH $| $*NOPHISH$* $| TAG		$: <TAGPHISH>
RPHISH $| NO $| PHISH $| $*NOPHISH$* $| BLOCK	$: <REJPHISH>
RPHISH $| NO $| PHISH $| $* +NOPHISH$* $| ASK	$: <TAGPHISH>
RPHISH $| NO $| PHISH $| $* !NOPHISH$* $| ASK	$: <REJPHISH>

R<TAGPHISH>										$: $(EL_Math + $@ 64 $@ $&{ELSpamsign} $) $| $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgPhish', `confEL_TagErrMsgPhish', `"message is probably a phish scam"')> $| 3
R<REJPHISH>										$#error $@ 5.7.1 $: ifdef(`confEL_ErrFromPhish', `confEL_ErrFromPhish', `"554 PHISHFR Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as a phish scam."')
',`dnl
RPHISH $| NO $| PHISH	$#error $@ 5.7.1 $: ifdef(`confEL_ErrFromPhish', `confEL_ErrFromPhish', `"554 PHISHFR Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as a phish scam."')
')
')
')

