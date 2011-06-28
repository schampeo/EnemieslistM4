divert(-1)dnl
#
# Copyright (c) 2004-2011 hesketh.com/inc. All rights reserved.
#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_Check_Header_XMailer.m4,v 1.35 2011/05/17 18:00:36 schampeo Exp $')
divert(-1)dnl

LOCAL_CONFIG
#------------------------------------------------------------------------
# enemieslist.com X-Mailer: header check patterns
#------------------------------------------------------------------------
# known bulk mailer signatures
#
# Writely was acquired by Google and is now used for Docs
KEL_BadXMailers regex -a@SPAM -f (Blacksheep|Dynamailer|ARELIS|erotic\-mailer|Message.*sent.*on.*behalf.*of.*client|opt_in|Shizzel|Spyder.*Mail|supuh|zuper\-mailer|EZ\-Zender|eGroups.*Message.*Poster|Broadc@stHTML|PHPBulkEmailer|Optin|southlandbroaden|Email\ Panther|IKON\ Marketing|Mcamp|TEME|PornEmails|Noavar|Mighty\ Mail|N/A|MailMagicPro|magmag|Bold\ Mail|Cumming\ Mailer|Gigi\ Mail|RLSP\ Mailer|N\.B\.S\.\ V[0-9]|b1gMail|TTBOARD|(casual|Serious)\ Mail\ [0-9].[0-9][a-z]|EM:\ [0-9]\.[0-9]+|MultiMailer|X\-Topica\-Id|AnonMail_Version|KYX\ CP/M\ FNORD\ 5602|kukushka\ v|cBizOne|iChieve\ RocketMail|StreamSend|LinkAssistant|CP\-Email.Builder|nrxszvo^gsvlyerlfh\.xln|Email\ Marketer\ Business\ Edition\ [0-9]+|sxmailerd)

# Atriks/Greenhorse (Brian Haberstroh, ROKSO spammer)
KEL_AtriksXMailers regex -a@SPAM -f ^.*(Free\ Market\ Email\ Services|Your\ SMTP\ Server\ v\.|Assemblage\ Mail\ Server\ Pro|Open\ Door\ Email\ Server|Spearhead\ Webmail\ Server|SMTP\ Generic\ \(Version|Our\ Email\ Server|Extended\ SMTP\ [0-9]|Webmail\ Community\ [0-9]\.[0-9]|MySMTP\ .*ail\ Server|Next\ Mailer\ \(Ver|Team\ Mail|24/7\ Mail\ Systems|\(version\ [0-9]\.[0-9]\)\ ESMTP\ Server|AcquireWeb\ Professional|Assemblage\ Mail\ Server|Atriks|BASIC\ SMTP\ Answers|Can\ Mail\ [0-9]\.[0-9]|Company\ Mail\ Systems\ \-\ Version|Corporate\ Webmail\ Systems|ESMTP\ \(Version\ [0-9]\.[0-9]\)|Email\ Portal\ v\.\ [0-9]\.[0-9]|Enhanced\ Email\ Server|Enhanced\ Mail\ Server\ [0-9]\.[0-9]|Enhanced\ SMTP\ \(Version\ [0-9]\.[0-9]\)|Enterprise\ Email\ Server\ \(Version\ [0-9]\.[0-9]\)|Envision\ Email\ Solutions|Extended\ SMTP\ [0-9]|Gathering\ X\-Mailer|Mails\ Made\ Easy|Non\-stop\ Email\ Services|Origin\ Advanced\ Webmail\ Solutions|Professional\ Mail\ Service|Professional\ Webmail\ Solutions|Prototype\ \ Email\ Service|Resolution\ Mail\ Server\ [0-9]\.[0-9]|SMTP\ Platform|Simple\ Mail\ Solutions|Sovereign\ SMTP\ Systems|Team\ Mail|Together\ Email\ Systems|Unlimited\ Email\ Solutions\ \-\ Version|Webmail\ [0-9]\.[0-9]\ Optimized|Webmail\ Community\ [0-9]\.[0-9]|Webmail\ Service\ by\ SMTP|Pro\ Mailer\ V[0-9]\.[0-9]|Will\ Mail\ \(version\ [0-9]\.[0-9]|Spam\ Filter\ XMTP\ \(ver..+\)|Delver[0-9]+)

# check for Outlook
KEL_SillyOutlook regex -a<BROKEN> Outlook

# Yes, we have actually seen blank X-Mailers in spam
KEL_BlankXMailer regex -a@SPAM ^$

ifdef(`_EL_NO419XMAILER', `dnl
# useful for quarantining 419/AFF spam 
KEL_419XMailers regex -a419 ^ *(AtMail\ Lite|Command\-Line\ Mailer|Direccion\.com|freemail|GoMail|Interfejs\ WWW\ poczty\ Wirtualnej\ Polski|iPlanet Messenger Express\ 5\.2\ HotFix\ 1\.14\ \(built (Oct|Nov)\ (10|18|29) 2003\)|livemail\.co\.uk\ Webmail|LycosMail|Quality\ Web\ Email|SkyMail\ 2002|SquirrelMail\ \(version 1.2.10.lt-1\)|WebMail\.ROL\!ro|Web\ XMail\ 3.2a|ZBTA\ tsanba\ p1.1|ZMAIL\.PT\ 6\.8\.4|Masrawy\ Web\ Mail\er|IceWarp\ Web\ Mail\ 4\.2\.1)
')dnl

ifdef(`_EL_TWOWORDXMAILER', `dnl
# catches spam with 2-4 lowercase dictionary words as a tracking device
KEL_TwoWordXMailer regex -f -s1,2,3,4 -a<MATCH> ([a-z]+) ([a-z]+) ?([a-z]*)? ?([a-z]*)?$
')dnl

ifdef(`_EL_ONEWORDXMAILER', `dnl
# catches spam with 1 lowercase dictionary word as a tracking device
KEL_OneWordXMailer regex -f -s1 -a<MATCH> ^\ ?([a-z]+)$
')dnl

ifdef(`_EL_VERSIONNUMGIBBERISH', `dnl
# specific spamware signature
KEL_VersionNumDotGibberish regex -aMATCH Version\ [0-9]\.GkE[A-Za-z]+
')dnl

ifdef(`_EL_DISTRUST_THEBAT', `dnl
KEL_TheBatXMailer regex -f -a<MATCH> The\ Bat
')dnl

KEL_XMailerChecks sequence EL_BadXMailers EL_AtriksXMailers EL_BlankXMailer ifdef(`_EL_VERSIONNUMGIBBERISH', `EL_VersionNumDotGibberish')

KEL_XPHPScript1 regex -a@SPAM (images/hack|inboxmassmailer|upload/script/script)
KEL_XPHPScriptChecks sequence EL_XPHPScript1

LOCAL_RULESETS
#------------------------------------------------------------------------
# enemieslist.com X-Mailer header checks
#------------------------------------------------------------------------
HX-Mailer: $>EL_Check_Header_XMailer
# this conflicts with X-O-IP check for 419s
#HX-PHP-Script: $>EL_Check_Header_XMailer

SEL_Check_Header_XMailer
ifdef(`_EL_TRACE', `dnl
R$*					$: $1 $(EL_Log "XMailer w/ " $1 "; score: " $&{ELSuspiciousCount} "." $)
')dnl

R$*						$: $(EL_SillyOutlook $&{currHeader} $) $| $(EL_Math & $@ 1 $@ $&{ELHasHeader} $)
ifelse(_EL_IGNORE_OUTLOOK_NOMSGID, 1, `dnl
# we are ignoring broken Outlook so we set a fake Message-ID flag IFF 
# there is not already one set. If there *is* one it screws up the bits
R$*<BROKEN> $| 0		$: $1<FLAG> $| $(EL_Math + $@ 1 $@ $&{ELHasHeader} $) $| $(EL_Log "workaround Outlook mid." $)
R$*<FLAG> $| $* $| $*	$: $(EL_SetVar {ELHasHeader} $@ $2 $) 
# 32 is the bitwise value for the X-Mailer header
R$*						$: $1 $| $(EL_Math + $@ 32 $@ $&{ELHasHeader} $)
R$* $| $*				$: $(EL_SetVar {ELHasHeader} $@ $2 $)
R$*						$: $(EL_Log "ELHasHeader (xmailer): " $&{ELHasHeader} $)
',`dnl
# 32 is the bitwise value for the X-Mailer header
R$*<BROKEN> $| $*	$: $1 $| $(EL_Math + $@ 32 $@ $&{ELSpamsign} $)
R$* $| $*			$: $(EL_SetVar {ELSpamSign} $@ $2 $)
R$*					$: $1
')dnl

ifdef(`_EL_SKIPLOCAL', `dnl
R$*					$: $1 $| $&{client_addr}
R$* $| 127.0.0.1	$@
')dnl

# skip whitelisted hosts
R$*			$: $&{ELWhitelisted}
R$+:$+		$@

R$*					$: $(EL_XMailerChecks $&{currHeader} $)
R@SPAM				$#error $@ 5.7.1 $: ifdef(`confEL_ErrXMailer', `confEL_ErrXMailer', `"554 BDHDXML Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it contains a suspicious header (X-Mailer:)."')

R$*					$: $(EL_XPHPScriptChecks $&{currHeader} $)
R@SPAM				$#error $@ 5.7.1 $: ifdef(`confEL_ErrXPHPScript', `confEL_ErrXPHPScript', `"554 BDHDXPS Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it contains a suspicious header (X-PHP-Script:)."')

ifdef(`_EL_NO419XMAILER', `dnl
# tag messages sent with mail software abused by 419/aff scammers
R$*			$: $(EL_419XMailers $&{currHeader} $)
R419		$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsg419AFFXMailer', `confEL_TagErrMsg419AFFXMailer', `"may be 419 spam based on XMailer header"')> $| 2
')dnl

ifdef(`_EL_TWOWORDXMAILER', `dnl
# catch specific two-four lowercase dictionary word spam signature/tracker
R$*								$: $(EL_TwoWordXMailer $&{currHeader} $)
R$+ $| $+ $| $+ $| $+<MATCH>	$: $(EL_Wordlist $1 $) $| $(EL_Wordlist $2 $) $| $(EL_Wordlist $3 $) $| EL_Wordlist $4 $)
RW$* $| W$* $| W$* $| $*		$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsg2DictXMailer', `confEL_TagErrMsg2DictXMailer', `"XMailer made up of random dictionary words"')> $| 3
RW$* $| W$* $| $* $| $*			$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsg2DictXMailer', `confEL_TagErrMsg2DictXMailer', `"XMailer made up of random dictionary words"')> $| 3
R$* $| W$* $| W$* $| $*			$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsg2DictXMailer', `confEL_TagErrMsg2DictXMailer', `"XMailer made up of random dictionary words"')> $| 3
RW$* $| $* $| W$* $| $*			$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsg2DictXMailer', `confEL_TagErrMsg2DictXMailer', `"XMailer made up of random dictionary words"')> $| 3
R$+ $| $+ $| $+ $| $@<MATCH>	$: $(EL_Wordlist $1 $) $| $(EL_Wordlist $2 $) $| $(EL_Wordlist $3 $)
RW$* $| W$* $| $*				$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsg2DictXMailer', `confEL_TagErrMsg2DictXMailer', `"XMailer made up of random dictionary words"')> $| 3
R$* $| W$* $| W$*				$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsg2DictXMailer', `confEL_TagErrMsg2DictXMailer', `"XMailer made up of random dictionary words"')> $| 3
RW$* $| $* $| W$*				$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsg2DictXMailer', `confEL_TagErrMsg2DictXMailer', `"XMailer made up of random dictionary words"')> $| 3
R$+ $| $+ $| $@ $| $@<MATCH>	$: $(EL_Wordlist $1 $) $| $(EL_Wordlist $2 $)
RW$* $| W$* 					$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsg2DictXMailer', `confEL_TagErrMsg2DictXMailer', `"XMailer made up of random dictionary words"')> $| 3
RW$* $| W$* 					$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsg2DictXMailer', `confEL_TagErrMsg2DictXMailer', `"XMailer made up of random dictionary words"')> $| 3
R$*								$: $&{currHeader}
')dnl

ifdef(`_EL_ONEWORDXMAILER', `dnl
# catch specific one lowercase dictionary word spam signature/tracker
R$*							$: $(EL_OneWordXMailer $&{currHeader} $)
R$+<MATCH>					$: $(EL_Wordlist $1 $)
RW$*						$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsg1DictXMailer', `confEL_TagErrMsg1DictXMailer', `"XMailer is a single random dictionary word"')> $| 2
R$*							$: $&{currHeader}
')dnl

ifdef(`_EL_B0RKEN', `dnl
R$*					$: $(EL_B0rkenRatware $&{currHeader} $)
R@SPAM				$#error $@ 5.7.1 $: ifdef(`confEL_ErrB0rkenRatware', `confEL_ErrB0rkenRatware', `"554 B0RKENR Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it appears to have been sent by laughably broken spam software."')
')dnl

ifdef(`_EL_DISTRUST_THEBAT', `dnl
R$*					$: $(EL_TheBatXMailer $&currHeader} $)
R<MATCH>			$: $>EL_TagSuspicious <"mailer claims to be the Bat"> $| 1
')dnl
