divert(-1)dnl
#
# Copyright (c) 2004-2011 hesketh.com/inc. All rights reserved.

# See the file LICENSE in the distribution for details.

#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_Check_Header_Subject.m4,v 1.44 2011/05/26 13:28:52 schampeo Exp $')
divert(-1)dnl

LOCAL_CONFIG
#------------------------------------------------------------------------
# enemieslist.com Subject: header check patterns and call
#------------------------------------------------------------------------
HSubject: $>EL_Check_Header_Subject

ifdef(`_EL_REJECT_YAHOO_SPAM', `dnl
KEL_YahooSpamguard regex -f -a@SPAM \[spam\]
')dnl

ifdef(`_EL_SPAMX', `dnl
KEL_SpamX1 regex -f -a@SPAM EMail\ Abuse\ Complaint\ [0-9]{2}/[0-9]{2}/[0-9]{2}\ [0-9]+:[0-9]+:[0-9]+\ [AP]M
KEL_SpamX2 regex -f -a@SPAM [0-9]{1,2}/[0-9]{1,2}/[0-9]{2}\ \*\ [0-9]{1,2}:[0-9]{1,2}:[0-9]{1,2}\ [AP]M\ email abuse
KEL_SpamX sequence EL_SpamX1 EL_SpamX2
')dnl

ifdef(`_EL_GLOBAL_MARKETING', `dnl
KEL_SubjectAdvertEmailAddy regex -f -a_SPAMSIGN_ ^Advert:\ *[a-z]+@[a-z\-]+\.com
')dnl

ifdef(`_EL_EMAILHELLOINC', `dnl
KEL_SubjectSexuallyExplicit regex -f -a@SPAM ^\ ?(\[?SEXUALLY\-?\ ?EXPLICIT|Sexual:Explicit|sexually-explicit|\(Sexually\ Explict\)|SEXUALLY\ EXPLlClT|Fwd:\ sexually\ explicit|.*SEXUALLY-EXPLICIT|.*Sexually\ Explicit)
')dnl

KEL_SubjectListVendor regex -a@SPAM \[\ [0-9a-z]{16}\]\ \:

KEL_SubjectLinkExchange regex -a@SPAM (Invitation|Reminder|Request).*(Link.*Exchang|Exchang.*Link)
KEL_SubjectLinkExchange2 regex -a@SPAM Link.*Exchang.*(Invitation|Proposal|Request)
KEL_SubjectLinkExchange3 regex -a@SPAM Link.*Exchang

KEL_SubjectLinkExchanges sequence EL_SubjectLinkExchange EL_SubjectLinkExchange2 EL_SubjectLinkExchange3 

KEL_SubjectCialis regex -a_SPAMSIGN_ ^.*(C1AL.IS|C1.ALIS|LE.V1TRA|LEV1.TRA|V_I_A_G_R_A|_XANAX_|v\|@grA|V\|cod\|n|V-1-A-G-R-A|PEN1S|VlAGRA|V1AGKRA|CIAL1.S|VIAG.RA|C[1I].AL[1I]S|C[1I]A.L[1I]S|C[1I]AL[1I].S|C_[1I]AL[1I]S|C[1I][\.\'\-]?A[\.\'\-]?L[I1]S|C[1I]~AL[1I]S|C[1I]AL[11]~?S|LEV[1I]T~?RA)

KEL_SubjectRolex regex -a@SPAM (Rolex.*\[[a-z]+\]$|Rolex.*Watch|nice ROLEX|Motorolex|Rolex.*Cartier.*Brietling|Louis\ Vuitton|Replica.Rolex.Swiss.Watches|Italian\-crafted.Rolex)

KEL_SubjectOnlinePharm regex -a@SPAM The.Ultimate.Online.Pharmaceutical

KEL_SubjectHashbuster regex -a_SPAMSIGN_ ^.+    .+[0-9a-z]+$

KEL_SubjectDuckzUS regex -a_SPAMSIGN_ ^ [`_'\*,"^;:\.\-]

KEL_SubjectHi regex -f -a_SPAMSIGN_ ^(hi|Hi)$

KEL_SubjectBlank regex -a_SPAMSIGN_ ^$

KEL_SubjectSixFigures regex -a@SPAM (Receive.up.to|We.have|Take.up.to).\\$[0-9]{3},[0-9]{3}\ $

KEL_SubjectTwoLowercaseWords regex -f -a_SPAMSIGN_ ^[a-z]+ [a-z]+$

KEL_SubjectParisHilton regex -a_SPAMSIGN_ ^.*pa*r*.*i*s*.*hi.*l.*ton

KEL_SubjectUnknownISO regex -f -a@SPAM =\?UNKNOWN

KEL_SubjectStrangeB5 regex -f -a@SPAM ^.?\^\[\\$B.[\\$>@]

KEL_SubjectHoneygirl regex -a@SPAM ^.*message\ waiting\ from\ honeygirl[0-9]+

KEL_Subject150FDAApprovedMeds regex -a@SPAM ^Over.*[0-9]+.*FDA.*Approved.*Meds

# removed from sequence 02/14/08 for FPs
KEL_SubjectParenNumber regex -f -a@SPAM ^.*\([0-9]+\).+\([0-9]+\)

# ??? last two bits are dictionary words, so if we see FPs add dict checks
KEL_SubjectYourMoney1 regex -f -a@SPAM (Your.(cash|future|health|money):?\)),.[a-z\-]+[\-\ ]?[a-z\-]+
KEL_SubjectYourMoney2 regex -f -a@SPAM (Fun|Future|Hi|Life|Order Status|Success),.[a-z]+[\-\ ][a-z]+
KEL_SubjectYourMoney sequence EL_SubjectYourMoney1 EL_SubjectYourMoney2

KEL_SubjectExtremeCI regex -f -a@SPAM (Come in here|Discover the latest|Enjoy the newest|Fresh stuff|Get the freshest|Hot.n.new|Just added|Just out|Just published|Never seen stuff|Never-seen|New New|New and hot|Recently added|The newest)[:\ \.]?(Any man dreams to be the best and the most special one|Boost your manhood to astonishing levels|But without any results|Every man wishes it|I am sure it was|I think, yes|It will be great|Its the best thing you had ever seen.|Now you could grant your wish|Now you have chance to do it|Surely you only dream of it|Most quality products for anyone who wants to become a champion in bed|Rock hard manhood, multiple explosions and several times more semen volume)[:\ \.]?(Be delighted with|Delight in|Enjoy|Everything a real man would ever need|Feel Pleasure from|Take pleasure from)

KEL_SubjectMustToRead regex -f -a@SPAM (Essential|Grand|Momentous|Serious|Significant|Very important|Weighty)\ (letter|message|note)\. You\ (have|must|need|require|should)\ to\ read\.

KEL_Subject_tanha_rahe_nejateIRAN regex -a@SPAM tanha.rahe.nejate.IRAN

KEL_Subject_Dooniz regex -a@SPAM dooniz\.(com|org)

KEL_SubjectSubstrings1 sequence EL_SubjectHashbuster EL_SubjectDuckzUS EL_SubjectCialis EL_SubjectHi EL_SubjectBlank EL_SubjectParisHilton EL_SubjectTwoLowercaseWords EL_Subject150FDAApprovedMeds EL_SubjectUnknownISO EL_SubjectRolex EL_SubjectSixFigures

KEL_SubjectSubstrings sequence EL_SubjectSubstrings1 EL_SubjectOnlinePharm EL_SubjectYourMoney EL_SubjectExtremeCI EL_Subject_tanha_rahe_nejateIRAN EL_Subject_Dooniz

ifdef(`_EL_BLOCK_VIRUS_BY_SUBJECT', `dnl
KEL_SubjectAlertWorm regex -a<VIRUS> (Alert|ATTN|Malware Alert|Spyware Alert|Spyware Detected|Trojan Alert|Trojan Detected|Virus Activity Detected|Virus Alert|Virus Detected|Warning|Worm Activity Detected|Worm Alert|Worm Detected)\!$

KEL_SubjectMimailC regex -a_VIRUS_ ^ don.t be late!\ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ .+$

KEL_SubjectMyDoom regex -f -a_VIRUS_ ^.*(hi|hello|test|Test|Hi|Hello|Server Report|Error|Mail Transaction Failed|TEST|Status|HELLO|Mail Delivery System|HI|ERROR|Infected Email has been Cleaned|swfhmadizhoe)

KEL_SubjectSober regex -f -a_VIRUS_ (Gegen.das.Vergessen|Verbrechen.der.deutschen.Frau|Dresden.Bombing.Is.To.Be.Regretted.Enormously|Graeberschaendung.auf.bundesdeutsche.Anordnung|Deutsche.Buerger.trauen.sich.nicht....|S.O.S..Kiez\!.Polizei.schlaegt.Alarm|Schily.ueber.Deutschland|Massenhafter.Steuerbetrug.durch.auslaendische.Arbeitnehmer|The.Whore.Lived.Like.a.German|Transparenz.ist.das.Mindeste|Volk.wird.nur.zum.zahlen.gebraucht\!|Trotz.Stellenabbau|Augen.auf|Armenian.Genocide.Plagues.Ankara.90.Years.On|Du.wirst.ausspioniert.....\!|Dresden.1945|Blutige.Selbstjustiz|Turkish.Tabloid.Enrages.Germany.with.Nazi.Comparisons|Multi-Kulturell.=.Multi-Kriminell|60.Jahre.Befreiung|Vorbildliche.Aktion|Auf.Streife.durch.den.Berliner.Wedding|Tuerkei.in.die.EU|Paranoider.Deutschenmoerder.kommt.in.Psychiatrie|Hier.sind.wir.Lehrer.die.einzigen.Auslaender|4,8.Mill..Osteuropaeer.durch.Fischer-Volmer.Erlass|Du.wirst.zum.Sklaven.gemacht\!\!\!|Deutsche.werden.kuenftig.beim.Arzt.abgezockt|Auslaenderpolitik|Auslaender.bevorzugt)

KEL_SubjectSobigF regex -f -a_VIRUS_ ^.*(Thank you!|Your details|Details|My Details|Approved|Your Application|Wicked screensaver|That movie)

KEL_SubjectBagle regex -a_VIRUS_ ^[ ]*ID [a-z]+\.\.\.\ thanks

KEL_SubjectBagle2 regex -a_VIRUS_ ^ (E-mail\ account\ disabling\ warning|E-mail\ account\ security\ warning|Email\ account\ utilization\ warning|Important\ notify\ about\ your\ e-mail\ account|Notify\ about\ using\ the\ e-mail\ account|Notify\ about\ your\ e-mail\ account\ utilization|Warning\ about\ your\ e-mail\ account)

KEL_SubjectsBagle sequence EL_SubjectBagle EL_SubjectBagle2

KEL_SubjectVirusBounce regex -f -a_VIRUS_ ^.*(ALERTE\ \-\ Vous\ avez\ envoye\ un\ mail\ avec\ virus|ALERTE\:\ un\ virus\ a\ |ALERT\!\ Virus\ found\ in\ your\ mail|Anti-Virus\ Notification|AntiVir\ ALERT|Anti\-Virus\ Notification|Antigen\ Notification|Antigen\ found\ VIRUS|Antivirus\ stopped\ your\ message|BANNED\ FILENAME|Disallowed\ attachment\ type\ found|Email\ Quarantined\ Due\ to\ Virus|Failed\ to\ clean\ virus\ file|File\ blocked\ -\ ScanMail\ for\ Lotus|Inflex\ scan\ report\ \[[0-9]+\]|InterScan\ NT\ Alert|MMS\ Notification|MailSure\ Virus\ Alert|Message\ deleted|NAV\ detected\ a\ virus|Norton\ Anti.*\ detected|Ochrona\ antywirusowa|RAV\ AntiVirus\ scan|RECIPIENT\ \!\ Virus\ Notify\ \!|Report\ to\ Sender|Returned\ due\ to\ virus\;\ was\:|SAV\ detected\ a\ violation\ in\ a\ |SENDER\ \!\ Virus\ Notify\ \!|ScanMail\ Message\:\ To\ Sender\,\ virus\ found\ |Symantec\ AntiVirus|This\ message\ contains\ unsolicited\ data|VIRUS\ .*\ IN\ MAIL\ FROM\ YOU|VIRUS\ .*IN\ YOUR\ MAIL|VIRUS\ NO\ SEU\ EMAIL|Virus\ Alert|Virus\ Check\ Alert|Virus\ Detected\ by\ Network\ Assoc|Virus\ Notification\ from\ Redstone|Virus\ Notification\:|Virus\ Quarantine\ Notification|Virus\ Warning|Virus\ found\ in\ |Virus\ in\ Ihrer\ Nachricht|Virus\ in\:|Votre\ message\ contient\ un\ virus|Warning\:\ E-mail\ viruses\ detected|WorldSecure\ Server\ notification|\[SmartFilter\]\ Virus\ Alert\ |\[Virus\ detected\]|\{VIRUS\?\}|message\ .*\ contains\ a\ virus|virus\ found\ in\ sent\ message|virus\ trouve\ dans\ le\ message\ envoye|virus\ trovato\ in\ un\ messaggio\ inviato|Returned\ due\ to\ virus/Retourn|Content\ violation|MailMarshal\ has\ detected\ a\ Virus)

KEL_SubjectVirus sequence EL_SubjectMimailC EL_SubjectSobigF
')dnl

KEL_SubjectBarracudaBackscatter regex -f \*\*Message\ you\ sent\ blocked\ by\ our\ bulk\ email\ filter\*\*$

KEL_SubjectLocalpartComma regex -f -a@SPAM ^(YOURS:)*ifdef(`confEL_LocalpartComma', `confEL_LocalpartComma', `(cat|Cat|champeon|Editor|Mtucker|Rachel|Schampeo|andreiv|heather|info|rachel|scha|schampeo|steve|Akelly|alice|Alice|Asp|asp|books|catalogs|Criptions|Dennis|Dmk|Dmw|dwm|EDITORIAL|Efitzpatrick|efitzpatrick|friend|Friend|Hosting|Info|joa|Joanne|joanne|kimb|kimbryant|Kozmomessengerbag|lmorse|Lmorse|Loring|michael|Michael|Michael Sippey|Neva|Okeefe|Rahul|rahul|Readermail|Simonstl|simonstl|Sippey Michael|Slamdunk|Stacey|Support|tbyfield|Tracey)'),

KEL_SubjectLocalpartColon regex -f -a@SPAM ^(YOURS:)*ifdef(`confEL_LocalpartColon', `confEL_LocalpartColon', `(Akelly|alice|Alice|Asp|asp|books|catalogs|Criptions|Dennis|Dmk|Dmw|dwm|EDITORIAL|Efitzpatrick|efitzpatrick|friend|Friend|Hosting|Info|joa|Joanne|joanne|kimb|kimbryant|Kozmomessengerbag|lmorse|Lmorse|Loring|michael|Michael|Michael Sippey|Neva|Okeefe|Rahul|rahul|Readermail|Simonstl|simonstl|Sippey Michael|Slamdunk|Stacey|tbyfield|Tracey)'):

KEL_SubjectCommaSpaceLocalpart regex -f -a@SPAM ,\ ifdef(`confEL_CommaSpaceLocalpart', `confEL_CommaSpaceLocalpart', `(Simonstl)')

KEL_LocalpartApostrophe regex -f -a@SPAM ifdef(`confEL_LocalpartApostrophe', `confEL_LocalpartApostrophe', `(Simonstl)')\'s

ifdef(`_EL_HIBIT_SUBJECT', `dnl
KEL_SubjectHibits regex -m -b -f -a<HIBIT> [€-ÿ]
KEL_SubjectLobits regex -m -b -f -a<HIBIT> [-]
KEL_SubjectHibit sequence EL_SubjectHibits EL_SubjectLobits
KEL_SubjectUnwantedISO regex -a<HIBIT> ^.*=\?ifdef(`confEL_UnwantedISO', `confEL_UnwantedISO', `(big5|[Gg][Bb]2312|ks_c_5601\-1987|windows\-125[125]|koi8\-r|ISO\-2022\-JP)')
')dnl

ifdef(`_EL_MILLIONSFORGERY', `dnl
# NOTE: this must come in the first included file; also used by EL_C_H_To.
# this is to catch completely fictional addressees from Millions CDs
# e.g., some millions CD has "Mignetta Doody" as the name for webmaster@
# one of our domains, which is, even as these things go, pretty silly.
KEL_ToMillionsCD regex -f -a@SPAM ifdef(`confEL_ToMillionsCD', `confEL_ToMillionsCD', `Mignetta.*Doody')
')dnl

KEL_SubjectPumpAndDump regex -a_SPAMSIGN_ (st-0ck|St0ck|Trading|Cribsheet|wall st-reet|sto.ck|5t0ck)

KEL_Subjects200604 regex -a@SPAM (You.have.received.a.postcard|tanha.rahe.nejate.IRAN|Million.Potential.Travellers.Are.Waiting|Fax.Advertising.Works|Full.of.health..Then.don.t.click|Chegou.uma.charge.para.voce|shame.of.sex..we.can.change.it|is.most.modern.and.safe.way.not.to.cover|Voce.Recebeu.uma.Charge.Humortadela|Massive.PE.patch.sale|increase.in.sexual.desire|VIP.watches)

KEL_SubjectChecks2 sequence EL_SubjectLinkExchanges EL_SubjectSubstrings EL_SubjectLocalpartComma EL_SubjectLocalpartColon EL_SubjectCommaSpaceLocalpart EL_LocalpartApostrophe EL_SubjectParenNumber EL_SubjectBarracudaBackscatter EL_SubjectPumpAndDump EL_Subjects200604 ifdef(`_EL_MILLIONSFORGERY', `EL_ToMillionsCD')

KEL_SubjectChecks sequence EL_SubjectMustToRead EL_SubjectListVendor EL_SubjectChecks2

LOCAL_RULESETS
#------------------------------------------------------------------------
# enemieslist.com Subject header checks
#------------------------------------------------------------------------
SEL_Check_Header_Subject
ifdef(`_EL_TRACE', `dnl
R$*					$: $1 $(EL_Log "Subject w/ " $1 "; score: " $&{ELSuspiciousCount} "." $)
')dnl

# set our header-tracker
# but we need to make sure it has not yet been set
R$*					$: $1 $| $(EL_Math & $@ 4 $@ $&{ELHasHeader} $)
R$* $| 1			$: $1 $(EL_Log "subject flag already set." $)
R$* $| 0			$: $1 $| $(EL_Math + $@ 4 $@ $&{ELHasHeader} $)
R$* $| $*			$: $(EL_SetVar {ELHasHeader} $@ $2 $)
R$*					$: $(EL_Log "ELHasHeader (subj): " $&{ELHasHeader} $)

ifdef(`_EL_SKIPLOCAL', `dnl
R$*					$: $1 $| $&{client_addr}
R$* $| 127.0.0.1	$@
')dnl

# skip whitelisted hosts
R$*				$: $&{ELWhitelisted}
R$+:$+			$@

ifdef(`_EL_B0RKEN', `dnl
R$*					$: $(EL_B0rkenRatware $&{currHeader} $)
R@SPAM				$#error $@ 5.7.1 $: ifdef(`confEL_ErrB0rkenRatware', `confEL_ErrB0rkenRatware', `"554 B0RKENR Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it appears to have been sent by laughably broken spam software."')
')dnl

R$*					$: $(EL_SubjectChecks $&{currHeader} $)
R@SPAM				$#error $@ 5.7.1 $: ifdef(`confEL_ErrSubjectMatch', `confEL_ErrSubjectMatch', `"554 BADSUBJ Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. (Subject: matched known spam signature)."')

R$*					$: $(EL_SubjectChecks $&{currHeader} $)
R_SPAMSIGN_			$: <OK> $(EL_Math + $@ 1 $@ $&{ELSpamsign} $)
R<OK>$*				$: $(EL_SetVar {ELSpamsign} $@ $1 $)
R$*					$: $&{ELSpamsign} 
R5					$#error $@ 5.7.1 $: ifdef(`confEL_ErrSubjectFrom', `confEL_ErrSubjectFrom', `"554 SUBJFRM Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. (Subject:, From: matched known spam signature)."')

ifdef(`_EL_EMAILHELLOINC', `dnl
R$+					$: $(EL_SubjectSexuallyExplicit $&{currHeader} $)
R@SPAM				$#error $@ 5.7.1 $: ifdef(`confEL_ErrSubjectEmailHello', `confEL_ErrSubjectEmailHello', `"554 XPLICIT Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. Sexually explicit unsolicited mail not welcome here."')
')dnl

ifdef(`_EL_BLOCK_VIRUS_BY_SUBJECT', `dnl
R$*					$: $(EL_SubjectsBagle $&{currHeader} $)
R_VIRUS_			$#error $@ 5.7.1 $: ifdef(`confEL_ErrSubjectBagle', `confEL_ErrSubjectBagle', `"554 SUBJBGL Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as a suspected Bagle virus delivery attempt."')

R$*					$: $(EL_SubjectSober $&{currHeader} $)
R_VIRUS_			$#error $@ 5.7.1 $: ifdef(`confEL_ErrSubjectSober', `confEL_ErrSubjectSober', `"554 SUBJSBR Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as a suspected Sober virus delivery attempt."')

R$*					$: $(EL_SubjectVirusBounce $&{currHeader} $)
R_VIRUS_			$#error $@ 5.7.1 $: ifdef(`confEL_ErrSubjectVirusBounce', `confEL_ErrSubjectVirusBounce', `"554 SBJVRSB Contact "$&{ELContactEmail}" if this is in error, but this is probably a bogus virus notification. Update your antivirus software not to accept-then-bounce to forged senders."')

R$*					$: $(EL_SubjectAlertWorm $&{currHeader} $)
R<VIRUS>			$#error $@ 5.7.1 $: ifdef(`confEL_ErrAlertWorm', `confEL_ErrAlertWorm', `"554 ALRTWRM Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as a virus due to the Subject header."')

R$*					$: $(EL_SubjectVirus $&{currHeader} $)
R<VIRUS>			$#error $@ 5.7.1 $: ifdef(`confEL_ErrAlertWorm', `confEL_ErrAlertWorm', `"554 ALRTWRM Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as a virus due to the Subject header."')
')dnl

ifdef(`_EL_HIBIT_SUBJECT', `dnl
R$*					$: $(EL_SubjectHibit $&{currHeader} $)
R$*<HIBIT>			$#error $@ 5.7.1 $: ifdef(`confEL_ErrSubjectHibit', `confEL_ErrSubjectHibit', `"554 SUBJHIB Contact "$&{ELContactEmail}" if this is in error, but this message was rejected. It contains non-ASCII characters in the Subject: header. cf. RFC 2822 Section 2.2."')

R$*					$: $(EL_SubjectUnwantedISO $&{currHeader} $)
R$*<HIBIT>			$#error $@ 5.7.1 $: ifdef(`confEL_ErrSubjectUnwantedISO', `confEL_ErrSubjectUnwantedISO', `"554 ISOENCD Contact "$&{ELContactEmail}" if this is in error, but this message was rejected. Please resend without encoded Subject: header if this is not spam."')

R$*					$: $(EL_SubjectStrangeB5 $&{currHeader} $)
R@SPAM				$#error $@ 5.7.1 $: ifdef(`confEL_ErrSubjectUnwantedISO', `confEL_ErrSubjectUnwantedISO', `"554 ISOENCD Contact "$&{ELContactEmail}" if this is in error, but this message was rejected. Please resend without encoded Subject: header if this is not spam."')
')dnl

ifdef(`_EL_REJECT_YAHOO_SPAM', `dnl
R$*						$: $(EL_YahooSpamguard $&{currHeader} $) $| $&{client_name}
R@SPAM $| $* yahoo.com	$#error $@ 5.7.1 $: ifdef(`confEL_ErrSubjectYahooSpam', `confEL_ErrSubjectYahooSpam', `"554 YAHOOSG Contact "$&{ELContactEmail}" if this is in error, but if Yahoo thinks this is spam, we do not want it either."')
')dnl

ifdef(`_EL_SPAMX', `dnl
R$*					$: $(EL_SpamX $&{currHeader} $)
R@SPAM				$#error $@ 5.7.1 $: ifdef(`confEL_ErrSubjectSpamX', `confEL_ErrSubjectSpamX', `"554 NOSPAMX Contact "$&{ELContactEmail}" if this is in error, but we do not accept SpamX abuse reports."')
')dnl
