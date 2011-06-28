divert(-1)dnl
#
# Copyright (c) 2004-2011 hesketh.com/inc. All rights reserved.

# See the file LICENSE in the distribution for details.

#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_Check_Header_From.m4,v 1.46 2011/05/17 19:57:56 schampeo Exp $')
divert(-1)dnl

define(`_EL_CHECK_FROM', `1')dnl

LOCAL_CONFIG
#------------------------------------------------------------------------
# enemieslist.com From: header check patterns and call
#------------------------------------------------------------------------
HFrom: $>EL_Check_Header_From

ifdef(`_EL_DAZZLING', `dnl
# check for dazzling spammer - possibly to be deprecated
KEL_DazzlingSpammerbiz regex -a@SPAM @(bright|dazzling|fabulous|famous|fantastic|friendly|gorgeous|mighty|smart|witty|wonderful)(bernies|dans|dons|george|henrys|mickeys|omars|ozzies|sandys|teds|vinnies)\.biz

KEL_DazzlingSpammernet regex -a@SPAM @(bright|dazzling|fabulous|famous|fantastic|friendly|mighty|smart|witty|wonderful)(andrews|arnolds|chads|chesters|daniels|edwards|georges|johns|larrys|leonards|lukes|marks|matthews|oscars|phillips|prestons|rogers|sams|simons|stuarts|tonys)\.net

KEL_DazzlingSpammerus regex -a@SPAM @(bright|dazzling|fabulous|famous|fantastic|friendly|gorgeous|mighty|right|smart|winderful|witty|wonderful)(bernies|bobbys|carls|dans|dons|franklins|george|georges|harolds|henrys|jeffreys|jerrys|larrys|leonards|lukes|marks|michaels|mickeys|nevilles|omars|ozzies|patricks|phillips|phillps|prestons|roberts|sandys|simons|teds|thomas|tonys|vinnies|walters|williams)\.us

KEL_DazzlingSpammer sequence EL_DazzlingSpammerbiz EL_DazzlingSpammernet EL_DazzlingSpammerus
')dnl

ifdef(`_EL_RUN_ZALKO', `dnl
# run-zalko.com spam signature
KEL_FromRunZalko regex -f -aMATCH [A-Z][a-z]+[A-Z]?[a-z]*\ [A-Z][a-z]+[A-Z]?[a-z]*\ <(Adam|Adred|Adro|Aimel|Alan|Alay|Alen|Aley|Alia|Alicess|Alie|Alle|Allen|Alley|Amy|Andra|Andris|Andy|Angel|Angeley|Angelly|Angelic|Anne|Art|Arthade|Ashle|Barles|Bart|Ben|Beth|Betty|BigHue|BigJohn|Billes|Billian|Billip|Bobio|Boby|Bradlex|BradleyBiggeroo|Braig|Bre|Bred|Breg|Bremy|Bren|Brichau|Bristin|Bruck|Bry|Caniett|Cara|Carbaro|Carcian|Caren|Carethr|Carisan|Carista|Caristi|Cark|Carler|Carol|Carolen|Cassice|Cathler|Catina|Catrine|Chadlex|Chara|Chaul|Chriami|Chrian|Christi|Chrynth|Chuce|Clan|Claudia|Corew|Courthi|Crad|CuteyBrad|Dan|Dance|Dane|Daven|David|Deandac|Deathri|Debetty|Deirdra|Dena|Denny|Denry|Der|Dia|Diana|Don|Dony|Dondy|Dora|Dorolis|Doug|Douge|DrillSargeant|Duan|Edwart|Eiley|Emilen|Emileen|Emiley|Emily|Eria|Erie|Ernesto|Euge|Eugen|Euger|Evan|Fradles|Fraig|Frey|Gardo|Garlex|Garry|Gen|HandSolo|HanSolo|Harreg|Heathia|Hela|Helle|Hen|Ivan|Jack|Jamin|Jana|Jas|Jasonat|Jayne|Jen|Jene|Jenne|Jesa|Jessy|Jim|Joana|Joselli|Julie|Juliet|Julise|Julizab|Jusa|Kara|Karol|Kartne|Kary|Kath|Kathara|Kathel|Katina|Keithar|Keler|Ken|Keve|Kevenny|Kimbett|Krie|Kriette|Krina|Krine|Krissa|Kristal|Kristy|Lando|Larles|Laudian|Laura|Laure|Lauren|Laurick|Laurtne|Lea|Leah|Leathle|Leatrie|LittleBigBobbyBlue|Loracy|Lorolys|Luke|MaleLovers|Mara|Marandr|Mariste|Maristi|Marlen|Marol|Maroly|Maron|Marotha|Mart|Mary|Mathan|Mel|Melairl|Melie|Meller|Mica|Micard|Michaun|Michero|Mike|Monia|Monie|Monicky|Natrist|Natt|Nice|Niciany|Niney|Pat|Pathene|Paunth|Perey|Peterek|Phill|Ran|Raymona|Rebori|Rob|Rodd|Roger|Ruben|Ruber|Russ|Rustin|Ryan|Samin|San|SargeantSteel|Sary|Scot|Scotthe|SexyShaun|SexyTyrone|SeymourDicks|Shandra|Shane|Shanist|Shartha|Sherine|Sherris|Sherist|Sonice|Sten|Stena|Stendra|Steph|Ster|Steve|Stevid|Stuarry|Stew|Sustine|Suzaber|SweetyBraden|Sylvia|Taronic|Taronie|Terindr|Thel|Tim|Toby|Todd|Tra|Valie|Verley|Viciani|Vick|Victoph|Wade|Walteve|Wayne|Zach)[0-9a-z]{4}@
')dnl

KEL_AsteriskLocalPart regex -a@SPAM <\*@

KEL_NewPenisPatch regex -a@SPAM (PENiS[0-9]+PATCH|NEW\.Penis\.Patch\.[0-9]+|PillsPenis[0-9]+)@aol\.com

KEL_SavvyInvestor regex -a@SPAM (Savvy.*Investor|Term.*Quotes|ChiefEditor|SpecialEdition|stockscan).*@

KEL_SpecialDeals regex -a@SPAM SpecialDeals@

KEL_EndsWithDogFrom123 regex -a@SPAM dog@(123box\.co\.uk|activatormail\.com|betterthanhotmail\.com|quickwebmail\.com)

KEL_PlanetPhat regex -a@SPAM Planet.*Phat

KEL_UrgentMarketAlert regex -a@SPAM (MarketWatchAlert|InvestorAlerts|IssueOfTheWeek|ThePickOfTheYear|UrgentMarketAlert|UrgentMarketUpdate)[0-9]+@

KEL_From_Dooniz regex -a@SPAM dooniz\.(com|org)

KEL_KnownSpammers sequence EL_AsteriskLocalPart EL_NewPenisPatch EL_SavvyInvestor EL_PlanetPhat EL_SpecialDeals EL_EndsWithDogFrom123 EL_UrgentMarketAlert EL_From_Dooniz

KEL_CommonStrings1 regex -a@SPAM (0005644986|[0-9]+70866|AirTravel[a-z][a-z]+|AutoInsurancePros.+|AutoLoanExperts.+|BrokerTrainingCenter.+|cashcard[0-9]|CashNowSweeps|Celularinsanity|Cost-Effective-Marketing|DoctorsChoice|dyoung[0-9][0-9].+|EliminateBugs|elizbethsave_mylife2003|dotcomasset|helpingurbiz)@

KEL_CommonStrings2 regex -a@SPAM (evtwqmigru|GenericViagra[0-9]|hjyyy|internetexposure|Leads4u|LendersCompete|livenlearn[0-9]+|LV\.Singles|marketman[0-9]|MedPills[0-9]+.*|MonsterSizedClitties|lotto_commission|moresexforyou[0-9]+|mortgageleads|num1sxy|rjnr|infoline1|sweepstake)@

KEL_CommonStrings3 regex -a@SPAM (ReadyToDeal|sanscoservices[0-9]+|selectos22|stockupnow[a-z]+|SAFEMODE|marketingmanagement[0-9]+|newergirl[0-9]|WealthManager|bkgroundchk|LeadsGalore|opti1a1|emarket4u|VIAGRA|PROPECIA)@

KEL_CommonStrings sequence EL_CommonStrings1 EL_CommonStrings2 EL_CommonStrings3

KEL_CommonSubstrings1 regex -a@SPAM -f (affiliatesoffer\-|dermalptch1|dermalptc|gt_lastone|poiuqwe|v37ackh|singlesconnect|ruolu|ozsqllp|lgp41wfj|steflorea|stocknews|xxifb34dt|wonder21jeanette|travelincentives).*@

KEL_CommonSubstrings2 regex -a@SPAM -f (whitney21gordon|unlimiteddownloads|secretsofinternetcash|International_Real_Estate_Auction|Viagra|Cialis|Retrovir|Xanax|Vicodin|Plavix|Evista|Nexium|Glucophage|Purinethol).*@

KEL_CommonSubstrings3 regex -a@SPAM -f (Imitrex|Diflucan|Flomax|Arava[, ]|Propecia|Lamictal|testdriveomnipod|xyxyxyxyxyxyxyxyxyxyxyxyxyxyxyxyxyxyxyxyxyxyx|workfromhome|StockPromo|Productive\.List|Warrior.Custom.Golf|snd_pcm_[hs]w_params_[gs]et|Invenio.Sales|highway4u).*@

KEL_CommonSubstrings4 regex -a@SPAM -f (HomelandSecIssue|HotPicks|HottestMarketPick|IncredibleGrowth|MarketMakersReport|MarketOpportunity|PoisedToMove|PoisedToSoar|SecurityIssue|UrgentIssueAlert)[0-9]+@

KEL_CommonSubstrings5 regex -a@SPAM (Electronic\ Greeting|Greeting\-Cards|GreetingCard|Hallmark\ E\-Card|PostCard|Postcard|Riversongs)

KEL_CommonSubstrings sequence EL_CommonSubstrings1 EL_CommonSubstrings2 EL_CommonSubstrings3 EL_CommonSubstrings4 ifdef(`_EL_BLOCK_POSTCARDS', `EL_CommonSubstrings5')

KEL_AlphaEightNumbersAlpha regex -a@SPAM ^[A-Z][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][A-Z]@
KEL_AlphaElevenNumbersAlpha regex -a@SPAM ^[A-Z][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][A-Z]@

KEL_AlphaNumbersAlpha sequence EL_AlphaEightNumbersAlpha EL_AlphaElevenNumbersAlpha

KEL_FromEverCo regex -a@SPAM ([a-z]+_[0-9]{1,2}[a-z]).*<\1@

KEL_FromBackrefdvc regex -f -a_SPAMSIGN_ \"<ifdef(`confEL_Backrefdvc', `confEL_Backrefdvc', `(fofoo|babar)')@(AOL|ATT|BELLSOUTH|EARTHLINK|earthlink|HOTMAIL|MSN|USA|WEBTV|YAHOO)

KEL_FromCialis regex -f -a_SPAMSIGN_ ^ *\".*\"<[a-z]+@(adelphia\.net|ameritech\.net|att\.net|bellsouth\.net|bigpond\.com|btinternet\.com|cablespeed\.com|charter\.net|comcast\.net|cox\.net|cs\.com|earthlink\.net|excite\.com|hanmail\.net|juno\.com|mindspring\.com|netzero\.net|ntlworld\.com|optonline\.net|pacbell\.net|prodigy\.net|swbell\.net|sympatico\.ca|t\-online\.de|verizon\.net|webtv\.net|worldnet\.att\.net)

KEL_FromSoftwareSpammers regex -f -a_SPAMSIGN_ ^ *\"[A-Z][a-z]+\ \"\ <[a-z]+@

ifdef(`_EL_MOBSTER', `dnl
KEL_FromMobsterISyphilitic regex -f -a_SPAMSIGN_ \"[A-Z][a-z]+\ [A-Z]\.\ [A-Z][a-z]+\"\ <[A-Za-z\.\_0-9\-]+@
ifdef(`_EL_WORDLIST', `dnl
KEL_FromMobsterWordlist regex -f -s1,2,3 \"([A-Z][a-z]+)\ [A-Z]\.\ ([A-Z][a-z]+)\"\ <([A-Z]*[a-z\.\_]+)@
KEL_FromMobsterWordlistRoot regex -f -s1,3,5 \"([A-Z][a-z]+)(d|s|ing|ize|ed)?\ [A-Z]\.\ ([A-Z][a-z]+)(d|s|ing|ize|ed)?"\ <([A-Z]*[a-z\.\_]+)(d|s|ing|ize|ed)?@
')dnl
')dnl

KEL_GetSender2LDgTLD regex -a<2LD> -s1 .*@([a-z0-9\-]+)\.[a-z]+\ *>

KEL_GetSender2LDccTLD regex -a<2LD> -s1 .*@([a-z0-9\-]+)\.(co|com|ne|net|or|org)\.[a-z]+\ *>

KEL_GetSender2LD sequence EL_GetSender2LDgTLD EL_GetSender2LDccTLD

KEL_GetHELO2LD regex -a<2LD> -s1 ^[a-z0-9\-]+[a-z]([0-9]+\.com)$

KEL_FromXMLXSLT regex -a@SPAM <xsl:value\-of\ select

ifdef(`_EL_FOAD_DIRECTMEDS', `dnl
KEL_DirectmedsBiz regex -a<YES> -s1,2 \"([A-Z][a-z]+)\"<([a-z]+)@(sylviasaint\-freesite|yahoo)\.com>
')dnl

ifdef(`_EL_HOTMAIL_419', `dnl
KEL_Hotmail419Sender regex -a<AFF> ^((info|irish|govern|mr|rev|uk)|.*(assist|attorney|bank|barrister|bonolotaagencia|claim|fortune|jackpot|king|loteria|lottery|lotto|mariam|prince|promo|relief|sweepstake|win))

KEL_HotmailOrigin regex -a<YES> ^bay[0-9]+\-(dav|f)[0-9]+\.bay[0-9]+\.hotmail\.com$
')

ifdef(`_EL_HIBIT_FROM', `dnl
KEL_FromHibits regex -m -b -f -a<HIBIT> [-ÿ]
KEL_FromLobits regex -m -b -f -a<HIBIT> [-]
KEL_FromHibit sequence EL_FromHibits EL_FromLobits
KEL_FromUnwantedISO regex -a<HIBIT> ^.*=\?ifdef(`confEL_UnwantedISO', `confEL_UnwantedISO', `(big5|[Gg][Bb]2312|ks_c_5601\-1987|windows\-125[125]|koi8\-r|ISO\-2022\-JP)')
')dnl


KEL_FromChecks sequence EL_KnownSpammers EL_CommonSubstrings EL_CommonStrings EL_AlphaNumbersAlpha EL_FromEverCo ifdef(`_EL_DAZZLING', `EL_DazzlingSpammer') EL_FromBackrefdvc EL_FromCialis EL_FromSoftwareSpammers EL_FromXMLXSLT

LOCAL_RULESETS
#------------------------------------------------------------------------
# enemieslist.com From header checks
#------------------------------------------------------------------------
SEL_Check_Header_From
ifdef(`_EL_TRACE', `dnl
R$*					$: $1 $(EL_Log "From w/ " $1 "; score: " $&{ELSuspiciousCount} "." $)
')dnl

# set the ELHasHeader macro regardless
# but we need to make sure it has not yet been set
R$*					$: $1 $| $(EL_Math & $@ 2 $@ $&{ELHasHeader} $)
R$* $| 1			$: $1 $(EL_Log "from flag already set." $)
R$* $| 0			$: $1 $| $(EL_Math + $@ 2 $@ $&{ELHasHeader} $)
R$* $| $*			$: $(EL_SetVar {ELHasHeader} $@ $2 $)
R$*					$: $(EL_Log "ELHasHeader (from): " $&{ELHasHeader} $)

ifdef(`_EL_SKIPLOCAL', `dnl
R$*					$: $1 $| $&{client_addr}
R$* $| 127.0.0.1	$@
')dnl

# skip whitelisted hosts
R$*					$: $&{ELWhitelisted}
R$+:$+				$@

R$*					$: $(EL_FromChecks $&{currHeader} $)
R@SPAM				$#error $@ 5.7.1 $: ifdef(`confEL_ErrFrom', `confEL_ErrFrom', `"554 BADFROM Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it contains a suspicious header (From:)"')

ifdef(`_EL_HOTMAIL_419', `dnl
# ??? currently buggy - do not use.
R$*							$: $(EL_HotmailOrigin $&{client_name} $) $| $(EL_Offwhitelist $&{client_name} $) $| $(EL_Hotmail419Sender $&{currHeader} $) $| $&{INHEADERS}
ifelse(_EL_POLICY, 1, `dnl
R<YES> $| 419 $| <AFF> $| YES	$: $&{ELPolicyUser} $| $&{ELPolicySwitch}
R<YES> $| O $| <AFF> $| YES		$: $&{ELPolicyUser} $| $&{ELPolicySwitch}
R$* HOTM419 $* $| TAG			$: <TAGHOTM419>
R$* HOTM419 $* $| BLOCK			$: <REJHOTM419>
R$* +HOTM419 $* $| ASK			$: <TAGHOTM419>
R$* !HOTM419 $* $| ASK			$: <REJHOTM419>

# if no match try default policy
R$*							$: $(EL_HotmailOrigin $&{client_name} $) $| $(EL_Offwhitelist $&{client_name} $) $| $(EL_Hotmail419Sender $&{currHeader} $) $| $&{INHEADERS}
R<YES> $| 419 $| <AFF> $| YES	$: $(EL_Policy default $) $| $&{ELPolicySwitch}
R<YES> $| O $| <AFF> $| YES		$: $(EL_Policy default $) $| $&{ELPolicySwitch}
R$* HOTM419 $* $| TAG			$: <TAGHOTM419>
R$* HOTM419 $* $| BLOCK			$: <REJHOTM419>
R$* +HOTM419 $* $| ASK			$: <TAGHOTM419>
R$* !HOTM419 $* $| ASK			$: <REJHOTM419>

',`
R<YES> $| 419 $| <AFF> $| YES	$: <TAGHOTM419>
')dnl

R<TAGHOTM419>				$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgHotmail419', `confEL_TagErrMsgHotmail419', `"probably 419/advanced fee fraud scam mail relayed via hotmail"')> $| 0
R<REJHOTM419>				$#error $@ 5.7.1 $: ifdef(`confEL_ErrHotmail419', `confEL_ErrHotmail419', `"554 HOTM419 Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as a likely advance fee fraud."')
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

ifdef(`_EL_HIBIT_FROM', `dnl
R$*					$: $(EL_FromHibit $&{currHeader} $)
R$*<HIBIT>			$#error $@ 5.7.1 $: ifdef(`confEL_ErrFromHibit', `confEL_ErrFromHibit', `"554 FROMHIB Contact "$&{ELContactEmail}" if this is in error, but this message was rejected. It contains non-ASCII characters in the From: header. cf. RFC 2822 Section 2.2."')

R$*					$: $(EL_FromUnwantedISO $&{currHeader} $)
R$*<HIBIT>			$#error $@ 5.7.1 $: ifdef(`confEL_ErrFromUnwantedISO', `confEL_ErrFromUnwantedISO', `"554 ISOENCD Contact "$&{ELContactEmail}" if this is in error, but this message was rejected. Please resend without encoded From: header if this is not spam."')
')dnl

ifdef(`_EL_FOAD_DIRECTMEDS', `dnl
ifelse(_EL_WORDLIST, 1, `dnl
R$*					$: $(EL_DirectmedsBiz $&{currHeader} $)
R$+ $| $+<YES>		$: $(EL_Wordlist $1 $) $| $(EL_Wordlist $2 $) 
RN$* $| N$* 		$: $>EL_TagSuspicious <"probably directmeds.biz spammer"> $| 4
R$*					$: $&{currHeader}
', `
_EL_FOAD_DIRECTMEDS requires _EL_WORDLIST in order to work properly.
')dnl
')dnl

ifdef(`_EL_B0RKEN', `dnl
R$*					$: $(EL_B0rkenRatware $&{currHeader} $)
R@SPAM				$#error $@ 5.7.1 $: ifdef(`confEL_ErrB0rkenRatware', `confEL_ErrB0rkenRatware', `"554 B0RKENR Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it appears to have been sent by laughably broken spam software."')
')dnl

R$*					$: $(EL_FromChecks $&{currHeader} $)
R_SPAMSIGN_			$: <OK> $(EL_Math + $@ 4 $@ $&{ELSpamsign} $)
R<OK>$*				$: $(EL_SetVar {ELSpamsign} $@ $1 $)
R$*					$: $&{ELSpamsign}

R5					$#error $@ 5.7.1 $: ifdef(`confEL_ErrFromSubject', `confEL_ErrFromSubject', `"554 BADFRSB Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. (Subject:, From: matched known spam signature)."')

R20					$#error $@ 5.7.1 $: ifdef(`confEL_ErrFromTo', `confEL_ErrFromTo', `"554 BADFRTO Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. (To:, From: matched known spam signature)."')


ifdef(`_EL_DOMAIN_BLACKLIST', `dnl
# ??? bug: make sure this checks the sender as well as the recipient!

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
RSPAMMER			$: <REJDOMAINSBL>
RS					$: <REJDOMAINSBL>
')dnl
R<TAGDOMAINSBL>								$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgFromBL', `confEL_TagErrMsgFromBL', `"message sent from domain in local blacklist"')> $| 4
R<REJDOMAINSBL>								$#error $@ 5.7.1 $: ifdef(`confEL_ErrFromSpammerDomain', `confEL_ErrFromSpammerDomain', `"554 BADFRDM Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. We do not accept mail from your domain."')
')dnl

ifdef(`_EL_PHISH', `dnl
R$*					$: $1
ifelse(_EL_PHISH_LOOSE, 1, `dnl
R$*					$: $(EL_PhishFromDomains $&{currHeader} $) $| $&{ELPhishProperOrigin}
ifelse(_EL_POLICY, 1, `dnl
R$- $| $- 			$: $1 $| $2 $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
RPHISH $| NO $| $*NOPHISH$* $| TAG		$: <TAGNOPHISH>
RPHISH $| NO $| $*NOPHISH$* $| BLOCK	$: <REJNOPHISH>
RPHISH $| NO $| $* +NOPHISH$* $| ASK	$: <TAGNOPHISH>
RPHISH $| NO $| $* !NOPHISH$* $| ASK	$: <REJNOPHISH>

# if no match try default policy
R$* $| $* $| $*							$: $1 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
RPHISH $| NO $| $*NOPHISH$* $| TAG		$: <TAGNOPHISH>
RPHISH $| NO $| $*NOPHISH$* $| BLOCK	$: <REJNOPHISH>
RPHISH $| NO $| $* +NOPHISH$* $| ASK	$: <TAGNOPHISH>
RPHISH $| NO $| $* !NOPHISH$* $| ASK	$: <REJNOPHISH>
',`dnl
RPHISH $| NO 		$#error $@ 5.7.1 $: ifdef(`confEL_ErrFromPhish', `confEL_ErrFromPhish', `"554 PHISHFR Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as a phish scam."')
')
',`
R$*						$: $(EL_PhishFromDomains $&{currHeader} $) $| $&{ELPhishProperOrigin} $| $(EL_PhishMailFromLocalparts $&{mail_addr} $)
ifelse(_EL_POLICY, 1, `dnl
R$- $| $- $| $-			$: $1 $| $2 $| $3 $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
RPHISH $| NO $| PHISH $| $*NOPHISH$* $| TAG		$: <TAGNOPHISH> 
RPHISH $| NO $| PHISH $| $*NOPHISH$* $| BLOCK	$: <REJNOPHISH> 
RPHISH $| NO $| PHISH $| $* +NOPHISH$* $| ASK	$: <TAGNOPHISH> 
RPHISH $| NO $| PHISH $| $* !NOPHISH$* $| ASK	$: <REJNOPHISH> 

# if no match try default policy
R$* $| $* $| $* $| $* $| $*						$: $1 $| $2 $| $3 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
RPHISH $| NO $| PHISH $| $*NOPHISH$* $| TAG		$: <TAGNOPHISH> 
RPHISH $| NO $| PHISH $| $*NOPHISH$* $| BLOCK	$: <REJNOPHISH> 
RPHISH $| NO $| PHISH $| $* +NOPHISH$* $| ASK	$: <TAGNOPHISH> 
RPHISH $| NO $| PHISH $| $* !NOPHISH$* $| ASK	$: <REJNOPHISH> 
',`dnl
RPHISH $| NO $| PHISH							$: <REJNOPHISH>
')
')
R<TAGNOPHISH>							$: $(EL_Math + $@ 64 $@ $&{ELSpamsign} $) $| $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgPhish', `confEL_TagErrMsgPhish', `"message is probably a phish scam"')> $| 3
R<REJNOPHISH>							$#error $@ 5.7.1 $: ifdef(`confEL_ErrFromPhish', `confEL_ErrFromPhish', `"554 PHISHFR Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as a phish scam."')
')

ifdef(`_EL_FirstMLastZZ', `dnl
ifdef(`_EL_DEBUG', `dnl
R$*						$: $(EL_Log "EL rDNS of "$&{client_addr}": "$&{client_name} $)
')dnl
R$*						$: $&{currHeader}
R$*						$: $(EL_FirstMLastZZSeq $1 $) $| $&{client_resolve}
R_SPAMSIGN_ $| FAIL		$#error $@ 5.7.1 $: ifdef(`confEL_ErrFromFMLZZFail', `confEL_ErrFromFMLZZFail', `"554 FMLZZFA Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. Your From: address looks fishy, and your mail server lacks reverse DNS."')

R$*						$: $&{currHeader}
R$*						$: $(EL_FirstMLastZZSeq $1 $) $| $&{client_resolve}
R_SPAMSIGN_ $| TEMP		$#error $@ 5.7.1 $: ifdef(`confEL_ErrFromFMLZZTemp', `confEL_ErrFromFMLZZTemp', `"554 FMLZZTP Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. Your From: address looks fishy, and your mail server seems to lack reverse DNS."')

ifdef(`_EL_DEBUG', `dnl
R$*						$: $(EL_Log "EL fmlzz: " $&{currHeader} " " $&{s} " " $&{mail_addr} "." $)
')dnl
R$*						$: $&{currHeader}
R$*						$: $(EL_FirstMLastZZSeq $1 $) $| $(EL_FirstMLastZZccTLDs $&{s} $) $| $(EL_FirstMLastZZccTLDs $&{mail_addr} $)
R_SPAMSIGN_ $| MATCH $| MATCH	$#error $@ 5.7.1 $: ifdef(`confEL_ErrFromFMLZZccTLD', `confEL_ErrFromFMLZZccTLD', `"554 FMLZZCC Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. Your From: address is suspect."')

R$*						$: $&{currHeader}
R$*						$: $(EL_FirstMLastZZSeq $1 $) $| $&{ELRecdHeaderCount}
R_SPAMSIGN_ $| 0		$#error $@ 5.7.1 $: ifdef(`confEL_ErrFromFMLZZdirectToMX', `confEL_ErrFromFMLZZdirectToMX', `"554 FMLZZMX Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. Your From: address is suspect and we do not accept direct-to-MX mail here."')

ifdef(`_EL_TAG_SUSPICIOUS', `dnl
# and tag the rest for filtering
R$*					$: $&{currHeader}
R$*					$: $(EL_FirstMLastZZSeq $1 $)
ifelse(_EL_POLICY, 1, `dnl
R$-					$: $1 $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
R_SPAMSIGN_ $| $*FMLZZ$* $| TAG		$: <TAGFMLZZ>
R_SPAMSIGN_ $| $*FMLZZ$* $| BLOCK	$: <REJFMLZZ>
R_SPAMSIGN_ $| $* +FMLZZ$* $| ASK	$: <TAGFMLZZ>
R_SPAMSIGN_ $| $* !FMLZZ$* $| ASK	$: <REJFMLZZ>

# if no match try default policy
R$* $| $* $| $*						$: $1 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
R_SPAMSIGN_ $| $*FMLZZ$* $| TAG		$: <TAGFMLZZ>
R_SPAMSIGN_ $| $*FMLZZ$* $| BLOCK	$: <REJFMLZZ>
R_SPAMSIGN_ $| $* +FMLZZ$* $| ASK	$: <TAGFMLZZ>
R_SPAMSIGN_ $| $* !FMLZZ$* $| ASK	$: <REJFMLZZ>
', `dnl
R_SPAMSIGN_							$: <TAGFMLZZ>
')dnl
R<TAGFLMZZ>							$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgFishyFromflast', `confEL_TagErrMsgFishyFromflast', `"fishy from header (flast)"')> $| 3
R<REJFMLZZ>							$#error $@ 5.7.1 $: ifdef(`confEL_ErrFromFMLZZ', `confEL_ErrFromFMLZZ', `"554 FMLZZ Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. Your From: address is suspect."')
')dnl
')dnl

ifdef(`_EL_MOBSTER', `dnl
R$*					$: $(EL_FromMobsterISyphilitic $&{currHeader} $)
R_SPAMSIGN_			$: <OK> $(EL_Math + $@ 8 $@ $&{ELSpamsign} $) 
R<OK>$*				$: $(EL_SetVar {ELSpamsign} $@ $1 $)
')dnl

ifdef(`_EL_WORDLIST', `dnl
ifelse(_EL_POLICY, 1, `dnl
# first try it after stripping any suffixes from the words
R$*							$: $(EL_FromMobsterWordlistRoot $&{currHeader} $)
R$* $| $* $| $*				$: $(EL_Wordlist $1 $) $| $(EL_Wordlist $2 $) $| $(EL_Wordlist $3 $) $| $&{INHEADERS} $| $&{ELPolicyUser} $| $&{ELPolicySwitch} ifdef(`_EL_DEBUG', `$(EL_Log "EL Mobster1: " $1 ", "$2", "$3", " $&{INHEADERS} $)')
R$* $| W$* $| W$* $| YES $| $*MOBSTER$* $| TAG		$: <TAGMOBSTOXXROOT>
RW$* $| W$* $| $* $| YES $| $*MOBSTER$* $| TAG		$: <TAGMOBSTXXOROOT>
RW$* $| $* $| W$* $| YES $| $*MOBSTER$* $| TAG		$: <TAGMOBSTXOXROOT>
RW$* $| W$* $| W$* $| YES $| $*MOBSTER$* $| TAG		$: <TAGMOBSTXXXROOT>
R$* $| W$* $| W$* $| YES $| $*MOBSTER$* $| BLOCK	$: <REJMOBSTOXXROOT>
RW$* $| W$* $| $* $| YES $| $*MOBSTER$* $| BLOCK	$: <REJMOBSTXXOROOT>
RW$* $| $* $| W$* $| YES $| $*MOBSTER$* $| BLOCK	$: <REJMOBSTXOXROOT>
RW$* $| W$* $| W$* $| YES $| $*MOBSTER$* $| BLOCK	$: <REJMOBSTXXXROOT>
R$* $| W$* $| W$* $| YES $| $* +MOBSTER$* $| ASK	$: <TAGMOBSTOXXROOT>
RW$* $| W$* $| $* $| YES $| $* +MOBSTER$* $| ASK	$: <TAGMOBSTXXOROOT>
RW$* $| $* $| W$* $| YES $| $* +MOBSTER$* $| ASK	$: <TAGMOBSTXOXROOT>
RW$* $| W$* $| W$* $| YES $| $* +MOBSTER$* $| ASK	$: <TAGMOBSTXXXROOT>
R$* $| W$* $| W$* $| YES $| $* !MOBSTER$* $| ASK	$: <REJMOBSTOXXROOT>
RW$* $| W$* $| $* $| YES $| $* !MOBSTER$* $| ASK	$: <REJMOBSTXXOROOT>
RW$* $| $* $| W$* $| YES $| $* !MOBSTER$* $| ASK	$: <REJMOBSTXOXROOT>
RW$* $| W$* $| W$* $| YES $| $* !MOBSTER$* $| ASK	$: <REJMOBSTXXXROOT>

# if no match try default policy
R$* $| $* $| $* $| $* $| $* $| $*					$: $1 $| $2 $| $3 $| $4 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
R$* $| W$* $| W$* $| YES $| $*MOBSTER$* $| TAG		$: <TAGMOBSTOXXROOT>
RW$* $| W$* $| $* $| YES $| $*MOBSTER$* $| TAG		$: <TAGMOBSTXXOROOT>
RW$* $| $* $| W$* $| YES $| $*MOBSTER$* $| TAG		$: <TAGMOBSTXOXROOT>
RW$* $| W$* $| W$* $| YES $| $*MOBSTER$* $| TAG		$: <TAGMOBSTXXXROOT>
R$* $| W$* $| W$* $| YES $| $*MOBSTER$* $| BLOCK	$: <REJMOBSTOXXROOT>
RW$* $| W$* $| $* $| YES $| $*MOBSTER$* $| BLOCK	$: <REJMOBSTXXOROOT>
RW$* $| $* $| W$* $| YES $| $*MOBSTER$* $| BLOCK	$: <REJMOBSTXOXROOT>
RW$* $| W$* $| W$* $| YES $| $*MOBSTER$* $| BLOCK	$: <REJMOBSTXXXROOT>
R$* $| W$* $| W$* $| YES $| $* +MOBSTER$* $| ASK	$: <TAGMOBSTOXXROOT>
RW$* $| W$* $| $* $| YES $| $* +MOBSTER$* $| ASK	$: <TAGMOBSTXXOROOT>
RW$* $| $* $| W$* $| YES $| $* +MOBSTER$* $| ASK	$: <TAGMOBSTXOXROOT>
RW$* $| W$* $| W$* $| YES $| $* +MOBSTER$* $| ASK	$: <TAGMOBSTXXXROOT>
R$* $| W$* $| W$* $| YES $| $* !MOBSTER$* $| ASK	$: <REJMOBSTOXXROOT>
RW$* $| W$* $| $* $| YES $| $* !MOBSTER$* $| ASK	$: <REJMOBSTXXOROOT>
RW$* $| $* $| W$* $| YES $| $* !MOBSTER$* $| ASK	$: <REJMOBSTXOXROOT>
RW$* $| W$* $| W$* $| YES $| $* !MOBSTER$* $| ASK	$: <REJMOBSTXXXROOT>



# then try it with the words themselves
R$*							$: $(EL_FromMobsterWordlist $&{currHeader} $)
R$* $| $* $| $*				$: $(EL_Wordlist $1 $) $| $(EL_Wordlist $2 $) $| $(EL_Wordlist $3 $) $| $&{INHEADERS} $| $&{ELPolicyUser} $| $&{ELPolicySwitch} ifdef(`_EL_DEBUG', `$(EL_Log "EL Mobster2: " $1 ", "$2", "$3", " $&{INHEADERS} $)')
R$* $| W$* $| W$* $| YES $| $*MOBSTER$* $| TAG		$: <TAGMOBSTOXX>
RW$* $| W$* $| $* $| YES $| $*MOBSTER$* $| TAG		$: <TAGMOBSTXXO>
RW$* $| $* $| W$* $| YES $| $*MOBSTER$* $| TAG		$: <TAGMOBSTXOX>
RW$* $| W$* $| W$* $| YES $| $*MOBSTER$* $| TAG		$: <TAGMOBSTXXX>
R$* $| W$* $| W$* $| YES $| $*MOBSTER$* $| BLOCK	$: <REJMOBSTOXX>
RW$* $| W$* $| $* $| YES $| $*MOBSTER$* $| BLOCK	$: <REJMOBSTXXO>
RW$* $| $* $| W$* $| YES $| $*MOBSTER$* $| BLOCK	$: <REJMOBSTXOX>
RW$* $| W$* $| W$* $| YES $| $*MOBSTER$* $| BLOCK	$: <REJMOBSTXXX>
R$* $| W$* $| W$* $| YES $| $* +MOBSTER$* $| ASK	$: <TAGMOBSTOXX>
RW$* $| W$* $| $* $| YES $| $* +MOBSTER$* $| ASK	$: <TAGMOBSTXXO>
RW$* $| $* $| W$* $| YES $| $* +MOBSTER$* $| ASK	$: <TAGMOBSTXOX>
RW$* $| W$* $| W$* $| YES $| $* +MOBSTER$* $| ASK	$: <TAGMOBSTXXX>
R$* $| W$* $| W$* $| YES $| $* !MOBSTER$* $| ASK	$: <REJMOBSTOXX>
RW$* $| W$* $| $* $| YES $| $* !MOBSTER$* $| ASK	$: <REJMOBSTXXO>
RW$* $| $* $| W$* $| YES $| $* !MOBSTER$* $| ASK	$: <REJMOBSTXOX>
RW$* $| W$* $| W$* $| YES $| $* !MOBSTER$* $| ASK	$: <REJMOBSTXXX>

# if no match try default policy
R$* $| $* $| $* $| $* $| $* $| $*					$: $1 $| $2 $| $3 $| $4 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
R$* $| W$* $| W$* $| YES $| $*MOBSTER$* $| TAG		$: <TAGMOBSTOXX>
RW$* $| W$* $| $* $| YES $| $*MOBSTER$* $| TAG		$: <TAGMOBSTXXO>
RW$* $| $* $| W$* $| YES $| $*MOBSTER$* $| TAG		$: <TAGMOBSTXOX>
RW$* $| W$* $| W$* $| YES $| $*MOBSTER$* $| TAG		$: <TAGMOBSTXXX>
R$* $| W$* $| W$* $| YES $| $*MOBSTER$* $| BLOCK	$: <REJMOBSTOXX>
RW$* $| W$* $| $* $| YES $| $*MOBSTER$* $| BLOCK	$: <REJMOBSTXXO>
RW$* $| $* $| W$* $| YES $| $*MOBSTER$* $| BLOCK	$: <REJMOBSTXOX>
RW$* $| W$* $| W$* $| YES $| $*MOBSTER$* $| BLOCK	$: <REJMOBSTXXX>
R$* $| W$* $| W$* $| YES $| $* +MOBSTER$* $| ASK	$: <TAGMOBSTOXX>
RW$* $| W$* $| $* $| YES $| $* +MOBSTER$* $| ASK	$: <TAGMOBSTXXO>
RW$* $| $* $| W$* $| YES $| $* +MOBSTER$* $| ASK	$: <TAGMOBSTXOX>
RW$* $| W$* $| W$* $| YES $| $* +MOBSTER$* $| ASK	$: <TAGMOBSTXXX>
R$* $| W$* $| W$* $| YES $| $* !MOBSTER$* $| ASK	$: <REJMOBSTOXX>
RW$* $| W$* $| $* $| YES $| $* !MOBSTER$* $| ASK	$: <REJMOBSTXXO>
RW$* $| $* $| W$* $| YES $| $* !MOBSTER$* $| ASK	$: <REJMOBSTXOX>
RW$* $| W$* $| W$* $| YES $| $* !MOBSTER$* $| ASK	$: <REJMOBSTXXX>
', `dnl
# first try it after stripping any suffixes from the words
R$*									$: $(EL_FromMobsterWordlistRoot $&{currHeader} $)
R$* $| $* $| $*						$: $(EL_Wordlist $1 $) $| $(EL_Wordlist $2 $) $| $(EL_Wordlist $3 $) $| $&{INHEADERS} ifdef(`_EL_DEBUG', `$(EL_Log "EL Mobster1: " $1 ", "$2", "$3", " $&{INHEADERS} $)')
R$* $| W$* $| W$*	$| YES		$: <TAGMOBSTOXXROOT>
RW$* $| W$* $| $* $| YES		$: <TAGMOBSTXXOROOT>
RW$* $| $* $| W$* $| YES		$: <TAGMOBSTXOXROOT>
RW$* $| W$* $| W$* $| YES		$: <TAGMOBSTXXXROOT>

# then try it with the words themselves
R$*									$: $(EL_FromMobsterWordlist $&{currHeader} $)
R$* $| $* $| $*						$: $(EL_Wordlist $1 $) $| $(EL_Wordlist $2 $) $| $(EL_Wordlist $3 $) $| $&{INHEADERS} ifdef(`_EL_DEBUG', `$(EL_Log "EL Mobster2: " $1 ", "$2", "$3", " $&{INHEADERS} $)')
R$* $| W$* $| W$* $| YES		$: <TAGMOBSTOXX>
RW$* $| W$* $| $* $| YES		$: <TAGMOBSTXXO>
RW$* $| $* $| W$* $| YES		$: <TAGMOBSTXOX>
RW$* $| W$* $| W$* $| YES		$: <TAGMOBSTXXX>
')dnl

R<TAGMOBSTOXXROOT>		$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgMobsterOXXRoot', `confEL_TagErrMsgMobsterOXXRoot', `"fishy from header (mobster wordlist) oxx recd root"')> $| 4
R<TAGMOBSTXXOROOT>		$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgMobsterXXORoot', `confEL_TagErrMsgMobsterXXORoot', `"fishy from header (mobster wordlist) xxo recd root"')> $| 4
R<TAGMOBSTXOXROOT>		$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgMobsterXOXRoot', `confEL_TagErrMsgMobsterXOXRoot', `"fishy from header (mobster wordlist) xox recd root"')> $| 4
R<TAGMOBSTXXXROOT>		$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgMobsterXXXRoot', `confEL_TagErrMsgMobsterXXXRoot', `"fishy from header (mobster wordlist) xxx recd root"')> $| 4
R<REJMOBSTOXXROOT>		$#error $@ 5.7.1 $: ifdef(`confEL_ErrFromMobsterWordlistOXXroot', `confEL_ErrFromMobsterWordlistOXXroot ', `"554 WRDOXXR Contact "$&{ELContactEmail}" if this is in error, but "$&{currHeader}" reminds us of some spam we got once. (oxx root)"')
R<REJMOBSTXXOROOT>		$#error $@ 5.7.1 $: ifdef(`confEL_ErrFromMobsterWordlistXXOroot', `confEL_ErrFromMobsterWordlistXXOroot', `"554 WRDXXOR Contact "$&{ELContactEmail}" if this is in error, but "$&{currHeader}" reminds us of some spam we got once. (xxo root)"')
R<REJMOBSTXOXROOT>		$#error $@ 5.7.1 $: ifdef(`confEL_ErrFromMobsterWordlistXOXroot', `confEL_ErrFromMobsterWordlistXOXroot', `"554 WRDXOXR Contact "$&{ELContactEmail}" if this is in error, but "$&{currHeader}" reminds us of some spam we got once. (xox root)"')
R<REJMOBSTXXXROOT>		$#error $@ 5.7.1 $: ifdef(`confEL_ErrFromMobsterWordlistXXXroot', `confEL_ErrFromMobsterWordlistXXXroot', `"554 WRDXXXR Contact "$&{ELContactEmail}" if this is in error, but "$&{currHeader}" reminds us of some spam we got once. (xxx root)"')

R<TAGMOBSTOXX>			$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgMobsterOXX', `confEL_TagErrMsgMobsterOXX', `"fishy from header (mobster wordlist) oxx recd"')> $| 4
R<TAGMOBSTXXO>			$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgMobsterXXO', `confEL_TagErrMsgMobsterXXO', `"fishy from header (mobster wordlist) xxo recd"')> $| 4
R<TAGMOBSTXOX>			$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgMobsterXOX', `confEL_TagErrMsgMobsterXOX', `"fishy from header (mobster wordlist) xox recd"')> $| 4
R<TAGMOBSTXXX>			$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgMobsterXXX', `confEL_TagErrMsgMobsterXXX', `"fishy from header (mobster wordlist) xxx recd"')> $| 4
R<REJMOBSTOXX>			$#error $@ 5.7.1 $: ifdef(`confEL_ErrFromMobsterWordlistOXX', `confEL_ErrFromMobsterWordlistOXX ', `"554 WORDOXX Contact "$&{ELContactEmail}" if this is in error, but "$&{currHeader}" reminds us of some spam we got once. (oxx)"')
R<REJMOBSTXXO>			$#error $@ 5.7.1 $: ifdef(`confEL_ErrFromMobsterWordlistXXO', `confEL_ErrFromMobsterWordlistXXO', `"554 WORDXXO Contact "$&{ELContactEmail}" if this is in error, but "$&{currHeader}" reminds us of some spam we got once. (xxo)"')
R<REJMOBSTXOX>			$#error $@ 5.7.1 $: ifdef(`confEL_ErrFromMobsterWordlistXOX', `confEL_ErrFromMobsterWordlistXOX', `"554 WORDXOX Contact "$&{ELContactEmail}" if this is in error, but "$&{currHeader}" reminds us of some spam we got once. (xox)"')
R<REJMOBSTXXX>			$#error $@ 5.7.1 $: ifdef(`confEL_ErrFromMobsterWordlistXXX', `confEL_ErrFromMobsterWordlistXXX', `"554 WORDXXX Contact "$&{ELContactEmail}" if this is in error, but "$&{currHeader}" reminds us of some spam we got once. (xxx)"')
')dnl

ifdef(`_EL_RUN_ZALKO', `dnl
R$*					$: $(EL_FromRunZalko $&{currHeader} $) $| $&{client_resolve}
RMATCH $| FAIL		$#error $@ 5.7.1 $: ifdef(`confEL_ErrFromRunZalkoFail', `confEL_ErrFromRunZalkoFail', `"554 RNZALKF Contact "$&{ELContactEmail}" if this is in error, but your address looks fishy and your mail server lacks reverse DNS. (AS/MI)"')
RMATCH $| TEMP		$#error $@ 5.7.1 $: ifdef(`confEL_ErrFromRunZalkoTemp', `confEL_ErrFromRunZalkoTemp', `"554 RNZALKT Contact "$&{ELContactEmail}" if this is in error, but your address looks fishy and your mail server seems to lack reverse DNS. (AS/MI)"')
RMATCH $| $*		$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgAmberSky', `confEL_TagErrMsgAmberSky', `"message looks like Masterly Intl./Amber Sky"')> $| 4
')dnl

ifdef(`_EL_2LDHELOFORGERY', `dnl
# From: Income 4You <income4u@pc4me.us>
# HELO: pc4me893.com
#
# need to get "pc4me" and check to see if HELO matches pc4me\d+.com
#
R$*								$: $(EL_GetSender2LD $&{currHeader} $)
# pc4me<2LD>           pc4me 
R$*<2LD>						$: $1 $| $(EL_GetHELO2LD $&{s} $) ifdef(`_EL_DEBUG', `$(EL_Log "EL s/h: " $1 $)')
# pc4me 893.com
R$* $| $*<2LD>					$: $(dequote ""$1""$2"" $) ifdef(`_EL_DEBUG', `$(EL_Log "EL s/h: " $1 "" $2 "; helo: " $&s $)')
ifelse(_EL_POLICY, 1, `dnl
R$+								$: $1 $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
R$&s $| $*HELORAT$* $| TAG 		$: <TAGHELORAT>
R$&s $| $*HELORAT$* $| BLOCK	$: <REJHELORAT>
R$&s $| $* +HELORAT$* $| ASK	$: <TAGHELORAT>
R$&s $| $* !HELORAT$* $| ASK	$: <REJHELORAT>

# if no match try default policy
R$* $| $* $| $* 				$: $1 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
R$&s $| $*HELORAT$* $| TAG 		$: <TAGHELORAT>
R$&s $| $*HELORAT$* $| BLOCK	$: <REJHELORAT>
R$&s $| $* +HELORAT$* $| ASK	$: <TAGHELORAT>
R$&s $| $* !HELORAT$* $| ASK	$: <REJHELORAT>
', `dnl
R$&s							$: <TAGHELORAT>
')dnl

R<TAGHELORAT>				$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgSenderHELO', `confEL_TagErrMsgSenderHELO', `"message sent by sender/helo ratware"')> $| 4
R<REJHELORAT>				$#error $@ 5.7.1 $: ifdef(`confEL_ErrSenderHELORatware', `confEL_ErrSenderHELORatware', `"554 HELORAT Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as a probable 419/advance fee fraud scam."')
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

R<TAGURIBL>						$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgFromURIBL', `confEL_TagErrMsgFromURIBL', `"message from header contains domain in uribl.com blacklist"')> $| 4
R<REJURIBL>						$#error $@ 5.7.1 $: ifdef(`confEL_ErrFromURIBL', `confEL_ErrFromURIBL', `"554 URIBLFR Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. We do not accept mail sent from your domain as it is listed by uribl.com."')
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

# if no match try default policy
R$* $| $* $| $* 				$: $1 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
R$+ $| $*SURBL$* $| TAG			$: <TAGSURBL>
R$+ $| $*SURBL$* $| BLOCK		$: <REJSURBL>
R$+ $| $* +SURBL$* $| ASK		$: <TAGSURBL>
R$+ $| $* !SURBL$* $| ASK		$: <REJSURBL>


R<TAGSURBL>						$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgFromSURBL', `confEL_TagErrMsgFromSURBL', `"from header contains domain in surbl.org blacklist"')> $| 4
R<REJSURBL>						$#error $@ 5.7.1 $: ifdef(`confEL_ErrFromSURBL', `confEL_ErrFromSURBL', `"554 SURBLFR Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. We do not accept mail sent from your domain as it is listed by surbl.org."')
')dnl
')dnl

