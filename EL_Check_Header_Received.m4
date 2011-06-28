divert(-1)dnl
#
# Copyright (c) 2004-2011 hesketh.com/inc. All rights reserved.
#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_Check_Header_Received.m4,v 1.46 2011/05/17 18:44:48 schampeo Exp $')
divert(-1)dnl

LOCAL_CONFIG
#------------------------------------------------------------------------
# enemieslist.com Received: header check patterns
#------------------------------------------------------------------------
ifdef(`_EL_BLOCK_TINIT_WEBMAIL', `
KEL_TinITWebmail1 regex -a@SPAM from.pswm[0-9]+ .+ by vsmtp[0-9]+\.tin\.it
KEL_TinITWebmail2 regex -a@SPAM from.pswm[0-9]+\.cp\.tin\.it
KEL_TinITWebmailSeq sequence EL_TinITWebmail1 EL_TinITWebmail2
')dnl

KEL_WindowsXPSpammers regex -a@SPAM from.[0-z]{3}@localhost.by.[0-z]{3,4}\.int

KEL_BadReceivedHELO regex -a@SPAM ^from \(HELO [0-z]+\)

KEL_GetHelimoreHELO regex -a<HELIMORE> -s1 from.+\(HELO.([0-9a-z]+\.com)\)

KEL_BadReceived1 regex -a@SPAM ^from \[[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\] by [\-\.0-z]+ with ESMTP id [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]; [A-Z][a-z][a-z], [0-9][0-9].*[A-Z][a-z][a-z] [0-9][0-9][0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][[0-9] [\+\-][0-1][0-9][0-9]0$

KEL_BadReceived2 regex -a@SPAM ^from.*\[[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[^0-9]+\]

KEL_Ralsky1 regex -a@SPAM (\[|\(|\s)211\.158\.[3456789]
KEL_Ralsky2 regex -a@SPAM (\[|\(|\s)218\.70\.1[345]
KEL_Ralsky3 regex -a@SPAM (\[|\(|\s)219\.153\.1[45]
KEL_Ralsky4 regex -a@SPAM (\[|\(|\s)218\.10\.57
KEL_Ralsky5 regex -a@SPAM (\[|\(|\s)218\.70\.1[01]
KEL_Ralsky6 regex -a@SPAM (\[|\(|\s)218\.70\.[89]
KEL_Ralsky7 regex -a@SPAM (\[|\(|\s)218\.10\.190

KEL_Ralsky sequence EL_Ralsky1 EL_Ralsky2 EL_Ralsky3 EL_Ralsky4 EL_Ralsky5 EL_Ralsky6 EL_Ralsky7

# per Suresh Ramasubramanian
KEL_ForgedOutblazeReceived regex -a@SPAM mr\.outblaze\.com

# to stop "Noun V. Noun" spammer - always uses forged headers
# got OK from Chris Pugmire @ Netwinsite - no valid email has these in headers
KEL_ForgedNetwinsite regex -a@SPAM from.*mail[0-9]*\.(surgeweb|netwinsite)

KEL_ForgedInAnotherCom regex -a@SPAM from.*\(in[0-9]?\.another\.com

KEL_ForgedMX9Earthlink regex -a@SPAM from\ earthlink\..*\(mx[0-9]\.earthlink\.net\ \[207\.217\.125

KEL_ReceivedYahooCom regex -aYES yahoo\.com
KEL_ForgedYahooCom regex -n -a@SPAM yahoo\.com.*\[(61\.135\.128|64\.157\.4\.|66\.163\.|66\.218\.|202\.1\.23|202\.43\.[12]|203\.199\.70|211\.119\.129|211\.233\.53\.|216\.136\.|216\.145\.54\.|217\.12\.12\.)

KEL_TwoOhOhDotSixSeven regex -a@SPAM (\[|\(|\s)200\.67\.

KEL_ReceivedDarkMailer regex -f -a@SPAM (HELO|from)\ DM\ \(

ifdef(`_EL_DEPRECATED', `dnl
KEL_OurIPinReceived regex -a<FORGED> from.*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+.*by\ ifdef(`confEL_LOCAL_IP', `confEL_LOCAL_IP') 

# disabled because Lsoft LSMTP puts remote IP, not HELO, in this header:
#
# Received: from 216.27.21.196 by WALNUT.EASE.LSOFT.COM (SMTPL release 1.0i) with
#          TCP; Wed, 10 Nov 2004 10:47:38 -0400
#KEL_OurIPinReceivedHELO regex -a<FORGED> from\ ifdef(`confEL_LOCAL_IP', `confEL_LOCAL_IP')

KEL_OurHostnameinReceived1 regex -a<FORGED> from\ [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+.*\.by\ ifdef(`confEL_LOCAL_HOSTNAME', `confEL_LOCAL_HOSTNAME')

KEL_OurHostnameinReceived2 regex -a<FORGED> from\ ifdef(`confEL_LOCAL_HOSTNAME', `confEL_LOCAL_HOSTNAME')\ \(\[[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\]\)

# Received: from 12.156.70.194 (HELO mxmail.valkyrie.net)
#        by webdesign-l.com with esmtp (RDPXMZBBC MKPCOS) id g7v6Ur-eNjupQ-Gu
#        for owner-list@webdesign-l.com; Thu, 23 Aug 2007 22:55:10 +0400
 
KEL_OurHostnameinReceived3 regex -a<FORGED> by\ ifdef(`confEL_LOCAL_DOMAINS', `confEL_LOCAL_DOMAINS')\ with\ esmtp\ \([A-Z]{9,12}\ [A-Z]{5,6}\)\ id

KEL_OurHostnameinReceived sequence EL_OurHostnameinReceived1 EL_OurHostnameinReceived2 EL_OurHostnameinReceived3

KEL_OurDomainsinReceived1 regex -a<FORGED> from\ [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+.*by\ ifdef(`confEL_LOCAL_DOMAINS', `confEL_LOCAL_DOMAINS') 
KEL_OurDomainsinReceived2 regex -a<FORGED> from\ ifdef(`confEL_LOCAL_DOMAINS', `confEL_LOCAL_DOMAINS')\ \(\[[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\]\)
KEL_OurDomainsinReceived3 regex -a<FORGED> from\ unknown\ \(HELO\ ifdef(`confEL_LOCAL_DOMAINS', `confEL_LOCAL_DOMAINS')\ \(\[[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\]\)

KEL_OurDomainsinReceived sequence EL_OurDomainsinReceived1 EL_OurDomainsinReceived2 EL_OurDomainsinReceived3

KEL_ForgedUsInReceived sequence EL_OurIPinReceived EL_OurHostnameinReceived EL_OurDomainsinReceived
')dnl

ifdef(`_EL_FORGED_CLASS_W', `dnl
KEL_OurIPinReceived regex -a<FORGED> -s1 from.*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+.*by.\[?([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\]\)

# disabled because Lsoft LSMTP puts remote IP, not HELO, in this header:
#
# Received: from 216.27.21.196 by WALNUT.EASE.LSOFT.COM (SMTPL release 1.0i) with
#          TCP; Wed, 10 Nov 2004 10:47:38 -0400
#KEL_OurIPinReceivedHELO regex -a<FORGED> -s1 from.\[?([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\]\)

KEL_OurHostnameinReceived1 regex -a<FORGED> -s1 from\ [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+.*\.by.([0-9a-z\-\_\.]+)

KEL_OurHostnameinReceived2 regex -a<FORGED> -s1 from\ ([0-9a-z\-\_\.]+)\ \(\[[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\]\)

KEL_OurHostnameinReceived3 regex -a<FORGED> -s1 from\ unknown\ \(HELO ([0-9a-z\-\_\.]+)\)\ \(\[[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\]\)

KEL_OurHostnameinReceived sequence EL_OurHostnameinReceived1 EL_OurHostnameinReceived2 EL_OurHostnameinReceived3

KEL_OurDomainsinReceived1 regex -a<FORGED> -s1 from\ [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+.*by\ ([0-9a-z\-\_\.]+)
KEL_OurDomainsinReceived2 regex -a<FORGED> -s1 from\ ([0-9a-z\-\_\.]+)\ \(.*\[[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\]\)
KEL_OurDomainsinReceived3 regex -a<FORGED> -s1 from\ unknown\ \(HELO ([0-9a-z\-\_\.]+)\ \(\[[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\]\)
# 
# bogus "must to read" pump and dump junk (Stration?)
# Received: from 66.150.163.173 (HELO m2.spamarrest.com)
#     by hesketh.com with esmtp (+3-Z89+3>7/> ,6Q>))
#
# Received: from 207.255.193.6 (HELO accel-main.accellenet.com)
#     by lists.state.tx.us with esmtp (4;V*0(?1)2U +7JG*)
#
KEL_OurDomainsinReceived4 regex -f -a<FORGED> -s1 from.*by\ ([0-9a-z\-\.]+)\ with\ esmtp\ \(

KEL_OurDomainsinReceived sequence EL_OurDomainsinReceived1 EL_OurDomainsinReceived2 EL_OurDomainsinReceived3 EL_OurDomainsinReceived4

KEL_ForgedUsInReceived sequence EL_OurIPinReceived EL_OurHostnameinReceived EL_OurDomainsinReceived
')dnl

ifdef(`_EL_CHECKINJECTION', `dnl
KEL_GetInjectingIP1 regex -a<IP> -s1 from..+.\(.*\[([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\].*\)

# Received: from unknown (HELO User) (18@usedemail.com@65.24.243.208 with login)
#  by smtp008.bizmail.sc5.yahoo.com with SMTP; 5 Aug 2005 22:16:12 -0000

KEL_GetInjectingIP2 regex -a<IP> -s1 from.+@([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+).with.login

# Received: from host1-240.pool81118.interbusiness.it (HELO simonstl.com) (81.118.240.1)
#  by MTA069A.interbusiness.it with ESMTP; 12 Aug 2005 10:07:49 +0200

KEL_GetInjectingIP3 regex -a<IP> -s1 from.+\(HELO.+\).\(([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\)

# Received: from [10.10.6.204] (Forwarded-For: [62.59.40.138])
# by ms-mss-01.socal.rr.com (mshttpd); Mon, 02 Jan 2006 04:00:46 -0800

KEL_GetInjectingIP4 regex -a<IP> -s1 \(Forwarded\-For:\ \[([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\]\)

# Received: from ml82.128.18.165.multilinks.com ([82.128.18.165]:2717 helo=User)
#  by 10.mx.freenet.de with esmtpa (ID infocbn.com5@freenet.de) (port 25)
#   (Exim 4.68 #1) id 1JFBx0-0003zW-4b; Wed, 16 Jan 2008 18:21:21 +0100
KEL_GetInjectingIP5 regex -a<IP> -s1 from\ .*\(\[([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\]:[0-9]+\ helo=.+\)

# Received: from 72.3.137.83 (proxying for 41.219.242.33, 192.168.100.82)
#   (SquirrelMail authenticated user kkm1)
#   by mail.avacom.net with HTTP;
#   Thu, 17 Jan 2008 08:16:48 -0000 (Etc/GMT)
KEL_GetInjectingIP6 regex -a<IP> -s1 from\ [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\ \(proxying\ for\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)
			
ifdef(`_EL_GMAIL10SLASH8', `dnl
# check for broken gmail 10/8 injection point
# Received: by 10.36.115.15 with HTTP; Tue, 23 Aug 2005 08:09:09 -0700 (PDT)
KEL_GetInjectingIPGmail108 regex -a<IP> -s1 by.(10\.[0-9]+\.[0-9]+\.[0-9]+).with.HTTP
')dnl

KEL_GetInjectingIP sequence EL_GetInjectingIP1 EL_GetInjectingIP2 EL_GetInjectingIP3 EL_GetInjectingIP4 EL_GetInjectingIP5 EL_GetInjectingIP6
')dnl

# special rule for bigpond.com/iol.pt 419 spammers
KEL_MSHTTPD419 regex -aGOAWAY from.*\[(192\.168\.115\.|172\.16\.4\.).*(bigpond\.com|mstore[0-9]\.iol\.pt).*\(mshttpd\)

# rule to catch forged postfix headers
KEL_ForgedPostfixESMTP regex -a@SPAM -f with.esmtp.id.[0-9A-F]{10}.for

# rule to catch phish scams via perfora.net
KEL_ReceivedIPForgedByCGI regex -a@SPAM -f \(IP.may.be.forged.by.CGI.script\)

# rule to catch bogus "Qostfix" 
KEL_NoQostfix regex -a@SPAM -f (Hostfix|Qostfix,.from.userid.[0-9]+|Wostfix\ [0-9]+\ [0-9]+)

ifdef(`_EL_TAGRECDFORGERY', `dnl
# look for obviously forged (a-or-cname [dot.ted.qu.ad]) where the a-or-cname
# is not the rDNS for the IP in question
KEL_LookupPTR dns -RPTR -d5s -r2
KEL_LookupA dns -RA -d5s -r2
KEL_LookupCNAME dns -RCNAME -d5s -r2
KEL_ReceivedIPForged -s1,2 \((.+)\ \[([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\)
')dnl

KEL_RecdFakeSendmail1 regex -a<FORGED> \(8\.13\.4\/8\.13\.4\)\ with\ SMTP\ id\ [0-9a-z]{22,23}
KEL_RecdFakeSendmail2 regex -a<FORGED> \(8\.13\.2\/8\.13\.2\)\ with\ SMTP\ id\ [0-9a-z]{14,15}
KEL_RecdFakeSendmail sequence EL_RecdFakeSendmail1 EL_RecdFakeSendmail2

KEL_RecdWithMosap regex -a@SPAM -f 'with Mosap;'

KEL_RecdByNil regex -a@SPAM -f by\ \;

KEL_ReceivedChecks1 sequence EL_NoQostfix EL_RecdWithMosap EL_RecdByNil EL_ReceivedDarkMailer

KEL_ReceivedChecks sequence EL_BadReceivedHELO EL_BadReceived1 EL_BadReceived2 ifdef(`_EL_DAZZLING', `EL_DazzlingSpammer') EL_Ralsky EL_TwoOhOhDotSixSeven EL_ForgedNetwinsite EL_ForgedInAnotherCom EL_ForgedMX9Earthlink EL_ForgedPostfixESMTP EL_WindowsXPSpammers EL_ReceivedChecks1

KEL_RecdFromNobodyByHostWithLocal regex -a<MATCH> -s1 -f from\ nobody\ by\ (.+)\ with local\ \(Exim

ifdef(`_EL_FOAD_VIPWATCHES', `dnl
# relatively new ratware signature - uses dictionary words in IDENT
# Received: from hilarity.bioinformatics.org
# (IDENT:whippany.coneflower@thine.geoserve.net [127.0.0.1])
#        by one.bioinformatics.org (8.11.0/8.8.0) with ESMTP id g62JGOH20278
#        for <bcpabipn@inergy.net>; Tue, 17 Jan 2006 13:01:17 +0200
KEL_VIPWatches regex -s1,2 IDENT:([a-z]+)\.([a-z]+)@
')dnl

ifdef(`_EL_FOAD_WENBZR', `dnl
# Ralsky sock puppet? Hideously forged Received: header with typos, comes
# after non-Received headers like Subject:, and contains random times.
# e.g. %RND_TIME:%RND_TIME
KEL_WenbzrForgedReceived regex -f -a@SPAM from.?[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\ by\ by[0-9][a-z]+\.[a-z]+[0-9]\.(hotmail|msn|yahoo)\.com\ with\ HTTP;[A-Z]
')dnl

ifdef(`_EL_DEPRECATED', `dnl
ifdef(`_EL_OPENPHARMACY', `dnl
KEL_OpenPharmacyForgedRecd regex -a@SPAM from.?.+by\ ifdef(`confEL_LOCAL_IP', `confEL_LOCAL_IP');
')dnl
')dnl

ifdef(`_EL_FOAD_MEDKITINFO', `dnl
# Received: from [93.215.66.25] (port=4382 helo=[Dominicans])
#    by veloz-221-24.hotlink.com.br with esmtp 
#    id 12354012669vibrated27924
# --
# Received: from [193.214.195.113] (port=4089 helo=[classifier])
#    by h-81-15-194-38.dolsat.pl with esmtp 
#    id 5945543464bathroom2841
# -- 
# Received: from [136.40.54.26] (port=3555 helo=[Aidan])
#    by uzinsider.galati.rdsnet.ro with esmtp
#    id 949267934Troy86549
# --
# Received: from 100.45.119.67  (EHLO farming)
#    by sojcak.kkcable.cz with SMTP; Thu, 15 Sep 2005 17:36:35 +0200
#    id 6445321453seaside73091

KEL_MedkitInfoReceived1 regex -s1,2,3 from.\[?([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\]?.\(port=[0-9]+.helo=\[([A-Za-z][a-z]+)\].*by.*with.esmtp.*id.[0-9]+([a-z]+)[0-9]+
KEL_MedkitInfoReceived2 regex -s1,2,3 from.\[?([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\]?.\([EH][EH]LO ([A-Za-z][a-z]+)\].*by.*with.SMTP.*id.[0-9]+([a-z]+)[0-9]+

KEL_MedkitInfoReceived sequence EL_MedkitInfoReceived1 EL_MedkitInfoReceived2

KEL_MedkitInfoRoot1 regex -s1,2,4 from.\[?([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\]?.\([EH][EH]LO ([A-Za-z][a-z]+)(d|s|ing|ize|ed)?\].*by.*with.esmtp.*id.[0-9]+([a-z]+)(d|s|ing|ize|ed)?[0-9]+
KEL_MedkitInfoRoot2 regex -s1,2,4 from.\[?([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\]?.\(port=[0-9]+.helo=\[([A-Za-z][a-z]+)(d|s|ing|ize|ed)?\].*by.*with.SMTP.*id.[0-9]+([a-z]+)(d|s|ing|ize|ed)?[0-9]+

KEL_MedkitInfoRoot sequence EL_MedkitInfoRoot1 EL_MedkitInfoRoot2
')dnl

# Mobster forged Received: header pattern
KEL_RecdMobsterPostfix regex -a<HOST> -s1 by\ (.+)\ \(Postfix\)

# A -> B; A -> C Hello I am bored today email header forgery check.
KEL_RecdHelloIAmBored1 regex -a<BORED> -s1 from\ \[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\].by.[0-9a-z\-\.]+;
KEL_RecdHelloIAmBored2 regex -a<BORED> -s1 from\ \[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\].by.[0-9a-z\-\.]+;.[MTWFS]..,
KEL_RecdHelloIAmBored3 regex -a<BORED> -s1 from\ ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}).by.[0-9a-z\-\.]+;
KEL_RecdHelloIAmBored4 regex -a<BORED> -s1 from\ \(([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\).by.[0-9a-z\-\.]+.with
KEL_RecdHelloIAmBored sequence EL_RecdHelloIAmBored1 EL_RecdHelloIAmBored2 EL_RecdHelloIAmBored3 EL_RecdHelloIAmBored4

# e.g.:
# Received: from unknown (HELO User) (34@evilroots.com@69.74.45.97 with login)
#  by smtp102.biz.mail.re2.yahoo.com with SMTP; 11 Aug 2005 21:50:31 -0000

KEL_YahooPhishUser1 regex -f -aMATCH from.unknown.\(HELO.User\).\([a-z0-9]+@[a-z0-9]+\.(com|info|us)@[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+.with.login
KEL_YahooPhishUser2 regex -f -aMATCH from.unknown.\(HELO.User\).\([a-z0-9]+@[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+

# Received: from User
# Received: from [69.94.114.32] (helo=User)
# Received: from [218.239.45.223] (port=1638 helo=User)
# Received: from vds-371473.amen-pro.com ([62.193.212.84] helo=User)
# Received: from softdnserror (HELO User) (70.88.165.177)
# Received: from [63.225.218.99] (account kreynolds HELO User)
# Received: from USER ([62.194.37.153]) by tomts18-srv.bellnexxia.net
KEL_VariousPhishUserHELOs1 regex -f -aMATCH from.User
KEL_VariousPhishUserHELOs2 regex -f -aMATCH from.*\(helo=User\)
KEL_VariousPhishUserHELOs3 regex -f -aMATCH from.*\(port=[0-9]+\ helo=User\)
KEL_VariousPhishUserHELOs4 regex -f -aMATCH from.*\(\[[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\]\ helo=User\)
KEL_VariousPhishUserHELOs5 regex -f -aMATCH from.*\(.*HELO\ User\)
KEL_VariousPhishUserHELOs6 regex -f -aMATCH from.USER.\(\[[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\]\)
KEL_VariousPhishUserHELOs7 regex -f -aMATCH from.*\(\[[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+\]\ helo=User\)
KEL_VariousPhishUserHELOs sequence EL_VariousPhishUserHELOs1 EL_VariousPhishUserHELOs2 EL_VariousPhishUserHELOs3 EL_VariousPhishUserHELOs4 EL_VariousPhishUserHELOs5 EL_VariousPhishUserHELOs6 EL_VariousPhishUserHELOs7

KEL_PhishUser sequence EL_YahooPhishUser1 EL_YahooPhishUser2 EL_VariousPhishUserHELOs

LOCAL_RULESETS
#------------------------------------------------------------------------
# enemieslist.com Received header checks
#------------------------------------------------------------------------
HReceived: $>+EL_Check_Header_Received
SEL_Check_Header_Received
ifdef(`_EL_TRACE', `dnl
R$*					$: $1 $(EL_Log "Received w/ " $1 "; score: " $&{ELSuspiciousCount} "." $)
')dnl

ifdef(`_EL_SKIPLOCAL', `dnl
R$*					$: $1 $| $&{client_addr}
R$* $| 127.0.0.1	$@
')dnl

# skip whitelisted hosts
R$*					$: $&{ELWhitelisted}
R$+:$+				$@

R$*					$: $(EL_ReceivedChecks $&{currHeader} $)
R@SPAM				$#error $@ 5.7.1 $: ifdef(`confEL_ErrRecdBad', `confEL_ErrRecdBad', `"554 BADRECD Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it contains a suspicious header (Received:)"')

R$*							$: $&{INHEADERS} $| $(EL_RecdFakeSendmail $&{currHeader} $)
RYES $| <FORGED>			$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgForgedSendmailRecd', `confEL_TagErrMsgForgedSendmailRecd', `"forged Received: header"')> $| 3

ifdef(`_EL_REJECT_FORGED_RECD', `dnl
R$*							$: $&{INHEADERS} $| $(EL_ForgedUsInReceived $&{currHeader} $)
#RYES $| <FORGED>			$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgForgedUsInRecd', `confEL_TagErrMsgForgedUsInRecd', `"our IP/hostname in Received: header"')> $| 1
RYES $| $*<FORGED>			$: $1 $| $(EL_Log "EL forged recd: " $1 $)
# skip "localhost"
Rlocalhost $| $*				$: <SKIP>
Rlocalhost.localdomain $| $*	$: <SKIP>
R$=w $| $*						$#error $@ 5.7.1 $: ifdef(`confEL_ErrRecdForged', `confEL_ErrRecdForged', `"554 RECDFRG Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it contains a forged header (Received:)"')
R$*.$=w							$#error $@ 5.7.1 $: ifdef(`confEL_ErrRecdForged', `confEL_ErrRecdForged', `"554 RECDFRG Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it contains a forged header (Received:)"')
')dnl

ifdef(`_EL_TAG_FORGED_RECD', `dnl
R$*						$: $&{INHEADERS} $| $(EL_ForgedUsInReceived $&{currHeader} $)
RYES $| $*<FORGED>		$: $1 $(EL_Log "EL forged recd: " $1 $)
# skip "localhost"
Rlocalhost				$: <SKIP>
Rlocalhost.localdomain	$: <SKIP>
R$=w					$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgForgedUsInRecd', `confEL_TagErrMsgForgedUsInRecd', `"our IP/hostname in Received: header"')> $| 4
R$*.$=w					$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgForgedUsInRecd', `confEL_TagErrMsgForgedUsInRecd', `"our IP/hostname in Received: header"')> $| 4
')dnl

ifdef(`_EL_BLOCK_TINIT_WEBMAIL', `dnl
R$*						$: $&{INHEADERS} $| $(EL_TinITWebmailSeq $&{currHeader} $)
RYES $| @SPAM			$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgTinITWebmail', `confEL_TagErrMsgTinITWebmail', `"tin.it webmail is compromised"')> $| 4
')dnl

ifdef(`_EL_UNSAFE', `dnl
# catch the Hello I am bored today forgeries
# ...and apparently mail from Rob McEwen and anyone using IceWarp
R$*						$: $&{INHEADERS} $| $(EL_RecdHelloIAmBored $&{currHeader} $)
RYES $| $+<BORED>		$: $1 
R$&{client_addr} 		$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgForgedBoredRecd', `confEL_TagErrMsgForgedBoredRecd', `"silly forged Received: header"')> $| 4
')dnl

ifdef(`_EL_CHECKINJECTION', `dnl
ifelse(`_EL_BLACKLIST', `dnl
R$*						$: $&{INHEADERS} $| $(EL_GetInjectingIP $&{currHeader} $)
RYES $| $-.$-.$-.$-<IP>	$: $(EL_Blacklist $1.$2.$3.$4 $)
R$-.$-.$-.$-			$: $(EL_Blacklist $1.$2.$3 $)
R$-.$-.$-				$: $(EL_Blacklist $1.$2 $)
R$-.$-					$: $(EL_Blacklist $1 $)
RFOAD					$: $>EL_TagSuspicious <"message injected by blacklisted host"> $| 3
',`
_EL_CHECKINJECTION requires one of _EL_BLACKLIST or _EL_PERMBLACKLIST!
')dnl
ifelse(`_EL_PERMBLACKLIST', `dnl
R$*						$: $&{INHEADERS} $| $(EL_GetInjectingIP $&{currHeader} $)
RYES $| $-.$-.$-.$-<IP>	$: $(EL_PermBlacklist $1.$2.$3.$4 $)
R$-.$-.$-.$-			$: $(EL_PermBlacklist $1.$2.$3 $)
R$-.$-.$-				$: $(EL_PermBlacklist $1.$2 $)
R$-.$-					$: $(EL_PermBlacklist $1 $)
RDIEDIEDIE				$: $>EL_TagSuspicious <"message injected by permanently blacklisted host"> $| 4
RP				$: $>EL_TagSuspicious <"message injected by permanently blacklisted host"> $| 4
',`
_EL_CHECKINJECTION requires one of _EL_BLACKLIST or _EL_PERMBLACKLIST!
')dnl

ifdef(`_EL_CHECK_BOGUS_HELO', `dnl
R$*						$: $&{INHEADERS} $| $(EL_Check_BogusHELO419 $&{currHeader} $)
RYES $| $+<HELIMORE>	$: $>EL_TagSuspicious <"probably 419 spam based on HELO reported by Received header">
R$* $| $*				$: $&{currHeader}
')dnl

ifdef(`_EL_GMAIL10SLASH8', `dnl
R$*											$: $&{INHEADERS} $| $(EL_GetInjectingIPGmail108 $&{currHeader} $) $| $&{mail_from}
RYES $| $-.$-.$-.$-<IP> $| $+@gmail.com		$: $>EL_TagSuspicious <"message injected by broken GMail NAT, lacks proper injection IP"> $| 1
')dnl

ifdef(`_EL_CHECKINJECTINGIP_SBLXBL', `dnl

SBL-XBL is deprecated in favor of ZEN, please check your config.

')dnl

ifdef(`_EL_CHECKINJECTINGIP_ZEN', `dnl
R$*						$: $&{INHEADERS} $| $(EL_GetInjectingIP $&{currHeader} $)
RYES $| $-.$-.$-.$-<IP>	$: $1.$2.$3.$4 $| <?> $(dnsbl $4.$3.$2.$1.zen.spamhaus.org. $: OK $)
R$+ $| <?>OK			$: OKSOFAR
R$+ $| <?>$+<TMP>		$: TMPOK
R$+ $| <?>$+			$>EL_TagSuspicious <"http://www.spamhaus.org/query/bl?ip="$1> $| 4
')dnl

')dnl

R$*					$: $(EL_MSHTTPD419 $&{currHeader} $)
RGOAWAY				$#error $@ 5.7.1 $: ifdef(`confEL_ErrRecd419', `confEL_ErrRecd419', `"554 RECD419 Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as a variant of a Nigerian 419 scam."')

R$*					$: $(EL_Math + $@ 1 $@ $&{ELRecdHeaderCount} $)
R$*					$: $(EL_SetVar {ELRecdHeaderCount} $@ $1 $)
ifdef(`_EL_DEBUG', `dnl
R$*					$: $(EL_Log "EL Received cnt: " $&{ELRecdHeaderCount} $)
')dnl

ifdef(`_EL_B0RKEN', `dnl
R$*					$: $(EL_B0rkenRatware $&{currHeader} $)
R@SPAM				$#error $@ 5.7.1 $: ifdef(`confEL_ErrB0rkenRatware', `confEL_ErrB0rkenRatware', `"554 B0RKENR Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it appears to have been sent by laughably broken spam software."')
')dnl

ifdef(`_EL_FOAD_WENBZR', `dnl
R$*					$: $(EL_WenbzrForgedReceived $&{currHeader} $)
R@SPAM				$#error $@ 5.7.1 $: ifdef(`confEL_ErrRecdForged', `confEL_ErrRecdForged', `"554 RECDFRG Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it contains a forged header (Received:)"')
')dnl

ifdef(`_EL_DEPRECATED', `dnl
ifdef(`_EL_OPENPHARMACY', `dnl
R$*					$: $(EL_OpenPharmacyForgedRecd $&{currHeader} $)
R@SPAM				$#error $@ 5.7.1 $: ifdef(`confEL_ErrRecdForged', `confEL_ErrRecdForged', `"554 RECDFRG Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it contains a forged header (Received:)"')
')dnl
')dnl

ifdef(`_EL_FOAD_MEDKITINFO', `dnl
# check to see if the current header returns three things: an IP, a word (helo)
# and a word (embedded in bogus esmtp id string)
R$*							$: $(EL_MedkitInfoReceived $&{currHeader} $)
ifdef(`_EL_POLICY', `dnl
R$* $| $* $| $*				$: $1 $| $(EL_Wordlist $2 $) $| $(EL_Wordlist $3 $) $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
R$+.$+.$+.$+ $| W$* $| W$* $| $*MEDKIT$* $| TAG		$: <TAGMEDKIT>
R$+.$+.$+.$+ $| W$* $| W$* $| $*MEDKIT$* $| BLOCK	$: <REJMEDKIT>
R$+.$+.$+.$+ $| W$* $| W$* $| $* +MEDKIT$* $| ASK	$: <TAGMEDKIT>
R$+.$+.$+.$+ $| W$* $| W$* $| $* !MEDKIT$* $| ASK	$: <REJMEDKIT>
# also check for names, not just words
R$+.$+.$+.$+ $| N$* $| N$* $| $*MEDKIT$* $| TAG		$: <TAGMEDKIT>
R$+.$+.$+.$+ $| N$* $| N$* $| $*MEDKIT$* $| BLOCK	$: <REJMEDKIT>
R$+.$+.$+.$+ $| N$* $| N$* $| $* +MEDKIT$* $| ASK	$: <TAGMEDKIT>
R$+.$+.$+.$+ $| N$* $| N$* $| $* !MEDKIT$* $| ASK	$: <REJMEDKIT>
# finally, quarantine if the second is a word or name regardless
R$+.$+.$+.$+ $| $- $| W$* $| $*MEDKIT$* $| TAG		$: <TAGMEDKIT>
R$+.$+.$+.$+ $| $- $| N$* $| $*MEDKIT$* $| TAG		$: <TAGMEDKIT>

# if no match, try default policy
R$* $| $* $| $* $| $* $| $*							$: $1 $| $2 $| $3 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
R$+.$+.$+.$+ $| W$* $| W$* $| $*MEDKIT$* $| TAG		$: <TAGMEDKIT>
R$+.$+.$+.$+ $| W$* $| W$* $| $*MEDKIT$* $| BLOCK	$: <REJMEDKIT>
R$+.$+.$+.$+ $| W$* $| W$* $| $* +MEDKIT$* $| ASK	$: <TAGMEDKIT>
R$+.$+.$+.$+ $| W$* $| W$* $| $* !MEDKIT$* $| ASK	$: <REJMEDKIT>
# also check for names, not just words
R$+.$+.$+.$+ $| N$* $| N$* $| $*MEDKIT$* $| TAG		$: <TAGMEDKIT>
R$+.$+.$+.$+ $| N$* $| N$* $| $*MEDKIT$* $| BLOCK	$: <REJMEDKIT>
R$+.$+.$+.$+ $| N$* $| N$* $| $* +MEDKIT$* $| ASK	$: <TAGMEDKIT>
R$+.$+.$+.$+ $| N$* $| N$* $| $* !MEDKIT$* $| ASK	$: <REJMEDKIT>
# finally, quarantine if the second is a word or name regardless
R$+.$+.$+.$+ $| $- $| W$* $| $*MEDKIT$* $| TAG		$: <TAGMEDKIT>
R$+.$+.$+.$+ $| $- $| N$* $| $*MEDKIT$* $| TAG		$: <TAGMEDKIT>

R<TAGMEDKIT>				$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgMedkitInfo', `confEL_TagErrMsgMedkitInfo', `"probably medkit.info spam gang"')> $| 4
R<REJMEDKIT>				$#error $@ 5.7.1 $: ifdef(`confEL_ErrMedkitInfo', `confEL_ErrMedkitInfo', `"554 MEDKIT Contact "$&{ELContactEmail}" if this is in error, but we believe this message to be spam."')
', `
R$* $| $* $| $*				$: $1 $| $(EL_Wordlist $2 $) $| $(EL_Wordlist $3 $)
R$+.$+.$+.$+ $| W$* $| W$*	$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgMedkitInfo', `confEL_TagErrMsgMedkitInfo', `"probably medkit.info spam gang"')> $| 4
# also check for names, not just words
R$+.$+.$+.$+ $| N$* $| N$*	$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgMedkitInfo', `confEL_TagErrMsgMedkitInfo', `"probably medkit.info spam gang"')> $| 4
')dnl

# now check for the root word
R$*							$: $(EL_MedkitInfoRoot $&{currHeader} $)
ifdef(`_EL_POLICY', `dnl
R$* $| $* $| $*				$: $1 $| $(EL_Wordlist $2 $) $| $(EL_Wordlist $3 $) $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
R$+.$+.$+.$+ $| W$* $| W$* $| $*MEDKIT$* $| TAG		$: <TAGMEDKITINFO>
R$+.$+.$+.$+ $| W$* $| W$* $| $*MEDKIT$* $| BLOCK	$: <REJMEDKITINFO>
R$+.$+.$+.$+ $| W$* $| W$* $| $* +MEDKIT$* $| ASK	$: <TAGMEDKITINFO>
R$+.$+.$+.$+ $| W$* $| W$* $| $* !MEDKIT$* $| ASK	$: <REJMEDKITINFO>
# also check for names, not just words
R$+.$+.$+.$+ $| N$* $| N$* $| $*MEDKIT$* $| TAG		$: <TAGMEDKITINFO>
R$+.$+.$+.$+ $| N$* $| N$* $| $*MEDKIT$* $| BLOCK	$: <REJMEDKITINFO>
R$+.$+.$+.$+ $| N$* $| N$* $| $* +MEDKIT$* $| ASK	$: <TAGMEDKITINFO>
R$+.$+.$+.$+ $| N$* $| N$* $| $* !MEDKIT$* $| ASK	$: <REJMEDKITINFO>

# if no match try default policy
R$* $| $* $| $* $| $* $| $* 						$: $1 $| $2 $| $3 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
R$+.$+.$+.$+ $| W$* $| W$* $| $*MEDKIT$* $| TAG		$: <TAGMEDKITINFO>
R$+.$+.$+.$+ $| W$* $| W$* $| $*MEDKIT$* $| BLOCK	$: <REJMEDKITINFO>
R$+.$+.$+.$+ $| W$* $| W$* $| $* +MEDKIT$* $| ASK	$: <TAGMEDKITINFO>
R$+.$+.$+.$+ $| W$* $| W$* $| $* !MEDKIT$* $| ASK	$: <REJMEDKITINFO>
# also check for names, not just words
R$+.$+.$+.$+ $| N$* $| N$* $| $*MEDKIT$* $| TAG		$: <TAGMEDKITINFO>
R$+.$+.$+.$+ $| N$* $| N$* $| $*MEDKIT$* $| BLOCK	$: <REJMEDKITINFO>
R$+.$+.$+.$+ $| N$* $| N$* $| $* +MEDKIT$* $| ASK	$: <TAGMEDKITINFO>
R$+.$+.$+.$+ $| N$* $| N$* $| $* !MEDKIT$* $| ASK	$: <REJMEDKITINFO>

R<TAGMEDKITINFO>			$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgMedkitInfoRoot', `confEL_TagErrMsgMedkitInfoRoot', `"probably medkit.info spam gang (root)"')> $| 4
R<REJMEDKITINFO>			$#error $@ 5.7.1 $: ifdef(`confEL_ErrMedkitInfo', `confEL_ErrMedkitInfo', `"554 MEDKIT Contact "$&{ELContactEmail}" if this is in error, but we believe this message to be spam."')
', `
R$* $| $* $| $*				$: $1 $| $(EL_Wordlist $2 $) $| $(EL_Wordlist $3 $)
R$+.$+.$+.$+ $| W$* $| W$*	$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgMedkitInfoRoot', `confEL_TagErrMsgMedkitInfoRoot', `"probably medkit.info spam gang (root)"')> $| 4
# also check for names, not just words
R$+.$+.$+.$+ $| N$* $| N$*	$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgMedkitInfoRoot', `confEL_TagErrMsgMedkitInfoRoot', `"probably medkit.info spam gang (root)"')> $| 4
')dnl
')dnl

ifdef(`_EL_FOAD_VIPWATCHES', `dnl
# check to see if the current header returns two words embedded in bogus
# IDENT string
R$*						$: $(EL_VIPWatches $&{currHeader} $)
ifdef(`_EL_POLICY', `dnl
R$* $| $*				$: $(EL_Wordlist $1 $) $| $(EL_Wordlist $2 $) $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
RW$* $| W$* $| $*VIPWATCH$* $| TAG		$: <TAGVIPWATCH>
RW$* $| W$* $| $*VIPWATCH$* $| BLOCK	$: <REJVIPWATCH>
RW$* $| W$* $| $* +VIPWATCH$* $| ASK	$: <TAGVIPWATCH>
RW$* $| W$* $| $* !VIPWATCH$* $| ASK	$: <REJVIPWATCH>

# if no match try default policy
R$* $| $* $| $* $| $*					$: $1 $| $2 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
RW$* $| W$* $| $*VIPWATCH$* $| TAG		$: <TAGVIPWATCH>
RW$* $| W$* $| $*VIPWATCH$* $| BLOCK	$: <REJVIPWATCH>
RW$* $| W$* $| $* +VIPWATCH$* $| ASK	$: <TAGVIPWATCH>
RW$* $| W$* $| $* !VIPWATCH$* $| ASK	$: <REJVIPWATCH>

R<TAGVIPWATCH>				$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgVipWatches', `confEL_TagErrMsgVipWatches', `"probably vip watches spam gang"')> $| 4
R<REJVIPWATCH>				$#error $@ 5.7.1 $: ifdef(`confEL_ErrVipWatches', `confEL_ErrVipWatches', `"554 VIPWATCH Contact "$&{ELContactEmail}" if this is in error, but we believe this message to be spam."')
', `
R$* $| $*				$: $(EL_Wordlist $1 $) $| $(EL_Wordlist $2 $)
RW$* $| W$*	$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgVipWatches', `confEL_TagErrMsgVipWatches', `"probably vip watches spam gang"')> $| 4
')dnl
')dnl

ifdef(`_EL_TRUSTPERFORA', `dnl
# catch phishing stuff sent from perfora.net
R$*					$: $(EL_ReceivedIPForgedByCGI $&{currHeader} $)
R@SPAM				$#error $@ 5.7.1 $: ifdef(`confEL_ErrRecdForged', `confEL_ErrRecdForged', `"554 RECDFRG Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it contains a forged header (Received:)"')
')dnl

# catch phishing stuff sent via yahoo (or anywhere else)
R$*					$: $(EL_PhishUser $&{currHeader} $)
RMATCH				$#error $@ 5.7.1 $: ifdef(`confEL_ErrYahooUserPhish', `confEL_ErrYahooUserPhish', `"554 PSHUSER Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as a phishing scam; it contains a suspicious header (Received:)"')
R$*					$: $&{currHeader}

ifdef(`_EL_GEOBLOCK', `dnl
# checks origin of message based on comprehensive list of netblocks as
# assigned to various country codes and rejects if message came from a
# country from which you do not want Webmail. Originally designed for
# prevention of Nigerian "419" scams, now broader and features the ability
# to block on any known geographic data. Based on work by Bruce Gingery.

R$*						$: $&{INHEADERS} $| $1
RNO $| $*				$@ OK
R$@ $| $*				$@ OK
RYES $| $*				$: $1

# now check to see if any Received: header contains IP in forbidden netspace
# and came from suspected Webmail interface or similar
R$*						$: $(EL_WebIP $&{currHeader} $) $| $1
R$*<IP> $| $*			$: $1<IP> $| $2 ifdef(`_EL_DEBUG', `$(EL_Log "EL geo: "$1 $)')

R$-.$-.$-.$-<IP> $| $*	$: $(EL_CheckGeographic $1.$2.$3.$4 $)<IP> $| $5 
R$-.$-.$-.$-<IP> $| $*	$: $(EL_CheckGeographic $1.$2.$3 $)<IP> $| $5 
R$-.$-.$-<IP> $| $*		$: $(EL_CheckGeographic $1.$2 $)<IP> $| $4 
R$-.$-<IP> $| $*		$: $(EL_CheckGeographic $1 $)<IP> $| $3 

R$* $| $*				$: $1 $| $2 ifdef(`_EL_DEBUG', `$(EL_Log "EL geo got: " $1 ": " $2 $)')

# strip <IP> tag from the first token but keep it on passthrough
ifdef(`_EL_POLICY', `dnl
R$*<IP> $| $*									$: $(EL_CheckISOCode $1 $) $| $1<IP> $| $2 $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
RMATCH $| $* $| $* $| $*419GEO$* $| TAG			$: <TAG419SCAM>
RMATCH $| $* $| $* $| $*419GEO$* $| BLOCK		$: <REJ419SCAM>
RMATCH $| $* $| $* $| $* +419GEO$* $| ASK		$: <TAG419SCAM>
RMATCH $| $* $| $* $| $* !419GEO$* $| ASK		$: <REJ419SCAM>

# ok, we did not match, so we strip off the ISOCode check return value
R$* $| $* $| $* $| $* $| $*						$: $2 $| $3
',`
R$*<IP> $| $*			$: $(EL_CheckISOCode $1 $) $| $1<IP> $| $2

# return 554 because we are past start of DATA phase
RMATCH $| $* $| $*		$: <REJ419SCAM>

# ok, we did not match, so we strip off the ISOCode check return value
R$* $| $* $| $*			$: $2 $| $3

')dnl

# check for proxy webmail hosts
Rproxy<IP> $| $*					$: <REJ419PROXY>

# check for satellite Internet 
Rsatellite<IP> $| $*				$: <REJ419SATELLITE>

# check for oft-abused webmail
Rwebmail<IP> $| $*					$: <REJ419SCAM>

# now check against a set of known abused webmail hosts
R192.168$*<IP> $| $* bigpond $*		$: <REJ419SCAM>
R192.168$*<IP> $| $* tin.it $*		$: <REJ419SCAM>
R192.168$*<IP> $| $* iol.cz $*		$: <REJ419SCAM>
R172.16$*<IP>  $| $* iol.pt $*		$: <REJ419SCAM>
R172.16$*<IP>  $| $* libero.it $*	$: <REJ419SCAM>
R172.20$*<IP>  $| $* gazeta.pl $*	$: <REJ419SCAM>
R172.22$*<IP>  $| $* voila.fr $*	$: <REJ419SCAM>

R<TAG419SCAM>			$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsg419Geo', `confEL_TagErrMsg419Geo', `"probably 419 scam based on geography of sender"')> $| 2	
R<REJ419SCAM>			$#error $@ 5.1.8 $: ifdef(`confEL_ErrRecdGeographic', `confEL_ErrRecdGeographic', `"554 RCD419G Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as a likely variant of a Nigerian 419 scam based on its origin."')

R<REJ419PROXY>			$#error $@ 5.1.8 $: ifdef(`confEL_ErrGeographicProxy', `confEL_ErrGeographicProxy', `"554 RCD419P Contact "$&{ELContactEmail}" if this is in error, but your message was rejected. We do not accept mail sent via Webmail accounts that hide behind proxies."')

R<REJ419SATELLITE>		$#error $@ 5.1.8 $: ifdef(`confEL_ErrGeographicSatellite', `confEL_ErrGeographicSatellite', `"554 RCD419S Contact "$&{ELContactEmail}" if this is in error, but your message was rejected. We do not accept mail sent via Webmail accounts from satellite links."')
')dnl

ifdef(`_EL_GEOBLOCK_SQUIRRELMAIL', `dnl
R$*						$: $&{INHEADERS} $| $1
RNO $| $*				$@ OK
R$@ $| $*				$@ OK
RYES $| $*				$: $1

# cleanup from previous
R$-<IP> $| $+			$: $2

R$*											$: $(EL_WebIPSquirrelMail $&{currHeader} $) $| $1
R$-.$-.$-.$-.10.$-.$-.$-<IP> $| $*			$: $(EL_CheckGeographic $1.$2.$3.$4 $)<IP> $| $8 ifdef(`_EL_DEBUG', `$(EL_Log "EL geo 10/8: "       $1"."$2"."$3"."$4 $)')
R$-.$-.$-.$-.172.16.$-.$-<IP> $| $*			$: $(EL_CheckGeographic $1.$2.$3.$4 $)<IP> $| $7 ifdef(`_EL_DEBUG', `$(EL_Log "EL geo 172.16/16: "  $1"."$2"."$3"."$4 $)')
R$-.$-.$-.$-.192.168.$-.$-<IP> $| $*		$: $(EL_CheckGeographic $1.$2.$3.$4 $)<IP> $| $7 ifdef(`_EL_DEBUG', `$(EL_Log "EL geo 192.168/16: " $1"."$2"."$3"."$4 $)')

R$-.$-.$-.$-<IP> $| $*						$: $(EL_CheckGeographic $1.$2.$3 $)<IP>    $| $5 ifdef(`_EL_DEBUG', `$(EL_Log "EL geo: "       $1"."$2"."$3 $)')

R$-.$-.$-<IP> $| $*							$: $(EL_CheckGeographic $1.$2 $)<IP>       $| $4 ifdef(`_EL_DEBUG', `$(EL_Log "EL geo: "       $1"."$2 $)')

R$-.$-<IP> $| $*							$: $(EL_CheckGeographic $1 $)<IP>          $| $3 ifdef(`_EL_DEBUG', `$(EL_Log "EL geo: "       $1 $)')

R$* $| $* 									$: $1 $| $2 ifdef(`_EL_DEBUG', `$(EL_Log "EL geo got: " $1 ": " $2 $)')

# this next is identical to the previous section
# strip <IP> tag from the first token but keep it on passthrough
ifdef(`_EL_POLICY', `dnl
R$*<IP> $| $*									$: $(EL_CheckISOCode $1 $) $| $1<IP> $| $2 $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
RMATCH $| $* $| $* $| $*419GEO$* $| TAG			$: <TAG419SCAM>
RMATCH $| $* $| $* $| $*419GEO$* $| BLOCK		$: <REJ419SCAM>
RMATCH $| $* $| $* $| $* +419GEO$* $| ASK		$: <TAG419SCAM>
RMATCH $| $* $| $* $| $* !419GEO$* $| ASK		$: <REJ419SCAM>

# ok, we did not match, so we strip off the ISOCode check return value
R$* $| $* $| $* $| $* $| $*						$: $2 $| $3
',`
R$*<IP> $| $*			$: $(EL_CheckISOCode $1 $) $| $1<IP> $| $2

# return 554 because we are past start of DATA phase
RMATCH $| $* $| $*		$: <REJ419SCAM>

# ok, we did not match, so we strip off the ISOCode check return value
R$* $| $* $| $*			$: $2 $| $3

')dnl

# check for proxy webmail hosts
Rproxy<IP> $| $*					$: <REJ419PROXY>

# check for satellite Internet 
Rsatellite<IP> $| $*				$: <REJ419SATELLITE>

# check for oft-abused webmail
Rwebmail<IP> $| $*					$: <REJ419SCAM>

# now check against a set of known abused webmail hosts
R192.168$*<IP> $| $* bigpond $*		$: <REJ419SCAM>
R192.168$*<IP> $| $* tin.it $*		$: <REJ419SCAM>
R192.168$*<IP> $| $* iol.cz $*		$: <REJ419SCAM>
R172.16$*<IP>  $| $* iol.pt $*		$: <REJ419SCAM>
R172.16$*<IP>  $| $* libero.it $*	$: <REJ419SCAM>
R172.20$*<IP>  $| $* gazeta.pl $*	$: <REJ419SCAM>
R172.22$*<IP>  $| $* voila.fr $*	$: <REJ419SCAM>

R<TAG419SCAM>			$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsg419Geo', `confEL_TagErrMsg419Geo', `"probably 419 scam based on geography of sender"')> $| 2	
R<REJ419SCAM>			$#error $@ 5.1.8 $: ifdef(`confEL_ErrRecdGeographic', `confEL_ErrRecdGeographic', `"554 RCD419G Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as a likely variant of a Nigerian 419 scam based on its origin."')

R<REJ419PROXY>			$#error $@ 5.1.8 $: ifdef(`confEL_ErrGeographicProxy', `confEL_ErrGeographicProxy', `"554 RCD419P Contact "$&{ELContactEmail}" if this is in error, but your message was rejected. We do not accept mail sent via Webmail accounts that hide behind proxies."')

R<REJ419SATELLITE>		$#error $@ 5.1.8 $: ifdef(`confEL_ErrGeographicSatellite', `confEL_ErrGeographicSatellite', `"554 RCD419S Contact "$&{ELContactEmail}" if this is in error, but your message was rejected. We do not accept mail sent via Webmail accounts from satellite links."')
')dnl

# using #discard per instructions from Suresh Ramasubramian
R$*						$: $(EL_ForgedOutblazeReceived $&{currHeader} $)
R@SPAM					$#discard $: discard

# check for mobster HELO in header
R$*						$: $(EL_RecdMobsterPostfix $&{currHeader} $)
R$*<HOST>				$: $1 $| $(EL_Math & $@ 8 $@ $&{ELSpamsign} $)  $(EL_Log "EL Mobster HELO:" $1 $)
R$&{s} $| 8				$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgMobster', `confEL_TagErrMsgMobster', `"almost certainly mobster"')> $| 4

# check for "from nobody by $host with local" Exim header
R$*						$: $(EL_RecdFromNobodyByHostWithLocal $&{currHeader} $)
R$+<MATCH>				$: <?> $(EL_HostIP $1.g.enemieslist.com. $)
R<?>$+.$+.2.2			$: $>EL_TagSuspicious <"received from nobody by known webhost"> $| 2
R<?>$+.$+.0.$+			$: $>EL_TagSuspicious <"received from nobody by known generic"> $| 2
R<?>$+.$+.2.11			$: $>EL_TagSuspicious <"received from nobody by known legit"> $| 1

