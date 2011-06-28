divert(-1)dnl
#
# Copyright (c) 2004-2011 hesketh.com/inc. All rights reserved.
#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_Geographic.m4,v 1.31 2011/05/13 22:03:48 schampeo Exp $')
divert(-1)dnl

define(`_EL_GEOBLOCK', `1')

LOCAL_CONFIG
# enemieslist.com 419 point of origin database
# credits: Bruce Gingery for the idea and early code
#
# IP Netblock crossref by their ISO 2-letter country code or keyword
#
# Keywords:
#  satellite  - satellite ISP (block registered to different ccTLD)
#  proxy      - proxy service, obscures sender origin
#  webmail    - not in suspect geography but provides webmail service
#
# file format: 
# dot.ted.qu.ad    tab   ISOCODE

KEL_CheckGeographic ifdef(`confEL_GEOGRAPHIC_FILE', `confEL_DB_MAP_TYPE' `confEL_GEOGRAPHIC_FILE')

KEL_CheckISOCode regex -aMATCH ^ifdef(`confEL_GEOGRAPHIC_ISOCODES', `confEL_GEOGRAPHIC_ISOCODES', `(BJ|BW|CI|GH|KR|NG|RW|ZA|TG|ZW)')

# extract webmail IP from common Received: headers
KEL_WebIP1 regex -a<IP> -s1 from.?\[?([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}).*(via|with).(DAV|HTTP)

KEL_WebIP2 regex -a<IP> -s1 from.*\[?([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\ by\ [0-9a-z\-\.]+(bigpond\.com|cox\.net|gci\.net|iol\.[a-z]+|o2\.ie|monash\.edu\.au|rcn\.net|ttml\.co\.in|universia\.pt|usd\.edu)\ (\(mshttpd\))

KEL_WebIP3 regex -a<IP> -s1 via.HTTP.client.([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})

# need this one because the headers are too long and the =with HTTP= is
# stripped before the match is attempted. Stripped final closing paren from
# pattern due to the occasional username containing a period, and therefore
# not being matched by sendmail regex .+
#
# needs to come AFTER EL_WebIP26
KEL_WebIP4 regex -a<IP> -s1 from.?\[?([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}).*\(SquirrelMail\ authenticated\ user\ .+

# WebMail from Romania
KEL_WebIP5 regex -a<IP> -s1 from.?\(?\[?([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}).*by.www

# freeserve Javamail
KEL_WebIP6 regex -a<IP> -s1 from.?wwinf300[0-9]\ \(wwinf300[0-9] (\[172\.22\.159\.[0-9]+\])

# Bogus Lycos "Unknown/Local" Received
KEL_WebIP7 regex -a<IP> -s1 from.?Unknown/Local\ \(\[(\?\.\?\.\?\.\?)\]\)

# b0rken Bigpond/Telstra JavaMail
KEL_WebIP8 regex -a<IP> -s1 from.?unknown.?\(HELO.owaxs0[12]\.opwv\.email\.bigpond\.com\).?\(?([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})

# phpmailer
KEL_WebIP9 regex -a<IP> -s1 from.?phpmailer.?\(?\[?([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}).*HTTP

# iol.cz, road runner, probably others
KEL_WebIP10 regex -a<IP> -s1 from.?\[?([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]?.?\(Forwarded-For:\ unknown\)

KEL_WebIP11 regex -a<IP> -s2 from.?\[?([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]?.?\(Forwarded-For:.?\[?([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]?\)

# Received: from [10.240.3.197] (Forwarded-For: 62.194.11.42, [10.240.3.197])
# by mstr4.srv.hcvlny.cv.net (mshttpd); Fri, 30 Mar 2007 08:25:15 +0000 (GMT)

# Received: from [10.240.3.214] (Forwarded-For: 62.51.157.61, [10.240.3.214])
# by mstr9.srv.hcvlny.cv.net (mshttpd); Tue, 29 May 2007 19:21:50 +0000 (GMT)

KEL_WebIP12 regex -a<IP> -s2 from.?\[?([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]?.?\(Forwarded-For:.?\[?([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]?,\ \[?([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]?\)

# libero.it
KEL_WebIP13 regex -a<IP> -s1 from.?libero\.it.?\((172\.16\.[0-9]{1,3}\.[0-9]{1,3})\)

# rediffmail
KEL_WebIP14 regex -a<IP> -s1 from.?unknown.?\(([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\).*(via|with).(HTTP)

# UebiMiau
KEL_WebIP15 regex -a<IP> -s1 from.?client.?([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}).?for.?UebiMiau

# web3000.it, AZet.sk
KEL_WebIP16 regex -a<IP> -s1 from.?client.?([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}).?for.*\(webmail.?client\)

# Received: from h6210059076.dsl.speedlinq.nl (h6210059076.dsl.speedlinq.nl [62.100.59.76]) 
#        by webmail.zoom.co.uk (IMP) with HTTP 

# IMP
KEL_WebIP17 regex -a<IP> -s1 from.+\(.+\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\].*by.?.+\(IMP\).?with.?HTTP

# Received: from 193.219.234.36 (unverified [193.219.234.36])
# by mail.wearab.net (VisualOffice 4.02)   
# with WEBMAIL id 91138;
# Fri, 29 Apr 2005 03:35:40 +0000
KEL_WebIP18 regex -a<IP> -s1 from.+\(.+\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\].*by.?.+\(VisualOffice.?[0-9]\.[0-9]+\).?with.?WEBMAIL

# Received: from rndf-ip-nas-1-p199.telkom-ipnet.co.za
# (telkomsa179024%40telkomsa.net@rndf-ip-nas-1-p199.telkom-ipnet.co.za
# [155.239.64.199]) by rndf-ip-wxl-1.saix.net (SlipStream SP Server 3.2.44
# built 2004/11/09 15:45:33 -0500 (EST)); Wed, 20 Jul 2005 10:27:26 +0200 
# (SAST)

KEL_WebIP19 regex -a<IP> -s1 from.+\(.+\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\].*by.*\(SlipStream.SP.Server

# Received: from 83.45.119.70 ([83.45.119.70]) by 209.59.180.38 (Horde) with
#       HTTP for <john@csavfin.com>; Mon, 15 Aug 2005 13:14:12 -0400
# or
# Received: from dhcp84.4u.com.gh (dhcp84.4u.com.gh [80.87.83.84]) by
#       w4.mail.sapo.pt (Horde) with HTTP for <robmensah@sapo.pt>; Thu, 15 Sep 2005 13:03:38 +0100

KEL_WebIP20 regex -a<IP> -s1 from.+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\ .+\(Horde\).with.HTTP

# Received: from mainmanxa7nrtf ([196.3.60.17])
#        by starcomms.com (8.13.1/8.13.1) with SMTP id j7P6uQrB079588;
#        Thu, 25 Aug 2005 06:56:31 GMT
KEL_WebIP21 regex -a<IP> -s1 from.[a-z0-9]+.\(([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\)

# Received: from [195.166.233.110] (HELO golden2)
#  by linkserve.org (CommuniGate Pro SMTP 4.2)
#  with SMTP id 51247; Fri, 26 Aug 2005 21:44:43 -0100
KEL_WebIP22 regex -a<IP> -s1 from.\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\].\(HELO.([a-z0-9]+)\)

# Received: from  [196.25.255.210] as user thomasndlela@optusnet.com.au by
#    webmail.optusnet.com.au with HTTP;
KEL_WebIP23 regex -a<IP> -s1 from.*\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\].as.user.+by.+with.HTTP

# Received: from Http Client 83.229.103.18 by 64.97.168.16 for Recipient(ID
#    Suppressed); 2005-08-30 15:08:53 UTC
KEL_WebIP24 regex -a<IP> -s1 from.Http.Client.([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}).by.*for.Recipient

# Received: from 196-207-13-66.netcomng.com ([::ffff:196.207.13.66]) by
#       fe-3c.inet.it via I-SMTP-5.2.3-521
#       id ::ffff:196.207.13.66+NOKXHhmblIV; Thu, 11 May 2006 11:13:47 +0200
KEL_WebIP25 regex -a<IP> -s1 from.*\(\[::ffff:([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]\).?by.*via.I\-SMTP

# Received: from 212.100.250.213 (proxying for 196.2.121.25)
#        (SquirrelMail authenticated user charles_obiang@eaalp.com)      
#        by www.corecluster.net with HTTP;
#        Sun, 6 Aug 2006 12:29:04 -0000 (GMT)
# Received: from 58.227.194.87 (proxying for 78.138.0.102)
#        (SquirrelMail authenticated user sawitree@gibthai.com)
#        by mail.gibthai.com with HTTP;
#        Tue, 26 Aug 2008 23:13:29 +0700 (ICT)
KEL_WebIP26 regex -a<IP> -s1 from.*.\(proxying.for.([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\).*SquirrelMail.*with.HTTP

# Received: from [62.128.164.76] by smailcenter66.comcast.net;
#        Sat, 14 Oct 2006 17:17:13 +0000
#
# not technically webmail
KEL_WebIP27 regex -a<IP> -s1 from.*\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\].by.smailcenter[0-9]+

# Received: from patisp.net.mundo-r.com (HELO machado02) ([213.60.113.178])
#  by smtp2.mundo-r.com with ESMTP; 15 Oct 2006 22:56:04 +0200
#
# also not technically webmail
KEL_WebIP28 regex -a<IP> -s1 from.*\(HELO.[0-9a-z\-]+\).\(\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]

# Received: from [212.122.64.16] (helo=freemail.lt)
#        by mx2.skynet.lt with smtp (Exim 4.60 (FreeBSD))
#        (envelope-from <infopromotion004@freemail.lt>)
#        id 1HEYV3-000FkZ-J5; Wed, 07 Feb 2007 00:09:17 +0200
KEL_WebIP29 regex -a<IP> -s1 from.*\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]\ \(helo=

# Received: from pc02 ( [41.204.33.126])
#        by mx.google.com with ESMTP id c1sm1408854ugf.2007.03.21.06.34.23;
#        Wed, 21 Mar 2007 06:34:54 -0700 (PDT)
# also not necessarily webmail
KEL_WebIP30 regex -a<IP> -s1 from.*\(.*\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\].*by\ mx\.google\.com

# Received: from 190.170.20.162, 81.199.61.89 by webmail.west.cox.net;
KEL_WebIP31 regex -a<IP> -s2 from ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}),\ ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\ by webmail

# Received: (from ms09.lnh.mail.rcn.net [88.15.246.182])
#        by ms09.lnh.mail.rcn.net (MOS 3.7.5a-GA)
#        with HTTP/1.1 id BFG40726 (AUTH hkates@rcn.com);
#        Thu, 12 Apr 2007 17:30:10 -0400 (EDT)
KEL_WebIP32 regex -a<IP> -s1 from.+\ \[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\].*with\ HTTP

# ig.com.br stupidity
# X-Originating-IP: [200.226.130.70]10.229.16.15, 193.220.178.110
KEL_WebIP33 regex -a<IP> -s1 \[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\][0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3},.?([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})

# att.net
# Received: from [213.185.118.199] by sccqwbc03;
#       Sat, 18 Aug 2007 11:55:47 +0000
KEL_WebIP34 regex -a<IP> -s1 from.?\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\].?by.?scc

# laposte.net
# Received: from laposte.net (unknown [82.128.23.56])
#        by mwinf8414.laposte.net (SMTP Server) with ESMTP id DEFB9E000087;
#        Sun, 26 Aug 2007 17:32:58 +0200 (CEST)
KEL_WebIP35 regex -a<IP> -s1 from.?laposte\.net\ \(.*\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]\)

# Received: from [193.93.99.146] ([193.93.99.146]:2080 "EHLO User"
#        rhost-flags-FAIL-FAIL-OK-FAIL) by ps19.test.onet.pl with ESMTPA
#        id S184553314AbXJIQhAg1wsh (ORCPT <rfc822;heather@hesketh.com>);
#        Tue, 9 Oct 2007 15:37:00 -0100
KEL_WebIP36 regex -a<IP> -s1 from.?\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\].?\(\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\]:[0-9]+.?\"[EH][EH]LO.?User\ .*

# Received: from 75-3.vgccl.net ([41.220.75.3]) by
#        webmail15.syd.optusnet.com.au with http
#        (user=meritmerit@optusnet.com.au);    Sat, 24 Nov 2007 02:44:41 +1100
KEL_WebIP37 regex -a<IP> -s1 from.+\(\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]\).*by.webmail.*with.http

# Received: from [196.1.176.195] (port=62897 helo=mx.freenet.de)
#       by 12.mx.freenet.de with esmtpa (ID fmf.board7@freenet.de) (port 25)
#       (Exim 4.68 #1) id 1JAXmo-0006J1-IA; Thu, 03 Jan 2008 22:39:35 +0100
KEL_WebIP38 regex -a<IP> -s1 from.?\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\].?\(port			

# Received: from ml82.128.18.179.multilinks.com ([82.128.18.179]:2460 helo=mail.com)
#       by 13.mx.freenet.de with esmtpa (ID focinc_0056@freenet.de) (port 25) (Exim 4.68 #1)
#       id 1JGWuu-00072E-Bg; Sun, 20 Jan 2008 10:56:43 +0100
KEL_WebIP39 regex -a<IP> -s1 from.?.+.?\(\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]:[0-9]+

# Received: from ml82.128.13.132.multilinks.com (ml82.128.13.132.multilinks.com
#       [82.128.13.132])  by compuserve.de ([10.228.3.105])  with ESMTP via
#       TCP; 30 Jan 2008 22:46:14 -0000
KEL_WebIP40 regex -a<IP> -s1 from.?.+.?\(.+\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]

# Received: from savf@absamail.co.za [81.199.172.190] by absamail.co.za
#       with NetMail ModWeb Module; Sat, 26 Jan 2008 22:09:52 +0200
KEL_WebIP41 regex -a<IP> -s1 from.?.+.?\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\].?by.?absamail

# Received: from [195.245.108.34] by fwebmail32.isp.att.net;
#       Wed, 30 Jan 2008 14:31:11 +0000
KEL_WebIP42 regex -a<IP> -s1 from.?\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\].?by.fwebmail[0-9]+\.isp\.att\.net

# Received: from ml82.128.18.231.multilinks.com [82.128.18.231] by
#        smtp.gia.org.sg with SMTP;   Tue, 23 Sep 2008 00:47:40 +0800
KEL_WebIP43 regex -a<IP> -s1 from.?.*multilinks.com.?\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]

# Received: from unknown (HELO user) (82.128.2.59)
#        by 202.201.0.148 with SMTP; Fri, 14 Nov 2008 05:03:30 +0800
KEL_WebIP44 regex -a<IP> -s1 from.unknown..user...([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}).*by.*with.SMTP

# Received: from mrs_naphikoffi@tedescom.net (qaumenatalia@41.207.1.184 with
#        login) by smtp112.biz.mail.re2.yahoo.com with SMTP;
#        18 Jul 2010 07:49:05 -0700 PDT
KEL_WebIP45 regex -a<IP> -s1 from .+\(.+@([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}).with.login

# maximuma.net
# Received: from tv.maximuma.net (unknown [91.196.148.8])
# Received: from laposte.net (unknown [82.128.23.56])
KEL_WebIP46 regex -a<IP> -s1 from.?tv\.maximuma\.net\ \(.*\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]\)

# yet another User check
# Received: from xt254e.stansat.pl ([83.243.37.78]:2924 helo=User)
KEL_WebIP47 regex -a<IP> -s1 from.?.+ \(\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]:[0-9]+.?helo=User\)

# Special pattern for SquirrelMail for dealing with when the injection IP is RFC1918
# so we have to take the first IP instead
# Received: from 81.199.63.32 (proxying for 192.168.5.26) (SquirrelMail
#        authenticated user cja51) by webmail.sirisonline.com with HTTP;
KEL_WebIPSquirrelMail regex -a<IP> -d. -s1,2 from\ ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}).\(proxying.for.([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\).*SquirrelMail.*with.HTTP

# restored WebIP2 after tightening up the pattern
# moved up 29 after failure to catch this example:
# Received: from [41.208.176.148] (helo=[10.0.0.9])
#       by asmtp-out3.blueyonder.co.uk with esmtpa (Exim 4.52)
#       id 1KEXGI-00078W-DT; Thu, 03 Jul 2008 23:26:47 +0100
#
# moved up 26 after failing to catch this example:
# Received: from 81.199.180.84 (proxying for 172.16.0.41)
#       (SquirrelMail authenticated user teleinfo)
#       by webmail.copaco.com.py with HTTP;
#       Sat, 5 Jul 2008 12:20:31 -0400 (PYT)
#
KEL_WebIPseq1 sequence EL_WebIP29 EL_WebIP26 EL_WebIP1  EL_WebIP2  EL_WebIP3  EL_WebIP4  EL_WebIP5  EL_WebIP6  EL_WebIP7  EL_WebIP8  EL_WebIP9  EL_WebIP10 
KEL_WebIPseq2 sequence EL_WebIP11 EL_WebIP12 EL_WebIP14 EL_WebIP15 EL_WebIP16 EL_WebIP17 EL_WebIP18 EL_WebIP19 EL_WebIP20 EL_WebIP21 EL_WebIP22 EL_WebIP23 
KEL_WebIPseq3 sequence EL_WebIP24 EL_WebIP25 EL_WebIP26 EL_WebIP27 EL_WebIP28 EL_WebIP30 EL_WebIP31 EL_WebIP32 EL_WebIP33 EL_WebIP34 EL_WebIP35 
KEL_WebIPseq4 sequence EL_WebIP36 EL_WebIP37 EL_WebIP38 EL_WebIP39 EL_WebIP40 EL_WebIP41 EL_WebIP42 EL_WebIP43 EL_WebIP44 EL_WebIP45 EL_WebIP46 EL_WebIP47

KEL_WebIP sequence EL_WebIPseq4 EL_WebIPseq3 EL_WebIPseq2 EL_WebIPseq1


