divert(-1)dnl
#
# Copyright (c) 2004-2011 hesketh.com/inc. All rights reserved.
#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_Check_Header_XOriginatingIP.m4,v 1.30 2011/05/17 17:53:47 schampeo Exp $')
divert(-1)dnl

LOCAL_CONFIG
#------------------------------------------------------------------------
# enemieslist.com X-Originating-IP: header check pattern and call
#------------------------------------------------------------------------
HX-Abuse: $>EL_Check_Header_XOriginatingIP
HX-DBMAIL-Originating-IP: $>EL_Check_Header_XOriginatingIP
HX-EN-OrigIP: $>EL_Check_Header_XOriginatingIP
HX-Forwarded-For: $>EL_Check_Header_XOriginatingIP
HX-IP: $>EL_Check_Header_XOriginatingIP
HX-IPAddress: $>EL_Check_Header_XOriginatingIP
HX-Origin: $>EL_Check_Header_XOriginatingIP
HX-Originating-IP: $>EL_Check_Header_XOriginatingIP
HX-OriginatingIP: $>EL_Check_Header_XOriginatingIP
HX-ORIGINATE-IP: $>EL_Check_Header_XOriginatingIP
HX-Origination-IP: $>EL_Check_Header_XOriginatingIP
HX-Originator: $>EL_Check_Header_XOriginatingIP
HX-PHP-Script: $>EL_Check_Header_XOriginatingIP
HX-Sender-IP: $>EL_Check_Header_XOriginatingIP
HX-SenderIP: $>EL_Check_Header_XOriginatingIP
HX-User-Info: $>EL_Check_Header_XOriginatingIP
HX-WebmailUserIP: $>EL_Check_Header_XOriginatingIP
HX-wmSenderIP: $>EL_Check_Header_XOriginatingIP
HxOriginalSenderIP: $>EL_Check_Header_XOriginatingIP

KEL_BadXOriginatingIPs regex -f -a@SPAM (%CUSTOM_IP|2004hosting|unknown via proxy|ALT|RND_NUMBER)

# disabled this test due to FPs. Restored it so the geographic checks would work again
KEL_XOrigWithoutBrackets regex -a<IP> -s1 ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)

KEL_XOIPWithSender regex -a<IP> -s1 \ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) \(.+@.+\)

KEL_XOIPWithBrackets regex -a<IP> -s1 \[([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\]$

# X-Originating-IP: [10.17.1.39]unknown, 196.220.6.190
KEL_XOIPWithBracketsEtc regex -a<IP> -s1 \[[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\]unknown,\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)

KEL_XPHPScript1 regex -a<IP> -s1 for\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)$

# X-PHP-Script: horn.gda.pl/index.php for unknown, 213.185.106.204
KEL_XPHPScript2 regex -s<IP> -s1 for\ .*,\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)$

KEL_XPHPScript sequence EL_XPHPScript1 EL_XPHPScript2

# X-Originating-IP: from 196.220.0.10 by mail.charter.net; Sat, 14 Oct 2006 21:38:41 -0400
# X-Origination-IP: from 196.201.131.214 by webmail-146.home.nl; Fri, 17 Nov 2006 1:28:03 +0100
KEL_XOIPCharter regex -a<IP> -s1 from ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) by 

# X-Abuse: 715855777 / 81.91.239.211
KEL_XAbuse regex -a<IP> -s1 /\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)$

KEL_VariousOriginatingIPHeaders sequence EL_XOIPWithBrackets EL_XOIPWithBracketsEtc EL_XOrigWithoutBrackets EL_XPHPScript EL_XOIPCharter EL_XAbuse

KEL_BogusXOrig sequence EL_BadXOriginatingIPs 

ifdef(`_EL_HOTMAIL_XOIP_BORKEN', `dnl
KEL_HotmailInjectionPoints regex -a<YES> \[?(64\.4\.[56][0-9]*\.[0-9]+|65\.54\.[12][0-9]{2}\.[0-9]+)\]?
')

LOCAL_RULESETS
#------------------------------------------------------------------------
# enemieslist.com X-Originating-IP header checks
#------------------------------------------------------------------------
SEL_Check_Header_XOriginatingIP
ifdef(`_EL_TRACE', `dnl
R$*					$: $1 $(EL_Log "XOriginatingIP w/ " $1 "; score: " $&{ELSuspiciousCount} "." $)
')dnl

ifdef(`_EL_SKIPLOCAL', `dnl
R$*					$: $1 $| $&{client_addr}
R$* $| 127.0.0.1	$@
')dnl

# skip whitelisted hosts
R$*					$: $&{ELWhitelisted}
R$+:$+				$@

R$*					$: $(EL_BogusXOrig $&{currHeader} $)
R@SPAM				$#error $@ 5.7.1 $: ifdef(`confEL_ErrXOriginatingIP', `confEL_ErrXOriginatingIP', `"554 BDHDXOI Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it contains a suspicious header. (XOIP)"')

ifdef(`_EL_B0RKEN', `dnl
R$*					$: $(EL_B0rkenRatware $&{currHeader} $)
R@SPAM				$#error $@ 5.7.1 $: ifdef(`confEL_ErrB0rkenRatware', `confEL_ErrB0rkenRatware', `"554 B0RKENR Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it appears to have been sent by laughably broken spam software."')
')

ifdef(`_EL_GEOBLOCK', `dnl
R$*					$: $(EL_VariousOriginatingIPHeaders $&{currHeader} $) $| $1
R$*<IP> $| $*			$: $1<IP> $| $2 ifdef(`_EL_DEBUG', `$(EL_Log "EL geographic: "$1 $)')

R$-.$-.$-.$-<IP> $| $*	$: $(EL_CheckGeographic $1.$2.$3.$4 $)<IP> $| $5
R$-.$-.$-.$-<IP> $| $*	$: $(EL_CheckGeographic $1.$2.$3 $)<IP> $| $5
R$-.$-.$-<IP> $| $*		$: $(EL_CheckGeographic $1.$2 $)<IP> $| $4
R$-.$-<IP> $| $*		$: $(EL_CheckGeographic $1 $)<IP> $| $3

R$* $| $*				$: $1 $| $2 ifdef(`_EL_DEBUG', `$(EL_Log "EL geographic check got: " $1 ": " $2 $)')

# strip <IP> tag from the first token but keep it on passthrough
R$*<IP> $| $*			$: $(EL_CheckISOCode $1 $) $| $1<IP> $| $2

# return 554 because we are past start of DATA phase
RMATCH $| $* $| $*		$#error $@ 5.1.8 $: ifdef(`confEL_ErrRecdGeographic', `confEL_ErrRecdGeographic', `"554 RCD419G Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as a likely variant of a Nigerian 419 scam based on its origin."')

# ok, we did not match, so we strip off the ISOCode check return value
R$* $| $* $| $*			$: $2 $| $3

# check for proxy webmail hosts
Rproxy<IP> $| $*		$#error $@ 5.1.8 $: ifdef(`confEL_ErrGeographicProxy', `confEL_ErrGeographicProxy', `"554 RCD419P Contact "$&{ELContactEmail}" if this is in error, but your message was rejected. We do not accept mail sent via Webmail accounts that hide behind proxies."')

# check for satellite Internet 
Rsatellite<IP> $| $*	$#error $@ 5.1.8 $: ifdef(`confEL_ErrGeographicSatellite', `confEL_ErrGeographicSatellite', `"554 RCD419S Contact "$&{ELContactEmail}" if this is in error, but your message was rejected. We do not accept mail sent via Webmail accounts from satellite links."')

# check for oft-abused webmail
Rwebmail<IP> $| $*		$#error $@ 5.1.8 $: ifdef(`confEL_ErrRecdGeographic', `confEL_ErrRecdGeographic', `"554 RCD419G Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as a likely variant of a Nigerian 419 scam based on its origin."')

# now check against a set of known abused webmail hosts
R192.168 $* <IP> $| $* bigpond $*		$#error $@ 5.1.8 $: ifdef(`confEL_ErrRecdGeographic', `confEL_ErrRecdGeographic', `"554 RCD419G Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as a likely variant of a Nigerian 419 scam."')
R192.168 $* <IP> $| $* tin.it $*		$#error $@ 5.1.8 $: ifdef(`confEL_ErrRecdGeographic', `confEL_ErrRecdGeographic', `"554 RCD419G Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as a likely variant of a Nigerian 419 scam."')
R192.168 $* <IP> $| $* iol.cz $*		$#error $@ 5.1.8 $: ifdef(`confEL_ErrRecdGeographic', `confEL_ErrRecdGeographic', `"554 RCD419G Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as a likely variant of a Nigerian 419 scam."')
R172.16 $* <IP> $| $* iol.pt $*			$#error $@ 5.1.8 $: ifdef(`confEL_ErrRecdGeographic', `confEL_ErrRecdGeographic', `"554 RCD419G Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as a likely variant of a Nigerian 419 scam."')
R172.16 $* <IP> $| $* libero.it $*		$#error $@ 5.1.8 $: ifdef(`confEL_ErrRecdGeographic', `confEL_ErrRecdGeographic', `"554 RCD419G Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as a likely variant of a Nigerian 419 scam."')
R172.20 $* <IP> $| $* gazeta.pl $*		$#error $@ 5.1.8 $: ifdef(`confEL_ErrRecdGeographic', `confEL_ErrRecdGeographic', `"554 RCD419G Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as a likely variant of a Nigerian 419 scam."')
R172.22 $* <IP> $| $* voila.fr $*		$#error $@ 5.1.8 $: ifdef(`confEL_ErrRecdGeographic', `confEL_ErrRecdGeographic', `"554 RCD419G Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as a likely variant of a Nigerian 419 scam."')

R$* $| $*				$: $2

')

ifdef(`_EL_HOTMAIL_XOIP_BORKEN', `dnl
R$*						$: $(EL_HotmailInjectionPoints $&{currHeader} $)
R<YES>					$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgHotmailBorken', `confEL_TagErrMsgHotmailBorken', `"Probably a 419 scam; injected via broken hotmail NAT interface"')> $| 1
R$*						$: $(EL_Log "EL: hotmail check failed with " $1 $)
')
