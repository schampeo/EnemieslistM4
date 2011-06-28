divert(-1)dnl
#
# Copyright (c) 2004-2011 hesketh.com/inc. All rights reserved.
#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_Check_Header_XAOLIP.m4,v 1.12 2011/05/17 18:20:38 schampeo Exp $')
divert(-1)dnl

LOCAL_CONFIG
#------------------------------------------------------------------------
# enemieslist.com X-AOL-IP: header check pattern and call
#------------------------------------------------------------------------
HX-AOL-IP: $>EL_Check_Header_XAOLIP

LOCAL_RULESETS
#------------------------------------------------------------------------
# enemieslist.com X-AOL-IP header checks
#------------------------------------------------------------------------
SEL_Check_Header_XAOLIP
ifdef(`_EL_TRACE', `dnl
R$*					$: $1 $(EL_Log "XAOLIP w/ " $1 "; score: " $&{ELSuspiciousCount} "." $)
')dnl

ifdef(`_EL_SKIPLOCAL', `dnl
R$*					$: $1 $| $&{client_addr}
R$* $| 127.0.0.1	$@
')dnl

# skip whitelisted hosts
R$*					$: $&{ELWhitelisted}
R$+:$+				$@

ifdef(`_EL_GEOBLOCK', `dnl
# grab IP and check against geographic IP crossref
R$* [$*] $*			$: $2
R$-.$-.$-.$-		$: $(EL_CheckGeographic $1.$2.$3.$4 $)
R$-.$-.$-.$-		$: $(EL_CheckGeographic $1.$2.$3 $)
R$-.$-.$-.$-		$: $(EL_CheckGeographic $1.$2 $)

# return 554 because we are past start of DATA phase
RMATCH 				$#error $@ 5.1.8 $: ifdef(`confEL_ErrRecdGeographic', `confEL_ErrRecdGeographic', `"554 RCD419G Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as a likely variant of a Nigerian 419 scam based on its origin."')

R$*						$: $(EL_WebIP $&{currHeader} $) $| $1
R$*<IP> $| $*			$: $1<IP> $| $2 ifdef(`_EL_DEBUG', `$(EL_Log "EL geo: "$1 $)')

R$-.$-.$-.$-<IP> $| $*	$: $(EL_CheckGeographic $1.$2.$3.$4 $)<IP> $| $5
R$-.$-.$-.$-<IP> $| $*	$: $(EL_CheckGeographic $1.$2.$3 $)<IP> $| $5
R$-.$-.$-<IP> $| $*		$: $(EL_CheckGeographic $1.$2 $)<IP> $| $4

R$* $| $*				$: $1 $| $2 ifdef(`_EL_DEBUG', `$(EL_Log "EL geo got: " $1 ": " $2 $)')

# strip <IP> tag from the first token but keep it on passthrough
R$*<IP> $| $*			$: $(EL_CheckISOCode $1 $) $| $1<IP> $| $2

# return 554 because we are past start of DATA phase
RMATCH $| $* $| $*		$#error $@ 5.1.8 $: ifdef(`confEL_ErrRecdGeographic', `confEL_ErrRecdGeographic', `"554 RCD419G Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as a likely variant of a Nigerian 419 scam based on its origin."')

# ok, we did not match, so we strip off the ISOCode check return value
R$* $| $* $| $*			$: $2 $| $3

# check for proxy webmail hosts
Rproxy<IP> $| $*			$#error $@ 5.1.8 $: ifdef(`confEL_ErrGeographicProxy', `confEL_ErrGeographicProxy', `"554 RCD419P Contact "$&{ELContactEmail}" if this is in error, but your message was rejected. We do not accept mail sent via Webmail accounts that hide behind proxies."')

# check for satellite Internet 
Rsatellite<IP> $| $*		$#error $@ 5.1.8 $: ifdef(`confEL_ErrGeographicSatellite', `confEL_ErrGeographicSatellite', `"554 RCD419S Contact "$&{ELContactEmail}" if this is in error, but your message was rejected. We do not accept mail sent via Webmail accounts from satellite links."')

# check for oft-abused webmail
Rwebmail<IP> $| $*			$#error $@ 5.1.8 $: ifdef(`confEL_ErrRecdGeographic', `confEL_ErrRecdGeographic', `"554 RCD419G Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as a likely variant of a Nigerian 419 scam based on its origin."')
')dnl

