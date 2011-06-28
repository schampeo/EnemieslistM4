divert(-1)dnl
#
# Copyright (c) 2004-2011 hesketh.com/inc. All rights reserved.

# See the file LICENSE in the distribution for details.

#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_Check_Header_XAntivirus.m4,v 1.18 2011/05/17 18:14:50 schampeo Exp $')
divert(-1)dnl

LOCAL_CONFIG
#------------------------------------------------------------------------
# enemieslist.com X-Antivirus: et al. header check patterns and calls
#------------------------------------------------------------------------
HX-AntiVirus: $>EL_Check_Header_XAntivirus
HX-GMX-Antivirus: $>EL_Check_Header_XAntivirus
HX-Kaspersky-Antivirus: $>EL_Check_Header_XAntivirus
HX-RAV-Antivirus: $>EL_Check_Header_XAntivirus
HX-Virus-Status: $>EL_Check_Header_XAntivirus
HX-Virus-Scanned: $>EL_Check_Header_XAntivirus

LOCAL_RULESETS
#------------------------------------------------------------------------
# enemieslist.com X-Antivirus et al. header checks
#------------------------------------------------------------------------
SEL_Check_Header_XAntivirus
ifdef(`_EL_TRACE', `dnl
R$*					$: $1 $(EL_Log "XAntivirus w/ " $1 "; score: " $&{ELSuspiciousCount} "." $)
')dnl

ifdef(`_EL_SKIPLOCAL', `dnl
R$*					$: $1 $| $&{client_addr}
R$* $| 127.0.0.1	$@
')dnl

# skip whitelisted hosts
R$*					$: $&{ELWhitelisted}
R$+:$+				$@

R$*					$: $(EL_Math + $@ 2 $@ $&{ELSpamsign} $)
R$*					$: $(EL_SetVar {ELSpamsign} $@ $1 $)

ifdef(`_EL_B0RKEN', `dnl
R$*					$: $(EL_B0rkenRatware $&{currHeader} $)
R@SPAM				$#error $@ 5.7.1 $: ifdef(`confEL_ErrB0rkenRatware', `confEL_ErrB0rkenRatware', `"554 B0RKENR Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it appears to have been sent by laughably broken spam software."')
')dnl

ifdef(`_EL_MOBSTER', `dnl
R$*					$: $(EL_Math & $@ 8 $@ $&{ELSpamsign} $) $| $(EL_Math & $@ 2 $@ $&{ELSpamsign} $) $| $&{client_resolve}
R8 $| 2 $| FAIL		$#error $@ 5.7.1 $: ifdef(`confEL_ErrXAntiVirusMobsterFail', `confEL_ErrXAntiVirusMobsterFail', `"554 MBSTAVF Contact "$&{ELContactEmail}" if this is in error, but we are pretty sure you are a spammer... and your server lacks reverse DNS"')

R8 $| 2 $| TEMP		$#error $@ 5.7.1 $: ifdef(`confEL_ErrXAntiVirusMobsterTemp', `confEL_ErrXAntiVirusMobsterTemp', `"554 MBSTAVT Contact "$&{ELContactEmail}" if this is in error, but we are pretty sure you are a spammer... and your server seems to lack reverse DNS"')
')dnl
