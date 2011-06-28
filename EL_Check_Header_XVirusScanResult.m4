divert(-1)dnl
#
# Copyright (c) 2004-6 hesketh.com/inc. All rights reserved.

# See the file LICENSE in the distribution for details.

#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_Check_Header_XVirusScanResult.m4,v 1.9 2011/05/17 19:51:01 schampeo Exp $')dnl
divert(-1)dnl

LOCAL_CONFIG
#------------------------------------------------------------------------
# enemieslist.com X-Virus-Scan-Result: header check patterns and calls
#------------------------------------------------------------------------
HX-Virus-Scan-Result: $>EL_Check_Header_XVirusScanResult

KEL_CheckForRepairedVirus regex -a<NOISE> -s1 ^.?Repaired.[0-9]+\ (.+)$

LOCAL_RULESETS
#------------------------------------------------------------------------
# enemieslist.com X-Virus-Scan-Result: header checks
#------------------------------------------------------------------------
SEL_Check_Header_XVirusScanResult
ifdef(`_EL_TRACE', `dnl
R$*					$: $1 $(EL_Log "XVirusScanResult w/ " $1 "; score: " $&{ELSuspiciousCount} "." $)
')dnl

ifdef(`_EL_SKIPLOCAL', `dnl
R$*					$: $1 $| $&{client_addr}
R$* $| 127.0.0.1	$@
')dnl

ifdef(`_EL_DEBUG', `dnl
R$*					$: $(EL_Log "EL X-Virus-Scan-Result: " $&{currHeader} $)
')dnl

# skip whitelisted hosts
R$*					$: $&{ELWhitelisted}
R$+:$+				$@

ifdef(`_EL_B0RKEN', `dnl
R$*					$: $(EL_B0rkenRatware $&{currHeader} $)
R@SPAM				$#error $@ 5.7.1 $: ifdef(`confEL_ErrB0rkenRatware', `confEL_ErrB0rkenRatware', `"554 B0RKENR Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it appears to have been sent by laughably broken spam software."')
')dnl

R$*					$: $(EL_CheckForRepairedVirus $&{currHeader} $)
R<NOISE> $| $+		$#error $@ 5.7.1 $: ifdef(`confEL_ErrXVirusScanResult', `confEL_ErrXVirusScanResult', `"554 REPAIRED Contact "$&{ELContactEmail}" if this is in error, but we do not want repaired viruses, as there is nothing useful left."')


