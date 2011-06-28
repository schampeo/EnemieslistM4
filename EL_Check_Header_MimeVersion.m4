divert(-1)dnl
#
# Copyright (c) 2004-2011 hesketh.com/inc. All rights reserved.

# See the file LICENSE in the distribution for details.

#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_Check_Header_MimeVersion.m4,v 1.10 2011/05/17 18:49:47 schampeo Exp $')dnl
divert(-1)dnl

LOCAL_CONFIG
#------------------------------------------------------------------------
# enemieslist.com MIME-Version: header check patterns and calls
#------------------------------------------------------------------------
HMIME-Version: $>EL_Check_Header_Mimeversion
#HMime-Version: $>EL_Check_Header_Mimeversion

# MIME-Version: 1.0 (produced by ashmancompetitioneverywhere 76.16)
KEL_BogusMimeVersion01 regex -a@SPAM \(produced by [a-z]+ [0-9]+\.[0-9]+\)

# MIME-Version: 1.0 (specificpolarogram deuterium bastard.5) 
KEL_BogusMimeVersion02 regex -a@SPAM \(produced by [a-z]+ [a-z]+ [a-z]+\.[0-9]+\)

# MIME-Version: 1.0 (produced by  7.1)
KEL_BogusMimeVersion03 regex -a@SPAM \(produced by  [0-9]+\.[0-9]+\)

KEL_MimeVersionChecks sequence EL_BogusMimeVersion01 EL_BogusMimeVersion02 EL_BogusMimeVersion03

LOCAL_RULESETS
#------------------------------------------------------------------------
# enemieslist.com MIME-Version header checks
#------------------------------------------------------------------------
SEL_Check_Header_Mimeversion
ifdef(`_EL_TRACE', `dnl
R$*					$: $1 $(EL_Log "Mimeversion w/ " $1 "; score: " $&{ELSuspiciousCount} "." $)
')dnl

ifdef(`_EL_SKIPLOCAL', `dnl
R$*					$: $1 $| $&{client_addr}
R$* $| 127.0.0.1	$@
')dnl

# skip whitelisted hosts
R$*					$: $&{ELWhitelisted}
R$+:$+				$@

R$*					$: $&{currHeader} $| $&{INHEADERS}
R$+ $| YES			$: <R> $(EL_Math + $@ 2048 $@ $&{ELHasHeader} $)
R<R>$*				$: <R> $(EL_SetVar {ELHasHeader} $@ $1 $)
R<R>$*				$: $(EL_Log "ELHasHeader (mime-version): " $&{ELHasHeader} $)

R$*					$: $&{currHeader}
R$*					$: $(EL_MimeVersionChecks $1 $)
R@SPAM				$#error $@ 5.7.1 $: ifdef(`confEL_ErrBogusMimeVersion', `confEL_ErrBogusMimeVersion', `"554 MIMEVRS Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it contains a forged header."')

ifdef(`_EL_B0RKEN', `dnl
R$*					$: $(EL_B0rkenRatware $&{currHeader} $)
R@SPAM				$#error $@ 5.7.1 $: ifdef(`confEL_ErrB0rkenRatware', `confEL_ErrB0rkenRatware', `"554 B0RKENR Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it appears to have been sent by laughably broken spam software."')
')dnl
