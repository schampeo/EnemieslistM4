divert(-1)dnl
#
# Copyright (c) 2004-2011 hesketh.com/inc. All rights reserved.
#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_Check_Header_XAuthenticationWarning.m4,v 1.17 2011/05/17 18:12:05 schampeo Exp $')
divert(-1)dnl

LOCAL_CONFIG
#------------------------------------------------------------------------
# enemieslist.com X-Authentication-Warning checks and call
#------------------------------------------------------------------------
HX-Authentication-Warning: $>EL_Check_Header_XAuthenticationWarning

KEL_PassatOwner regex -a@SPAM majordom.*set.*sender.*to.*passat\-Owner
KEL_XAuthWarnSetOwner regex -a@SPAM :(apache|nobody|majordom|www|[a-z]+[0-9]+[a-z]+)\ set\ sender\ to.+using\ \-[a-z]
KEL_XAuthWarnNoHELOProtocol regex -a@SPAM didn.t\ use\ HELO\ protocol
KEL_XAuthWarnGibberish regex -a@SPAM ^\ ?[a-z]+\ [a-z]+
KEL_XAuthWarnHost regex -a<HOST> -s1 ^\ ?([0-9a-z\-\.]+):

KEL_XAuthenticationWarning sequence EL_PassatOwner EL_XAuthWarnGibberish EL_XAuthWarnSetOwner EL_XAuthWarnNoHELOProtocol

LOCAL_RULESETS
#------------------------------------------------------------------------
# enemieslist.com X-Authentication-Warning checks
#------------------------------------------------------------------------
SEL_Check_Header_XAuthenticationWarning
ifdef(`_EL_TRACE', `dnl
R$*					$: $1 $(EL_Log "XAuthenticationWarning w/ " $1 "; score: " $&{ELSuspiciousCount} "." $)
')dnl

ifdef(`_EL_SKIPLOCAL', `dnl
R$*					$: $1 $| $&{client_addr}
R$* $| 127.0.0.1	$@
')dnl

# skip whitelisted hosts
R$*			$: $&{ELWhitelisted}
R$+:$+		$@

ifdef(`_EL_B0RKEN', `dnl
R$*					$: $(EL_B0rkenRatware $&{currHeader} $)
R@SPAM				$#error $@ 5.7.1 $: ifdef(`confEL_ErrB0rkenRatware', `confEL_ErrB0rkenRatware', `"554 B0RKENR Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it appears to have been sent by laughably broken spam software."')
')dnl

R$*					$: $(EL_XAuthenticationWarning $&{currHeader} $)
R@SPAM				$#error $@ 5.7.1 $: ifdef(`confEL_ErrXAuthenticationWarning', `confEL_ErrXAuthenticationWarning', `"554 BDHDXAW Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam (X-Authentication-Warning)."')

R$*					$: $(EL_XAuthWarnHost $&{currHeader} $)
R$*<HOST>			$: $(EL_HostIP $1 $@ FAIL $) ifdef(`_EL_DEBUG', `$(EL_Log "EL XAuth: " $1 $)')
RFAIL				$#error $@ 5.7.1 $: ifdef(`confEL_ErrXAuthenticationWarning', `confEL_ErrXAuthenticationWarning', `"554 BDHDXAW Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam (X-Authentication-Warning)."')
