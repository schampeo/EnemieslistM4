divert(-1)dnl
#
# Copyright (c) 2007-2011 hesketh.com/inc. All rights reserved.
#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_Check_Header_XAmavisAlert.m4,v 1.5 2011/05/17 18:16:47 schampeo Exp $')
divert(-1)dnl

LOCAL_CONFIG
#------------------------------------------------------------------------
# enemieslist.com X-Amavis-Alert: header ruleset call
#------------------------------------------------------------------------
KEL_Amavis_Alert regex -a<AMAVIS> (BAD\ HEADER|BANNED\ FILENAME|INFECTED)

HX-Amavis-Alert: $>EL_Check_Header_XAmavisAlert

LOCAL_RULESETS
#------------------------------------------------------------------------
# enemieslist.com X-Amavis-Alert: header checks
#------------------------------------------------------------------------
SEL_Check_Header_XAmavisAlert
ifdef(`_EL_TRACE', `dnl
R$*					$: $1 $(EL_Log "XAmavisAlert w/ " $1 "; score: " $&{ELSuspiciousCount} "." $)
')dnl

ifdef(`_EL_SKIPLOCAL', `dnl
R$*					$: $1 $| $&{client_addr}
R$* $| 127.0.0.1	$@
')dnl

# skip whitelisted hosts
R$*					$: $&{ELWhitelisted}
R$+:$+				$@

R$*					$: $(EL_Amavis_Alert $&{currHeader} $) 

??? need to add in policy token checks, callbacks

R<AMAVIS>			$#error $@ 5.7.1 $: ifdef(`confEL_ErrAmavisAlert', `confEL_ErrAmavisAlert', `"554 AMAVIS Contact "$&{ELContactEmail}" if this is in error, but your message was rejected because it failed an Amavis check on the sending host."')
R<AMAVIS>			$>EL_TagSuspicious <ifdef(`confEL_TagErrMsgAmavis', `confEL_TagErrMsgAmavis', `"tagged by amavis"')> $| 4
')dnl

