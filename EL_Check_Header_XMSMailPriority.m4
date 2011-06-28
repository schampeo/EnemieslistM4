divert(-1)dnl
#
# Copyright (c) 2004-2011 hesketh.com/inc. All rights reserved.

# See the file LICENSE in the distribution for details.

#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_Check_Header_XMSMailPriority.m4,v 1.15 2011/05/17 18:03:52 schampeo Exp $')
divert(-1)dnl

LOCAL_CONFIG
#------------------------------------------------------------------------
# enemieslist.com X-MSMail-Priority: header check pattern and call
#------------------------------------------------------------------------
HX-MSMailPriority: $>EL_Check_Header_XMSMailPriority

KEL_XMSMP regex -f -a_VIRUS_ ^.*Normal

LOCAL_RULESETS
#------------------------------------------------------------------------
# enemieslist.com X-MSMail-Priority: header checks
# note: primarily here for MyDoom check in check_eoh
#------------------------------------------------------------------------
SEL_Check_Header_XMSMailPriority
ifdef(`_EL_TRACE', `dnl
R$*					$: $1 $(EL_Log "XMSMailPriority w/ " $1 "; score: " $&{ELSuspiciousCount} "." $)
')dnl

ifdef(`_EL_SKIPLOCAL', `dnl
R$*					$: $1 $| $&{client_addr}
R$* $| 127.0.0.1	$@
')dnl

ifdef(`_EL_B0RKEN', `dnl
R$*					$: $(EL_B0rkenRatware $&{currHeader} $)
R@SPAM				$#error $@ 5.7.1 $: ifdef(`confEL_ErrB0rkenRatware', `confEL_ErrB0rkenRatware', `"554 B0RKENR Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it appears to have been sent by laughably broken spam software."')
')dnl

