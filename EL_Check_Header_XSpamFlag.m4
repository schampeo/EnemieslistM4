divert(-1)dnl
#
# Copyright (c) 2007-2011 hesketh.com/inc. All rights reserved.

# See the file LICENSE in the distribution for details.

#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_Check_Header_XSpamFlag.m4,v 1.8 2011/05/17 17:48:18 schampeo Exp $')
divert(-1)dnl

LOCAL_CONFIG
#------------------------------------------------------------------------
# enemieslist.com X-Spam-Flag header check regexes
#------------------------------------------------------------------------
# check for a certain value in X-Spam-Flag: header to reject probable
# spam not otherwise rejected by intermediate relay.
#
# e.g.
# X-AOL-IP: 200.121.242.27
# X-Spam-Flag: YES
KEL_XSpamFlag regex -a<YES> -f ^\ ?YES$

LOCAL_RULESETS
#------------------------------------------------------------------------
# enemieslist.com X-Spam-Flag header check ruleset
#------------------------------------------------------------------------
HX-Spam-Flag: $>EL_Check_Header_XSpamFlag
HX-SPAM-FLAG: $>EL_Check_Header_XSpamFlag
SEL_Check_Header_XSpamFlag
dnl ifdef(`_EL_TRACE', `dnl
R$*					$: $1 $(EL_Log "XSpamFlag w/ " $1 "; score: " $&{ELSuspiciousCount} ". CurrRcpt: " $&{EL_CurrRcpt} "; INHEADERS: " $&{INHEADERS} $)
dnl ')dnl

ifdef(`_EL_SKIPLOCAL', `dnl
R$*					$: $1 $| $&{client_addr}
R$* $| 127.0.0.1	$@
')dnl

# skip whitelisted hosts
R$*					$: $&{ELWhitelisted}
R$+:$+				$@

ifdef(`_EL_ACCEPT_ALL_LOCAL_ROLE_ACCTS', `dnl
# skip role accounts
R$*					$: $1 $| $>canonify $&{EL_CurrRcpt}
ifdef(`_EL_TENTATIVE_ROLEACCTS', `dnl
# ??? bug: should be configurable via m4
# but here we only accept abuse if it does not fail any other checks
R$* $| abuse <@ $=w . >				$: OKSOFAR
R$* $| postmaster <@ $=w . >		$#OK
', `dnl
R$* $| abuse <@ $=w . >				$#OK
R$* $| postmaster <@ $=w . >		$#OK
R$* $| $*							$: $1
')dnl
')dnl

R$*					$: $&{INHEADERS} $| $(EL_XSpamFlag $&{currHeader} $) 
RYES $| $*<YES> 	$#error $@ 5.7.1 $: ifdef(`confEL_ErrXSpamFlag', `confEL_ErrXSpamFlag', `"554 XSPMFLG Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam (should have been rejected by relay)."')

