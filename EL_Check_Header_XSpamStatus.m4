divert(-1)dnl
#
# Copyright (c) 2005 hesketh.com/inc. All rights reserved.
#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_Check_Header_XSpamStatus.m4,v 1.13 2011/05/17 15:36:11 schampeo Exp $')
divert(-1)dnl

LOCAL_CONFIG
#------------------------------------------------------------------------
# enemieslist.com X-Spam-Status header check regexes
#------------------------------------------------------------------------
# check for a certain value in X-Spam-Status: header to reject probable
# spam not otherwise rejected by intermediate relay.
#
# Updated to include "Yes" for out-1.mail.amis.net, who is so dumb they
# let this header slip by their systems and into mine:
# X-Spam-Status: Yes, score=35.19 required=5 tests=[BAYES_99=6,
#        DATE_IN_FUTURE_03_06=1.961, HTML_IMAGE_ONLY_24=1.841,
#        HTML_MESSAGE=0.001, INFO_TLD=1.273, RAZOR2_CF_RANGE_51_100=0.5,     
#        RAZOR2_CF_RANGE_E8_51_100=1.5, RAZOR2_CHECK=0.5,
#        RCVD_IN_WHOIS_BOGONS=2.43, UPPERCASE_25_50=0, URIBL_AB_SURBL=3.812,
#        URIBL_JP_SURBL=4.087, URIBL_OB_SURBL=3.008, URIBL_SBL=1.639,
#        URIBL_SC_SURBL=4.498, URIBL_WS_SURBL=2.14]
KEL_XSpamStatus regex -a<YES> -s3 (No|Yes),.(hits|score)=([0-9]+\.[0-9]+)\ .*

LOCAL_RULESETS
#------------------------------------------------------------------------
# enemieslist.com X-Spam-Status header check ruleset
#------------------------------------------------------------------------
HX-Spam-Status: $>EL_Check_Header_XSpamStatus
SEL_Check_Header_XSpamStatus
ifdef(`_EL_TRACE', `dnl
R$*					$: $1 $(EL_Log "XSpamStatus w/ " $1 "; score: " $&{ELSuspiciousCount} "." $)
')dnl

ifdef(`_EL_SKIPLOCAL', `dnl
R$*					$: $1 $| $&{client_addr}
R$* $| 127.0.0.1	$@
')dnl

# skip whitelisted hosts
R$*					$: $&{ELWhitelisted}
R$+:$+				$@

ifdef(`_EL_POLICY', `dnl
R$*									$: ${INHEADERS} $| $(EL_XSpamStatus $&{currHeader} $) $| $&{ELPolicyUser}
RYES $| $+<YES> $| $*TRUSTSA:$-$*	$: $(EL_Math l $@ $1 $@ $3 $) $(EL_Log "X-Spam-Status check: "$1"/"$3 $)

# if no match try default policy
RYES $| $* $| $*			$: $1 $| $(EL_Policy default $)
R$+<YES> $| $*TRUSTSA:$-$*	$: $(EL_Math l $@ $1 $@ $3 $) $(EL_Log "X-Spam-Status check: "$1"/"$3 $)

RFALSE						$#error $@ 5.7.1 $: ifdef(`confEL_ErrXSpamStatus', `confEL_ErrXSpamStatus', `"554 XSPMSTS Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam (should have been rejected by relay)."')

')dnl

