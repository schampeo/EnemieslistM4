divert(-1)dnl
#
# Copyright (c) 2006-2011 hesketh.com/inc. All rights reserved.
#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_Check_Header_XCloudmarkScore.m4,v 1.9 2011/05/17 18:10:17 schampeo Exp $')dnl
divert(-1)dnl

LOCAL_CONFIG
#------------------------------------------------------------------------
# enemieslist.com X-Cloudmark-Score header check regexes
#------------------------------------------------------------------------
# check for a certain value in X-Cloudmark-Score: header to reject probable
# spam not otherwise rejected by intermediate relay.
KEL_XCloudmarkScore regex -a<YES> -s1 :.([0-9]+\.[0-9]+)\ .*

LOCAL_RULESETS
#------------------------------------------------------------------------
# enemieslist.com X-Cloudmark-Score header check ruleset
#------------------------------------------------------------------------
HX-Cloudmark-Score: $>EL_Check_Header_XCloudmarkScore
SEL_Check_Header_XCloudmarkScore
ifdef(`_EL_TRACE', `dnl
R$*					$: $1 $(EL_Log "XCloudmarkScore w/ " $1 "; score: " $&{ELSuspiciousCount} "." $)
')dnl

ifdef(`_EL_SKIPLOCAL', `dnl
R$*					$: $1 $| $&{client_addr}
R$* $| 127.0.0.1	$@
')dnl

# skip whitelisted hosts
R$*					$: $&{ELWhitelisted}
R$+:$+				$@

ifdef(`_EL_POLICY', `dnl
R$*							$: $(EL_XCloudmarkScore $&{currHeader} $) $| $&{ELPolicyUser}
R$+<YES> $| $*TRUSTCM:$-$*	$: $(EL_Math l $@ $1 $@ $3 $) $(EL_Log "X-Cloudmark-Score: "$1"/"$3 $)

# if no match try default policy
R$* $| $* 					$: $1 $| $(EL_Policy default $)
R$+<YES> $| $*TRUSTCM:$-$*	$: $(EL_Math l $@ $1 $@ $3 $) $(EL_Log "X-Cloudmark-Score: "$1"/"$3 $)

RFALSE						$#error $@ 5.7.1 $: ifdef(`confEL_ErrXCloudmark', `confEL_ErrXCloudmark', `"554 XCLOUDMS Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam (should have been rejected by relay)."')
')dnl
