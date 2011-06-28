divert(-1)dnl
#
# Copyright (c) 2004-2011 hesketh.com/inc. All rights reserved.

# See the file LICENSE in the distribution for details.

#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_Check_Header_ContentEncoding.m4,v 1.13 2011/05/17 19:17:35 schampeo Exp $')
divert(-1)dnl

LOCAL_CONFIG
#------------------------------------------------------------------------
# enemieslist.com Content-Encoding: header check patterns and call
#------------------------------------------------------------------------
HContent-Encoding: $>EL_Check_Header_ContentEncoding

KEL_ContentEncodingBogus regex -a@SPAM BitbitNUM

KEL_ContentEncoding sequence EL_ContentEncodingBogus ifdef(`_EL_B0RKEN', `EL_B0rkenRatware')

LOCAL_RULESETS
#------------------------------------------------------------------------
# enemieslist.com Content-Encoding: header checks
#------------------------------------------------------------------------
SEL_Check_Header_ContentEncoding
ifdef(`_EL_TRACE', `dnl
R$*					$: $1 $(EL_Log "ContentEncoding w/ " $1 "; score: " $&{ELSuspiciousCount} "." $)
')dnl

ifdef(`_EL_SKIPLOCAL', `dnl
R$*					$: $1 $| $&{client_addr}
R$* $| 127.0.0.1	$@
')dnl

# skip whitelisted hosts
R$*			$: $&{ELWhitelisted}
R$+:$+		$@

R$*					$: $(EL_ContentEncoding $&{currHeader} $)
R@SPAM				$#error $@ 5.7.1 $: ifdef(`confEL_ErrContentEncoding', `confEL_ErrContentEncoding', `"554 BADHDCE Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; suspicious header (Content-Encoding)"')


