divert(-1)dnl
#
# Copyright (c) 2004-2011 hesketh.com/inc. All rights reserved.
#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_Check_Header_XComment.m4,v 1.18 2011/05/17 18:08:59 schampeo Exp $')
divert(-1)dnl

LOCAL_CONFIG
#------------------------------------------------------------------------
# enemieslist.com X-Comment: header check patterns and call
#------------------------------------------------------------------------
HX-Comment: $>EL_Check_Header_XComment

KEL_XCommentBadRFC822 regex -a<RFC822> ^.*Sending.*client.*does.*not.*conform.*to.*RFC822.*minimum.*requirements
KEL_XComment29Chars regex -f -a@SPAM ^\ [a-z]{29}$

KEL_XCommentChecks sequence EL_XCommentBadRFC822 EL_XComment29Chars

LOCAL_RULESETS
#------------------------------------------------------------------------
# enemieslist.com X-Comment header checks
#------------------------------------------------------------------------
SEL_Check_Header_XComment
ifdef(`_EL_TRACE', `dnl
R$*					$: $1 $(EL_Log "XComment w/ " $1 "; score: " $&{ELSuspiciousCount} "." $)
')dnl

ifdef(`_EL_SKIPLOCAL', `dnl
R$*					$: $1 $| $&{client_addr}
R$* $| 127.0.0.1	$@
')dnl

# skip whitelisted hosts
R$*				$: $&{ELWhitelisted}
R$+:$+			$@

ifdef(`_EL_B0RKEN', `dnl
R$*					$: $(EL_B0rkenRatware $&{currHeader} $)
R@SPAM				$#error $@ 5.7.1 $: ifdef(`confEL_ErrB0rkenRatware', `confEL_ErrB0rkenRatware', `"554 B0RKENR Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it appears to have been sent by laughably broken spam software."')
')dnl

R$*					$: $(EL_XCommentChecks $&{currHeader} $)
R@SPAM				$#error $@ 5.7.1 $: ifdef(`confEL_ErrXComment', `confEL_ErrXComment', `"554 BADHDXC Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it contains a suspicious header (X-Comment)."')

R<RFC822>			$#error $@ 5.7.1 $: ifdef(`confEL_ErrXCommentRFC822', `confEL_ErrXCommentRFC822', `"554 XCBDDAT Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; if it does not conform to RFC822 minimum requirements, we do not want it, either."')
