divert(-1)dnl
#
# Copyright (c) 2004-2011 hesketh.com/inc. All rights reserved.
#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_Check_Header_XMimeTrack.m4,v 1.14 2011/05/17 17:57:21 schampeo Exp $')
divert(-1)dnl

LOCAL_CONFIG
#------------------------------------------------------------------------
# enemieslist.com X-MIMETrack: header check patterns and call
#------------------------------------------------------------------------
HX-MimeTrack: $>EL_Check_Header_XMIMETrack

KEL_XMimeTrackRandom regex -a@SPAM ^.*(%RND_DATE_ONLY|%RND_MONTH_DAY_YEAR|%RND_TIME)

#KEL_XMimeTrackChecks sequence 

LOCAL_RULESETS
#------------------------------------------------------------------------
# enemieslist.com X-MIMETrack header checks
#------------------------------------------------------------------------
SEL_Check_Header_XMIMETrack
ifdef(`_EL_TRACE', `dnl
R$*					$: $1 $(EL_Log "XMIMETrack w/ " $1 "; score: " $&{ELSuspiciousCount} "." $)
')dnl


ifdef(`_EL_SKIPLOCAL', `dnl
R$*					$: $1 $| $&{client_addr}
R$* $| 127.0.0.1	$@
')dnl

# skip whitelisted hosts
R$*					$: $&{ELWhitelisted}
R$+:$+				$@

ifdef(`_EL_B0RKEN', `dnl
R$*					$: $(EL_B0rkenRatware $&{currHeader} $)
R@SPAM				$#error $@ 5.7.1 $: ifdef(`confEL_ErrB0rkenRatware', `confEL_ErrB0rkenRatware', `"554 B0RKENR Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it appears to have been sent by laughably broken spam software."')
')dnl

R$*					$: $(EL_XMimeTrackRandom $&{currHeader} $)
R@SPAM				$#error $@ 5.7.1 $: ifdef(`confEL_ErrXMimeTrack', `confEL_ErrXMimeTrack', `"554 BDHDXMT Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. It contains a suspicious header (X-MIMETrack)."')

