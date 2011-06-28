divert(-1)dnl
#
# Copyright (c) 2004-2011 hesketh.com/inc. All rights reserved.

# See the file LICENSE in the distribution for details.

#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_Check_Header_Date.m4,v 1.21 2011/05/17 19:11:35 schampeo Exp $')
divert(-1)dnl

LOCAL_CONFIG
#------------------------------------------------------------------------
# enemieslist.com Date header checks
#------------------------------------------------------------------------
HDate: $>EL_Check_Header_Date

# this to deal with b0rken ratware producing garbage like this:
# Date: 5/5/2004X-Mailer: Spyder Mailer 1.2
KEL_DateB0rken regex -a@SPAM X\-Mailer

# and this:
# Date: Fri, 6 8 4 23:50:18 -7
KEL_DateSilliness regex -a@SPAM ^[A-Z][a-z]{2}, [0-9] [0-9] [0-9] [0-9]{2}:[0-9]{2}:[0-9]{2}\ \-[0-9]$

KEL_DashedDate regex -f -a@SPAM ^.?[A-Z][a-z]{2},.[0-9]{2}\-[A-Z][a-z]{2}\-[0-9]{4}

KEL_DateYourHealth regex -f -@SPAM ([\-\+][0-9][0-9][2468]0|\ 0000)$

# need to look at translating this into sendmail regex?
# http://mail-archives.apache.org/mod_mbox/spamassassin-commits/200607.mbox/%3C20060711142730.AECFF1A981A@eris.apache.org%3E
# header AXB_FAKETZ   Date =~ /[\+-](?!([0-9]{2}00)|0230|0330|0530|0545|0930|1030|1130)[0-9]{4}$/
# score  AXB_FAKETZ   2.22

KEL_DateOddTZ regex -n -@SPAM [\-\+][01][0123456789][03]0

KEL_DateChecks sequence EL_DateB0rken EL_DateSilliness EL_DashedDate EL_DateYourHealth ifdef(`_EL_B0RKEN', `EL_B0rkenRatware')

LOCAL_RULESETS
#------------------------------------------------------------------------
# enemieslist.com Date header checks
#------------------------------------------------------------------------
SEL_Check_Header_Date
ifdef(`_EL_TRACE', `dnl
R$*					$: $1 $(EL_Log "Date w/ " $1 "; score: " $&{ELSuspiciousCount} "." $)
')dnl

ifdef(`_EL_SKIPLOCAL', `dnl
R$*					$: $1 $| $&{client_addr}
R$* $| 127.0.0.1	$@
')dnl

# skip whitelisted hosts
R$*				$: $&{ELWhitelisted}
R$+:$+			$@

# check for multiple Date: headers
#R$*					$: $1 $| $(EL_Math & $@ 2056 $@ $&{ELHasHeader} $)
#R$* $| 2056			$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMultipleDates', `confEL_TagErrMultipleDates', `"message contains multiple Date: headers"')> $| 1
#R$* $| 0			$: $1 $| $(EL_Math + $@ 2056 $@ $&{ELHasHeader} $)
#R$* $| $*			$: $(EL_SetVar {ELHasHeader} $@ $2 $)
#R$*					$: $(EL_Log "ELHasHeader (date): " $&{ELHasHeader} $)

R$*					$: $(EL_DateChecks $&{currHeader} $)
R@SPAM				$#error $@ 5.7.1 $: ifdef(`confEL_ErrDate', `confEL_ErrDate', `"554 BADDATE Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam (invalid Date header)."')

ifdef(`_EL_TAGODDTZ', `dnl
# not safe to use yet
R$*				$: $(EL_DateOddTZ $&{currHeader} $)
R@SPAM			$>EL_TagSuspicious <"message Date: header has very odd timezone"> | 1
')dnl



