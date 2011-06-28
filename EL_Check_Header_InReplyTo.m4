divert(-1)dnl
#
# Copyright (c) 2004-2011 hesketh.com/inc. All rights reserved.
#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id')
divert(-1)dnl

LOCAL_CONFIG
#------------------------------------------------------------------------
# enemieslist.com In-Reply-To: header check pattern and call
#------------------------------------------------------------------------
HIn-Reply-To: $>EL_Check_Header_InReplyTo

KEL_InReplyToForged regex -a@SPAM  <[A-Z0-9]{16}@ifdef(`confEL_BogusInReplyToDomains', `confEL_BogusInReplyToDomains', `(example.com|example.net|example.org)')

ifdef(`_EL_CHECK_BOGUS_INREPLYTO', `dnl
KEL_InReplyToBogus regex -a@SPAM -n <.+@.+>
')dnl

# Yahoo bug
KEL_StupidYahooInReplyTo regex -a<BROKEN> ^\ ?6667$

# ??? todo: add checks for exact same Message-ID, References, and In-Reply-To
# headers (shoppingdoneforyou.com)

ifdef(`_EL_FINANCIALNETVENTURE', `dnl
# match e.g. <Y55Z.CAJRwRwP$BLARyCxARDV.LxV.X00ZWY>
KEL_FinancialNetVentureInReplyTo regex -f -a@SPAM [A-Za-z]+\.(LxV|wNC|xAP)\.[A-Z0-9]{6}>
')dnl

LOCAL_RULESETS
#------------------------------------------------------------------------
# enemieslist.com In-Reply-To: header checks
#------------------------------------------------------------------------
SEL_Check_Header_InReplyTo
ifdef(`_EL_TRACE', `dnl
R$*					$: $1 $(EL_Log "InReplyTo w/ " $1 "; score: " $&{ELSuspiciousCount} "." $)
')dnl

ifdef(`_EL_SKIPLOCAL', `dnl
R$*					$: $1 $| $&{client_addr}
R$* $| 127.0.0.1	$@
')dnl

# skip whitelisted hosts
R$*				$: $&{ELWhitelisted}
R$+:$+			$@

# stupid workaround for Yahoo! mail stupidity - return if header contains 6667
R$*				$: $(EL_StupidYahooInReplyTo $&{currHeader} $)
R$*<BROKEN>		$@

ifdef(`_EL_B0RKEN', `dnl
R$*					$: $(EL_B0rkenRatware $&{currHeader} $)
R@SPAM				$#error $@ 5.7.1 $: ifdef(`confEL_ErrB0rkenRatware', `confEL_ErrB0rkenRatware', `"554 B0RKENR Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it appears to have been sent by laughably broken spam software."')
')dnl

R$*					$: $(EL_InReplyToForged $&{currHeader} $) $| $&{INHEADERS}
R@SPAM $| YES		$#error $@ 5.7.1 $: ifdef(`confEL_ErrInReplyToForged', `confEL_ErrInReplyToForged', `"554 FREPLYT Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it contains a suspicious header. (forged In-Reply-To)"')

ifdef(`_EL_FINANCIALNETVENTURE', `dnl
R$*					$: $(EL_FinancialNetVentureInReplyTo $&{currHeader} $)
R@SPAM				$#error $@ 5.7.1 $: ifdef(`confEL_ErrInReplyToTracker', `confEL_ErrInReplyToTracker', `"554 IRTTRCK Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. We do not accept email containing tracking devices."')
')dnl

ifdef(`_EL_CHECK_BOGUS_INREPLYTO', `dnl
R$*					$: $(EL_InReplyToBogus $&{currHeader} $) $| $&{INHEADERS}
R@SPAM $| YES		$#error $@ 5.7.1 $: ifdef(`confEL_ErrInReplyToBogus', `confEL_ErrInReplyToBogus', `"554 BREPLYT Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it contains a suspicious header. (bogus In-Reply-To)"')
')dnl


