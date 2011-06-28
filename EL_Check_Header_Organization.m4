divert(-1)dnl
#
# Copyright (c) 2004-2011 hesketh.com/inc. All rights reserved.

# See the file LICENSE in the distribution for details.

#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_Check_Header_Organization.m4,v 1.13 2011/05/17 18:46:57 schampeo Exp $')
divert(-1)dnl

LOCAL_CONFIG
#------------------------------------------------------------------------
# enemieslist.com Organization: header check patterns and call
#------------------------------------------------------------------------
HOrganization: $>EL_Check_Header_Organization

KEL_OrganizationNumeric regex -a@SPAM ^.?[0-9]+$

KEL_OrganizationWordDotWord regex -a@SPAM ^.?[a-z]+\.[a-z]+$

KEL_Organization sequence EL_OrganizationNumeric EL_OrganizationWordDotWord

LOCAL_RULESETS
#------------------------------------------------------------------------
# enemieslist.com Organization: header checks
#------------------------------------------------------------------------
SEL_Check_Header_Organization
ifdef(`_EL_TRACE', `dnl
R$*					$: $1 $(EL_Log "Organization w/ " $1 "; score: " $&{ELSuspiciousCount} "." $)
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

R$*					$: $(EL_Organization $&{currHeader} $)
R@SPAM				$#error $@ 5.7.1 $: ifdef(`confEL_ErrOrganization', `confEL_ErrOrganization', `"554 SPAMORG Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; suspicious header (Organization)"')


