divert(-1)dnl
#
# Copyright (c) 2004-2011 hesketh.com/inc. All rights reserved.
#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_Check_Header_XLibrary.m4,v 1.15 2011/05/17 18:06:19 schampeo Exp $')
divert(-1)dnl

#------------------------------------------------------------------------
# enemieslist.com X-Library: header check patterns and call
#------------------------------------------------------------------------
HX-Library: $>EL_Check_Header_XLibrary

KEL_XLibraryIndy regex -a@SPAM ^.*Indy

#------------------------------------------------------------------------
# enemieslist.com X-Library: header checks
#------------------------------------------------------------------------
SEL_Check_Header_XLibrary
ifdef(`_EL_TRACE', `dnl
R$*					$: $1 $(EL_Log "XLibrary w/ " $1 "; score: " $&{ELSuspiciousCount} "." $)
')dnl

ifdef(`_EL_SKIPLOCAL', `dnl
R$*					$: $1 $| $&{client_addr}
R$* $| 127.0.0.1	$@
')dnl

# skip whitelisted hosts
R$*			$: $&{ELWhitelisted}
R$+:$+		$@

ifdef(`_EL_B0RKEN', `dnl
R$*					$: $(EL_B0rkenRatware $&{currHeader} $)
R@SPAM				$#error $@ 5.7.1 $: ifdef(`confEL_ErrB0rkenRatware', `confEL_ErrB0rkenRatware', `"554 B0RKENR Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it appears to have been sent by laughably broken spam software."')
')dnl

R$*					$: $(EL_XLibraryIndy $&{currHeader} $)
R@SPAM				$#error $@ 5.7.1 $: ifdef(`confEL_ErrXLibrary', `confEL_ErrXLibrary', `"554 BADHDXL Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; suspicious header (X-Library)"')

