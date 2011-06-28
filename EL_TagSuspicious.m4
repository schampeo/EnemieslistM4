divert(-1)dnl
#
# Copyright (c) 2004-2011 hesketh.com/inc. All rights reserved.
#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_TagSuspicious.m4,v 1.14 2011/05/13 21:03:49 schampeo Exp $')
divert(-1)dnl

define(`_EL_TAG_SUSPICIOUS', `1')

LOCAL_CONFIG
#------------------------------------------------------------------------
# enemieslist.com header tagging 
#------------------------------------------------------------------------
H?${ELSuspicious}?ifdef(`confEL_HeaderSuspicious', `confEL_HeaderSuspicious', `X-EL-Suspicious'): ${ELSuspicious}
C{persistentMacros} {ELSuspicious}
H?${ELSuspiciousCount}?ifdef(`confEL_HeaderSuspiciousScore', `confEL_HeaderSuspiciousScore', `X-EL-Suspicious-Score'): ${ELSuspiciousCount}
C{persistentMacros} {ELSuspiciousCount}

LOCAL_RULESETS
#------------------------------------------------------------------------
# enemieslist.com header tagging of suspicious conditions
# first arg is <reason>
# second arg is a value to associate with count, for scoring
#------------------------------------------------------------------------
SEL_TagSuspicious
ifdef(`_EL_TRACE', `dnl
R<$*> $| $-			$: <$1> $| $2 $(EL_Log "EL in EL_TagSuspicious w/ " $1 " / " $2 " (" $&{ELSuspiciousCount} ")" $)
')dnl

# strip quotes
R<$*> $| $-			$: <$(dequote $1 $)> $| $2

# increment score
R<$*> $| $-				$: <$1> $| $(EL_Math + $@ $2 $@ $&{ELSuspiciousCount} $)
R<$*> $| $-				$: <$1> $(EL_SetVar {ELSuspiciousCount} $@ $2 $)

# check for other warnings and catch them
#                          new     old
R<$*>					$: <$1> $| <$&{ELSuspicious}>

# if there are no other warnings, just set flag to current arg and return
R<$*> $| <>				$@ $(EL_SetVar {ELSuspicious} $@ $1 $) ifdef(`_EL_DEBUG_SCORE', `$(EL_Log "EL ELSusp init: " $1 ", count " $&{ELSuspiciousCount} $) ')

# else set it to concatenation of new and old
# ??? problem here is that the errors are largely duplicated
R<$+> $| <$+> 		$: <$1; $2> 

# defang and set variable to concatenated string
R<$+>				$: $(EL_SetVar {ELSuspicious} $@ $1 $) $| $1 
R$* $| $*			$: <DONE> ifdef(`_EL_DEBUG_SCORE', `$(EL_Log "EL ELSusp now " $2 ", cnt " $&{ELSuspiciousCount} $) ')

