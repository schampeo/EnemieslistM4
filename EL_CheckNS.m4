divert(-1)dnl
#
# Copyright (c) 2004-2011 hesketh.com/inc. All rights reserved.
#
# questions? <support@enemieslist.com>
#
# original version contributed by Bruce Gingery

divert(0)dnl
VERSIONID(`$Id: EL_CheckNS.m4,v 1.5 2011/05/17 19:38:50 schampeo Exp $')dnl
divert(-1)dnl

define(`_EL_CHECKNS', `1')dnl

LOCAL_CONFIG
#
# enemieslist.com banned nameserver lookup maps
#
KEL_LookupNS dns -RNS -d5s -r2
KEL_BannedNS ifdef(`confEL_BADNS_FILE', `confEL_DB_MAP_TYPE' `confEL_BADNS_FILE')

LOCAL_RULESETS
#------------------------------------------------------------------------
# enemieslist.com name server checks
#
# only argument is HELO string or domain of MAIL FROM: sender
# called from Local_check_mail (cf. EL_CheckBestMX.m4)
#------------------------------------------------------------------------
SEL_CheckBannedNS
# check NS against known banned name servers db
R$*						$: $&{mail_addr}
R<$*@$*>				$: <$1@$2> $| $(EL_LookupNS $2 $)

R$* $| $*				$: $1 $| $[ $2 $]
R$* $| $*				$: $1 $| $2

R$* $| $-.$-.$-.$-.		$: $1 $| $2.$3.$4.$5
R$* $| $-.$-.$-.$-		$: $1 $| $(EL_BannedNS $2.$3.$4.$5 $)
R$* $| $-.$-.$-.$-		$: $1 $| $(EL_BannedNS $2.$3.$4 $)
R$* $| $-.$-.$-.$-		$: $1 $| $(EL_BannedNS $2.$3 $)
R$* $| $-.$-.$-.$-		$: $1 $| $(EL_BannedNS $2 $)
R$* $| BANNED			$@ <BANNED>
R$* $| B				$@ <BANNED>
R$*						$@
