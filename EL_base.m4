divert(-1)dnl
#
# Copyright (c) 2004-2011 hesketh.com/inc. All rights reserved.

# See the file LICENSE in the distribution for details.

#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_base.m4,v 1.17 2011/05/13 21:00:57 schampeo Exp $')
divert(-1)dnl

LOCAL_CONFIG
# make sure we have a syslog map defined
KEL_Log syslog -S

# and a macro for storage (for legibility)
KEL_SetVar macro

# EL_HostIP checks for A records
KEL_HostIP dns -RA -d30s -t -TTEMP

# EL_IsAnIP checks to see if a "hostname" is actually a bracketed IP
KEL_IsAnIP regex -a<IP> ^\[[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\]$

# EL_GetTLD checks to see if a hostname (PTR) contains focused TLD
KEL_GetTLD regex -a<TLD> -s1 \.(ifdef(`confEL_NOFCrDNS_TLDs', `confEL_NOFCrDNS_TLDs', `(ar|br|co|do|eg|es|fr|gr|gt|id|il|in|it|ky|lv|md|mx|my|pe|ph|pl|pt|ro|ru|th|tr|tv|ua|vn|za)'))\.?$

# EL_GetEmailAddress checks for up to three email addresses, returns one???
KEL_GetEmailAddress regex -a<ADDR> -s3 ^ *(([^><@,]*<)?([^<>@, ]+@[^@><, ]+)>?)

# EL_Math does math
KEL_Math arith

# define standard role accounts
KEL_CheckForRoleAccount regex -a<ROLE> ifdef(`confEL_ROLE_ACCOUNTS', `confEL_ROLE_ACCOUNTS', `(abuse|hostmaster|postmaster|webmaster)')@

# used by several other files
KEL_Generic419Sender regex -a<AFF> ^((award|claim|euro|info|irish|govern|rev|scamvictmpayment|swiss|uk|winners)|.*(assist|attorney|bank|barrister|bonolotaagencia|claim|fortune|jackpot|loteri|lottery|loto|lotto|mariam|million|prince|promo|relief|sweeps|win)).*@

# define our contacts, to be used in rejection error messages
# can also use a URL for either value
# ??? bug: should change the names to reflect when they are used
D{ELContactEmail}ifdef(`confEL_CONTACT_EMAIL', `confEL_CONTACT_EMAIL')
D{ELContactPhone}ifdef(`confEL_CONTACT_PHONE', `confEL_CONTACT_PHONE')

