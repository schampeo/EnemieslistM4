divert(-1)dnl
#
# Copyright (c) 2004-2011 hesketh.com/inc. All rights reserved.

# See the file LICENSE in the distribution for details.

#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_B0rkenRatware.m4,v 1.28 2011/05/17 19:50:08 schampeo Exp $')
divert(-1)dnl

define(`_EL_B0RKEN')dnl

LOCAL_CONFIG
#------------------------------------------------------------------------
# enemieslist.com checks for b0rken randomizing ratware
#------------------------------------------------------------------------
KEL_B0rkenRatware1 regex -f -a@SPAM %(AMS_MESSAGE_SUBJECT|AMS_NEXTPART|CUSTOM_DIGIT|CUSTOM_HELO|CUSTOM_ID|CUSTOM_MAILFRONNAMEBIG|CUSTOM_NUM|FROM_USER|MESSAGEID|REC_WITH|RECEIVED|RND_DATE_TIME|RND_LC_CHAR|RND_MIX\[[0-9]+\]|RNDDIGIT[0-9]+|RNDLCCHAR[0-9]+|RNDUCCHAR[0-9]+|TO_NAME)

# (DOMAIN_FOR_MAILING|RND_|RNDLCCHAR|CURRENT_DATE_TIME|THE2_HEADER_RND_DIGITS_2|TO_NAME|RANDOM_|
# \#random\#|xmailer%|RAND_|\^Fdomains^%|PRI_PROXY%|message_id%|ALLDIGIT%|25RND_WORD|MAKE_TXT|
# REC_WITH|FROM_USER|MESSAGEID|MAILING_DOMAIN|WILD_CARD|OLATTACH|rnddg|CUST_WORD|CUSTOM_|ND_LC_CHAR|
# STATIC_[0-9]WORD|S_FROM_DOMAIN|LIST_IP|S_[0-9]FROM_DOMAIN|UNIQUE_STRING|<Name>,|\#BOUNDARY\#|
# \#MULTIPART\-BOUNDARY\#|from_name|from_email|Lines.longer.than.SMTP.allows.found.and.truncated|REAL_DATE)

KEL_B0rkenRatware2 regex -f -a@SPAM (Lines.longer.than.SMTP.allows.found.and.truncated|RND_WORD)

ifelse(_EL_LIBSUNRE, 1, `dnl
# libre on old suns is broken so we avoid problematic regexes
KEL_B0rkenRatware sequence EL_B0rkenRatware1 EL_B0rkenRatware2
',`
KEL_B0rkenRatware3 regex -f -a@SPAM \\$$(FIRSTNAME|LASTNAME|RANDOM|SUBJECT|[Ff]ield[0-9],?|domain)
KEL_B0rkenRatware sequence EL_B0rkenRatware1 EL_B0rkenRatware2 EL_B0rkenRatware3
')dnl

ifelse(_EL_DONT_B0RKCHECK_ALL_HEADERS, 1, `dnl
#H*: $>EL_Check_B0rkenRatware
',`
H*: $>EL_Check_B0rkenRatware
')dnl

LOCAL_RULESETS
#------------------------------------------------------------------------
# enemieslist.com check for b0rken randomizing ratware
#------------------------------------------------------------------------
SEL_Check_B0rkenRatware
ifdef(`_EL_SKIPLOCAL', `dnl
R$*					$: $1 $| $&{client_addr}
R$* $| 127.0.0.1	$@
')dnl

R$*					$: $(EL_B0rkenRatware1 $&{currHeader} $)
R@SPAM				$#error $@ 5.7.1 $: ifdef(`confEL_ErrB0rkenRatware1', `confEL_ErrB0rkenRatware1', `"554 B0RKENR Contact "$&{ELContactEmail}" if this is in error, but your message was rejected (regex replacement error)."')

R$*					$: $(EL_B0rkenRatware2 $&{currHeader} $)
R@SPAM				$#error $@ 5.7.1 $: ifdef(`confEL_ErrB0rkenRatware2', `confEL_ErrB0rkenRatware2', `"554 B0RKENR Contact "$&{ELContactEmail}" if this is in error, but your message was rejected; it appears to have been mangled by the previous relay and is damaged."')

ifelse(_EL_LIBSUNRE, 1, `dnl
# libre on old suns is broken so we avoid problematic regexes
',`
R$*					$: $(EL_B0rkenRatware3 $&{currHeader} $)
R@SPAM				$#error $@ 5.7.1 $: ifdef(`confEL_ErrB0rkenRatware3', `confEL_ErrB0rkenRatware3', `"554 B0RKENR Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it appears to have been sent by laughably broken spam software."')
')dnl
