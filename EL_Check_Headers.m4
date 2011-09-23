divert(-1)dnl
#
# Copyright (c) 2004-2011 hesketh.com/inc. All rights reserved.

# See the file LICENSE in the distribution for details.

#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_Check_Headers.m4,v 1.34 2011/05/13 22:13:18 schampeo Exp $')
divert(-1)dnl

LOCAL_CONFIG
#------------------------------------------------------------------------
# enemieslist.com miscellaneous header checks for headers only found in spam
#------------------------------------------------------------------------
HMS-OrigTo: $>EL_Check_Header_Exists
HMesg-ID: $>EL_Check_Header_Exists
HRecieved: $>EL_Check_Header_Exists
HReply_to: $>EL_Check_Header_Exists
HX-1: $>EL_Check_Header_Exists
HX-AmazingDeals4You-Userid: $>EL_Check_Header_Exists
HX-AR: $>EL_Check_Header_Exists
HX-AskVersion: $>EL_Check_Header_Exists
#HX-BBounce: $>EL_Check_Header_Exists
HX-BrCs: $>EL_Check_Header_Exists
HX-CS-IP: $>EL_Check_Header_Exists
#HX-Campaign: $>EL_Check_Header_Exists
HX-ChoiceMail-Registration-Request: $>EL_Check_Header_Exists
HX-ClientHost: $>EL_Check_Header_Exists
Hx-delete-me: $>EL_Check_Header_Exists
HX-Delivery: $>EL_Check_Header_Exists
HX-DTR5: $>EL_Check_Header_Exists
# also used by StrongMail (netflix et al.)
#HX-Destination-ID: $>EL_Check_Header_Exists
# possibly eMerge? SA no longer checks for this header
# probably "MailKing"
#HX-EM-Registration: $>EL_Check_Header_Exists
HX-ENVID: $>EL_Check_Header_Exists
HX-Find: $>EL_Check_Header_Exists
HX-GreatestDot-ID: $>EL_Check_Header_Exists
HX-happygoldlucky-MsgID: $>EL_Check_Header_Exists
HX-ICPINFO: $>EL_Check_Header_Exists
# x-identity-key seems to be Mozilla shorthand
#HX-Identity-Key: $>EL_Check_Header_Exists
HX-INFO_AZ: $>EL_Check_Header_Exists
HX-INFO_BZ: $>EL_Check_Header_Exists
HX-INFO_CZ: $>EL_Check_Header_Exists
HX-InsiderzEdge-ID: $>EL_Check_Header_Exists
HX-JLH: $>EL_Check_Header_Exists
HX-JM: $>EL_Check_Header_Exists
# apparently used by legitimate rewards program per CXC
#HX-Job: $>EL_Check_Header_Exists
HX-LCM: $>EL_Check_Header_Exists
HX-Mailer-Sent-By: $>EL_Check_Header_Exists
HX-Mailid: $>EL_Check_Header_Exists
# used by Netflix in addition to hardcore spammers
#HX-MailingID: $>EL_Check_Header_Exists
# removed the next three 09/24/07 due to FPs
#HX-MailPersonEmail: $>EL_Check_Header_Exists
#HX-MailPersonHistoryID: $>EL_Check_Header_Exists
#HX-MailPersonSubscriberID: $>EL_Check_Header_Exists
HX-MailTransfer: $>EL_Check_Header_Exists
HX-Mid: $>EL_Check_Header_Is_A_Hash
HX-Moo: $>EL_Check_Header_Exists
HX-Nediorn: $>EL_Check_Header_Exists
HX-Nexttime: $>EL_Check_Header_Exists
HX-Nominal: $>EL_Check_Header_Exists
HX-RM: $>EL_Check_Header_Exists
ifdef(`_EL_REJECT_XROCKETDSI', `dnl
HX-RocketDSI: $>EL_Check_Header_Exists
')dnl
HX-Rot: $>EL_Check_Header_Exists
HX-SavingzBuy-ID: $>EL_Check_Header_Exists
HX-SavingzBuy-Userid: $>EL_Check_Header_Exists
HX-SavingzBuy-Recipient: $>EL_Check_Header_Exists
HX-Sendera: $>EL_Check_Header_Exists
HX-SP-Track-ID: $>EL_Check_Header_Exists
HX-Streamsendid: $>EL_Check_Header_Exists
HX-Strings-Info: $>EL_Check_Header_Exists
# used by t-online.de, apparently
#HX-TOI-MSGID: $>EL_Check_Header_Exists
HX-Transfer-Number: $>EL_Check_Header_Exists
HX-Transfer-Stamp: $>EL_Check_Header_Exists
# apparently, x-unsent does not mean anything
#HX-Unsent: $>EL_Check_Header_Exists
HX-Version-Info: $>EL_Check_Header_Exists
HX-WCMailID: $>EL_Check_Header_Exists
# used by thawte/rjs0.com
#HX-cid: $>EL_Check_Header_Exists
# used by eweek
#HX-eid: $>EL_Check_Header_Exists
HX-lid: $>EL_Check_Header_Exists
Hage-Info: $>EL_Check_Header_Exists
HX-USED-EQUIPMENT-REQUEST: $>EL_Check_Header_Exists
HX-Sp@mX: $>EL_Check_Header_Exists
# VC Sterling / emarketers
HX-VCM: $>EL_Check_Header_Exists

# checks for various stupid headers only inserted when the message is
# so garbled/mangled/malformed that it should have been rejected
HSun-ONE-SMTP-Warning: $>EL_Check_B0rkenRatware

# check for md5 style hash
KEL_IsAHash regex -a<MATCH> \=$

LOCAL_RULESETS
#------------------------------------------------------------------------
# enemieslist.com miscellaneous header checks for headers only found in spam
#------------------------------------------------------------------------
SEL_Check_Header_Exists
ifdef(`_EL_TRACE', `dnl
R$*					$: $1 $(EL_Log "Exists w/ " $1 "; score: " $&{ELSuspiciousCount} "." $)
')dnl

# skip locally-originating mail
ifdef(`_EL_SKIPLOCAL', `dnl
R$*					$: $1 $| $&{client_addr}
R$* $| 127.0.0.1	$@
')dnl

# check for whitelisted host
R$*					$: $&{ELWhitelisted} 
# now reject the message if it's not a whitelisted host
R$@					$#error $@ 5.7.1 $: ifdef(`confEL_ErrCheck_Headers', `confEL_ErrCheck_Headers', `"554 BADHEAD Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it contains a suspicious header: " $&{hdr_name} "."')

SEL_Check_Header_Is_A_Hash
# skip locally-originating mail
ifdef(`_EL_SKIPLOCAL', `dnl
R$*					$: $1 $| $&{client_addr}
R$* $| 127.0.0.1	$@
')dnl

# check for whitelisted host
R$*					$: $&{ELWhitelisted} 

# now reject the message if it seems to contain a tracking device
R$*					$: $(EL_IsAHash $&{currHeader} $)
R<MATCH>			$>EL_TagSuspicious <ifdef(`confEL_TagErrMsgTracker', `confEL_TagErrMsgTracker', `"header contains tracking device"')> $| 2
