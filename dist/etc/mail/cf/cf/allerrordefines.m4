# $Id: allerrordefines.m4,v 1.4 2009/02/13 00:48:11 schampeo Exp $
define(`confEL_Err1CharAddys', `"550 1CHRADD Contact "$&{ELContactPhone}" if this is in error, but your mail was refused because your address is bogus."')dnl
define(`confEL_ErrB0rkenRatware', `"554 B0RKENR Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it appears to have been sent by laughably broken spam software."')dnl
define(`confEL_ErrBLSpammer', `"550 SPMRBLK Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail from your IP address, " $&{client_addr} ", which is in a netblock assigned to a known spammer."')dnl
define(`confEL_ErrBTP', `"554 BTPGRUP Contact "$&{ELContactPhone}" if this is in error, but your mail was refused as suspected spam. It looks rather a lot like the sort of trash the BTP Group likes to send us."')dnl
define(`confEL_ErrBadHelos', `"554 BADHELO Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail from hosts that announce themselves via HELO/EHLO as " $&s ", as when we do it is always spam."')dnl
define(`confEL_ErrBadReceived', `"554 NOTRACK Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail from your server as it does not provide adequate tracking of point of injection and is therefore heavily abused."')dnl
define(`confEL_ErrBannedNS', `"550 BANNDNS Contact "$&{ELContactPhone}" if this is in error, but your mail was refused because your domain shares an NS record with a spammer. Clean up your network."')dnl
define(`confEL_ErrBarracuda', `"554 BRACUDA Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail from servers running Barracuda spam appliances. When we do it is always outscatter."')dnl
define(`confEL_ErrBcc', `"554 BCCSPAM Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as unsolicited bulk/commercial mail. (Bcc)"')dnl
define(`confEL_ErrBccBlank', `"554 BCCBLNK Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as unsolicited bulk/commercial mail. (Bcc)"')dnl
define(`confEL_ErrBestMXBanned', `"550 BANNDMX Contact "$&{ELContactPhone}" if this is in error, but your mail was refused because your domain shares an MX record with a spammer. Clean up your network."')dnl
define(`confEL_ErrBestMXDot', `"550 MXISDOT Contact "$&{ELContactPhone}" if this is in error, but your mail was refused because your domain has repudiated mail."')dnl
define(`confEL_ErrBestMXHotmail', `"550 HOTMAIL Contact "$&{ELContactPhone}" if this is in error, but your mail was refused because it was believed to be forged. Use your providers outbound servers."')dnl
define(`confEL_ErrBestMXNoMXFail', `"550 NOMXFAL Contact "$&{ELContactPhone}" if this is in error, but your mail was refused because your domain lacks an MX record. We do not accept mail from anyone we can not complain about it to."')dnl
define(`confEL_ErrBestMXNoMXTemp', `"450 NOMXTMP Contact "$&{ELContactPhone}" if this is in error, but your mail was refused because your domain seems to lack an MX record. We do not accept mail from anyone we can not complain about it to."')dnl
define(`confEL_ErrBestMXOutblaze', `"550 OUTBLZE Contact "$&{ELContactPhone}" if this is in error, but your mail was refused because it was believed to be from a forged Outblaze domain. Use Outblaze outbound servers."')dnl
define(`confEL_ErrBestMXSeznam', `"550 FSEZNAM Contact "$&{ELContactPhone}" if this is in error, but your mail was refused because it was believed to be forged. Use your providers outbound servers."')dnl
define(`confEL_ErrBestMXYahoo', `"550 YAHOOFG Contact "$&{ELContactPhone}" if this is in error, but your mail was refused because it was believed to be forged. Use your providers outbound servers."')dnl
define(`confEL_ErrBlacklist', `"554 BLCKLST Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail from your IP address, " $&{client_addr} ", which has sent or tried to send us UCE/UBE or a virus recently."')dnl
define(`confEL_ErrBogusHelo419', `"554 AFFSPAM Contact "$&{ELContactPhone}" if this is in error, but your message from bogus HELO ("$&{s}") was not accepted. It is a known spam signature."')dnl
define(`confEL_ErrBogusHeloAtriks', `"554 FOOSPAM Contact "$&{ELContactPhone}" if this is in error, but your message from bogus HELO ("$&{s}") was not accepted. It is a known spam signature."')dnl
define(`confEL_ErrBogusHeloBadTLD', `"550 BADTLD Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail from servers that use bogus HELO strings like " $&{s} " (see RFC 2821, section 4.1.1.1)."')dnl
define(`confEL_ErrBogusHeloDotInternal', `"550 INTERNL Contact "$&{ELContactPhone}" if this is in error, but your mail was refused because you have a misconfigured mail server (tip: fix your HELO string per RFC 2821, section 4.1.1.1)."')dnl
define(`confEL_ErrBogusHeloDotLocal', `"550 DOTLOCL Contact "$&{ELContactPhone}" if this is in error, but your mail was refused because you have a misconfigured mail server (tip: fix your HELO string per RFC 2821, section 4.1.1.1)."')dnl
define(`confEL_ErrBogusHeloDottedIP', `"550 DOTQUAD Contact "$&{ELContactPhone}" if this is in error, but we do not accept mail from servers that use bogus HELO strings like " $&{s} " (see RFC 2821, section 4.1.1.1)."')dnl
define(`confEL_ErrBogusHeloNetbios', `"550 NETBIOS Contact "$&{ELContactPhone}" if this is in error, but we do not accept mail from servers that use bogus HELO strings like " $&{s} " (see RFC 2821, section 4.1.1.1)."')dnl
define(`confEL_ErrBogusHeloNumDotNum', `"550 NUM.NUM Contact "$&{ELContactPhone}" if this is in error, but your mail was refused because you have a misconfigured mail server (tip: fix your HELO string per RFC 2821, section 4.1.1.1)."')dnl
define(`confEL_ErrBogusHeloWordDotNumDotNum', `"550 WORDNUM Contact "$&{ELContactPhone}" if this is in error, but your mail was refused because you have a misconfigured mail server (tip: fix your HELO string per RFC 2821, section 4.1.1.1)."')dnl
define(`confEL_ErrBogusMimeVersion', `"554 MIMEVRS Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it contains a forged header."')dnl
define(`confEL_ErrBogusQuotedSender', `"550 BOGUSQS Contact "$&{ELContactPhone}" if this is in error, but your mail was refused because your sender address is bogus."')dnl
define(`confEL_ErrBogusRDNS', `"554 BADRDNS Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail from servers without fully-qualified rDNS."')dnl
define(`confEL_ErrBouncerHelo', `"554 BNCHELO Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail from your null sender; your system is broken and sending us bounces from forged mail we didnt send."')dnl
define(`confEL_ErrBouncerName', `"554 BOUNCER Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail from your null sender; your system is broken and sending us bounces from forged mail we didnt send."')dnl
define(`confEL_ErrCR', `"554 BOGUSCR Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail from your host, which issues bogus challenge/response messages in response to spam/virus traffic."')dnl
define(`confEL_ErrCacheFlowServer', `"550 CACHFLO Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail sent via CacheFlow Servers."')dnl
define(`confEL_ErrCapDotWordNumNum', `"550 CAPDWNN Contact "$&{ELContactPhone}" if this is in error, but your mail was refused as suspected spam."')dnl
define(`confEL_ErrCc', `"554 BUZZOFFC Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as unsolicited bulk/commercial mail. (Cc)"')dnl
define(`confEL_ErrCcCount', `"554 FIVECCS Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. Surely, five Cc: headers are enough."')dnl
define(`confEL_ErrCheck_Headers', `"554 BADHEAD Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it contains a suspicious header: " $&{hdr_name} "."')dnl
define(`confEL_ErrContentDescription', `"554 BADHDCD Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as a possible virus; it contains a suspicious header (Content-Description)."')dnl
define(`confEL_ErrContentDescriptionTracker', `"554 BDHDCDT Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as probable spam; it contains a suspicious header with embedded tracking device."')dnl
define(`confEL_ErrContentEncoding', `"554 BADHDCE Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; suspicious header (Content-Encoding)"')dnl
define(`confEL_ErrContentID', `"554 BDHDCID Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as a possible virus; it contains a suspicious header (Content-Id)."')dnl
define(`confEL_ErrContentIDSpam', `"554 BHDCIDS Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as a probable spam; it contains a suspicious header."')dnl
define(`confEL_ErrContentTypeAllExe', `"554 BADAEXE Contact "$&{ELContactEmail}" if this is in error, but we do not accept executable file attachments as an antivirus measure. We apologize for the inconvenience."')dnl
define(`confEL_ErrContentTypeAllZip', `"554 BADAZIP Contact "$&{ELContactEmail}" if this is in error, but we do not accept compressed file attachments as an antivirus measure. We apologize for the inconvenience."')dnl
define(`confEL_ErrContentTypeExe', `"554 BAD_EXE Contact "$&{ELContactEmail}" if this is in error, but we do not accept executable file attachments as an antivirus measure. We apologize for the inconvenience."')dnl
define(`confEL_ErrContentTypeSpam', `"554 BADHDCT Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it contains a suspicious header."')dnl
define(`confEL_ErrContentTypeVirus', `"554 VIRUSCT Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as a virus; it contains a suspicious header."')dnl
define(`confEL_ErrContentTypeZip', `"554 BAD_ZIP Contact "$&{ELContactEmail}" if this is in error, but we do not accept ZIP file attachments as an antivirus measure. We apologize for the inconvenience."')dnl
define(`confEL_ErrDate', `"554 BADDATE Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam (invalid Date header)."')dnl
define(`confEL_ErrDateWarning', `"554 BADDATW Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam (invalid Date header)."')dnl
define(`confEL_ErrDirectMedsBiz', `"554 DIRCTMD Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. It contains a laughably overused Message-Id: header."')dnl
define(`confEL_ErrDomainBlacklist', `"554 SDOMAIN Contact "$&{ELContactPhone}" if this is in error, but we do not accept mail from your domain."')dnl
define(`confEL_ErrEohMyDoom', `"554 MY_DOOM Contact "$&{ELContactEmail}" if this is in error; your message was rejected as a suspected MyDoom virus delivery attempt."')dnl
define(`confEL_ErrErrorsToSpammerDomain', `"554 ERSTOBL Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. We do not accept mail with a Errors-To: header containing your domain."')dnl
define(`confEL_ErrFrom', `"554 BADFROM Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it contains a suspicious header (From:)"')dnl
define(`confEL_ErrFrom419', `"554 FROM419 Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as a variant of a Nigerian 419 scam based on its origin."')dnl
define(`confEL_ErrFromFMLZZ', `"554 FMLZZ Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. Your From: address is suspect."')dnl
define(`confEL_ErrFromFMLZZFail', `"554 FMLZZFA Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. Your From: address looks fishy, and your mail server lacks reverse DNS."')dnl
define(`confEL_ErrFromFMLZZTemp', `"554 FMLZZTP Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. Your From: address looks fishy, and your mail server seems to lack reverse DNS."')dnl
define(`confEL_ErrFromFMLZZccTLD', `"554 FMLZZCC Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. Your From: address is suspect."')dnl
define(`confEL_ErrFromFMLZZdirectToMX', `"554 FMLZZMX Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. Your From: address is suspect and we do not accept direct-to-MX mail here."')dnl
define(`confEL_ErrFromMobsterFail', `"554 MBSTRFA Contact "$&{ELContactEmail}" if this is in error, but "$&{currHeader}" sounds fishy and your mail server lacks reverse DNS."')dnl
define(`confEL_ErrFromMobsterTemp', `"554 MBSTRTP Contact "$&{ELContactEmail}" if this is in error, but "$&{currHeader}" sounds fishy and your mail server seems to lack reverse DNS."')dnl
define(`confEL_ErrFromMobsterWordlistXOX', `"554 WORDXOX Contact "$&{ELContactEmail}" if this is in error, but "$&{currHeader}" reminds us of some spam we got once. (xox)"')dnl
define(`confEL_ErrFromMobsterWordlistXOXroot', `"554 WRDXOXR Contact "$&{ELContactEmail}" if this is in error, but "$&{currHeader}" reminds us of some spam we got once. (xox root)"')dnl
define(`confEL_ErrFromMobsterWordlistXXO', `"554 WORDXXO Contact "$&{ELContactEmail}" if this is in error, but "$&{currHeader}" reminds us of some spam we got once. (xxo)"')dnl
define(`confEL_ErrFromMobsterWordlistXXOroot', `"554 WRDXXOR Contact "$&{ELContactEmail}" if this is in error, but "$&{currHeader}" reminds us of some spam we got once. (xxo root)"')dnl
define(`confEL_ErrFromMobsterWordlistXXX', `"554 WORDXXX Contact "$&{ELContactEmail}" if this is in error, but "$&{currHeader}" reminds us of some spam we got once. (xxx)"')dnl
define(`confEL_ErrFromMobsterWordlistXXXroot', `"554 WRDXXXR Contact "$&{ELContactEmail}" if this is in error, but "$&{currHeader}" reminds us of some spam we got once. (xxx root)"')dnl
define(`confEL_ErrFromPhish', `"554 PHISHFR Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as a phish scam."')dnl
define(`confEL_ErrFromRunZalkoFail', `"554 RNZALKF Contact "$&{ELContactEmail}" if this is in error, but your address looks fishy and your mail server lacks reverse DNS. (AS/MI)"')dnl
define(`confEL_ErrFromRunZalkoTemp', `"554 RNZALKT Contact "$&{ELContactEmail}" if this is in error, but your address looks fishy and your mail server seems to lack reverse DNS. (AS/MI)"')dnl
define(`confEL_ErrFromSURBL', `"554 SURBLFR Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. We do not accept mail sent from your domain as it is listed by surbl.org."')dnl
define(`confEL_ErrFromSpammerDomain', `"554 BADFRDM Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. We do not accept mail from your domain."')dnl
define(`confEL_ErrFromSubject', `"554 BADFRSB Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. (Subject:, From: matched known spam signature)."')dnl
define(`confEL_ErrFromTo', `"554 BADFRTO Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. (To:, From: matched known spam signature)."')dnl
define(`confEL_ErrFromURIBL', `"554 URIBLFR Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. We do not accept mail sent from your domain as it is listed by uribl.com."')dnl
define(`confEL_ErrGenrdns', `"554 GENRDNS Contact <"$&{ELContactEmail}"> if in error, <"$&f">, but we refuse mail directly from hosts with generic reverse DNS; please use another outbound mail server, "$&{client_name}"."')dnl
define(`confEL_ErrGeographicProxy', `"554 RCD419P Contact "$&{ELContactEmail}" if this is in error, but your message was rejected. We do not accept mail sent via Webmail accounts that hide behind proxies."')dnl
define(`confEL_ErrGeographicSatellite', `"554 RCD419S Contact "$&{ELContactEmail}" if this is in error, but your message was rejected. We do not accept mail sent via Webmail accounts from satellite links."')dnl
define(`confEL_ErrGlowingEdge', `"554 GLWEDGE Contact "$&{ELContactPhone}" if this is in error, but your mail was refused as suspected spam. It looks rather a lot like the sort of trash Glowing Edge likes to send us."')dnl
define(`confEL_ErrHELOSURBL', `"554 SURBLHL Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. We do not accept mail sent from your domain as it is listed by surbl.org."')dnl
define(`confEL_ErrHELOURIBL', `"554 URIBLHL Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. We do not accept mail sent from your domain as it is listed by uribl.com."')dnl
define(`confEL_ErrHeaderTracker', `"554 HEADTRK Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. We do not accept email containing tracking devices."')dnl
define(`confEL_ErrHeloGenrdns', `"554 GENHELO Contact <"$&{ELContactEmail}"> if in error, <"$&f">, but we refuse mail directly from hosts that HELO with generic reverse DNS; please use another outbound mail server, "$&{client_name}"."')dnl
define(`confEL_ErrHibitHelo', `"554 HI_BITS Contact "$&{ELContactEmail}" if this is in error, but your HELO string is bogus (contains hibit characters)."')dnl
define(`confEL_ErrHotmail419', `"554 HOTM419 Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as a likely advance fee fraud."')dnl
define(`confEL_ErrInAddrArpa', `"554 INADDR Contact "$&{ELContactEmail}" if this is in error, but your message was rejected - your reverse DNS is bungled."')dnl
define(`confEL_ErrInReplyToBogus', `"554 BREPLYT Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it contains a suspicious header. (bogus In-Reply-To)"')dnl
define(`confEL_ErrInReplyToForged', `"554 FREPLYT Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it contains a suspicious header. (forged In-Reply-To)"')dnl
define(`confEL_ErrInReplyToTracker', `"554 IRTTRCK Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. We do not accept email containing tracking devices."')dnl
define(`confEL_ErrMXNumberBizUS', `"550 MXNUMBZ Contact "$&{ELContactPhone}" if this is in error, but your mail was refused as suspected spam. We have never received any legitimate mail from any host with a name like yours."')dnl
define(`confEL_ErrMedkitInfo', `"554 MEDKIT Contact "$&{ELContactEmail}" if this is in error, but we believe this message to be spam."')dnl
define(`confEL_ErrMessageIDSpammer', `"554 SPAMMID Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. It contains a suspicious header (Message-ID)."')dnl
define(`confEL_ErrMessageIDSpammerDomain', `"554 MIDSPAM Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. We do not accept mail with a Message-ID: from your domain."')dnl
define(`confEL_ErrMessageIDTracker', `"554 MIDTRCK Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. We do not accept messages containing target tracking devices."')dnl
define(`confEL_ErrMidSURBL', `"554 SURBLMID Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. We do not accept mail containing a Message-Id: from your domain as it is listed by surbl.org."')dnl
define(`confEL_ErrMidURIBL', `"554 URIBLMID Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. We do not accept mail containing a Message-Id: from your domain as it is listed by uribl.com."')dnl
define(`confEL_ErrMsgidAsAddr', `"554 SCRAPED Contact "$&{ELContactPhone}" if this is in error, but your mail was refused because you sent it to a bogus address; it is a Message-ID, not an email address; probably scraped from an online list archive."')dnl
define(`confEL_ErrNoBounce', `"554 NOBOUNCE Contact "$&{ELContactEmail}" if this is in error, but you are sending bounces to an address that sends no mail."')dnl
define(`confEL_ErrNoMsgID', `"554 NOMSGID Contact "$&{ELContactEmail}" if this is in error; your message was rejected as it lacks a Message-ID header and is therefore invalid."')dnl
define(`confEL_ErrNoMsgIDSubject', `"554 NOMIDSB Contact "$&{ELContactEmail}" if this is in error; your message was rejected as it lacks a Message-ID header and and a Subject header."')dnl
define(`confEL_ErrNoMsgIDandGenericRDNS', `"554 NOMIDGR Contact "$&{ELContactEmail}" if this is in error; your message was rejected as it lacks a Message-ID header and your host has generic reverse DNS."')dnl
define(`confEL_ErrNoMsgIDorRDNS', `"554 NOMIDDF Contact "$&{ELContactEmail}" if this is in error; your message was rejected as it lacks a Message-ID header and your host lacks reverse DNS."')dnl
define(`confEL_ErrNoRDNS', `"421 NORDNS Contact "$&{ELContactEmail}" if this is in error, but as far as we can tell, your reverse DNS is missing."')dnl
define(`confEL_ErrOrganization', `"554 SPAMORG Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; suspicious header (Organization)"')dnl
define(`confEL_ErrPermBlacklist', `"554 ROLEACT Contact "$&{ELContactPhone}" if this is in error, but we do not accept mail from your IP address, (" $&{client_addr} "), which has a history of spamming/abusing role accounts, e.g., abuse or postmaster."')dnl
define(`confEL_ErrPhish', `"554 PHISHES Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail from your host, which is a source of annoyingly large amounts of phish attempts."')dnl
define(`confEL_ErrPhishAntiabuse', `"554 PHISHAB Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as a phishing attempt from a compromised webmail system."')dnl
define(`confEL_ErrPhishNoBankAccount', `"554 NOBANK Contact "$&{ELContactEmail}" if this is in error, but you are sending phishing scams to an account that has no finances at all."')dnl
define(`confEL_ErrRecd419', `"554 RECD419 Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as a variant of a Nigerian 419 scam."')dnl
define(`confEL_ErrRecdBad', `"554 BADRECD Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it contains a suspicious header (Received:)"')dnl
define(`confEL_ErrRecdForged', `"554 RECDFRG Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it contains a forged header (Received:)"')dnl
define(`confEL_ErrRecdGeographic', `"554 RCD419G Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as a likely variant of a Nigerian 419 scam."')dnl
define(`confEL_ErrRecdNo419', `"554 RCDN419 Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as a likely variant of a Nigerian 419 scam."')dnl
define(`confEL_ErrReplyTo', `"554 REPLYTO Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it contains a suspicious header (Reply-To:)"')dnl
define(`confEL_ErrReplyToSURBL', `"554 SURBLRT Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. We do not accept mail containing a Reply-To: from your domain as it is listed by surbl.org."')dnl
define(`confEL_ErrReplyToSpammerDomain', `"554 RTOSPAM Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. We do not accept mail containing a Reply-To: from your domain."')dnl
define(`confEL_ErrReplyToURIBL', `"554 URIBLRT Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. We do not accept mail containing a Reply-To: from your domain as it is listed by uribl.com."')dnl
define(`confEL_ErrRightAnchor', `"554 RTANCHR  Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. We do not accept mail from hosts with generic names."')dnl
define(`confEL_ErrRightAnchorHelo', `"554 RTANCHH  Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. We do not accept mail from hosts that HELO with generic names."')dnl
define(`confEL_ErrRoleAcctHTML', `"554 ROLEHTM Contact "$&{ELContactPhone}" if this is in error, but we require messages sent to role accounts be plain text only (no multipart/alternative, aka HTML email, accepted)."')dnl
define(`confEL_ErrRoleAcctMultipart', `"554 ROLE_MP Contact "$&{ELContactPhone}" if this is in error, but we require messages sent to role accounts be plain text only (no multipart/alternative, aka HTML email, accepted)."')dnl
define(`confEL_ErrRoleAcctNoSubj', `"554 BLSBJRA Contact "$&{ELContactPhone}" if this is in error, or resend with a Subject: header. We do not accept blank mail to role accounts due to massive ongoing abuse."')dnl
define(`confEL_ErrRoleAcctTextPlainFlowed', `"554 ROLETPF Contact "$&{ELContactPhone}" if this is in error, but we require messages sent to role accounts be plain text only (no multipart/alternative, aka HTML email, or format=flowed accepted)."')dnl
define(`confEL_ErrSchizoLocalDomains', `"554 LOCLDOM Contact "$&{ELContactPhone}" if this is in error, but your mail was refused because you are forging your HELO string. I am " $&{s} ", not you."')dnl
define(`confEL_ErrSchizoLocalHostname', `"554 LOCALHN Contact "$&{ELContactPhone}" if this is in error, but your mail was refused because you are forging your HELO string. I am " $&{s} ", not you."')dnl
define(`confEL_ErrSchizoLocalIP', `"554 LOCALIP Contact "$&{ELContactPhone}" if this is in error, but your mail was refused because you are forging your HELO string. I am " $&{s} ", not you."')dnl
define(`confEL_ErrSchizoMailDotLocalDomains', `"554 LOCMDOM Contact "$&{ELContactPhone}" if this is in error, but your mail was refused because you are forging your HELO string. I am " $&{s} ", not you."')dnl
define(`confEL_ErrSender', `"554 BADSEND Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it contains a suspicious header (Sender:)"')dnl
define(`confEL_ErrSenderHELORatware', `"554 HELORAT Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as a probable 419/advance fee fraud scam."')dnl
define(`confEL_ErrSenderHibit', `"554 SENDHIB Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it contains a suspicious header (Sender:) (hibit)"')dnl
define(`confEL_ErrSenderSpammerDomain', `"554 SENDSPM Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. We do not accept mail sent from your domain."')dnl
define(`confEL_ErrSpaceInAddr', `"550 ADDRSPC Contact "$&{ELContactPhone}" if this is in error, but your mail was refused because the sender address is bogus."')dnl
define(`confEL_ErrSpamtrap', `"554 GO_AWAY Spammer tries again / nice people do not spam us! / will you never stop?"')dnl
define(`confEL_ErrSubjectBagle', `"554 SUBJBGL Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as a suspected Bagle virus delivery attempt."')dnl
define(`confEL_ErrSubjectEmailHello', `"554 XPLICIT Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. Sexually explicit unsolicited mail not welcome here."')dnl
define(`confEL_ErrSubjectFrom', `"554 SUBJFRM Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. (Subject:, From: matched known spam signature)."')dnl
define(`confEL_ErrSubjectHibit', `"554 SUBJHIB Contact "$&{ELContactEmail}" if this is in error, but this message was rejected. It contains non-ASCII characters in the Subject: header. cf. RFC 2822 Section 2.2."')dnl
define(`confEL_ErrSubjectMatch', `"554 BADSUBJ Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. (Subject: matched known spam signature)."')dnl
define(`confEL_ErrSubjectSober', `"554 SUBJSBR Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as a suspected Sober virus delivery attempt."')dnl
define(`confEL_ErrSubjectSpamX', `"554 NOSPAMX Contact "$&{ELContactEmail}" if this is in error, but we do not accept SpamX abuse reports."')dnl
define(`confEL_ErrSubjectUnwantedISO', `"554 ISOENCD Contact "$&{ELContactEmail}" if this is in error, but this message was rejected. Please resend without encoded Subject: header if this is not spam."')dnl
define(`confEL_ErrSubjectVirusBounce', `"554 SBJVRSB Contact "$&{ELContactEmail}" if this is in error, but this is probably a bogus virus notification. Update your antivirus software not to accept-then-bounce to forged senders."')dnl
define(`confEL_ErrSubjectYahooSpam', `"554 YAHOOSG Contact "$&{ELContactEmail}" if this is in error, but if Yahoo thinks this is spam, we do not want it either."')dnl
define(`confEL_ErrTenDotTenOrTwelve', `"554 TDTTMID Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. It contains a known spam signature."')dnl
define(`confEL_ErrTo', `"554 BADHDTO Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it contains a suspicious header (To:)"')dnl
define(`confEL_ErrToDomainBlacklist', `"554 TDOMAIN Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail sent to users in your domain."')dnl
define(`confEL_ErrToFromCialis', `"554 TO_FROM Contact "$&{ELContactEmail}" if this is in error, but your message was rejected; it seems to be spam (To/From)"')dnl
define(`confEL_ErrToSpamtrap', `"554 GO_AWAY Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as unsolicited bulk/commercial mail. (To)"')dnl
define(`confEL_ErrVipWatches', `"554 VIPWATCH Contact "$&{ELContactEmail}" if this is in error, but we believe this message to be spam."')dnl
define(`confEL_ErrVirus', `"554 VIRUS Contact "$&{ELContactEmail}" if this is in error, but we do not accept mail from your host, which is sending us viruses."')dnl
define(`confEL_ErrWenbzr', `"554 WENBZRS Contact "$&{ELContactPhone}" if this is in error, but your mail was refused as suspected spam. If this was a legitimate abuse report, call us instead."')dnl
define(`confEL_ErrWordwordCapNumletterCapletter', `"554 WWCNLCL Contact "$&{ELContactPhone}" if this is in error, but your mail was refused as suspected spam."')dnl
define(`confEL_ErrXAntiVirusMobsterFail', `"554 MBSTAVF Contact "$&{ELContactEmail}" if this is in error, but we are pretty sure you are a spammer... and your server lacks reverse DNS"')dnl
define(`confEL_ErrXAntiVirusMobsterTemp', `"554 MBSTAVT Contact "$&{ELContactEmail}" if this is in error, but we are pretty sure you are a spammer... and your server seems to lack reverse DNS"')dnl
define(`confEL_ErrXApparentlyFrom', `"554 BDHDXAF Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it contains a suspicious header. (X-Apparently-From)"')dnl
define(`confEL_ErrXAuthenticationWarning', `"554 BDHDXAW Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam (X-Authentication-Warning)."')dnl
define(`confEL_ErrXComment', `"554 BADHDXC Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it contains a suspicious header (X-Comment)."')dnl
define(`confEL_ErrXCommentRFC822', `"554 XCBDDAT Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; if it does not conform to RFC822 minimum requirements, we do not want it, either."')dnl
define(`confEL_ErrXIronport', `"554 BDHDXIP Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; if Ironport thinks it is spam, so do we."')dnl
define(`confEL_ErrXLibrary', `"554 BADHDXL Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; suspicious header (X-Library)"')dnl
define(`confEL_ErrXMailer', `"554 BDHDXML Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it contains a suspicious header (X-Mailer:)."')dnl
define(`confEL_ErrXMessageInfo', `"554 BDHDXMI Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it contains a suspicious header. (X-Message-Info)"')dnl
define(`confEL_ErrXMimeTrack', `"554 BDHDXMT Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. It contains a suspicious header (X-MIMETrack)."')dnl
define(`confEL_ErrXOriginatingIP', `"554 BDHDXOI Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it contains a suspicious header. (XOIP)"')dnl
define(`confEL_ErrXPriorityToken', `"554 XPRIORT Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam. It contains a suspicious header (X-Priority)."')dnl
define(`confEL_ErrXSpamDetect', `"554 XSPMDTC Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam (should have been rejected by relay)."')dnl
define(`confEL_ErrXSpamStatus', `"554 XSPMSTS Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam (should have been rejected by relay)."')dnl
define(`confEL_ErrXVirusScanResult', `"554 REPAIRED Contact "$&{ELContactEmail}" if this is in error, but we do not want repaired viruses, as there is nothing useful left."')dnl
define(`confEL_ErrYahooUserPhish', `"554 PSHUSER Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as a phishing scam; it contains a suspicious header (Received:)"')dnl
define(`confEL_TagErrMsg1DictXMailer', `"XMailer is a single random dictionary word"')dnl
define(`confEL_TagErrMsg2DictXMailer', `"XMailer made up of random dictionary words"')dnl
define(`confEL_TagErrMsg419AFFSource', `"common source of Nigerian 419 spam"')dnl
define(`confEL_TagErrMsg419AFFXMailer', `"may be 419 spam based on XMailer header"')dnl
define(`confEL_TagErrMsgAmberSky', `"message looks like Masterly Intl./Amber Sky"')dnl
define(`confEL_TagErrMsgBadNeighborhood', `"netblock of remote host IP "$&{client_addr}" listed in local blacklist"')dnl
define(`confEL_TagErrMsgBarracuda', `"remote host may be running a barracuda spam appliance."')dnl
define(`confEL_TagErrMsgBlacklistDomain', `"remote host "$&{client_name}" is in blacklisted domain."')dnl
define(`confEL_TagErrMsgBlacklistIP', `"remote host IP "$&{client_addr}" listed in local blacklist"')dnl
define(`confEL_TagErrMsgBogusHELO', `"remote host used bogus HELO "$&{s}"."')dnl
define(`confEL_TagErrMsgBogusrDNS', `"remote host has bogus rDNS "$&{client_name}"."')dnl
define(`confEL_TagErrMsgBouncer', `"Possible outscatter message from known insecure host"')dnl
define(`confEL_TagErrMsgChineseViagra', `"Looks like fake Chinese Viagra spam"')dnl
define(`confEL_TagErrMsgCompressedAttach', `"message contains compressed file attachment."')dnl
define(`confEL_TagErrMsgDirecttoMX', `"Message is direct-to-MX spam"')dnl
define(`confEL_TagErrMsgErrorsToBL', `"message errors-to header contains domain in local blacklist"')dnl
define(`confEL_TagErrMsgExecutableAttach', `"message contains executable file attachment."')dnl
define(`confEL_TagErrMsgFCrDNSHELO', `"HELO resolves to remote IP"')dnl
define(`confEL_TagErrMsgFishyFromflast', `"fishy from header (flast)"')dnl
define(`confEL_TagErrMsgForgedUsInRecd', `"our IP/hostname in Received: header"')dnl
define(`confEL_TagErrMsgFromBL', `"message sent from domain in local blacklist"')dnl
define(`confEL_TagErrMsgFromSURBL', `"from header contains domain in surbl.org blacklist"')dnl
define(`confEL_TagErrMsgFromURIBL', `"message from header contains domain in uribl.com blacklist"')dnl
define(`confEL_TagErrMsgGenericrDNS', `"remote host has generic reverse DNS"')dnl
define(`confEL_TagErrMsgGenericrDNSHELO', `"remote host has generic reverse DNS HELO"')dnl
define(`confEL_TagErrMsgHELOSURBL', `"HELO contains domain in surbl.org blacklist"')dnl
define(`confEL_TagErrMsgHELOURIBL', `"HELO contains domain in uribl.com blacklist"')dnl
define(`confEL_TagErrMsgHotmail419', `"probably 419/advanced fee fraud scam mail"')dnl
define(`confEL_TagErrMsgHotmailBorken', `"Probably a 419 scam; injected via broken hotmail NAT interface"')dnl
define(`confEL_TagErrMsgHTMLorMultipart', `"message contains HTML or multiple parts"')dnl
define(`confEL_TagErrMsgLikelyPhish', `"probable phish attempt"')dnl
define(`confEL_TagErrMsgMedkitInfo', `"probably medkit.info spam gang"')dnl
define(`confEL_TagErrMsgMedkitInfoRoot', `"probably medkit.info spam gang (root)"')dnl
define(`confEL_TagErrMsgMidBL', `"message-id header contains domain in local blacklist"')dnl
define(`confEL_TagErrMsgMidSURBL', `"message-id header contains domain in surbl.org blacklist"')dnl
define(`confEL_TagErrMsgMidURIBL', `"message-id  header contains domain in uribl.com blacklist"')dnl
define(`confEL_TagErrMsgMobster', `"almost certainly mobster"')dnl
define(`confEL_TagErrMsgMobsterOXX', `"fishy from header (mobster wordlist) oxx recd"')dnl
define(`confEL_TagErrMsgMobsterOXXRoot', `"fishy from header (mobster wordlist) oxx recd root"')dnl
define(`confEL_TagErrMsgMobsterXOX', `"fishy from header (mobster wordlist) xox recd"')dnl
define(`confEL_TagErrMsgMobsterXOXRoot', `"fishy from header (mobster wordlist) xox recd root"')dnl
define(`confEL_TagErrMsgMobsterXXO', `"fishy from header (mobster wordlist) xxo recd"')dnl
define(`confEL_TagErrMsgMobsterXXORoot', `"fishy from header (mobster wordlist) xxo recd root"')dnl
define(`confEL_TagErrMsgMobsterXXX', `"fishy from header (mobster wordlist) xxx recd"')dnl
define(`confEL_TagErrMsgMobsterXXXRoot', `"fishy from header (mobster wordlist) xxx recd root"')dnl
define(`confEL_TagErrMsgNobank', `"Banking message sent to address that has no finances"')dnl
define(`confEL_TagErrMsgNobounce', `"Bounce message sent to address that sends no mail"')dnl
define(`confEL_TagErrMsgNomsgid', `"Message has no Message-ID header"')dnl
define(`confEL_TagErrMsgNomsgidGenrdns', `"Message lacks Message-ID header and host has generic rDNS"')dnl
define(`confEL_TagErrMsgNomsgidNorDNS', `"Message lacks Message-ID header and host has no reverse DNS"')dnl
define(`confEL_TagErrMsgNomsgidSubj', `"Message has no Message-ID or Subject header"')dnl
define(`confEL_TagErrMsgNorDNS', `"remote host has no reverse DNS"')dnl
define(`confEL_TagErrMsgOddlyPosted', `"received headers out of order"')dnl
define(`confEL_TagErrMsgPhish', `"message is probably a phish scam"')dnl
define(`confEL_TagErrMsgReplyToBL', `"message reply-to header contains domain in local blacklist"')dnl
define(`confEL_TagErrMsgReplyToSURBL', `"message reply-to header contains domain in surbl.org blacklist"')dnl
define(`confEL_TagErrMsgReplyToURIBL', `"message reply-to header contains domain in uribl.com blacklist"')dnl
define(`confEL_TagErrMsgRightAnchor', `"remote host has generic hostname"')dnl
define(`confEL_TagErrMsgRightAnchorHelo', `"remote host used generic HELO"')dnl
define(`confEL_TagErrMsgSenderBL', `"message sender from domain in local blacklist"')dnl
define(`confEL_TagErrMsgSenderHELO', `"message sent by sender/helo ratware"')dnl
define(`confEL_TagErrMsgSpamtrap', `"Message addressed to a known spamtrap"')dnl
define(`confEL_TagErrMsgTaintedNS', `"domain shares a DNS server with a spammer"')dnl
define(`confEL_TagErrMsgToBL', `"message sent to domain in local blacklist"')dnl
define(`confEL_TagErrMsgTracker', `"header contains tracking device"')dnl
define(`confEL_TagErrMsgVipWatches', `"probably vip watches spam gang"')dnl
define(`confEL_TagErrMsgnonFCrDNSHELO', `"HELO does not resolve to remote IP"')dnl
