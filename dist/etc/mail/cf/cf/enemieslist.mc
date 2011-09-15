dnl ========================================================================
dnl Copyright (c) 2006-8 hesketh.com/inc. All rights reserved.
dnl ------------------------------------------------------------------------
dnl $Id: enemieslist.mc,v 1.10 2009/08/21 16:33:41 schampeo Exp $
dnl -- Sample m4 drop-in for enemieslist.com antispam package
dnl
dnl    NOTE: the following is here only for local testing during development
dnl    Your mileage (and configuration requirements) may vary.
divert(-1)
include(`../m4/cf.m4')
OSTYPE(`Darwin')dnl
DOMAIN(generic)dnl
define(`confDONT_BLAME_SENDMAIL',`GroupWritableDirPathSafe')dnl
DAEMON_OPTIONS(`Port=smtp, Name=MTA')dnl
dnl DAEMON_OPTIONS(`Port=25, Name=MTA Addr=127.0.0.1')
dnl DAEMON_OPTIONS(`Port=25, Name=MTA Addr=10.0.1.1')
DAEMON_OPTIONS(`Port=587, Name=MSA, M=Ea')dnl
define(`QUEUE_DIR', `/var/spool/mqueue')dnl
FEATURE(local_procmail)dnl
FEATURE(use_cw_file)dnl
FEATURE(use_ct_file)dnl
undefine(`UUCP_RELAY')
undefine(`BITNET_RELAY')
define(`confCF_VERSION', `"20070403"')dnl
define(`confCW_FILE', `/etc/mail/local-host-names')dnl
define(`confCT_FILE', `/etc/mail/trusted-users')dnl
define(`confDOMAIN_NAME', `enemieslist.com')dnl
define(`confFORWARD_PATH', `$z/.forward.$w:$z/.forward')dnl
define(`ALIAS_FILE', `/etc/mail/aliases')dnl
define(`confPRIVACY_FLAGS', `goaway')dnl
define(`confCHECKPOINT_INTERVAL', `4')dnl
define(`confMAX_DAEMON_CHILDREN',`48')dnl
define(`confMAX_MESSAGE_SIZE', `10485760')dnl
define(`confMIN_QUEUE_AGE',`5m')dnl
define(`confQUEUE_SORT_ORDER',`host')dnl
define(`confTO_IDENT', `0s')dnl
define(`_MID_IN_MAP_')dnl
define(`confLOG_LEVEL', `20')dnl
dnl 
dnl 
dnl    END dev-only local configuration
dnl 
dnl
dnl -- these must be enabled
dnl
FEATURE(`delay_checks', `friend')dnl
FEATURE(`use_client_ptr')dnl
FEATURE(access_db, `btree -T<TMPF> /etc/mail/access')dnl
dnl
dnl
dnl -- define your db map type. we have found btree to be fastest to rebuild
dnl
define(`confEL_DB_MAP_TYPE', `btree -T<TMPF>')dnl

dnl include your DNSBLs here
dnl -- we include this one so that 'dnsbl' map is defined properly for testing
FEATURE(`dnsbl', `cn.countries.nerd.dk', `"CHINABL Sorry, <"$&f">, your mail was rejected because we do not accept mail from China. Contact postmaster for more information. See http://countries.nerd.dk/more.html"')dnl
dnl

dnl ------------------------------------------------------------------------
dnl enemieslist.com global options
dnl ------------------------------------------------------------------------
dnl
dnl
dnl -- used to check HELO/EHLO arguments and forged headers.
dnl -- this is a regular expression representing all of your local domains
dnl -- deprecated in favor of an approach involving $=w
dnl
define(`confEL_LOCAL_DOMAINS', `(example)\.(com|net|org)')dnl
dnl
dnl
dnl -- this is the local hostname (e.g., the PTR for your primary IP)
dnl -- deprecated in favor of an approach involving $=w
dnl
define(`confEL_LOCAL_HOSTNAME', `mail\.example\.com')dnl
dnl
dnl
dnl -- this is the IP of your primary listening interface
dnl -- if you have multiple IPs you are listening on, make this a regex group
dnl -- deprecated in favor of an approach involving $=w
dnl
define(`confEL_LOCAL_IP', `10\.1\.1\.1')dnl
dnl
dnl
dnl -- this is the same IP but without the escape sequences
dnl
define(`confEL_LOCAL_IP_UNESCAPED', `10.1.1.1')dnl

dnl
dnl -- note that EMAIL and PHONE below can be URLs. EMAIL is used in all
dnl -- error messages after accepting mail for postmaster/abuse and PHONE
dnl -- is used in all error messages before accepting mail for postmaster.
dnl -- PHONE, therefore, is for folks we think are certainly spammers or
dnl -- whose mail servers have been spamming your role accounts and have 
dnl -- been blocked. Feel free to use URLs here instead of email/phone.
dnl
define(`confEL_CONTACT_EMAIL', `postmaster@example.com')dnl
define(`confEL_CONTACT_PHONE', `+1-555-555-1212')dnl
dnl
dnl
dnl -- this is a list of all of your role accounts; YMMV. It is used to
dnl -- specify whether permanentblacklist checks are run on mail with these
dnl -- accounts as recipients. It is of type regex.
dnl
define(`confEL_ROLE_ACCOUNTS', `(abuse|hostmaster|postmaster|webmaster)')dnl

dnl
dnl -- ISO country codes for countries we no longer accept webmail from due
dnl -- to massive ongoing advance fee fraud. Checks IP of injection point,
dnl -- if IP maps to one of the countries below the mail is refused. The
dnl -- following is simply a recommended configuration, you may wish to tweak.
dnl -- "africa" is for non-specific allocations or allocations we cannot verify
dnl -- due to lack of functioning rwhois service. It is of type regex.
dnl
define(`confEL_GEOGRAPHIC_ISOCODES', 
       `(africa|AE|AR|BF|BG|BJ|BW|CI|CY|DK|ES|ET|GH|IL|IR|KE|KR|LB|LV|ML|MR|MY|NG|NL|RW|SN|TG|TH|VN|ZA|ZW)')dnl

dnl
dnl -- Top Level Domains from which you want no mail if the sender has a
dnl -- non-forward-compatible rDNS PTR. It is of type regex.
dnl
define(`confEL_NOFCrDNS_TLDs',
	   `(ar|br|co|de|do|eg|es|fr|gr|gt|id|il|in|it|jo|ky|lv|md|mx|my|pe|ph|pl|pt|ro|ru|th|tr|tv|ua|vn|za)')dnl

dnl
dnl -- if you have domains that you know do not use Reply-To: headers you
dnl -- can block mail with forged Reply-To: headers containing their domain(s)
dnl -- If you do not have such domains leave this as is.
dnl -- It is of type regex.
dnl
define(`confEL_BogusInReplyToDomains', 
	   `(example.com|example.net|example.org)')dnl

dnl
dnl -- check for spam signature used by gothsonline.{org,info}; you will want
dnl -- to enable this and change the pattern below to use your own IP and
dnl -- capitalized localpart(s) if these guys are bothering you.
dnl -- the check looks for trackers/spamsign in the Message-ID header.
dnl -- It is of type regex.
dnl
dnl define(`confEL_Gothsonline',
dnl 	   `(Schampeo|Solutions|.+_Solutions_216\.27\.21\.196)')dnl

dnl
dnl -- check for spam signature used by backrefdvc.com. messages are sent from
dnl -- munged localparts (e.g., "schampeo" becomes "schschampeo" or "scha")
dnl -- enable if they are bothering you.
dnl -- It is of type regex.
dnl
dnl define(`confEL_Backrefdvc', `(exaexample|foofoobar|pospostmaster)')dnl

dnl
dnl -- this is for yet another Ralsky sock puppet with broken spamware (flast)
dnl -- that puts the recipient address into the To: header twice
dnl -- It is of type regex.
dnl
dnl define(`confEL_SameAddressTwice', `(me@example.com,\ me@example.com)')dnl

dnl
dnl -- catch millions CD spam with fictional recipient names or whois scrapes.
dnl -- This checks the Subject: header only.
dnl -- It is of type regex.
dnl
dnl define(`confEL_ToMillionsCD', `(Mailutilities|Firstname\ Lastname)')dnl

dnl
dnl -- catch spam with peculiar treatment of localpart (line starts with the
dnl -- localpart followed by a colon or comma)
dnl -- These are of type regex.
dnl
dnl define(`confEL_LocalpartColon', `(Abuse|Postmaster)')dnl
dnl define(`confEL_LocalpartComma', `(Abuse|Postmaster)')dnl

dnl
dnl -- if you know your users do not read Chinese, Korean, etc. block mail
dnl -- with unwanted content types below
dnl -- These are of type regex.
dnl
dnl define(`confEL_UnwantedISO', `(big5|[Gg][Bb]2312|ks_c_5601\-1987|windows\-125[125]|koi8\-r|ISO\-2022\-JP)')dnl

dnl
dnl -- define "tag" header name
dnl -- It is of type string.
dnl
define(`confEL_HeaderSuspicious', `X-EL-Suspicious')dnl

dnl
dnl -- define values for scoring: generic, static, dynamic HELO and rDNS
dnl
define(`confEL_ScoreHELOGEN', `4')dnl
define(`confEL_ScoreHELOGENStatic', `4')dnl
define(`confEL_ScoreHELOGENDynamic', `4')dnl
define(`confEL_ScoreGENRDNS', `3')dnl
define(`confEL_ScoreGENRDNSStatic', `2')dnl
define(`confEL_ScoreGENRDNSDynamic', `3')dnl
dnl
dnl -- also rightanchor scores for each
dnl
define(`confEL_ScoreRightHELOGeneric', `3')dnl
define(`confEL_ScoreRightHELOStatic', `2')dnl
define(`confEL_ScoreRightHELODynamic', `3')dnl
define(`confEL_ScoreRightGeneric', `3')dnl
define(`confEL_ScoreRightStatic', `2')dnl
define(`confEL_ScoreRightDynamic', `3')dnl

dnl -- looks like a Storm MID (default: 4)
define(`confEL_ScoreStormMID', `4')dnl
dnl -- 10or12@ MIDs (default: 3)
define(`confEL_Score10or12atMID', `3')dnl
dnl -- looks like a tracking device (default: 3)
define(`confEL_ScoreTrackMID', `3')dnl
dnl -- other suspicious MID pats (default: 3)
define(`confEL_ScoreSuspiciouskMID', `3')dnl

dnl
dnl -- define value for scoring message where domain is blacklisted
dnl
define(`confEL_ScoreDOMAINSBL', `4')dnl

dnl 
dnl -- define values for scoring fingerprinted hosts by OS version/patchlevel
dnl
define(`confEL_ScoreWin95', `5')dnl
define(`confEL_ScoreWin98', `4')dnl
define(`confEL_ScoreWin2000SP4', `1')dnl
define(`confEL_ScoreWin2000SP3', `2')dnl
define(`confEL_ScoreWin2000SP2', `3')dnl
define(`confEL_ScoreWin2000SP1', `3')dnl
define(`confEL_ScoreWinXP', `3')dnl
define(`confEL_ScoreWin2003', `1')dnl

dnl ------------------------------------------------------------------------
dnl -- Local db files
dnl -- NOTE: These files are located by default in your /etc/mail directory
dnl -- or wherever your sendmail.cf file lives. 
dnl ------------------------------------------------------------------------
dnl -- enable local antispam policy for default and for individual addresses
dnl -- also need to define policy flat file/db and include the policy m4
dnl
dnl -- EL_DEFAULT WAS the "canonical" form of the enemieslist rDNS rulesets.
dnl -- it is now deprecated and will be removed
dnl
dnl define(`_EL_DEFAULT', `1')dnl
define(`confEL_POLICY_FILE', `policy')dnl
define(`_EL_POLICY', `1')dnl

dnl
dnl -- define domain-specific abuse contacts; this will emit compact log lines
dnl -- that you can parse with a cronjob to send auto-reports of abuse to those
dnl -- ISPs that request such reports.
dnl
define(`confEL_ABUSE_CONTACTS_FILE', `abusecontacts')dnl
define(`_EL_REPORT_ABUSE', `1')dnl

dnl
dnl -- name/location of dictionary used to detect Mobster I. Syphilitic spam
dnl -- and other forgeries and header noise
dnl
define(`confEL_WORDLIST_FILE', `wordlist')dnl

dnl
dnl -- name/location of IP-based whitelist file
dnl
define(`confEL_WHITELIST_FILE', `whitelist')dnl

dnl
dnl -- name/location of IP-based blacklist file
dnl
define(`confEL_BLACKLIST_FILE', `blacklist')dnl

dnl
dnl -- name/location of domain blacklist file
dnl
define(`confEL_DOMAIN_BLACKLIST_FILE', `domains')dnl

dnl
dnl -- name/location of "offwhite" list file; may be used for filtering and
dnl -- quarantining (e.g., using procmail or client-side mail filters) mail
dnl -- from suspect or distrusted hosts that may also emit legitimate mail
dnl
define(`confEL_OFFWHITELIST_FILE', `offwhitelist')dnl

dnl
dnl -- name/location of spamtraps file, for catching mail also sent to legit
dnl -- addresses where spamtrap is embedded in To:, Cc: headers
dnl
define(`confEL_SPAMTRAPS_FILE', `spamtraps')dnl

dnl
dnl -- name/location of IP-based blacklist for IPs that have abused your
dnl -- role accounts in the past. Relies on confEL_ROLE_ACCOUNTS above.
dnl
define(`confEL_PERMANENTBLACKLIST_FILE', `permanentblacklist')dnl

dnl
dnl -- name/location of IP octet/netblock to ISO country code crosswalk
dnl -- for blocking unwanted mail injected from countries where abuse is
dnl -- rampant (e.g., advance fee fraud mail from NG)
dnl
define(`confEL_GEOGRAPHIC_FILE', `geographic')dnl

dnl
dnl -- name/location of file containing list of known bad HELO/EHLO strings
dnl -- commonly used by spamware or infected machines
dnl
define(`confEL_BADHELOS_FILE', `badhelos')dnl

dnl
dnl -- name/location of marginally useful list of "bad" MX IPs shared by
dnl -- spammers; a great idea that never panned out, but no harm in keeping
dnl -- it enabled anyway.
dnl
define(`confEL_BADMX_FILE', `bannedmx')dnl

dnl
dnl -- name/location of marginally useful list of "bad" NS IPs shared by
dnl -- spammers; a great idea that never panned out, but no harm in keeping
dnl -- it enabled anyway.
dnl
define(`confEL_BADNS_FILE', `bannedns')dnl

dnl DEPRECATED - use OUTSCATTER (below) as it has much finer-tuned tokens
dnl -- name/location of file containing hostnames/IPs of known outscatter
dnl -- sources; mail from null sender (and several other common localparts)
dnl -- will be refused from these hosts.
dnl
define(`confEL_BOUNCER_FILE', `bouncers')dnl

dnl
dnl -- name/location of file containing hostnames/IPs of known outscatter
dnl -- sources; mail from null sender (and several other common localparts)
dnl -- will be refused from these hosts.
dnl
define(`confEL_OUTSCATTER_FILE', `outscatter')dnl

dnl
dnl -- crazy hack that returns a 551 "user not local" forwarding request
dnl -- to outscatter senders in a vain attempt to get them to realize the
dnl -- scope of the problem. Probably pointless but it was fun.
dnl
define(`_EL_RETURN_OUTSCATTER', `1')dnl

dnl
dnl -- name/location of file containing "right anchor" substrings, formerly
dnl -- handled by access.db, but set aside for better control over rejects
dnl -- and trap addresses that you may want to feed into analysis or 
dnl -- honeypots. 
dnl
define(`confEL_RIGHTANCHOR_FILE', `rightanchors')dnl

dnl ------------------------------------------------------------------------
dnl -- Custom error definitions
dnl -- Any custom error or tagging messages should be defined here
dnl -- see http://enemieslist.com/downloads/allerrordefines.m4
dnl -- for list of all custom error and tag message defaults
dnl ------------------------------------------------------------------------

dnl ------------------------------------------------------------------------
dnl -- Debugging - fill your logs with lots of noisy junk that may or may
dnl -- not necessarily be useful for debugging
dnl ------------------------------------------------------------------------
define(`_EL_DEBUG', `1')dnl
dnl -- or just debug the TagSuspicious scores as they are set/incremented
define(`_EL_DEBUG_SCORE', `1')dnl

dnl ------------------------------------------------------------------------
dnl -- DNSBL lookup/logger interface support (not yet publically available)
dnl ------------------------------------------------------------------------
define(`_EL_DNSBL', `1')dnl

dnl ------------------------------------------------------------------------
dnl -- Switches for various antispam/forgery/virus/abuse checks
dnl ------------------------------------------------------------------------

dnl
dnl -- catch sender/helo ratware
dnl
define(`_EL_2LDHELOFORGERY', `1')dnl

dnl
dnl -- 4xx reply to hosts with no rDNS
dnl
define(`_EL_4XX_NORDNS', `1')dnl

dnl
dnl -- quarantine mail from hosts with no rDNS - if AOL can reject such
dnl -- messages, so can we. YMMV.
dnl
dnl define(`_EL_TAG_NORDNS', `1')dnl

dnl
dnl -- tag/score mail from hosts that HELO with a bracketed IP
dnl 
define(`_EL_TAG_HELO_BRACKETED_IP', `1')dnl

dnl
dnl -- slavishly obey the dictates of RFC 2142
dnl
define(`_EL_ACCEPT_ALL_LOCAL_ROLE_ACCTS', `1')dnl

dnl
dnl -- refuse mail with no Subject: header sent to role accounts
dnl
define(`_EL_BLANK_SUBJ_ROLEACCT', `1')dnl

dnl
dnl -- reject mail from Barracuda "antispam" appliances because it is all
dnl -- usually unwanted outscatter. May be becoming obsolete as more and
dnl -- more admins find clues under their desk.
dnl
define(`_EL_BLOCK_BARRACUDA', `1')dnl

dnl
dnl -- reject all mail sent via tin.it webmail systems, which are compromised
dnl 
define(`_EL_BLOCK_TINIT_WEBMAIL', `1')dnl

dnl
dnl -- special check to block mail from hosts with rDNS of . (dot)
dnl
define(`_EL_BLOCKDOTASRDNS', `1')dnl

dnl
dnl -- reject mail containing common executable attachments
dnl
define(`_EL_BLOCK_EXE', `1')dnl
dnl
dnl -- reject mail containing anything that looks like an executable
dnl
dnl define(`_EL_BLOCK_ALL_EXE', `1')dnl
dnl
dnl -- reject mail containing anything that looks like a compressed archive
dnl
dnl define(`_EL_BLOCK_ALL_ZIP', `1')dnl
dnl
dnl -- reject mail containing common compressed attachments
dnl
dnl define(`_EL_BLOCK_ZIP', `1')dnl

dnl
dnl -- assume that HTML email to role accounts is spam and respond accordingly
dnl
define(`_EL_BLOCK_HTML_TO_ROLEACCTS', `1')dnl

dnl 
dnl -- aggressively block anything that looks like a postcard phish
dnl
dnl define(`_EL_BLOCK_POSTCARDS', `1')dnl

dnl
dnl -- check for specific flavor of ratware that HELOs with forged names
dnl -- from various big North American ISPs and cable operators
dnl
define(`_EL_BOGUS_BIGISP_HELO', `1')dnl

dnl
dnl -- assume that malformed sender of form <"foo"@localhostname> is unwanted
dnl
define(`_EL_BOGUS_QUOTED_SENDER', `1')dnl

dnl DEPRECATED - use OUTSCATTER (below) instead
dnl -- this turns on bouncer/backscatter checks
dnl
dnl define(`_EL_BOUNCERS', `1')dnl

dnl
dnl -- this turns on bouncer/backscatter checks
dnl
define(`_EL_OUTSCATTER', `1')dnl

dnl
dnl -- check to see if sender domain has an MX record
dnl
define(`_EL_CHECK_BESTMX', `1')dnl

dnl
dnl -- check point of injection if possible against local blacklists
dnl
define(`_EL_CHECKINJECTION', `1')dnl

dnl
dnl -- assume that 5 digit Message-ID-style "address" is scraped and bogus
dnl
define(`_EL_CHECK_5DIGITMSGID_AS_ADDR', `1')dnl

dnl
dnl -- check to see if sender domain MX is listed as known bad/shared MX
dnl
define(`_EL_CHECK_BANNED_MX', `1')dnl

dnl
dnl -- check to see if sender domain NS is listed as known bad/shared NS
dnl
define(`_EL_CHECK_BANNED_NS', `1')dnl

dnl
dnl -- check for a wide variety of silly HELO strings ranging from NetBIOS
dnl -- names common to viruses to localhost to ".int" or ".local" suggestive
dnl -- of poorly maintained/configured or just slack mail servers (see below)
dnl
define(`_EL_CHECK_BOGUS_HELO', `1')dnl

dnl 
dnl -- check for bogus In-Reply-To headers containing domains you know are
dnl -- never used in Message-Id headers.
dnl -- Requires definition of confEL_BogusInReplyToDomains above in order
dnl -- to do anything terribly useful.
dnl
define(`_EL_CHECK_BOGUS_INREPLYTO', `1')dnl

dnl 
dnl -- switch to selectively turn on checking for .internal and .local
dnl -- some report false positives from refusing on this and must be able
dnl -- to discriminate between known malware patterns and badly configured
dnl -- mail servers
dnl
define(`_EL_BOGUSHELO_INTERNAL_LOCAL', `1')dnl

dnl
dnl -- check for bogus hotmail, outblaze, seznam forgeries
dnl
define(`_EL_CHECK_BOGUS_HOTMAIL', `1')dnl
define(`_EL_CHECK_BOGUS_OUTBLAZE', `1')dnl
define(`_EL_CHECK_BOGUS_SEZNAM', `1')dnl

dnl
dnl -- check for a variety of scraped Message-ID "addresses"
dnl -- deprecated in favor of approach using $=w
dnl define(`_EL_CHECK_MSGID_AS_ADDR', `1')dnl

dnl
dnl -- check for a variety of scraped Message-ID "addresses"
define(`_EL_CHECK_MSGID_AS_ADDR_CLASSW', `1')dnl

dnl
dnl -- check for a variety of bogus HELO formats that do not match the
dnl -- requirements set forth in RFC 2821
dnl
define(`_EL_CHECK_RFCBOGUS_HELO', `1')dnl

dnl
dnl -- check for hosts claiming to be /you/
dnl -- deprecated in favor of approach using $=w
dnl define(`_EL_CHECK_SCHIZO', `1')dnl

dnl 
dnl -- check for hosts claiming to be /you/
define(`_EL_CHECK_SCHIZO_CLASSW', `1')dnl

dnl
dnl -- check various message headers for domains listed in surbl.org
dnl
define(`_EL_CHECK_SURBL_DOMAIN', `1')dnl

dnl
dnl -- check various message headers for domains listed in uribl.com
dnl
define(`_EL_CHECK_URIBL_DOMAIN', `1')dnl

dnl
dnl -- check HELO for domains listed in surbl.org
dnl
define(`_EL_CHECK_SURBL_DOMAIN_HELO', `1')dnl

dnl
dnl -- check HELO for domains listed in uribl.com
dnl
define(`_EL_CHECK_URIBL_DOMAIN_HELO', `1')dnl

dnl
dnl -- check for "Dazzling" spammer (probably obsolete)
dnl
define(`_EL_DAZZLING', `1')dnl

dnl
dnl -- score probably fake "The Bat!" X-Mailer
dnl
define(`_EL_DISTRUST_THEBAT', `1')dnl

dnl
dnl -- reject mail with known blacklisted domains in certain headers     
dnl (From, Message-ID, To, Reply-To, etc.)
define(`_EL_DOMAIN_BLACKLIST', `1')dnl

dnl
dnl -- check for helloinc spammer (uses various illegal "sexually explicit"
dnl -- tokens in his subject lines)
dnl
define(`_EL_EMAILHELLOINC', `1')dnl

dnl
dnl -- check for a peculiar form of Message-ID or In-Reply-To header
dnl
define(`_EL_FINANCIALNETVENTURE', `1')dnl

dnl
dnl -- check for spam signature common to spam from BTP Group
dnl
define(`_EL_FOAD_BTP', `1')dnl

dnl
dnl -- check for spam signature common to spam for directmeds.biz
dnl
define(`_EL_FOAD_DIRECTMEDS', `1')dnl

dnl
dnl -- check for spam signature common to spam for spokeez.com
dnl -- may also see in blowback from forged spam runs. Sender has
dnl -- forged address of the form FirstMLastdictionary@
dnl
define(`_EL_FOAD_FirstMLastdictionary', `1')dnl

dnl
dnl -- check for spam signature common to spam for Glowing Edge
dnl
define(`_EL_FOAD_GLOWING_EDGE', `1')dnl

dnl
dnl -- check for spam signature common to spam for medkit.info
dnl
define(`_EL_FOAD_MEDKITINFO', `1')dnl

dnl
dnl -- check for spam signature common to spam for VIP Watches
dnl
define(`_EL_FOAD_VIPWATCHES', `1')dnl

dnl
dnl -- check for spam signature common to spam from wenbzr/virility pro
dnl
define(`_EL_FOAD_WENBZR', `1')dnl

dnl
dnl -- check for a variety of header forgeries involving your IP/domain
define(`_EL_FORGED_CLASS_W', `1')dnl

dnl
dnl -- check for spam signature common to Global Marketing
dnl
define(`_EL_GLOBAL_MARKETING', `1')dnl

dnl
dnl -- check for spam signature common to gothsonline
dnl
define(`_EL_GOTHSONLINE', `1')dnl

dnl
dnl -- reject mail with FROM containing >7bit ASCII
dnl
define(`_EL_HIBIT_FROM', `1')dnl

dnl
dnl -- reject mail with HELO containing >7bit ASCII
dnl
define(`_EL_HIBIT_HELO', `1')dnl

dnl
dnl -- reject mail with Subject: containing >7bit ASCII
dnl
define(`_EL_HIBIT_SUBJECT', `1')dnl

dnl
dnl -- reject mail containing X-RocketDSI header. It is all spam here.
dnl -- Yahoo! knows about the problem, but is not fixing it.
dnl
define(`_EL_REJECT_XROCKETDSI', `1')dnl

dnl
dnl -- check for common localparts in hotmail 419 spam
dnl
define(`_EL_HOTMAIL_419', `1')dnl

dnl
dnl -- check for common localparts in general 419 spam
dnl
define(`_EL_GENERIC_419', `1')dnl

dnl
dnl -- check for geographic origin of injection IP (for 419 scams)
dnl
define(`_EL_GEOBLOCK', `1')dnl

dnl
dnl -- and special check for "proxying for" SquirrelMail w/RFC1918
dnl -- injection IP and possibly prohibited relay server geography
dnl
define(`_EL_GEOBLOCK_SQUIRRELMAIL', `1')dnl

dnl
dnl -- quarantine 419/AFF scam mail sent via broken hotmail NAT interface
dnl -- NOTE: has moderately high FP rate
dnl
define(`_EL_HOTMAIL_XOIP_BORKEN', `1')dnl

dnl
dnl -- Outlook is deliberately broken, and does not include a Message-ID
dnl -- header in mail not sent via Exchange, to prevent exposure of local
dnl -- network names like "LAPTOP" or "OEM-SHDNFHDG" which are of very high
dnl -- value to anyone wanting to break into Windows networks without using
dnl -- any of the hundreds of other more obvious methods. This check excuses
dnl -- such broken mail from the "NOMSGID" checks below, on the grounds that
dnl -- the message is in fact deliberately broken and cannot be held 
dnl -- responsible, even if it lacks a Subject or comes from a misconfigured
dnl -- host with no or generic rDNS. YMMV.
dnl
define(`_EL_IGNORE_OUTLOOK_NOMSGID', `1')dnl

dnl
dnl -- Tag mail if HELO does not resolve to IP of connecting host
dnl -- One day we will be able to turn this on without FPs. Not yet.
dnl
dnl define(`_EL_MATCH_HELO_TO_IP', `1')dnl

dnl
dnl -- check if the Subject: matches confEL_ToMillionsCD. Many $millions
dnl -- CDs (containing "millions" of addresses) come with laughably bogus
dnl -- "real names", e.g., "Mignetta Doody", and these often show up in the
dnl -- To/Subject: headers and can safely be rejected
dnl
define(`_EL_MILLIONSFORGERY', `1')dnl

dnl
dnl -- check for "Mobster. I Syphilitic" spamware signature
dnl
define(`_EL_MOBSTER', `1')dnl

dnl
dnl -- check for ROKSO spammer Steve Goudreault. He likes to name his spam
dnl -- cannons "mx01.somestring.biz" or "mx23.otherstring.us".
dnl
define(`_EL_MXNUMBERBIZUS_HELO', `1')dnl

dnl
dnl -- check for X-Mailers found in 419 spam
dnl
define(`_EL_NO419XMAILER', `1')dnl

dnl
dnl -- reject mail from CacheFlow servers, common source of spam/abuse
dnl
define(`_EL_NOCACHEFLOW', `1')dnl

dnl
dnl -- reject mail from hosts without forward-compatible rDNS if their
dnl -- TLD is in the list defined by confEL_NOFCrDNS_TLDs
define(`_EL_NOFCRDNS', `1')dnl

dnl
dnl -- check X-Mailer value against wordlist to catch spam tracking devices
dnl
define(`_EL_ONEWORDXMAILER', `1')dnl
define(`_EL_TWOWORDXMAILER', `1')dnl

dnl
dnl -- check for spam signature containing forged header with our IP
dnl
define(`_EL_OPENPHARMACY', `1')dnl

dnl
dnl -- check for various signs of phishing scams
dnl
define(`_EL_PHISH', `1')dnl

dnl 
dnl -- quarantine messages containing images
dnl
define(`_EL_QUARANTINE_IMAGE_SPAM', `1')dnl

dnl 
dnl -- quick rejection of mail from hosts with no reverse DNS
dnl 
define(`_EL_QUICK_REFUSE_NORDNS', `1')dnl

dnl
dnl -- reject spam tagged by Yahoo! but forwarded anyway (trust SpamGuard)
dnl
define(`_EL_REJECT_YAHOO_SPAM', `1')dnl

dnl
dnl -- check for spam signature common to run-zalko spamgang
dnl
define(`_EL_RUN_ZALKO', `1')dnl

dnl
dnl -- check and refuse mail sent to the same address twice (spamware bug)
dnl -- requires confEL_SameAddressTwice be defined
dnl
define(`_EL_SAMEADDRTWICE', `1')dnl

dnl 
dnl -- scoring-based message rejection or quarantine
dnl
define(`_EL_SCORING', `1')dnl

dnl 
dnl -- treat HTML email as suspect, tag / score it as such
dnl 
define(`_EL_SCORE_HTML_AS_EVIL', `1')dnl

dnl
dnl -- check for spam signature common to Egyptian spammers settecltd.
dnl
define(`_EL_SETTECLTD', `1')dnl

dnl
dnl -- skip header and other checks for mail originating locally
dnl
define(`_EL_SKIPLOCAL', `1')dnl

dnl
dnl -- reject bogus SpamX spam complaints
dnl
define(`_EL_SPAMX', `1')dnl

dnl
dnl -- tag messages with no Message-ID header for quarantine
dnl -- NOTE: see also _EL_IGNORE_OUTLOOK_NOMSGID above
dnl
define(`_EL_TAG_NOMSGID', `1')dnl
dnl
dnl -- tag messages with no Message-ID header and generic rDNS for quarantine
dnl
define(`_EL_TAG_NOMSGID_AND_GENRDNS', `1')dnl
dnl
dnl -- tag messages with no Message-ID header and no rDNS for quarantine
dnl
define(`_EL_TAG_NOMSGID_OR_RDNS', `1')dnl
dnl
dnl -- tag messages with no Message-ID header and no Subject for quarantine
dnl
define(`_EL_TAG_NOMSGID_OR_SUBJECT', `1')dnl
dnl
dnl -- these next three are unreliable at best
dnl
dnl define(`_EL_REJECT_NOMSGID_AND_GENRDNS', `1')dnl
dnl define(`_EL_REJECT_NOMSGID_OR_RDNS', `1')dnl
dnl define(`_EL_REJECT_NOMSGID_OR_SUBJECT', `1')dnl

dnl
dnl -- do not immediately accept mail for role accounts. IOW, postpone such
dnl -- acceptance until after other checks have been performed
dnl
define(`_EL_TENTATIVE_ROLEACCTS', `1')dnl

dnl
dnl -- potentially unsafe check for Storm Message-Id format
dnl
dnl define(`_EL_UNSAFE_STORMCHECK', `1')dnl

dnl
dnl -- check for spam signature in X-Mailer header
dnl
define(`_EL_VERSIONNUMGIBBERISH', `1')dnl

dnl
dnl -- use the wordlist file
dnl
define(`_EL_WORDLIST', `1')dnl

dnl
dnl -- check for spam signature in message sender
dnl
define(`_EL_WORDWORDCAPNUMLETTERCAPLETTER', `1')dnl

dnl
dnl -- check for common spam signature; not safe yet
dnl
dnl define(`_EL_TENDOTTENORTWELVEAT', `1')dnl

dnl ------------------------------------------------------------------------
dnl -- Various switches that may be unsafe/unwise to use for various reasons
dnl ------------------------------------------------------------------------
dnl
dnl -- check for spam signature in message sender
dnl
dnl define(`_EL_CAPDOTWORDNUMNUM', `1')dnl
dnl
dnl -- skip b0rken check for unknown headers
dnl
dnl define(`_EL_DONT_B0RKCHECK_ALL_HEADERS', `1')dnl
dnl
dnl -- sadly, gmail often contains an RFC 1918 10/8 injection point
dnl
dnl define(`_EL_GMAIL10SLASH8', `1')dnl
dnl
dnl -- be a standards nazi and enforce FQDN in rDNS PTR (some day this will
dnl -- not cause zillions of FPs)
dnl
dnl define(`_EL_RDNSNOTFQDN', `1')dnl
dnl
dnl -- sadly, many "send to friend" and newsletters, etc. are direct-to-MX
dnl
dnl define(`_EL_TAG_DIRECTTOMX', `1')dnl

dnl
dnl -- for fingerprinting; requires a working p0f install
dnl -- and a copy of p0fqel.c from contrib directory 
dnl define(`_EL_FINGERPRINT', `1')dnl
dnl define(`confEL_P0FSOCK', `/var/run/p0fsock')dnl
dnl define(`confEL_P0FQEL', `/usr/sbin/p0fqel')dnl

dnl ------------------------------------------------------------------------
dnl -- various m4 files to set up maps, various spamware checks, and so on
dnl -- many of these require definitions of their filenames, as for example
dnl -- in confEL_POLICY_FILE or confEL_ABUSE_CONTACTS_FILE above
dnl ------------------------------------------------------------------------
dnl -- common definitions used by all EL files
HACK(`EL_base')dnl

HACK(`EL_B0rkenRatware')dnl
HACK(`EL_Badhelos')dnl
HACK(`EL_Blacklist')dnl
dnl HACK(`EL_Bouncers')dnl
HACK(`EL_Outscatter')dnl
HACK(`EL_CheckBestMX')dnl
HACK(`EL_CheckNS')dnl
HACK(`EL_DomainsBlacklist')dnl
HACK(`EL_FirstMLastZZ')dnl
HACK(`EL_Geographic')dnl
HACK(`EL_Offwhitelist')dnl
HACK(`EL_PermBlacklist')dnl
HACK(`EL_Phish')dnl
HACK(`EL_Policy')dnl
HACK(`EL_ReportAbuse')dnl
HACK(`EL_RightAnchors')dnl
HACK(`EL_Spamtrap')dnl
HACK(`EL_TagSuspicious')dnl
HACK(`EL_Whitelist')dnl
HACK(`EL_Wordlist')dnl

dnl ------------------------------------------------------------------------
dnl -- Individual header checks
dnl -- These enable checks for spamsign in the headers named below
dnl ------------------------------------------------------------------------
HACK(`EL_Check_Header_AutoSubmitted')dnl
HACK(`EL_Check_Header_Bcc')dnl
HACK(`EL_Check_Header_Cc')dnl
HACK(`EL_Check_Header_ContentDescription')dnl
HACK(`EL_Check_Header_ContentEncoding')dnl
HACK(`EL_Check_Header_ContentID')dnl
HACK(`EL_Check_Header_ContentType')dnl
HACK(`EL_Check_Header_Date')dnl
HACK(`EL_Check_Header_DateWarning')dnl
HACK(`EL_Check_Header_ErrorsTo')dnl
HACK(`EL_Check_Header_From')dnl
HACK(`EL_Check_Header_InReplyTo')dnl
HACK(`EL_Check_Header_MessageID')dnl
HACK(`EL_Check_Header_MimeVersion')dnl
HACK(`EL_Check_Header_Organization')dnl
HACK(`EL_Check_Header_Received')dnl
HACK(`EL_Check_Header_ReplyTo')dnl
HACK(`EL_Check_Header_Sender')dnl
HACK(`EL_Check_Header_Subject')dnl
HACK(`EL_Check_Header_To')dnl
HACK(`EL_Check_Header_XAntiAbuse')dnl
HACK(`EL_Check_Header_XAntivirus')dnl
HACK(`EL_Check_Header_XAOLIP')dnl          
HACK(`EL_Check_Header_XApparentlyFrom')dnl
HACK(`EL_Check_Header_XAuthenticationWarning')dnl
HACK(`EL_Check_Header_XCloudmarkScore')dnl
HACK(`EL_Check_Header_XComment')dnl
dnl disabled 09/28/06 due to FPs - do not use
dnl HACK(`EL_Check_Header_XIronport')dnl
HACK(`EL_Check_Header_XLibrary')dnl
HACK(`EL_Check_Header_XMSMailPriority')dnl
HACK(`EL_Check_Header_XMailScanner')dnl
HACK(`EL_Check_Header_XMailer')dnl
HACK(`EL_Check_Header_XMessageInfo')dnl
HACK(`EL_Check_Header_XMimeOLE')dnl
dnl HACK(`EL_Check_Header_XMimeTrack')dnl
HACK(`EL_Check_Header_XNAISpamFlag')dnl
HACK(`EL_Check_Header_XOriginalArrivalTime')dnl
HACK(`EL_Check_Header_XOriginatingIP')dnl
HACK(`EL_Check_Header_XPriority')dnl
HACK(`EL_Check_Header_XSpamDetect')dnl
HACK(`EL_Check_Header_XSpamFlag')dnl
HACK(`EL_Check_Header_XSpamStatus')dnl
HACK(`EL_Check_Header_XVirusScanResult')dnl

dnl -- checks for headers found only in spam/abusive email
HACK(`EL_Check_Headers')dnl

HACK(`EL_Check_Eoh')dnl

dnl for testing of fingerprinting
dnl HACK(`EL_Fingerprint')dnl

dnl ------------------------------------------------------------------------
dnl -- Drop-in replacement for Local_check_rcpt. This is where most of the
dnl -- non-header checks (HELO forgeries, 419 scams, etc.) are handled.
dnl -- As such, it is pretty much required if you want the package to catch
dnl -- most of the 100% guaranteed spam/bot/virus/zombie abuse.
dnl ------------------------------------------------------------------------
HACK(`EL_LocalCheckRcptConfig')dnl


