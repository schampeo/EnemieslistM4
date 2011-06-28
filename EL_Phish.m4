divert(-1)dnl
#
# Copyright (c) 2005-2011 hesketh.com/inc. All rights reserved.

# See the file LICENSE in the distribution for details.

#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_Phish.m4,v 1.37 2011/05/13 21:07:17 schampeo Exp $')
divert(-1)dnl

LOCAL_CONFIG
# forged phish senders
KEL_PhishFromDomains1 regex -aPHISH \@(53|abbey|absa|accountonline|alerts?\.bankofamerica|alerts?\.wachovia|alert\.wellsfargo|alliance\-leicester|amazon|anbtexas|anz|app\.rbc|azfcu\-onlineserv|bancorpsouthonline|bankofamercia|bankofamirecan|bankofamerica|bankofamerican|bankofamerika|bankofamer.ca|bankofoklahoma|bankoftexas|bankofthewest|barclays|barclaysukbank|bbandt|bbt|bellco|billing|billpay\.bankofamerica\.com|banksupportcenter|boa|(www\.)?campususacreditunion|cahoot|cardsatisfaction|capitalone|centralbank|charterone|chase|chaseinc|chaseonline)\.(co\.uk|co\.za|com|com\.au|coop|gov|info|net|org|us)

KEL_PhishFromDomains2 regex -aPHISH \@(citibank|citibankcards|citibusinessonline|citicards|citicorp|citigroup|citizensbank|citizensbankonline|cnbwax|colonialbank|columbusbankntrust|cs\.columbusbankntrust|comerica|commercebank|commerzbanking|commercialfed|creditunion|creditunion1|cscu|ctfs|cucwccu|cuna|customercenter)\.(co\.uk|com|coop|gov|info|net|org|us)

KEL_PhishFromDomains3 regex -aPHISH \@(desjardins|deutsche\-banks|dncu|ebay|e\-bay|ebay\-message|ebay\-payment|ebays|ebay\-staff|edsefcu|e\-gold|emessage\.wachovia|new\.egg|egg|energyfcu|epassporte|eppicardon|eppicardusa|etrade|fairwinds|fibrecu|firstflightfcu|firstmerit|firstpacificfunding|firsttennessee|flagstar|fnb\-columbia|fnbalaska|fultonbank|gaheritagefcu|guarantygroup|halifax|halifax\-online|hallmark|hancockbank|hsbc\-us|hsbc|hsbcplc|huntington)\.(co\.uk|com|coop|gov|info|net|org|us)

KEL_PhishFromDomains4 regex -aPHISH \@(ibancorpsouth|intl\.paypal|intrust|intrustbank|iowacreditunions|iucu\-online|jpmchase|jpmorgan\-chase|jpmorganchase|keybank|lassalle|lloyds|lloydstsb|lloydstsbonline|mail\.paypal|mandtbank|manhattanchasebank|marinefederalhb|mastercard|message|messagelabs|mfbbankonline|mibank|midamerica|moneybookers|msgcu|myisland|nafcu|national|nationalcity|nationwide|nationwidebuildingsociety\-email|natwest|ncua|netbank|nfb|nifcu|no\-paypal|northforkbank)\.(co\.uk|com|coop|gov|info|net|org|us)

KEL_PhishFromDomains5 regex -aPHISH \@(ohiosavings|onlinebanking|online\.boa|online\.wellsfargo|onlineservices\.ubs|onlinewachoviabank|onlinewellsfargobank|ornlfcu|nwolb|painewebber|papal|paypal\-online|pay.*p[ae]l.*|penfed|peoples|providian|querychase|quris|rbc|rbccentura|rbcroyalbank|regions|regionsbank|regionsnet)\.(co\.uk|com|coop|gov|info|net|org|us)

KEL_PhishFromDomains6 regex -aPHISH \@(sbbt|scotiabank|secure\.regions|security\.azfcu\-onlineserv|service|sky\-bank|skyfi|smithbarney|ssl\.jpmorgan|ssmb|ssmb\-edelivery|southtrust|southwest\-financial|standardbank|suntrust|swacuflash|tcf|tcfexpress|tdecu|ubs|us\.etrade|us\-wellsfargo|usbank|usbank\-email|visa|vystarcu|wachovia|wacovia|wamu|wammu|wells\-fargo\-support|wellsfargo|westernunion)\.(co\.uk|co\.za|com|coop|gov|info|net|org|us)

KEL_PhishFromDomains sequence EL_PhishFromDomains1 EL_PhishFromDomains2 EL_PhishFromDomains3 EL_PhishFromDomains4 EL_PhishFromDomains5 EL_PhishFromDomains6

# note this is only known good bank-owned domains!
# if the client_addr does not match one of these domains, and the sender
# does match one of the domains in the previous regex, it is probably a phish
#
# 09/29/05 - NOTE that chase.com sends from bankone.com
# 12/08/05 - NOTE also that chase.com now sends from bigfootinteractive.com
# 12/19/05 - NOTE chase.com also sends from jpmchase.com
# 02/27/06 - NOTE and from firstusa.com and alerts.chase.com
# 03/09/11 - NOTE chase now sending via secure-dx.com

KEL_PhishProperOriginDomains1 regex -aYES \.(53|abbey|accountonline|alerts\.bankofamerica|amazon|anz|azfcu|bancorpsouthonline|bankofamerica|bankofoklahoma|bankoftexas|bankofthewest|bankone|barclays|bbandt|bbt|bellco|billing|banksupportcenter|bigfootinteractive|cardsatisfaction|capitalone|centralbank)\.(co\.uk|com|coop|gov|net|org)

KEL_PhishProperOriginDomains2 regex -aYES \.(charterone|chase|chaseonline|citibank|citibankcards|citibusinessonline|citicards|citigroup|citizensbank|citizensbankonline|cnbwax|colonialbank|comerica|commercebank|commerzbanking|commercialfed|creditunion|creditunion1|cuna|cu|cwccu|customercenter|desjardins|deutsche\-bank|dncu)\.(co\.uk|com|coop|gov|net|org)

KEL_PhishProperOriginDomains3 regex -aYES \.(ebay|emailebay|edsefcu|e\-gold|egg|energyfcu|epassporte|fairwinds|fibrecu|firstflightfcu|firstmerit|firstpacificfunding|firsttennessee|flagstar|fnb\-columbia|fnbalaska|gaheritagefcu|guarantygroup|halifax|halifax\-online|hallmark|hancockbank|hsbc\-us|hsbc|huntington|intrust|intrustbank|iowacreditunions|iucu\-online)\.(co\.uk|com|coop|gov|net|org)

KEL_PhishProperOriginDomains4 regex -aYES \.(jpmchase|keybank|lasallebank|lloyds|lloydstsb|mandtbank|marinefederalhb|mastercard|mfbbankonline|midamerica|moneybookers|msgcu|nafcu|national|nationalcity|nationwide|nationwidebuildingsociety\-email|natwest|ncua|netbank|nfb|nwolb|northforkbank|ohiosavings|onlinebanking|onlineservices\.ubs)\.(co\.uk|com|coop|gov|net|org)

KEL_PhishProperOriginDomains5 regex -aYES \.(painewebber|paypal|penfed|peoples|postdirect|providian|quris|rbc|rbccentura|rbcroyalbank|regions|regionsbank|regionsnet|sbbt|scotiabank|secure\-dx|skyfi|sky\-bank|smb|smithbarney|southtrust|ssmb|ssmb\-edelivery|southwest\-financial|standardbank|suntrust|swacuflash|tcf|tcfexpress|tdecu|ubs|usbank|usbank\-email|visa|vystarcu|wachovia|wamu|wellsfargo|westernunion)\.(co\.uk|co\.za|com|coop|gov|net|org)

KEL_PhishProperOriginDomains sequence EL_PhishProperOriginDomains1 EL_PhishProperOriginDomains2 EL_PhishProperOriginDomains3 EL_PhishProperOriginDomains4 EL_PhishProperOriginDomains5

KEL_PhishMailFromLocalparts regex -aPHISH (accinfo|admin|anonymous|apache|aw\-confirm|business|cgi\-mailer\-bounces\-.*|contact|do\-not\-reply|eBay|formsubmission|ftpuser|guest|hostinguser|httpd|mastercard|member|mysql|nagios|new|nobody|office|onlinebanking|onlineservices|postgres|postmaster|root|security|service|service\.confirm|suspended|test|test1|tranzaction|update|update\-aconts|update\.service|upload|usuario|web|webstar|webusers|www|www\-data|wwwrun|wwwuser)
