divert(-1)dnl
#
# Copyright (c) 2004-2011 hesketh.com/inc. All rights reserved.

# See the file LICENSE in the distribution for details.

#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_Check_Header_ContentType.m4,v 1.30 2011/05/17 19:14:15 schampeo Exp $')
divert(-1)dnl

LOCAL_CONFIG
#------------------------------------------------------------------------
# enemieslist.com Content-Type: header check patterns
#------------------------------------------------------------------------
HContent-Type: $>EL_Check_Header_ContentType

KEL_ContentTypeMultipart  regex -aMATCH multipart/(alternative|mixed|related)
KEL_ContentTypeMultipartA regex -aMATCH multipart/alternative
KEL_ContentTypeMultipartM regex -aMATCH multipart/mixed
KEL_ContentTypeMultipartR regex -aMATCH multipart/related

KEL_ContentTypeTextHTML regex -aMATCH text/html

KEL_ContentTypeTextPlain regex -aMATCH text/plain
KEL_ContentTypeTextPlainFlowed regex -aMATCH text/plain;.*format=flowed

KEL_ContentTypeImage regex -f -aMATCH image/(gif|jpeg)

KEL_BogusTextHTML regex -a@SPAM ^(\ \ text/html;| text/html;;)

KEL_rfkindysadvnqw3nerasdf regex -a@SPAM boundary=.*rfkindysadvnqw3nerasdf

KEL_ContentTypeBiogenUSA regex -a@SPAM multipart/alternative.*boundary="\-\-[0-9]{17}

KEL_ContentTypeMotorsport regex -a@SPAM multipart/related.*boundary\-\-\-\-[0-f]{10}\-.+\.com\"$

KEL_CheckForBadContentTypeSeparator regex -a@SPAM qzsoft_directmail_seperator

KEL_SwenAttachment regex -a@VIRUS application/x-msdownload;.*name="(install|installer|pack|patch|q|update|upgrade)[0-9]+\.exe"

ifdef(`_EL_BLOCK_ZIP', `dnl
KEL_ContentTypeZip regex -a_VIRUS_ name=.*\.zip
')

ifdef(`_EL_BLOCK_ALL_ZIP', `dnl
KEL_ContentTypeAllZip regex -a_VIRUS_ name=.*\.(arc|cab|cil|cpp|rar|sit|zip)
')

ifdef(`_EL_BLOCK_EXE', `dnl
KEL_ContentTypeExe regex -a_VIRUS_ application\/octet-stream.*name=.*\.(bat|com|cpl|eml|exe|hta|ocx|pif|scr|vbs|vbx|vxd)
')

ifdef(`_EL_BLOCK_ALL_EXE', `dnl
KEL_ContentTypeAllExe regex -a_VIRUS_ application\/octet-stream.*name=.*\.(ade|adp|app|asf|asx|bas|bat|chm|class|\{CLSID\}|cmd|com|cpl|dat|dll|doc|dot|eml|exe|hlp|hta|hte|html?|isp|js|jse|jsp|lnk|mda|mdb|mde|mdw|mdz|msi|mst|nws|ocx|ops|pac|pcd|pif|pl|plx|pm|pot|prf|pps|ppt|reg|rtf|scf|scr|scp|sct|shm|shs|swf|tmpvbvbe|vbs|vbx|vcf|vxd|wmd|wmf|wms|wmz|wsc|wsf|wsh|xla|xlb|xlc|xld|xlk|xlm|xls|xlt|xlv|xlw|xnk|zlb)
')

KEL_ContentTypeChecks sequence EL_rfkindysadvnqw3nerasdf EL_SwenAttachment EL_ContentTypeBiogenUSA EL_ContentTypeMotorsport EL_BogusTextHTML EL_CheckForBadContentTypeSeparator

LOCAL_RULESETS
#------------------------------------------------------------------------
# enemieslist.com Content-Type header checks
#------------------------------------------------------------------------
SEL_Check_Header_ContentType
ifdef(`_EL_TRACE', `dnl
R$*					$: $1 $(EL_Log "ContentType w/ " $1 "; score: " $&{ELSuspiciousCount} "." $)
')dnl

# skip whitelisted hosts
R$*			$: $&{ELWhitelisted}
R$+:$+		$@

ifdef(`_EL_B0RKEN', `dnl
R$*					$: $(EL_B0rkenRatware $&{currHeader} $)
R@SPAM				$#error $@ 5.7.1 $: ifdef(`confEL_ErrB0rkenRatware', `confEL_ErrB0rkenRatware', `"554 B0RKENR Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it appears to have been sent by laughably broken spam software."')
')dnl

R$*					$: $(EL_ContentTypeChecks $&{currHeader} $)
R@SPAM				$#error $@ 5.7.1 $: ifdef(`confEL_ErrContentTypeSpam', `confEL_ErrContentTypeSpam', `"554 BADHDCT Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as spam; it contains a suspicious header."')
R@VIRUS				$#error $@ 5.7.1 $: ifdef(`confEL_ErrContentTypeVirus', `confEL_ErrContentTypeVirus', `"554 VIRUSCT Contact "$&{ELContactEmail}" if this is in error, but your message was rejected as a virus; it contains a suspicious header."')

ifdef(`_EL_BLOCK_ZIP', `dnl
R$*			$: $(EL_ContentTypeZip $&{currHeader} $)
ifelse(_EL_POLICY, 1, `dnl
R$-					$: $1 $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
R_VIRUS_ $| $*SOMEZIP$* $| TAG		$: <TAGSOMEZIP>
R_VIRUS_ $| $*SOMEZIP$* $| BLOCK	$: <REJSOMEZIP>
R_VIRUS_ $| $* +SOMEZIP$* $| ASK	$: <TAGSOMEZIP>
R_VIRUS_ $| $* !SOMEZIP$* $| ASK	$: <REJSOMEZIP>

# if no match try default policy
R$* $| $* $| $* 					$: $1 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
R_VIRUS_ $| $*SOMEZIP$* $| TAG		$: <TAGSOMEZIP>
R_VIRUS_ $| $*SOMEZIP$* $| BLOCK	$: <REJSOMEZIP>
R_VIRUS_ $| $* +SOMEZIP$* $| ASK	$: <TAGSOMEZIP>
R_VIRUS_ $| $* !SOMEZIP$* $| ASK	$: <REJSOMEZIP>
', `dnl
R_VIRUS_							$: <REJSOMEZIP>
')dnl
R<TAGSOMEZIP>						$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgCompressedAttach', `confEL_TagErrMsgCompressedAttach', `"message contains compressed file attachment."')> $| 3
R<REJSOMEZIP>						$#error $@ 5.7.1 $: ifdef(`confEL_ErrContentTypeZip', `confEL_ErrContentTypeZip', `"554 BAD_ZIP Contact "$&{ELContactEmail}" if this is in error, but we do not accept compressed file attachments as an antivirus measure. We apologize for the inconvenience."')
')dnl

ifdef(`_EL_BLOCK_ALL_ZIP', `dnl
R$*			$: $(EL_ContentTypeAllZip $&{currHeader} $)
ifelse(_EL_POLICY, 1, `dnl
R$-					$: $1 $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
R_VIRUS_ $| $*ALLZIP$* $| TAG		$: <TAGALLZIP>
R_VIRUS_ $| $*ALLZIP$* $| BLOCK		$: <REJALLZIP>
R_VIRUS_ $| $* +ALLZIP$* $| ASK		$: <TAGALLZIP>
R_VIRUS_ $| $* !ALLZIP$* $| ASK		$: <REJALLZIP>

# if no match try default policy
R$* $| $* $| $* 					$: $1 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
R_VIRUS_ $| $*ALLZIP$* $| TAG		$: <TAGALLZIP>
R_VIRUS_ $| $*ALLZIP$* $| BLOCK		$: <REJALLZIP>
R_VIRUS_ $| $* +ALLZIP$* $| ASK		$: <TAGALLZIP>
R_VIRUS_ $| $* !ALLZIP$* $| ASK		$: <REJALLZIP>
', `dnl
R_VIRUS_							$: <REJALLZIP>
')dnl
R<TAGALLZIP>						$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgCompressedAttach', `confEL_TagErrMsgCompressedAttach', `"message contains compressed file attachment."')> $| 3
R<REJALLZIP>						$#error $@ 5.7.1 $: ifdef(`confEL_ErrContentTypeAllZip', `confEL_ErrContentTypeAllZip', `"554 BADAZIP Contact "$&{ELContactEmail}" if this is in error, but we do not accept compressed file attachments as an antivirus measure. We apologize for the inconvenience."')
')dnl

ifdef(`_EL_BLOCK_EXE', `dnl
R$*			$: $(EL_ContentTypeExe $&{currHeader} $)
ifelse(_EL_POLICY, 1, `dnl
R$-					$: $1 $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
R_VIRUS_ $| $*SOMEEXE$* $| TAG		$: <TAGSOMEEXE> 
R_VIRUS_ $| $*SOMEEXE$* $| BLOCK	$: <REJSOMEEXE>
R_VIRUS_ $| $* +SOMEEXE$* $| ASK	$: <TAGSOMEEXE> 
R_VIRUS_ $| $* !SOMEEXE$* $| ASK	$: <REJSOMEEXE>

# if no match try default policy
R$* $| $* $| $* 					$: $1 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
R_VIRUS_ $| $*SOMEEXE$* $| TAG		$: <TAGSOMEEXE> 
R_VIRUS_ $| $*SOMEEXE$* $| BLOCK	$: <REJSOMEEXE>
R_VIRUS_ $| $* +SOMEEXE$* $| ASK	$: <TAGSOMEEXE> 
R_VIRUS_ $| $* !SOMEEXE$* $| ASK	$: <REJSOMEEXE>
', `dnl
R_VIRUS_							$: <REJSOMEEXE>
')dnl
R<TAGSOMEEXE>						$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgExecutableAttach', `confEL_TagErrMsgExecutableAttach', `"message contains executable file attachment."')> $| 3
R<REJSOMEEXE>						$#error $@ 5.7.1 $: ifdef(`confEL_ErrContentTypeExe', `confEL_ErrContentTypeExe', `"554 BAD_EXE Contact "$&{ELContactEmail}" if this is in error, but we do not accept executable file attachments as an antivirus measure. We apologize for the inconvenience."')
')dnl

ifdef(`_EL_BLOCK_ALL_EXE', `dnl
R$*			$: $(EL_ContentTypeAllExe $&{currHeader} $)
ifelse(_EL_POLICY, 1, `dnl
R$-					$: $1 $| $&{ELPolicyUser} $| $&{ELPolicySwitch}
R_VIRUS_ $| $*ALLEXE$* $| TAG		$: <TAGALLEXE>
R_VIRUS_ $| $*ALLEXE$* $| BLOCK		$: <REJALLEXE>
R_VIRUS_ $| $* +ALLEXE$* $| ASK		$: <TAGALLEXE>
R_VIRUS_ $| $* !ALLEXE$* $| ASK		$: <REJALLEXE>

# if no match try default policy
R$* $| $* $| $* 					$: $1 $| $(EL_Policy default $) $| $&{ELPolicySwitch}
R_VIRUS_ $| $*ALLEXE$* $| TAG		$: <TAGALLEXE>
R_VIRUS_ $| $*ALLEXE$* $| BLOCK		$: <REJALLEXE>
R_VIRUS_ $| $* +ALLEXE$* $| ASK		$: <TAGALLEXE>
R_VIRUS_ $| $* !ALLEXE$* $| ASK		$: <REJALLEXE>
', `dnl
R_VIRUS_							$: <REJALLEXE>
')dnl
R<TAGALLEXE>						$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgExecutableAttach', `confEL_TagErrMsgExecutableAttach', `"message contains executable file attachment."')> $| 3
R<REJALLEXE>						$#error $@ 5.7.1 $: ifdef(`confEL_ErrContentTypeAllExe', `confEL_ErrContentTypeAllExe', `"554 BADAEXE Contact "$&{ELContactEmail}" if this is in error, but we do not accept executable file attachments as an antivirus measure. We apologize for the inconvenience."')
')dnl

ifdef(`_EL_SKIPLOCAL', `dnl
# this is here instead of at the beginning so we can check outgoing mail
# for viruses and other undesirables (executables, compressed files).
R$*					$: $1 $| $&{client_addr}
R$* $| 127.0.0.1	$@
')dnl

ifdef(`_EL_BLOCK_HTML_TO_ROLEACCTS', `
# reject non plaintext mail for role accounts
R$*						$: $(EL_ContentTypeMultipart $&{currHeader} $) $| $(EL_CheckForRoleAccount $&{EL_CurrRcpt} $) $| $&{INHEADERS}
RMATCH $| <ROLE> $| YES	$#error $@ 5.7.1 $: ifdef(`confEL_ErrRoleAcctMultipart', `confEL_ErrRoleAcctMultipart', `"554 ROLE_MP Contact "$&{ELContactPhone}" if this is in error, but we require messages sent to role accounts be plain text only (no multipart/alternative, aka HTML email, accepted)."')

R$*						$: $(EL_ContentTypeTextHTML $&{currHeader} $) $| $(EL_CheckForRoleAccount $&{EL_CurrRcpt} $) $| $&{INHEADERS}
RMATCH $| <ROLE> $| YES	$#error $@ 5.7.1 $: ifdef(`confEL_ErrRoleAcctHTML', `confEL_ErrRoleAcctHTML', `"554 ROLEHTM Contact "$&{ELContactPhone}" if this is in error, but we require messages sent to role accounts be plain text only (no multipart/alternative, aka HTML email, accepted)."')
')dnl

ifdef(`_EL_SCORE_HTML_AS_EVIL', `
# score HTML email and/or multipart/alternative as suspect
R$*				$: $(EL_ContentTypeMultipart $&{currHeader} $) $| $&{INHEADERS}
RMATCH $| YES	$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgHTMLorMultipart', `confEL_TagErrMsgHTMLorMultipart', `"message contains HTML or has multiple parts"')> $| 1

R$*				$: $(EL_ContentTypeTextHTML $&{currHeader} $) $| $| $&{INHEADERS}
RMATCH $| YES	$: $>EL_TagSuspicious <ifdef(`confEL_TagErrMsgHTMLorMultipart', `confEL_TagErrMsgHTMLorMultipart', `"message contains HTML or has multiple parts"')> $| 1
')dnl

ifdef(`_EL_QUARANTINE_IMAGE_SPAM', `
R$*				$: $(EL_ContentTypeMultipartR $&{currHeader} $) $| $&{INHEADERS}
RMATCH $| YES	$: <R> $(EL_Math + $@ 64 $@ $&{ELHasHeader} $)
R<R>$*			$: <R> $(EL_SetVar {ELHasHeader} $@ $1 $)
R<R>$*			$: $(EL_Log "ELHasHeader (multipart/related): " $&{ELHasHeader} $)

R$*				$: $(EL_ContentTypeMultipartA $&{currHeader} $) $| $&{INHEADERS}
RMATCH $| NO	$: <A> $(EL_Math + $@ 128 $@ $&{ELHasHeader} $)
R<A>$*			$: <A> $(EL_SetVar {ELHasHeader} $@ $1 $)
R<A>$*			$: $(EL_Log "ELHasHeader (multipart/alternative): " $&{ELHasHeader} $)

R$*				$: $(EL_ContentTypeTextPlain $&{currHeader} $) $| $&{INHEADERS}
RMATCH $| NO	$: <P> $(EL_Math + $@ 256 $@ $&{ELHasHeader} $)
R<P>$*			$: <P> $(EL_SetVar {ELHasHeader} $@ $1 $)
R<P>$*			$: $(EL_Log "ELHasHeader (text/plain): " $&{ELHasHeader} $)

R$*				$: $(EL_ContentTypeTextHTML $&{currHeader} $) $| $&{INHEADERS}
RMATCH $| NO	$: <H> $(EL_Math + $@ 512 $@ $&{ELHasHeader} $)
R<H>$*			$: <H> $(EL_SetVar {ELHasHeader} $@ $1 $)
R<H>$*			$: $(EL_Log "ELHasHeader (text/html): " $&{ELHasHeader} $)

# and the final test - whether there is also an image attachment
R$*				$: $(EL_ContentTypeImage $&{currHeader} $) $| $&{INHEADERS}
RMATCH $| NO	$: <I> $(EL_Math + $@ 1024 $@ $&{ELHasHeader} $)
R<I>$*			$: <I> $(EL_SetVar {ELHasHeader} $@ $1 $)
R<I>$*			$: <DONE> $(EL_Log "ELHasHeader (image/whatever): " $&{ELHasHeader} $)

# if we have all of these, tag the message as likely image spam
R<DONE>$*		$: $(EL_Math & $@ 64 $@ $&{ELHasHeader} $) $| $(EL_Math & $@ 128 $@ $&{ELHasHeader} $) $| $(EL_Math & $@ 256 $@ $&{ELHasHeader} $) $| $(EL_Math & $@ 512 $@ $&{ELHasHeader} $) $| $(EL_Math & $@ 1024 $@ $&{ELHasHeader} $)
R64 $| 128 $| 256 $| 512 $| 1024	$: $>EL_TagSuspicious <"may be image-only spam"> $| 0
')dnl

ifdef(`_EL_CTWITHOUTMIMEV', `
R$*				$: $(EL_Math & $@ 2048 $@ $&{ELHasHeader} $) 
R0				$: $>EL_TagSuspicious <"content-type without mime-version"> $| 0
')dnl
