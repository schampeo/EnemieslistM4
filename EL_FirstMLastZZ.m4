divert(-1)dnl
#
# Copyright (c) 2004-2011 hesketh.com/inc. All rights reserved.
#
# questions? <support@enemieslist.com>
#
divert(0)dnl
VERSIONID(`$Id: EL_FirstMLastZZ.m4,v 1.18 2011/05/13 22:07:27 schampeo Exp $')
divert(-1)dnl

define(`_EL_FirstMLastZZ', `1')

define(`EL_FirstMLastZZReview', `20070807')dnl

LOCAL_CONFIG
#------------------------------------------------------------------------
# enemieslist.com 
# "First M. Last" <fmlast_zz@...> check for spamware signature
#------------------------------------------------------------------------
# check for ccTLDs in both mail_from and HELO
KEL_FirstMLastZZccTLDs regex -aMATCH -f (ae|at|au|be|by|ca|ch|cl|cu|cz|de|dk|es|gr|hu|is|it|jp|kr|lv|md|mx|nl|no|nu|nz|pt|ro|ru|se|si|ua|uk|us|ws|yu|za)$

# last_
# e.g. "First M. Last" <last_zz@example.com>
# e.g. "First Last" <last_zz@example.com>
KEL_FirstMLastZZ01 regex -f -a_SPAMSIGN_ "[A-Z]([a-z]+)\ [A-Z]*\.*\ *[A-Z]([a-z\-]+[A-Z]*[a-z]*)"\ <[a-z]\2_[a-z]{2}@
# last
# e.g. "First M. Last" <lastzz@example.com>
# e.g. "First Last" <lastzz@example.com>
# this rule has had several FPs here; seems to be most likely candidate
# for exclusion from the sequences
# removed 11/01/05
#KEL_FirstMLastZZ02 regex -f -a_SPAMSIGN_ "[A-Z]([a-z]+)\ [A-Z]*\.*\ *[A-Z]([a-z\-]+[A-Z]*[a-z]*)"\ <[a-z]\2[a-z]{2}@

# flast_
# e.g. "First M. Last" <flast_zz@example.com>
# e.g. "First Last" <flast_zz@example.com>
KEL_FirstMLastZZ03 regex -f -a_SPAMSIGN_ "[A-Z]([a-z]+)\ [A-Z]*\.*\ *[A-Z]([a-z\-]+[A-Z]*[a-z]*)"\ <[a-z][a-z]\2_[a-z]{2}@
# flast
# e.g. "First M. Last" <flastzz@example.com>
# e.g. "First Last" <flastzz@example.com>
KEL_FirstMLastZZ04 regex -f -a_SPAMSIGN_ "[A-Z]([a-z]+)\ [A-Z]*\.*\ *[A-Z]([a-z\-]+[A-Z]*[a-z]*)"\ <[a-z][a-z]\2[a-z]{2}@

# f.last_
# e.g. "First M. Last" <f.last_zz@example.com>
# e.g. "First Last" <f.last_zz@example.com>
KEL_FirstMLastZZ05 regex -f -a_SPAMSIGN_ "[A-Z]([a-z]+)\ [A-Z]*\.*\ *[A-Z]([a-z\-]+[A-Z]*[a-z]*)"\ <[a-z].[a-z]\2_[a-z]{2}@
# f.last
# e.g. "First M. Last" <f.lastzz@example.com>
# e.g. "First Last" <f.lastzz@example.com>
KEL_FirstMLastZZ06 regex -f -a_SPAMSIGN_ "[A-Z]([a-z]+)\ [A-Z]*\.*\ *[A-Z]([a-z\-]+[A-Z]*[a-z]*)"\ <[a-z].[a-z]\2[a-z]{2}@

# f.mlast_
# e.g. "First M. Last" <f.mlast_zz@example.com>
KEL_FirstMLastZZ07 regex -f -a_SPAMSIGN_ "[A-Z]([a-z]+)\ [A-Z]*\.*\ *[A-Z]([a-z\-]+[A-Z]*[a-z]*)"\ <[a-z].[a-z][a-z]\2_[a-z]{2}@
# f.mlast
# e.g. "First M. Last" <f.mlastzz@example.com>
KEL_FirstMLastZZ08 regex -f -a_SPAMSIGN_ "[A-Z]([a-z]+)\ [A-Z]*\.*\ *[A-Z]([a-z\-]+[A-Z]*[a-z]*)"\ <[a-z].[a-z][a-z]\2[a-z]{2}@

# f.m.last_
# e.g. "First M. Last" <f.m.last_zz@example.com>
KEL_FirstMLastZZ09 regex -f -a_SPAMSIGN_ "[A-Z]([a-z]+)\ [A-Z]*\.*\ *[A-Z]([a-z\-]+[A-Z]*[a-z]*)"\ <[a-z].[a-z].[a-z]\2_[a-z]{2}@
# f.m.last
# e.g. "First M. Last" <f.m.lastzz@example.com>
KEL_FirstMLastZZ10 regex -f -a_SPAMSIGN_ "[A-Z]([a-z]+)\ [A-Z]*\.*\ *[A-Z]([a-z\-]+[A-Z]*[a-z]*)"\ <[a-z].[a-z].[a-z]\2[a-z]{2}@

# f.m_last_
# e.g. "First M. Last" <f.m_last_zz@example.com>
KEL_FirstMLastZZ11 regex -f -a_SPAMSIGN_ "[A-Z]([a-z]+)\ [A-Z]*\.*\ *[A-Z]([a-z\-]+[A-Z]*[a-z]*)"\ <[a-z].[a-z]_[a-z]\2_[a-z]{2}@
# f.m_last
# e.g. "First M. Last" <f.m_lastzz@example.com>
KEL_FirstMLastZZ12 regex -f -a_SPAMSIGN_ "[A-Z]([a-z]+)\ [A-Z]*\.*\ *[A-Z]([a-z\-]+[A-Z]*[a-z]*)"\ <[a-z].[a-z]_[a-z]\2[a-z]{2}@

# f_last_
# e.g. "First M. Last" <f_last_zz@example.com>
# e.g. "First Last" <f_last_zz@example.com>
KEL_FirstMLastZZ13 regex -f -a_SPAMSIGN_ "[A-Z]([a-z]+)\ [A-Z]*\.*\ *[A-Z]([a-z\-]+[A-Z]*[a-z]*)"\ <[a-z]_[a-z]\2_[a-z]{2}@
# f_last
# e.g. "First M. Last" <f_lastzz@example.com>
# e.g. "First Last" <f_lastzz@example.com>
KEL_FirstMLastZZ14 regex -f -a_SPAMSIGN_ "[A-Z]([a-z]+)\ [A-Z]*\.*\ *[A-Z]([a-z\-]+[A-Z]*[a-z]*)"\ <[a-z]_[a-z]\2[a-z]{2}@

# f_mlast_
# e.g. "First M. Last" <f_mlast_zz@example.com>
KEL_FirstMLastZZ15 regex -f -a_SPAMSIGN_ "[A-Z]([a-z]+)\ [A-Z]*\.*\ *[A-Z]([a-z\-]+[A-Z]*[a-z]*)"\ <[a-z]_[a-z]\2_[a-z]{2}@
# f_mlast
# e.g. "First M. Last" <f_mlastzz@example.com>
KEL_FirstMLastZZ16 regex -f -a_SPAMSIGN_ "[A-Z]([a-z]+)\ [A-Z]*\.*\ *[A-Z]([a-z\-]+[A-Z]*[a-z]*)"\ <[a-z]_[a-z]\2[a-z]{2}@

# f_m.last_
# e.g. "First M. Last" <f_m.last_zz@example.com>
KEL_FirstMLastZZ17 regex -f -a_SPAMSIGN_ "[A-Z]([a-z]+)\ [A-Z]*\.*\ *[A-Z]([a-z\-]+[A-Z]*[a-z]*)"\ <[a-z]_[a-z].[a-z]\2_[a-z]{2}@
# f_m.last
# e.g. "First M. Last" <f_m.lastzz@example.com>
KEL_FirstMLastZZ18 regex -f -a_SPAMSIGN_ "[A-Z]([a-z]+)\ [A-Z]*\.*\ *[A-Z]([a-z\-]+[A-Z]*[a-z]*)"\ <[a-z]_[a-z].[a-z]\2[a-z]{2}@

# f_m_last_
# e.g. "First M. Last" <f_m_last_zz@example.com>
KEL_FirstMLastZZ19 regex -f -a_SPAMSIGN_ "[A-Z]([a-z]+)\ [A-Z]*\.*\ *[A-Z]([a-z\-]+[A-Z]*[a-z]*)"\ <[a-z]_[a-z]_[a-z]\2_[a-z]{2}@
# f_m_last
# e.g. "First M. Last" <f_m_last_zz@example.com>
KEL_FirstMLastZZ20 regex -f -a_SPAMSIGN_ "[A-Z]([a-z]+)\ [A-Z]*\.*\ *[A-Z]([a-z\-]+[A-Z]*[a-z]*)"\ <[a-z]_[a-z]_[a-z]\2[a-z]{2}@

# firstlast_
# e.g. "First M. Last" <firstlast_zz@example.com>
# e.g. "First Last" <firstlast_zz@example.com>
KEL_FirstMLastZZ21 regex -f -a_SPAMSIGN_ "[A-Z]([a-z]+)\ [A-Z]*\.*\ *[A-Z]([a-z\-]+[A-Z]*[a-z]*)"\ <[a-z]\1[a-z]\2_[a-z]{2}@
# firstlast
# e.g. "First M. Last" <firstlastzz@example.com>
# e.g. "First Last" <firstlastzz@example.com>
KEL_FirstMLastZZ22 regex -f -a_SPAMSIGN_ "[A-Z]([a-z]+)\ [A-Z]*\.*\ *[A-Z]([a-z\-]+[A-Z]*[a-z]*)"\ <[a-z]\1[a-z]\2[a-z]{2}@

# first.last_
# e.g. "First M. Last" <first.last_zz@example.com>
# e.g. "First Last" <first.last_zz@example.com>
KEL_FirstMLastZZ23 regex -f -a_SPAMSIGN_ "[A-Z]([a-z]+)\ [A-Z]*\.*\ *[A-Z]([a-z\-]+[A-Z]*[a-z]*)"\ <[a-z]\1.[a-z]\2_[a-z]{2}@
# first.last
# e.g. "First M. Last" <first.lastzz@example.com>
# e.g. "First Last" <first.lastzz@example.com>
KEL_FirstMLastZZ24 regex -f -a_SPAMSIGN_ "[A-Z]([a-z]+)\ [A-Z]*\.*\ *[A-Z]([a-z\-]+[A-Z]*[a-z]*)"\ <[a-z]\1.[a-z]\2[a-z]{2}@

# first.mlast_
# e.g. "First M. Last" <first.mlast_zz@example.com>
KEL_FirstMLastZZ25 regex -f -a_SPAMSIGN_ "[A-Z]([a-z]+)\ [A-Z]*\.*\ *[A-Z]([a-z\-]+[A-Z]*[a-z]*)"\ <[a-z]\1.[a-z][a-z]\2_[a-z]{2}@
# first.mlast
# e.g. "First M. Last" <first.mlastzz@example.com>
KEL_FirstMLastZZ26 regex -f -a_SPAMSIGN_ "[A-Z]([a-z]+)\ [A-Z]*\.*\ *[A-Z]([a-z\-]+[A-Z]*[a-z]*)"\ <[a-z]\1.[a-z][a-z]\2[a-z]{2}@

# first.m.last_
# e.g. "First M. Last" <first.m.last_zz@example.com>
KEL_FirstMLastZZ27 regex -f -a_SPAMSIGN_ "[A-Z]([a-z]+)\ [A-Z]*\.*\ *[A-Z]([a-z\-]+[A-Z]*[a-z]*)"\ <[a-z]\1.[a-z].[a-z]\2_[a-z]{2}@
# first.m.last
# e.g. "First M. Last" <first.m.lastzz@example.com>
KEL_FirstMLastZZ28 regex -f -a_SPAMSIGN_ "[A-Z]([a-z]+)\ [A-Z]*\.*\ *[A-Z]([a-z\-]+[A-Z]*[a-z]*)"\ <[a-z]\1.[a-z].[a-z]\2[a-z]{2}@

# first.m_last_
# e.g. "First M. Last" <first.m_last_zz@example.com>
KEL_FirstMLastZZ29 regex -f -a_SPAMSIGN_ "[A-Z]([a-z]+)\ [A-Z]*\.*\ *[A-Z]([a-z\-]+[A-Z]*[a-z]*)"\ <[a-z]\1.[a-z]_[a-z]\2_[a-z]{2}@
# first.m_last
# e.g. "First M. Last" <first.m_lastzz@example.com>
KEL_FirstMLastZZ30 regex -f -a_SPAMSIGN_ "[A-Z]([a-z]+)\ [A-Z]*\.*\ *[A-Z]([a-z\-]+[A-Z]*[a-z]*)"\ <[a-z]\1.[a-z]_[a-z]\2[a-z]{2}@

# first_last_
# e.g. "First M. Last" <first_last_zz@example.com>
# e.g. "First Last" <first_last_zz@example.com>
KEL_FirstMLastZZ31 regex -f -a_SPAMSIGN_ "[A-Z]([a-z]+)\ [A-Z]*\.*\ *[A-Z]([a-z\-]+[A-Z]*[a-z]*)"\ <[a-z]\1_[a-z]\2_[a-z]{2}@
# first_last
# e.g. "First M. Last" <first_lastzz@example.com>
# e.g. "First Last" <first_lastzz@example.com>
KEL_FirstMLastZZ32 regex -f -a_SPAMSIGN_ "[A-Z]([a-z]+)\ [A-Z]*\.*\ *[A-Z]([a-z\-]+[A-Z]*[a-z]*)"\ <[a-z]\1_[a-z]\2[a-z]{2}@

# first_mlast_
# e.g. "First M. Last" <first_mlast_zz@example.com>
KEL_FirstMLastZZ33 regex -f -a_SPAMSIGN_ "[A-Z]([a-z]+)\ [A-Z]*\.*\ *[A-Z]([a-z\-]+[A-Z]*[a-z]*)"\ <[a-z]\1_[a-z][a-z]\2_[a-z]{2}@
# first_mlast
# e.g. "First M. Last" <first_mlastzz@example.com>
KEL_FirstMLastZZ34 regex -f -a_SPAMSIGN_ "[A-Z]([a-z]+)\ [A-Z]*\.*\ *[A-Z]([a-z\-]+[A-Z]*[a-z]*)"\ <[a-z]\1_[a-z][a-z]\2[a-z]{2}@

# first_m.last_
# e.g. "First M. Last" <first_m.last_zz@example.com>
KEL_FirstMLastZZ35 regex -f -a_SPAMSIGN_ "[A-Z]([a-z]+)\ [A-Z]*\.*\ *[A-Z]([a-z\-]+[A-Z]*[a-z]*)"\ <[a-z]\1_[a-z].[a-z]\2_[a-z]{2}@
# first_m.last
# e.g. "First M. Last" <first_m.lastzz@example.com>
KEL_FirstMLastZZ36 regex -f -a_SPAMSIGN_ "[A-Z]([a-z]+)\ [A-Z]*\.*\ *[A-Z]([a-z\-]+[A-Z]*[a-z]*)"\ <[a-z]\1_[a-z].[a-z]\2[a-z]{2}@

# first_m_last_
# e.g. "First M. Last" <first_m_last_zz@example.com>
KEL_FirstMLastZZ37 regex -f -a_SPAMSIGN_ "[A-Z]([a-z]+)\ [A-Z]*\.*\ *[A-Z]([a-z\-]+[A-Z]*[a-z]*)"\ <[a-z]\1_[a-z]_[a-z]\2_[a-z]{2}@
# first_m_last
# e.g. "First M. Last" <first_m_lastzz@example.com>
KEL_FirstMLastZZ38 regex -f -a_SPAMSIGN_ "[A-Z]([a-z]+)\ [A-Z]*\.*\ *[A-Z]([a-z\-]+[A-Z]*[a-z]*)"\ <[a-z]\1_[a-z]_[a-z]\2[a-z]{2}@

# firstmlast_
# e.g. "First M. Last" <firstmlast_zz@example.com>
KEL_FirstMLastZZ39 regex -f -a_SPAMSIGN_ "[A-Z]([a-z]+)\ [A-Z]*\.*\ *[A-Z]([a-z\-]+[A-Z]*[a-z]*)"\ <[a-z]\2_[a-z]{2}@
# firstmlast
# e.g. "First M. Last" <firstmlastzz@example.com>
# removed 03/01/07 due to FP on "John Phelps" <phelpsja@gmail.com>
#
# possible to rejigger this pattern so it actually uses the middle initial?!?
#KEL_FirstMLastZZ40 regex -f -a_SPAMSIGN_ "[A-Z]([a-z]+)\ [A-Z]*\.*\ *[A-Z]([a-z\-]+[A-Z]*[a-z]*)"\ <[a-z]\2[a-z]{2}@

# firstm.last_
# e.g. "First M. Last" <firstm.last_zz@example.com>
KEL_FirstMLastZZ41 regex -f -a_SPAMSIGN_ "[A-Z]([a-z]+)\ [A-Z]*\.*\ *[A-Z]([a-z\-]+[A-Z]*[a-z]*)"\ <[a-z]\1[a-z].[a-z]\2_[a-z]{2}@
# firstm.last
# e.g. "First M. Last" <firstm.lastzz@example.com>
KEL_FirstMLastZZ42 regex -f -a_SPAMSIGN_ "[A-Z]([a-z]+)\ [A-Z]*\.*\ *[A-Z]([a-z\-]+[A-Z]*[a-z]*)"\ <[a-z]\1[a-z].[a-z]\2[a-z]{2}@

# firstm_last_
# e.g. "First M. Last" <firstm_last_zz@example.com>
KEL_FirstMLastZZ43 regex -f -a_SPAMSIGN_ "[A-Z]([a-z]+)\ [A-Z]*\.*\ *[A-Z]([a-z\-]+[A-Z]*[a-z]*)"\ <[a-z]\1[a-z]_[a-z]\2_[a-z]{2}@
# firstm_last
# e.g. "First M. Last" <firstm_lastzz@example.com>
KEL_FirstMLastZZ44 regex -f -a_SPAMSIGN_ "[A-Z]([a-z]+)\ [A-Z]*\.*\ *[A-Z]([a-z\-]+[A-Z]*[a-z]*)"\ <[a-z]\1[a-z]_[a-z]\2[a-z]{2}@

# fmlast_
# e.g. "First M. Last" <fmlast_zz@example.com>
KEL_FirstMLastZZ45 regex -f -a_SPAMSIGN_ "[A-Z]([a-z]+)\ [A-Z]*\.*\ *[A-Z]([a-z\-]+[A-Z]*[a-z]*)"\ <[a-z][a-z][a-z]\2_[a-z]{2}@
# fmlast
# e.g. "First M. Last" <fmlastzz@example.com>
KEL_FirstMLastZZ46 regex -f -a_SPAMSIGN_ "[A-Z]([a-z]+)\ [A-Z]*\.*\ *[A-Z]([a-z\-]+[A-Z]*[a-z]*)"\ <[a-z][a-z][a-z]\2[a-z]{2}@

# fm.last_
# e.g. "First M. Last" <fm.last_zz@example.com>
KEL_FirstMLastZZ47 regex -f -a_SPAMSIGN_ "[A-Z]([a-z]+)\ [A-Z]*\.*\ *[A-Z]([a-z\-]+[A-Z]*[a-z]*)"\ <[a-z][a-z].[a-z]\2_[a-z]{2}@
# fm.last
# e.g. "First M. Last" <fm.lastzz@example.com>
KEL_FirstMLastZZ48 regex -f -a_SPAMSIGN_ "[A-Z]([a-z]+)\ [A-Z]*\.*\ *[A-Z]([a-z\-]+[A-Z]*[a-z]*)"\ <[a-z][a-z].[a-z]\2[a-z]{2}@

# fm_last_
# e.g. "First M. Last" <fm_last_zz@example.com>
KEL_FirstMLastZZ49 regex -f -a_SPAMSIGN_ "[A-Z]([a-z]+)\ [A-Z]*\.*\ *[A-Z]([a-z\-]+[A-Z]*[a-z]*)"\ <[a-z][a-z]_[a-z]\2_[a-z]{2}@
# fm_last
# e.g. "First M. Last" <fm_lastzz@example.com>
KEL_FirstMLastZZ50 regex -f -a_SPAMSIGN_ "[A-Z]([a-z]+)\ [A-Z]*\.*\ *[A-Z]([a-z\-]+[A-Z]*[a-z]*)"\ <[a-z][a-z]_[a-z]\2[a-z]{2}@

# mlast_
# e.g. "First M. Last" <mlast_zz@example.com>
KEL_FirstMLastZZ51 regex -f -a_SPAMSIGN_ "[A-Z]([a-z]+)\ [A-Z]*\.*\ *[A-Z]([a-z\-]+[A-Z]*[a-z]*)"\ <[a-z][a-z]\2_[a-z]{2}@
# mlast
# e.g. "First M. Last" <mlastzz@example.com>
KEL_FirstMLastZZ52 regex -f -a_SPAMSIGN_ "[A-Z]([a-z]+)\ [A-Z]*\.*\ *[A-Z]([a-z\-]+[A-Z]*[a-z]*)"\ <[a-z][a-z]\2[a-z]{2}@

# m.last_
# e.g. "First M. Last" <m.last_zz@example.com>
KEL_FirstMLastZZ53 regex -f -a_SPAMSIGN_ "[A-Z]([a-z]+)\ [A-Z]*\.*\ *[A-Z]([a-z\-]+[A-Z]*[a-z]*)"\ <[a-z].[a-z]\2_[a-z]{2}@
# m.last
# e.g. "First M. Last" <m.lastzz@example.com>
KEL_FirstMLastZZ54 regex -f -a_SPAMSIGN_ "[A-Z]([a-z]+)\ [A-Z]*\.*\ *[A-Z]([a-z\-]+[A-Z]*[a-z]*)"\ <[a-z].[a-z]\2[a-z]{2}@

# m_last_
# e.g. "First M. Last" <m_last_zz@example.com>
KEL_FirstMLastZZ55 regex -f -a_SPAMSIGN_ "[A-Z]([a-z]+)\ [A-Z]*\.*\ *[A-Z]([a-z\-]+[A-Z]*[a-z]*)"\ <[a-z]_[a-z]\2_[a-z]{2}@
# m_last
# e.g. "First M. Last" <m_lastzz@example.com>
KEL_FirstMLastZZ56 regex -f -a_SPAMSIGN_ "[A-Z]([a-z]+)\ [A-Z]*\.*\ *[A-Z]([a-z\-]+[A-Z]*[a-z]*)"\ <[a-z]_[a-z]\2[a-z]{2}@

# firstzz
# new variation (Rolex spammer: afeet.com, hensi.com)
KEL_FirstZZ regex -f -a_SPAMSIGN_ "[A-Z]([a-z]+)"\ <[a-z]\1[a-z]{2}@

KEL_FirstMLastZZSeq00 sequence EL_FirstMLastZZ01 EL_FirstMLastZZ03 EL_FirstMLastZZ04 EL_FirstMLastZZ05 EL_FirstMLastZZ06 EL_FirstMLastZZ07 EL_FirstMLastZZ08 EL_FirstMLastZZ09 EL_FirstMLastZZ10 EL_FirstMLastZZ11 EL_FirstMLastZZ12 

KEL_FirstMLastZZSeq01 sequence EL_FirstMLastZZ13 EL_FirstMLastZZ14 EL_FirstMLastZZ15 EL_FirstMLastZZ16 EL_FirstMLastZZ17 EL_FirstMLastZZ18 EL_FirstMLastZZ19 EL_FirstMLastZZ20 EL_FirstMLastZZ21 EL_FirstMLastZZ22 EL_FirstMLastZZ23 EL_FirstMLastZZ24 

KEL_FirstMLastZZSeq02 sequence EL_FirstMLastZZ25 EL_FirstMLastZZ26 EL_FirstMLastZZ27 EL_FirstMLastZZ28 EL_FirstMLastZZ29 EL_FirstMLastZZ30 EL_FirstMLastZZ31 EL_FirstMLastZZ32 EL_FirstMLastZZ33 EL_FirstMLastZZ34 EL_FirstMLastZZ35 EL_FirstMLastZZ36 

KEL_FirstMLastZZSeq03 sequence EL_FirstMLastZZ37 EL_FirstMLastZZ38 EL_FirstMLastZZ39 EL_FirstMLastZZ41 EL_FirstMLastZZ42 EL_FirstMLastZZ43 EL_FirstMLastZZ44 EL_FirstMLastZZ45 EL_FirstMLastZZ46 EL_FirstMLastZZ47 EL_FirstMLastZZ48 

KEL_FirstMLastZZSeq04 sequence EL_FirstMLastZZ49 EL_FirstMLastZZ50 EL_FirstMLastZZ51 EL_FirstMLastZZ52 EL_FirstMLastZZ53 EL_FirstMLastZZ54 EL_FirstMLastZZ55 EL_FirstMLastZZ56 EL_FirstZZ

KEL_FirstMLastZZSeq sequence EL_FirstMLastZZSeq00 EL_FirstMLastZZSeq01 EL_FirstMLastZZSeq02 EL_FirstMLastZZSeq03 EL_FirstMLastZZSeq04

