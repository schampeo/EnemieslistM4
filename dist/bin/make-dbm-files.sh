#!/bin/sh

for i in `ls -1 /etc/mail/enemieslist/*`
do
	F=`basename $i`
	echo "making dbm file for $F"
	makemap -v btree /etc/mail/$F.db < $i
done
