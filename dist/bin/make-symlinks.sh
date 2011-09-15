#!/bin/sh

for i in `ls -1 /usr/local/enemieslist.com/dist/m4/`
do
  F=`basename $i`
  ln -s $i /etc/mail/cf/hack/$F
done
