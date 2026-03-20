#!/bin/bash
# LEGACY FILE — preserved for historical reference only.
# This script extracted XML attachments from a Maildir using munpack.
# Superseded by the IMAP poller in the current application.
#
DIR=/home/fetch/Maildir
LOG=/home/fetch/Maildir/getxml.log
date +"%m/%d/%y %H:%M:%S" >> $LOG
mv $DIR/new/* $DIR/process/landing/
cd $DIR/process/landing/
shopt -s nullglob
set +o history
for i in *
do
echo "processing $i" >> $LOG
mkdir $DIR/process/extract/$i
cp $i $DIR/process/extract/$i/
echo "saving backup $i to archive" >> $LOG
mv $i $DIR/process/archive
echo "unpacking $i" >> $LOG
munpack -C $DIR/process/extract/$i -q $DIR/process/extract/$i/$i
for filename in $DIR/process/extract/$i/*
do
echo "file is: "$filename >> $LOG
if [[ $filename =~ \.zip$ ]];
then
echo unzipping $filename >> $LOG
unzip $filename -d /tmp
elif [[ $filename =~ \.gz$ ]];
then
echo unzipping $f >> $LOG
gunzip $filename
chmod 664 $DIR/process/extract/$i/*.xml
cp $DIR/process/extract/$i/*.xml /tmp
fi
done
done
set -o history
shopt -u nullglob
echo "finishing.." >> $LOG
mv $DIR/process/extract/* /$DIR/process/store/
echo "done!" >> $LOG
