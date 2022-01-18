#!/bin/bash

# Things you can set:
zeek2es_path=~/Source/zeek2es/zeek2es.py
lambda_filter_file_dir=~/
num_of_lines=50000
logfiledelim=\\.
stream_prepend="logs-zeek-"
stream_ending=""
pythoncmd="python3"
zeek2esargs="-g -l $num_of_lines"

# Error checking
if [ "$#" -ne 1 ]; then
  echo "Usage: $0 LOGFILENAME" >&2
  echo >&2
  echo "Example:" >&2
  echo "  fswatch -m poll_monitor --event Created -r /data/logs/zeek |  awk '/^.*\/(conn|dns|http)\..*\.log\.gz$/' | parallel -j 16 $0 {}" :::: - >&2
  exit 1
fi

# Things set from the command line
logfile=$1

echo "Processing $logfile..."
regex="s/.*\/\([^0-9\.]*\)$logfiledelim[0-9].*\.log\.gz/\1/"
log_type=`echo $logfile | sed $regex`
echo $log_type

zeek2esargsplus=$zeek2esargs" -i $stream_prepend$log_type$stream_ending"

lambdafilterfile=$lambda_filter_file_dir$log_type"_filter.txt"

if [ -f $lambdafilterfile ]; then
  echo "  Using filter file "$lambdafilterfile
  $pythoncmd $zeek2es_path $logfile $zeek2esargsplus -f $lambdafilterfile
else
  echo "  No lambda filter file found for "$lambdafilterfile
  $pythoncmd $zeek2es_path $logfile $zeek2esargsplus
fi