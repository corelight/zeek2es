#!/bin/bash

# Things you can set:
zeek2es_path=~/Source/zeek2es/zeek2es.py
filter_file_dir=~/
num_of_lines=50000
logfiledelim=\\.
stream_prepend="logs-zeek-"
stream_ending=""
pythoncmd="python3"
zeek2esargs="-g -l $num_of_lines"

# Error checking
if [ "$#" -ne 2 ]; then
  echo "Usage: $0 LOGFILENAME \"ADDITIONAL_ARGS_TO_ZEEK2ES\"" >&2
  echo >&2
  echo "Example:" >&2
  echo "  fswatch -m poll_monitor --event Created -r /data/logs/zeek |  awk '/^.*\/(conn|dns|http)\..*\.log\.gz$/' | parallel -j 16 $0 {} \"\"" :::: - >&2
  exit 1
fi

# Things set from the command line
logfile=$1
additional_args=$2

echo "Processing $logfile..."
regex="s/.*\/\([^0-9\.]*\)$logfiledelim[0-9].*\.log\.gz/\1/"
log_type=`echo $logfile | sed $regex`
echo $log_type

zeek2esargsplus=$zeek2esargs" -i $stream_prepend$log_type$stream_ending "$additional_args

filterfile=$filter_file_dir$log_type"_filter.txt"

if [ -f $filterfile ]; then
  echo "  Using filter file "$filterfile
  $pythoncmd $zeek2es_path $logfile $zeek2esargsplus -f $filterfile
else
  echo "  No filter file found for "$filterfile
  $pythoncmd $zeek2es_path $logfile $zeek2esargsplus
fi