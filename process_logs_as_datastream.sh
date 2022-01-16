#!/bin/bash

# Things you can set:
zeek2es_path="~/Source/zeek2es/zeek2es.py"
lognamedelim="\."
lambda_filter_file_dir=~/
num_of_lines=100000
rollover_gb=50
stream_prepend="logs-zeek-"
stream_ending=""
pythoncmd="python3"
zeek2esargs="-g -l $num_of_lines -d $rollover_gb"

# Error checking
if [ "$#" -lt 3 ]; then
  echo "Usage: $0 NJOBS \"LIST_OF_LOGS_DELIMITED_BY_SPACES\" DIR1 DIR2 ..." >&2
  echo >&2
  echo "Example:" >&2
  echo "  time ./process_logs_as_datastream.sh 16 \"bgp conn dce_rpc dhcp dns dpd files ftp http irc kerberos modbus modbus_register_change mount mysql nfs notice ntlm ntp portmap radius reporter rdp rfb rip ripng sip smb_cmd smb_files smb_mapping smtp snmp socks ssh ssl syslog tunnel weird x509 vpn\" /usr/local/var/logs" >&2
  exit 1
fi

# Things set from the command line
njobs=$1
logs=$2
logdirs=${@:3}

# Iterate through the *.log.gz files in the supplied directory
for val in $logs; do
    zeek2esargsplus=$zeek2esargs" -i $stream_prepend$val$stream_ending"
    echo "Processing $val logs..."
    filename_re="/^.*\/"$val$lognamedelim".*\.log\.gz$/"

    lambdafilterfile=$lambda_filter_file_dir$val"_filter.txt"

    if [ -f $lambdafilterfile ]; then
      echo "  Using filter file "$lambdafilterfile
      find $logdirs | awk $filename_re | parallel -j $njobs $pythoncmd $zeek2es_path {} $zeek2esargsplus -f $lambdafilterfile :::: -
    else
      echo "  No lambda filter file found for "$lambdafilterfile
      find $logdirs | awk $filename_re | parallel -j $njobs $pythoncmd $zeek2es_path {} $zeek2esargsplus :::: -
    fi
done