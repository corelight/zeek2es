#!/bin/bash

# Things you can set:
zeek2es_path=~/Source/zeek2es/zeek2es.py
lognamedelim=\\.
lambda_filter_file_dir=~/
num_of_lines=50000
stream_prepend="logs-zeek-"
stream_ending=""
pythoncmd="python3"
zeek2esargs="-g -l $num_of_lines"

# Error checking
if [ "$#" -lt 4 ]; then
  echo "Usage: $0 NJOBS \"ADDITIONAL_ARGS_TO_ZEEK2ES\" \"LIST_OF_LOGS_DELIMITED_BY_SPACES\" DIR1 DIR2 ..." >&2
  echo >&2
  echo "Example:" >&2
  echo "  time $0 16 \"\" \"amqp bgp conn dce_rpc dhcp dns dpd files ftp http ipsec irc kerberos modbus modbus_register_change mount mqtt mysql nfs notice ntlm ntp ospf portmap radius reporter rdp rfb rip ripng sip smb_cmd smb_files smb_mapping smtp snmp socks ssh ssl stun syslog tunnel vpn weird wireguard x509\" /usr/local/var/logs" >&2
  exit 1
fi

# Things set from the command line
njobs=$1
additional_args=$2
logs=$3
logdirs=${@:4}

# Iterate through the *.log.gz files in the supplied directory
for val in $logs; do
    zeek2esargsplus=$zeek2esargs" -i $stream_prepend$val$stream_ending "$additional_args
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