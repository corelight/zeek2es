import sys
import subprocess
import json
import csv
import io
import requests
import datetime
import pytz
import re
import argparse

parser = argparse.ArgumentParser(description='Process Zeek ASCII logs into Elasticsearch.')
parser.add_argument('filename', 
                     help='The Zeek log in *.log or *.gz format.  Include the full path.')
parser.add_argument('-i', '--esindex', help='The Elasticsearch index name.')
parser.add_argument('-u', '--esurl', default="http://localhost:9200/", help='The Elasticsearch URL. (default: http://localhost:9200/)')
parser.add_argument('-l', '--lines', default=10000, type=int, help='Lines to buffer for RESTful operations. (default: 10,000)')
parser.add_argument('-n', '--name', default="", help='The name of the system to add to the index for uniqueness. (default: empty string)')
parser.add_argument('-m', '--timezone', default="GMT", help='The time zone of the Zeek logs. (default: GMT)')
parser.add_argument('-g', '--ingestion', action="store_true", help='Use the ingestion pipeline to do things like geolocate IPs and split services.  Takes longer, but worth it.')
parser.add_argument('-j', '--jsonlogs', action="store_true", help='Assume input logs are JSON.')
parser.add_argument('-r', '--origtime', action="store_true", help='Keep the numerical time format, not milliseconds as ES needs.')
parser.add_argument('-t', '--timestamp', action="store_true", help='Keep the time in timestamp format.')
parser.add_argument('-s', '--stdout', action="store_true", help='Print JSON to stdout instead of sending to Elasticsearch directly.')
parser.add_argument('-b', '--nobulk', action="store_true", help='Remove the ES bulk JSON header.  Requires --stdout.')
parser.add_argument('-z', '--supresswarnings', action="store_true", help='Supress any type of warning.  Die stoically and silently.')
args = parser.parse_args()

old_timezone = pytz.timezone(args.timezone)
gmt_timezone = pytz.timezone("GMT")

if args.esindex and args.stdout:
    print()
    print("Cannot write to Elasticsearch and stdout at the same time.")
    print()
    exit(-1)

if args.nobulk and not args.stdout:
    print()
    print("The nobulk option can only be used with the stdout option.")
    print()
    exit(-2)

if not args.timestamp and args.origtime:
    print()
    print("The origtime option can only be used with the timestamp option.")
    print()
    exit(-3)

filename = args.filename
                
if filename.split(".")[-1].lower() == "gz":
    # This works on Linux and MacOs
    zcat_name = ["gzip", "-d", "-c"]
else:
    zcat_name = ["cat"]

ingest_pipeline = {"description": "Zeek Log Ingestion Pipeline.", "processors": [ ]}

if args.ingestion:
    ingest_pipeline["processors"] += [{"dot_expander": {"field": "*"}}]
    ingest_pipeline["processors"] += [{"split": {"field": "service", "separator": ",", "ignore_missing": True, "ignore_failure": True}}]
    ingest_pipeline["processors"] += [{"geoip": {"field": "id.orig_h", "target_field": "geoip_orig", "ignore_missing": True}}]
    ingest_pipeline["processors"] += [{"geoip": {"field": "id.resp_h", "target_field": "geoip_resp", "ignore_missing": True}}]

if not args.jsonlogs:
    # Get the date

    zcat_process = subprocess.Popen(zcat_name+[filename], 
                                    stdout=subprocess.PIPE)

    head_process = subprocess.Popen(['head'], 
                                    stdin=zcat_process.stdout,
                                    stdout=subprocess.PIPE)

    grep_process = subprocess.Popen(['grep', '#open'], 
                                    stdin=head_process.stdout,
                                    stdout=subprocess.PIPE)

    try:
        log_date = datetime.datetime.strptime(grep_process.communicate()[0].decode('UTF-8').strip().split('\t')[1], "%Y-%m-%d-%H-%M-%S")
    except:
        if not args.supresswarnings:
            print()
            print("Date not found from Zeek log! {}".format(filename))
            print()
        exit(-4)

    # Get the path

    zcat_process = subprocess.Popen(zcat_name+[filename], 
                                    stdout=subprocess.PIPE)

    head_process = subprocess.Popen(['head'], 
                                    stdin=zcat_process.stdout,
                                    stdout=subprocess.PIPE)

    grep_process = subprocess.Popen(['grep', '#path'], 
                                    stdin=head_process.stdout,
                                    stdout=subprocess.PIPE)

    zeek_log_path = grep_process.communicate()[0].decode('UTF-8').strip().split('\t')[1]

    if not args.esindex:
        sysname = ""
        if (len(args.name) > 0):
            sysname = "{}_".format(args.name)

        es_index = "zeek_"+sysname+"{}_{}".format(zeek_log_path, log_date.date())
    else:
        es_index = args.esindex

    es_index = es_index.replace(':', '_').replace("/", "_")

    # Get the Zeek fields

    zcat_process = subprocess.Popen(zcat_name+[filename], 
                                    stdout=subprocess.PIPE)

    head_process = subprocess.Popen(['head'], 
                                    stdin=zcat_process.stdout,
                                    stdout=subprocess.PIPE)

    grep_process = subprocess.Popen(['grep', '#fields'], 
                                    stdin=head_process.stdout,
                                    stdout=subprocess.PIPE)

    fields = grep_process.communicate()[0].decode('UTF-8').strip().split('\t')[1:]

    # Get the Zeek types

    zcat_process = subprocess.Popen(zcat_name+[filename], 
                                    stdout=subprocess.PIPE)

    head_process = subprocess.Popen(['head'], 
                                    stdin=zcat_process.stdout,
                                    stdout=subprocess.PIPE)

    grep_process = subprocess.Popen(['grep', '#types'], 
                                    stdin=head_process.stdout,
                                    stdout=subprocess.PIPE)

    types = grep_process.communicate()[0].decode('UTF-8').strip().split('\t')[1:]

    # Read TSV

    zcat_process = subprocess.Popen(zcat_name+[filename], 
                                    stdout=subprocess.PIPE)

    grep_process = subprocess.Popen(['grep', '-v', '#'], 
                                    stdin=zcat_process.stdout,
                                    stdout=subprocess.PIPE)

    csv.field_size_limit(sys.maxsize)
    if len(types) > 0 and len(fields) > 0:
        read_tsv = csv.reader(io.TextIOWrapper(grep_process.stdout), delimiter="\t", quoting=csv.QUOTE_NONE)

        # Put mappings

        mappings = {"mappings": {"properties": dict(geoip_orig=dict(properties=dict(location=dict(type="geo_point"))), geoip_resp=dict(properties=dict(location=dict(type="geo_point"))))}}

        for i in range(len(fields)):
            if types[i] == "time":
                mappings["mappings"]["properties"][fields[i]] = {"type": "date"}
            elif types[i] == "addr":
                mappings["mappings"]["properties"][fields[i]] = {"type": "ip"}
            elif types[i] == "string":
                mappings["mappings"]["properties"][fields[i]] = {"type": "text"}

        # Put data

        putmapping = False
        putpipeline = False
        n = 0
        items = 0
        outstring = ""
        for row in read_tsv:
            d = dict(zeek_log_filename=filename, zeek_log_path=zeek_log_path)
            if (len(args.name) > 0):
                d["zeek_log_system_name"] = args.name
            i = 0
            added_val = False
            for col in row:
                if types[i] == "time":
                    if col != '-' and col != '(empty)':
                        mydt = datetime.datetime.fromtimestamp(float(col))
                        localized_mydt = old_timezone.localize(mydt)
                        gmt_mydt = localized_mydt.astimezone(gmt_timezone)
                        if not args.timestamp:
                            d[fields[i]] = "{}T{}".format(gmt_mydt.date(), gmt_mydt.time())
                        else:
                            if args.origtime:
                                d[fields[i]] = gmt_mydt.timestamp()
                            else:
                                d[fields[i]] = gmt_mydt.timestamp()*1000
                        added_val = True
                elif types[i] == "interval" or types[i] == "double":
                    if col != '-' and col != '(empty)':
                        d[fields[i]] = float(col)
                        added_val = True
                elif types[i] == "bool":
                    if col != '-' and col != '(empty)':
                        d[fields[i]] = col == "T"
                        added_val = True
                elif types[i] == "port" or types[i] == "count" or types[i] == "int":
                    if col != '-' and col != '(empty)':
                        d[fields[i]] = int(col)
                        added_val = True
                elif types[i].startswith("vector") or types[i].startswith("set"):
                    if col != '-' and col != '(empty)':
                        d[fields[i]] = col.split(",")
                        added_val = True
                else:
                    if col != '-' and col != '(empty)':
                        d[fields[i]] = col
                        added_val = True
                i += 1

            if added_val and "ts" in d:
                if not args.nobulk:
                    i = dict(index=dict(_index=es_index))
                    if len(ingest_pipeline["processors"]) > 0:
                        i["index"]["pipeline"] = "zeekgeoip"
                    outstring += json.dumps(i)+"\n"
                d["@timestamp"] = d["ts"]
                outstring += json.dumps(d)+"\n"
                n += 1
                items += 1
                if not args.stdout:
                    if putmapping == False:
                        res = requests.put(args.esurl+es_index, headers={'Content-Type': 'application/json'},
                                            data=json.dumps(mappings).encode('UTF-8'))
                        putmapping = True
                    if putpipeline == False and len(ingest_pipeline["processors"]) > 0:
                        res = requests.put(args.esurl+"_ingest/pipeline/zeekgeoip", headers={'Content-Type': 'application/json'},
                                            data=json.dumps(ingest_pipeline).encode('UTF-8'))
                        putpipeline = True

            if n >= args.lines:
                if not args.stdout:
                    res = requests.put(args.esurl+'/_bulk', headers={'Content-Type': 'application/json'},
                                        data=outstring.encode('UTF-8'))
                    if not res.ok:
                        if not args.supresswarnings:
                            print("WARNING! PUT did not return OK! Your index {} is incomplete.  Filename: {} Response: {} {}".format(es_index, filename, res, res.text))
                else:
                    print(outstring)
                outstring = ""
                n = 0

        if n != 0:
            # One last time
            if not args.stdout:
                res = requests.put(args.esurl+'/_bulk', headers={'Content-Type': 'application/json'},
                                    data=outstring.encode('UTF-8'))
                if not res.ok:
                    if not args.supresswarnings:
                        print("WARNING! PUT did not return OK! Your index {} is incomplete.  Filename: {} Response: {} {}".format(es_index, filename, res, res.text))
            else:
                print(outstring)
else:
    # Read JSON log
    zcat_process = subprocess.Popen(zcat_name+[filename], 
                                    stdout=subprocess.PIPE)
    j_in = io.TextIOWrapper(zcat_process.stdout)

    zeek_log_path = ""
    items = 0
    n = 0
    outstring = ""
    es_index = ""

    # Put mappings

    mappings = {"mappings": {"properties": dict(ts=dict(type="date"), geoip_orig=dict(properties=dict(location=dict(type="geo_point"))), geoip_resp=dict(properties=dict(location=dict(type="geo_point"))))}}
    mappings["mappings"]["properties"]["id.orig_h"] = {"type": "ip"}
    mappings["mappings"]["properties"]["id.resp_h"] = {"type": "ip"}
    putmapping = False
    putpipeline = False

    while True:
        line = j_in.readline()
        
        if not line:
            break

        j_data = json.loads(line)

        if "ts" in j_data:
            mydt = datetime.datetime.fromtimestamp(float(j_data["ts"]))
            localized_mydt = old_timezone.localize(mydt)
            gmt_mydt = localized_mydt.astimezone(gmt_timezone)

            if not args.timestamp:
                j_data["ts"] = "{}T{}".format(gmt_mydt.date(), gmt_mydt.time())
            else:
                if args.origtime:
                    j_data["ts"] = gmt_mydt.timestamp()
                else:
                    # ES uses ms
                    j_data["ts"] = gmt_mydt.timestamp()*1000

            if es_index == "":
                sysname = ""

                if (len(args.name) > 0):
                    sysname = "{}_".format(args.name)

                try:
                    zeek_log_path = re.search(".*\/([^\._]+).*", filename).group(1).lower()
                except:
                    print()
                    print("Log path cannot be found from filename: {}".format(filename))
                    print()
                    exit(-5)

                es_index = "zeek_{}{}_{}".format(sysname, zeek_log_path, gmt_mydt.date())
                es_index = es_index.replace(':', '_').replace("/", "_")

            if not args.stdout:
                if putmapping == False:
                    res = requests.put(args.esurl+es_index, headers={'Content-Type': 'application/json'},
                                        data=json.dumps(mappings).encode('UTF-8'))
                    putmapping = True
                if putpipeline == False and len(ingest_pipeline["processors"]) > 0:
                    res = requests.put(args.esurl+"_ingest/pipeline/zeekgeoip", headers={'Content-Type': 'application/json'},
                                        data=json.dumps(ingest_pipeline).encode('UTF-8'))
                    putpipeline = True

            if (len(args.name) > 0):
                j_data["zeek_log_system_name"] = args.name

            items += 1

            if not args.nobulk:
                i = dict(index=dict(_index=es_index))
                if len(ingest_pipeline["processors"]) > 0:
                    i["index"]["pipeline"] = "zeekgeoip"
                outstring += json.dumps(i)+"\n"
            j_data["@timestamp"] = j_data["ts"]
            outstring += json.dumps(j_data) + "\n"
            n += 1

            if n >= args.lines:
                if not args.stdout:
                    res = requests.put(args.esurl+es_index+'/_bulk', headers={'Content-Type': 'application/json'},
                                        data=outstring.encode('UTF-8'))
                    if not res.ok:
                        if not args.supresswarnings:
                            print("WARNING! PUT did not return OK! Your index {} is incomplete.  Filename: {} Response: {} {}".format(es_index, filename, res, res.text))
                else:
                    print(outstring)
                outstring = ""
                n = 0

    if n != 0:
        # One last time
        if not args.stdout:
            res = requests.put(args.esurl+es_index+'/_bulk', headers={'Content-Type': 'application/json'},
                                data=outstring.encode('UTF-8'))
            if not res.ok:
                if not args.supresswarnings:
                    print("WARNING! PUT did not return OK! Your index {} is incomplete.  Filename: {} Response: {} {}".format(es_index, filename, res, res.text))
        else:
            print(outstring)