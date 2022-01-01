import sys
import subprocess
import json
import csv
import io
import os
import requests
import datetime
import argparse

parser = argparse.ArgumentParser(description='Process Zeek ASCII logs into Elasticsearch.')
parser.add_argument('filename', 
                     help='The Zeek log in *.log or *.gz format.  Include the full path.')
parser.add_argument('-i', '--esindex', help='The Elasticsearch index name.')
parser.add_argument('-u', '--esurl', default="http://localhost:9200/", help='The Elasticsearch URL. (default: http://localhost:9200/)')
parser.add_argument('-l', '--lines', default=50000, type=int, help='Lines to buffer for RESTful operations. (default: 50,000)')
parser.add_argument('-n', '--name', default="", help='The name of the system to add to the index for uniqueness. (default: empty string)')
parser.add_argument('-c', '--checkindex', action="store_true", help='Check for the ES index first, and if it exists exit this program.')
parser.add_argument('-q', '--checkstate', action="store_true", help='Check the ES index state first, and if it exists exit this program.')
parser.add_argument('-t', '--humantime', action="store_true", help='Keep the time in human format.')
parser.add_argument('-s', '--stdout', action="store_true", help='Print JSON to stdout instead of sending to Elasticsearch directly.')
parser.add_argument('-b', '--nobulk', action="store_true", help='Remove the ES bulk JSON header.  Requires --stdout.')
parser.add_argument('-z', '--supresswarnings', action="store_true", help='Supress any type of warning.  Die silently.')
args = parser.parse_args()

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

filename = args.filename
                
if filename.split(".")[-1].lower() == "gz":
    # This works on Linux and MacOs
    zcat_name = ["gzip", "-d", "-c"]
else:
    zcat_name = ["cat"]

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
        print("Date not found from Zeek log!")
        print()
    exit(-3)

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
    es_index = "{}_{}_{}".format(log_date.date(), log_date.time(), zeek_log_path)
else:
    es_index = args.esindex

sysname = ""
if (len(args.name) > 0):
    sysname = "{}_".format(args.name)

es_index = "zeek_"+sysname+es_index.replace(':', '_').replace("/", "_")

if args.checkindex:
    if args.stdout:
        if not args.supresswarnings:
            print()
            print("You cannot check the index and dump the data to stdout.")
            print()
        exit(-4)

    res = requests.get(args.esurl+es_index)
    if res.ok:
        if not args.supresswarnings:
            print()
            print("This index {} already exists.  Exiting.".format(es_index))
            print()
        exit(-5)

if args.checkstate:
    if args.stdout:
        if not args.supresswarnings:
            print()
            print("You cannot check the index state and dump the data to stdout.")
            print()
        exit(-6)
        
    res = requests.get(args.esurl+es_index+'/_search', json=dict(query=dict(match=dict(zeek_log_imported_filename=filename))))
    if res.ok:
        for hit in res.json()['hits']['hits']:
            data = hit["_source"]
            if data['zeek_log_imported_filename'] == filename:
                if not args.supresswarnings:
                    print()
                    print("This index {} is already completed.  Exiting.".format(es_index))
                    print()
                exit(-7)

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

    mappings = {"mappings": {"properties": dict()}}

    for i in range(len(fields)):
        if types[i] == "time":
            mappings["mappings"]["properties"][fields[i]] = {"type": "date"}
        elif types[i] == "addr":
            mappings["mappings"]["properties"][fields[i]] = {"type": "ip"}
        elif types[i] == "string":
            mappings["mappings"]["properties"][fields[i]] = {"type": "text"}

    # Put data

    putmapping = False
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
                    if args.humantime:
                        mydt = datetime.datetime.fromtimestamp(float(col))
                        d[fields[i]] = "{}T{}".format(mydt.date(), mydt.time())
                    else:
                        d[fields[i]] = float(col)*1000
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

        if added_val:
            if not args.nobulk:
                outstring += "{ \"index\": { } }\n"
            outstring += json.dumps(d)+"\n"
            n += 1
            items += 1
            if not args.stdout:
                if putmapping is False:
                    requests.delete(args.esurl+es_index)
                    requests.put(args.esurl+es_index, headers={'Content-Type': 'application/json'},
                                    data=json.dumps(mappings).encode('UTF-8'))
                    putmapping = True

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

# Use a state document in our ES instance
if not args.stdout:
    now = datetime.datetime.utcnow()
    d = dict(zeek_log_imported_filename=filename, items=items, zeek_log_path=zeek_log_path, ts="{}T{}Z".format(now.date(), now.time()))
    if (len(args.name) > 0):
        d["zeek_log_system_name"] = args.name
    res = requests.post(args.esurl+es_index+'/_doc', json=d)
    if not res.ok:
        if not args.supresswarnings:
            print("WARNING! POST did not return OK to save your state info! Your index state {} is incomplete.  Filename: {} Response: {} {}".format(es_index, filename, res, res.text))