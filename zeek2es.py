import sys
import subprocess
import json
import csv
import io
import os
import requests
import argparse

parser = argparse.ArgumentParser(description='Process Zeek ASCII logs into Elasticsearch.')
parser.add_argument('filename', 
                     help='The Zeek log in *.log or *.gz format.  Include the full path.')
parser.add_argument('-i', '--esindex', help='The Elasticsearch index name.')
parser.add_argument('-u', '--esurl', default="http://localhost:9200/", help='The Elasticsearch URL. (default: http://localhost:9200/)')
parser.add_argument('-l', '--lines', default=50000, type=int, help='Lines to buffer for RESTful operations. (default: 50,000)')
parser.add_argument('-n', '--name', default="", help='The name of the system to add to the index for uniqueness. (default: empty string)')
parser.add_argument('-c', '--checkindex', action="store_true", help='Check for the ES index first, and if it exists exit this program.')
parser.add_argument('-s', '--stdout', action="store_true", help='Print JSON to stdout instead of sending to Elasticsearch directly.')
parser.add_argument('-b', '--nobulk', action="store_true", help='Remove the ES bulk JSON header.  Requires --stdout.')
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

if not args.esindex:
    dirname = os.path.dirname(filename).split("/")
    if len(dirname[-1]) == 0:
        print()
        print("To use this application with just a file name, the parent directory in the path needs to be a date string.")
        print("This keeps our index names unique for files that may not be.")
        print("Use a full file path to the Zeek log or specify the index you want.")
        print()
        exit(-3)
    datestr = dirname[-1]
    es_index = datestr + "_" + os.path.basename(filename)
else:
    es_index = args.esindex

sysname = ""
if (len(args.name) > 0):
    sysname = "{}_".format(args.name)

es_index = "zeek_"+sysname+es_index.replace(':', '_').replace("/", "_")

if args.checkindex:
    res = requests.get(args.esurl+es_index)
    if res.ok:
        print()
        print("This index {} already exists.  Exiting.".format(es_index))
        print()
        exit(-4)

if filename.split(".")[-1].lower() == "gz":
    # This works on Linux and MacOs
    zcat_name = ["gzip", "-d", "-c"]
else:
    zcat_name = ["cat"]

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

zeek_cut_process = subprocess.Popen(['zeek-cut', '-d', '-u'], 
                                    stdin=zcat_process.stdout,
                                    stdout=subprocess.PIPE)

csv.field_size_limit(sys.maxsize)
if len(types) > 0 and len(fields) > 0:
    read_tsv = csv.reader(io.TextIOWrapper(zeek_cut_process.stdout), delimiter="\t", quoting=csv.QUOTE_NONE)

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
    outstring = ""
    for row in read_tsv:
        d = dict()
        i = 0
        for col in row:
            if types[i] == "time":
                if col != '-' and col != '(empty)':
                    d[fields[i]] = col
            elif types[i] == "interval" or types[i] == "double":
                if col != '-' and col != '(empty)':
                    d[fields[i]] = float(col)
            elif types[i] == "bool":
                if col != '-' and col != '(empty)':
                    d[fields[i]] = col == "T"
            elif types[i] == "port" or types[i] == "count" or types[i] == "int":
                if col != '-' and col != '(empty)':
                    d[fields[i]] = int(col)
            elif types[i].startswith("vector") or types[i].startswith("set"):
                if col != '-' and col != '(empty)':
                    d[fields[i]] = col.split(",")
            else:
                if col != '-' and col != '(empty)':
                    d[fields[i]] = col
            i += 1
        if len(d.keys()) > 0:
            if not args.nobulk:
                outstring += "{ \"index\": { } }\n"
            outstring += json.dumps(d)+"\n"
            n += 1
            if not args.stdout:
                if putmapping is False:
                    with open(os.devnull, 'w') as devnull:
                        requests.delete(args.esurl+es_index)
                        requests.put(args.esurl+es_index, headers={'Content-Type': 'application/json'},
                                        data=json.dumps(mappings).encode('UTF-8'))
                    putmapping = True
        if n >= args.lines:
            if not args.stdout:
                with open(os.devnull, 'w') as devnull:
                    res = requests.put(args.esurl+es_index+'/_bulk', headers={'Content-Type': 'application/json'},
                                       data=outstring.encode('UTF-8'))
                    if not res.ok:
                        print("WARNING! PUT did not return OK! Your index {} is incomplete.  Filename: {} Response: {}".format(es_index, filename, res))
            else:
                print(outstring)
            outstring = ""
            n = 0
    if n != 0:
        # One last time
        if not args.stdout:
            with open(os.devnull, 'w') as devnull:
                res = requests.put(args.esurl+es_index+'/_bulk', headers={'Content-Type': 'application/json'},
                                   data=outstring.encode('UTF-8'))
                if not res.ok:
                    print("WARNING! PUT did not return OK! Your index {} is incomplete.  Filename: {} Response: {}".format(es_index, filename, res))
        else:
            print(outstring)