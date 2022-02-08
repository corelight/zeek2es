import sys
import subprocess
import json
import csv
import io
import requests
from requests.auth import HTTPBasicAuth
from urllib3.exceptions import InsecureRequestWarning
import datetime
import re
import argparse
import random
# Making these available for lambda filter input.
import ipaddress
import os

# The number of bits to use in a random hash.
hashbits = 128

# Disable SSL warnings.
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# We do this to add a little extra help at the end.
class MyParser(argparse.ArgumentParser):
    def print_help(self):
        super().print_help()
        print("")
        print("To delete indices:\n\n\tcurl -X DELETE http://localhost:9200/zeek*?pretty\n")
        print("To delete data streams:\n\n\tcurl -X DELETE http://localhost:9200/_data_stream/zeek*?pretty\n")
        print("To delete index templates:\n\n\tcurl -X DELETE http://localhost:9200/_index_template/zeek*?pretty\n")
        print("To delete the lifecycle policy:\n\n\tcurl -X DELETE http://localhost:9200/_ilm/policy/zeek-lifecycle-policy?pretty\n")
        print("You will need to add -k -u elastic_user:password if you are using Elastic v8+.\n")

# This takes care of arg parsing
def parseargs():
    parser = MyParser(description='Process Zeek ASCII logs into ElasticSearch.', formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('filename', 
                        help='The Zeek log in *.log or *.gz format.  Include the full path.')
    parser.add_argument('-i', '--esindex', help='The Elasticsearch index/data stream name.')
    parser.add_argument('-u', '--esurl', default="http://localhost:9200/", help='The Elasticsearch URL.  Use ending slash.  Use https for Elastic v8+. (default: http://localhost:9200/)')
    parser.add_argument('--user', default="", help='The Elasticsearch user. (default: disabled)')
    parser.add_argument('--passwd', default="", help='The Elasticsearch password. Note this will put your password in this shell history file.  (default: disabled)')
    parser.add_argument('-l', '--lines', default=10000, type=int, help='Lines to buffer for RESTful operations. (default: 10,000)')
    parser.add_argument('-n', '--name', default="", help='The name of the system to add to the index for uniqueness. (default: empty string)')
    parser.add_argument('-k', '--keywords', nargs="+", default="service", help='A list of text fields to add a keyword subfield. (default: service)')
    parser.add_argument('-a', '--lambdafilter', default="", help='A Python lambda function, when eval\'d will filter your output JSON dict. (default: empty string)')
    parser.add_argument('-f', '--filterfile', default="", help='A Python function file, when eval\'d will filter your output JSON dict. (default: empty string)')
    parser.add_argument('-y', '--outputfields', nargs="+", default="", help='A list of fields to keep for the output.  Must include ts. (default: empty string)')
    parser.add_argument('-d', '--datastream', default=0, type=int, help='Instead of an index, use a data stream that will rollover at this many GB.\nRecommended is 50 or less.  (default: 0 - disabled)')
    parser.add_argument('-o', '--logkey', nargs=2, action='append', metavar=('fieldname','filename'), default=[], help='A field to log to a file.  Example: uid uid.txt.  \nWill append to the file!  Delete file before running if appending is undesired.  \nThis option can be called more than once.  (default: empty - disabled)')
    parser.add_argument('-e', '--filterkeys', nargs=2, metavar=('fieldname','filename'), default="", help='A field to filter with keys from a file.  Example: uid uid.txt.  (default: empty string - disabled)')
    parser.add_argument('-g', '--ingestion', action="store_true", help='Use the ingestion pipeline to do things like geolocate IPs and split services.  Takes longer, but worth it.')
    parser.add_argument('-p', '--splitfields', nargs="+", default="", help='A list of additional fields to split with the ingestion pipeline, if enabled.\n(default: empty string - disabled)')
    parser.add_argument('-j', '--jsonlogs', action="store_true", help='Assume input logs are JSON.')
    parser.add_argument('-r', '--origtime', action="store_true", help='Keep the numerical time format, not milliseconds as ES needs.')
    parser.add_argument('-t', '--timestamp', action="store_true", help='Keep the time in timestamp format.')
    parser.add_argument('-s', '--stdout', action="store_true", help='Print JSON to stdout instead of sending to Elasticsearch directly.')
    parser.add_argument('-b', '--nobulk', action="store_true", help='Remove the ES bulk JSON header.  Requires --stdout.')
    parser.add_argument('-c', '--cython', action="store_true", help='Use Cython execution by loading the local zeek2es.so file through an import.\nRun python setup.py build_ext --inplace first to make your zeek2es.so file!')
    parser.add_argument('-w', '--hashdates', action="store_true", help='Use hashes instead of dates for the index name.')
    parser.add_argument('-z', '--supresswarnings', action="store_true", help='Supress any type of warning.  Die stoically and silently.')
    args = parser.parse_args()
    return args

# A function to send data in bulk to ES.
def sendbulk(args, outstring, es_index, filename):
    # Elastic username and password auth
    auth = None
    if (len(args['user']) > 0):
        auth = HTTPBasicAuth(args['user'], args['passwd'])

    if not args['stdout']:
        res = requests.put(args['esurl']+'/_bulk', headers={'Content-Type': 'application/json'}, 
                            data=outstring.encode('UTF-8'), auth=auth, verify=False)
        if not res.ok:
            if not args['supresswarnings']:
                print("WARNING! PUT did not return OK! Your index {} is incomplete.  Filename: {} Response: {} {}".format(es_index, filename, res, res.text))
    else:
        print(outstring)

# A function to send the datastream info to ES.
def senddatastream(args, es_index, mappings):
    # Elastic username and password auth
    auth = None
    if (len(args['user']) > 0):
        auth = HTTPBasicAuth(args['user'], args['passwd'])

    lifecycle_policy = {"policy": {"phases": {"hot": {"actions": {"rollover": {"max_primary_shard_size": "{}GB".format(args['datastream'])}}}}}}
    res = requests.put(args['esurl']+"_ilm/policy/zeek-lifecycle-policy", headers={'Content-Type': 'application/json'},
                        data=json.dumps(lifecycle_policy).encode('UTF-8'), auth=auth, verify=False)
    index_template = {"index_patterns": [es_index], "data_stream": {}, "composed_of": [], "priority": 500, 
                        "template": {"settings": {"index.lifecycle.name": "zeek-lifecycle-policy"}, "mappings": mappings["mappings"]}}
    res = requests.put(args['esurl']+"_index_template/"+es_index, headers={'Content-Type': 'application/json'},
                        data=json.dumps(index_template).encode('UTF-8'), auth=auth, verify=False)

# A function to send mappings to ES.
def sendmappings(args, es_index, mappings):
    # Elastic username and password auth
    auth = None
    if (len(args['user']) > 0):
        auth = HTTPBasicAuth(args['user'], args['passwd'])

    res = requests.put(args['esurl']+es_index, headers={'Content-Type': 'application/json'},
                        data=json.dumps(mappings).encode('UTF-8'), auth=auth, verify=False)

# A function to send the ingest pipeline to ES.
def sendpipeline(args, ingest_pipeline):
    # Elastic username and password auth
    auth = None
    if (len(args['user']) > 0):
        auth = HTTPBasicAuth(args['user'], args['passwd'])

    res = requests.put(args['esurl']+"_ingest/pipeline/zeekgeoip", headers={'Content-Type': 'application/json'},
                        data=json.dumps(ingest_pipeline).encode('UTF-8'), auth=auth, verify=False)

# Everything important is in here.
def main(**args):

    # Takes care of the fields we want to output, if not all.
    outputfields = []
    if (len(args['outputfields']) > 0):
        outputfields = args['outputfields']

    # Takes care of logging keys to a file.
    logkeyfields = []
    logkeys_fds = []
    if (len(args['logkey']) > 0):
        for lk in args['logkey']:
            thefield, thefile = lk[0], lk[1]
            f = open(thefile, "a+")
            logkeyfields.append(thefield)
            logkeys_fds.append(f)

    # Takes care of loading keys from a file to use in a filter.
    filterkeys = set()
    filterkeys_field = None
    if (len(args['filterkeys']) > 0):
        filterkeys_field = args['filterkeys'][0]
        filterkeys_file = args['filterkeys'][1]
        with open(filterkeys_file, "r") as infile:
            filterkeys = set(infile.read().splitlines())

    # This takes care of fields where we want to add the keyword field.
    keywords = []
    if (len(args['keywords']) > 0):
        keywords = args['keywords']

    # Error checking
    if args['esindex'] and args['stdout']:
        if not args['supresswarnings']:
            print("Cannot write to Elasticsearch and stdout at the same time.")
        exit(-1)

    # Error checking
    if args['nobulk'] and not args['stdout']:
        if not args['supresswarnings']:
            print("The nobulk option can only be used with the stdout option.")
        exit(-2)

    # Error checking
    if not args['timestamp'] and args['origtime']:
        if not args['supresswarnings']:
            print("The origtime option can only be used with the timestamp option.")
        exit(-3)

    # Error checking
    if len(args['lambdafilter']) > 0 and len(args['filterfile']) > 0:
        if not args['supresswarnings']:
            print("The lambdafilter option cannot be used with the filterfile option.")
        exit(-7)

    # This takes care of loading the Python filters.
    filterfilter = None
    if len(args['lambdafilter']) > 0:
        filterfilter = eval(args['lambdafilter'])

    if len(args['filterfile']) > 0:
        with open(args['filterfile'], "r") as ff:
            filterfilter = eval(ff.read())

    # The file we are processing.
    filename = args['filename']
                    
    # Detect if the log is compressed or not.
    if filename.split(".")[-1].lower() == "gz":
        # This works on Linux and MacOs
        zcat_name = ["gzip", "-d", "-c"]
    else:
        zcat_name = ["cat"]

    # Setup the ingest pipeline
    ingest_pipeline = {"description": "Zeek Log Ingestion Pipeline.", "processors": [ ]}

    if args['ingestion']:
        fields_to_split = []
        if len(args['splitfields']) > 0:
            fields_to_split = args['splitfields']
        ingest_pipeline["processors"] += [{"dot_expander": {"field": "*"}}]
        ingest_pipeline["processors"] += [{"split": {"field": "service", "separator": ",", "ignore_missing": True, "ignore_failure": True}}]
        for f in fields_to_split:
            ingest_pipeline["processors"] += [{"split": {"field": f, "separator": ",", "ignore_missing": True, "ignore_failure": True}}]
        ingest_pipeline["processors"] += [{"geoip": {"field": "id.orig_h", "target_field": "geoip_orig", "ignore_missing": True}}]
        ingest_pipeline["processors"] += [{"geoip": {"field": "id.resp_h", "target_field": "geoip_resp", "ignore_missing": True}}]

    # This section takes care of TSV logs.  Skip ahead for the JSON logic.
    if not args['jsonlogs']:
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
            if not args['supresswarnings']:
                print("Date not found from Zeek log! {}".format(filename))
            exit(-4)

        # Get the Zeek log path

        zcat_process = subprocess.Popen(zcat_name+[filename], 
                                        stdout=subprocess.PIPE)

        head_process = subprocess.Popen(['head'], 
                                        stdin=zcat_process.stdout,
                                        stdout=subprocess.PIPE)

        grep_process = subprocess.Popen(['grep', '#path'], 
                                        stdin=head_process.stdout,
                                        stdout=subprocess.PIPE)

        zeek_log_path = grep_process.communicate()[0].decode('UTF-8').strip().split('\t')[1]

        # Build the ES index.
        if not args['esindex']:
            sysname = ""
            if (len(args['name']) > 0):
                sysname = "{}_".format(args['name'])
            # We allow for hashes instead of dates in the index name.
            if not args['hashdates']:
                es_index = "zeek_"+sysname+"{}_{}".format(zeek_log_path, log_date.date())
            else:
                es_index = "zeek_"+sysname+"{}_{}".format(zeek_log_path, random.getrandbits(hashbits))
        else:
            es_index = args['esindex']

        es_index = es_index.replace(':', '_').replace("/", "_")

        # Get the Zeek fields from the log file.

        zcat_process = subprocess.Popen(zcat_name+[filename], 
                                        stdout=subprocess.PIPE)

        head_process = subprocess.Popen(['head'], 
                                        stdin=zcat_process.stdout,
                                        stdout=subprocess.PIPE)

        grep_process = subprocess.Popen(['grep', '#fields'], 
                                        stdin=head_process.stdout,
                                        stdout=subprocess.PIPE)

        fields = grep_process.communicate()[0].decode('UTF-8').strip().split('\t')[1:]

        # Get the Zeek types from the log file.

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

        grep_process = subprocess.Popen(['grep', '-E', '-v', '^#'], 
                                        stdin=zcat_process.stdout,
                                        stdout=subprocess.PIPE)

        # Make the max size 
        csv.field_size_limit(sys.maxsize)

        # Only process if we have a valid log file.
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
                    # Special cases
                    if fields[i] in keywords:
                        mappings["mappings"]["properties"][fields[i]] = {"type": "text", "fields": { "keyword": { "type": "keyword" }}}
                    else:
                        mappings["mappings"]["properties"][fields[i]] = {"type": "text"}

            # Put index template for data stream

            if args["datastream"] > 0:
                senddatastream(args, es_index, mappings)

            # Put data

            putmapping = False
            putpipeline = False
            n = 0
            items = 0
            outstring = ""
            ofl = len(outputfields)

            # Iterate through every row in the TSV.
            for row in read_tsv:
                # Build the dict and fill in any default info.
                d = dict(zeek_log_filename=filename, zeek_log_path=zeek_log_path)
                if (len(args['name']) > 0):
                    d["zeek_log_system_name"] = args['name']
                i = 0
                added_val = False

                # For each column in the row.
                for col in row:
                    # Process the data using a method for each type.  We also will only output fields of a certain name,
                    # if identified on the command line.
                    if types[i] == "time":
                        if col != '-' and col != '(empty)' and col != '' and (ofl == 0 or fields[i] in outputfields):
                            gmt_mydt = datetime.datetime.utcfromtimestamp(float(col))
                            if not args['timestamp']:
                                d[fields[i]] = "{}T{}".format(gmt_mydt.date(), gmt_mydt.time())
                            else:
                                if args['origtime']:
                                    d[fields[i]] = gmt_mydt.timestamp()
                                else:
                                    d[fields[i]] = gmt_mydt.timestamp()*1000
                            added_val = True
                    elif types[i] == "interval" or types[i] == "double":
                        if col != '-' and col != '(empty)' and col != '' and (ofl == 0 or fields[i] in outputfields):
                            d[fields[i]] = float(col)
                            added_val = True
                    elif types[i] == "bool":
                        if col != '-' and col != '(empty)' and col != '' and (ofl == 0 or fields[i] in outputfields):
                            d[fields[i]] = col == "T"
                            added_val = True
                    elif types[i] == "port" or types[i] == "count" or types[i] == "int":
                        if col != '-' and col != '(empty)' and col != '' and (ofl == 0 or fields[i] in outputfields):
                            d[fields[i]] = int(col)
                            added_val = True
                    elif types[i].startswith("vector") or types[i].startswith("set"):
                        if col != '-' and col != '(empty)' and col != '' and (ofl == 0 or fields[i] in outputfields):
                            d[fields[i]] = col.split(",")
                            added_val = True
                    else:
                        if col != '-' and col != '(empty)' and col != '' and (ofl == 0 or fields[i] in outputfields):
                            d[fields[i]] = col
                            added_val = True
                    i += 1

                # Here we only add data if there is a timestamp, and if the filter keys are used we make sure our key exists.
                if added_val and "ts" in d and (not filterkeys_field or (filterkeys_field and d[filterkeys_field] in filterkeys)):
                    # This is the Python function filtering logic.
                    filter_data = False
                    if filterfilter:
                        output = list(filter(filterfilter, [d]))
                        if len(output) == 0:
                            filter_data = True

                    # If we haven't filtered using the Python filter function...
                    if not filter_data:
                        # Log the keys to a file, if desired.
                        i = 0
                        for lkf in logkeyfields:
                            lkfd = logkeys_fds[i]
                            if lkf in d:
                                if isinstance(d[lkf], list):
                                    for z in d[lkf]:
                                        lkfd.write(z)
                                        lkfd.write("\n")
                                else:
                                    lkfd.write(d[lkf])
                                    lkfd.write("\n")
                            i += 1

                        # Create the bulk header.
                        if not args['nobulk']:
                            i = dict(create=dict(_index=es_index))
                            if len(ingest_pipeline["processors"]) > 0:
                                i["create"]["pipeline"] = "zeekgeoip"
                            outstring += json.dumps(i)+"\n"
                        # Prepare the output and increment counters
                        d["@timestamp"] = d["ts"]
                        outstring += json.dumps(d)+"\n"
                        n += 1
                        items += 1
                        # If we aren't using stdout, prepare the ES index/datastream.
                        if not args['stdout']:
                            if putmapping == False:
                                sendmappings(args, es_index, mappings)
                                putmapping = True
                            if putpipeline == False and len(ingest_pipeline["processors"]) > 0:
                                sendpipeline(args, ingest_pipeline)
                                putpipeline = True

                # Once we get more than "lines", we send it to ES
                if n >= args['lines']:
                    sendbulk(args, outstring, es_index, filename)
                    outstring = ""
                    n = 0

            # We do this one last time to get rid of any remaining lines.
            if n != 0:
                sendbulk(args, outstring, es_index, filename)
    else:
        # This does everything the TSV version does, but for JSON
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

        mappings = {"mappings": {"properties": dict(ts=dict(type="date"), geoip_orig=dict(properties=dict(location=dict(type="geo_point"))), 
                                                                            geoip_resp=dict(properties=dict(location=dict(type="geo_point"))))}}
        mappings["mappings"]["properties"]["id.orig_h"] = {"type": "ip"}
        mappings["mappings"]["properties"]["id.resp_h"] = {"type": "ip"}
        putmapping = False
        putpipeline = False
        putdatastream = False

        # We continue until broken.
        while True:
            line = j_in.readline()
            
            # Here is where we break out of the while True loop.
            if not line:
                break

            # Load our data so we can process it.
            j_data = json.loads(line)

            # Only process data that has a timestamp field.
            if "ts" in j_data:
                # Here we deal with the time output format.
                gmt_mydt = datetime.datetime.utcfromtimestamp(float(j_data["ts"]))

                if not args['timestamp']:
                    j_data["ts"] = "{}T{}".format(gmt_mydt.date(), gmt_mydt.time())
                else:
                    if args['origtime']:
                        j_data["ts"] = gmt_mydt.timestamp()
                    else:
                        # ES uses ms
                        j_data["ts"] = gmt_mydt.timestamp()*1000

                # This happens when we go through this loop the first time and do not have an es_index name.
                if es_index == "":
                    sysname = ""

                    if (len(args['name']) > 0):
                        sysname = "{}_".format(args['name'])

                    # Since the JSON logs do not include the Zeek log path, we try to guess it from the name.
                    try:
                        zeek_log_path = re.search(".*\/([^\._]+).*", filename).group(1).lower()
                    except:
                        print("Log path cannot be found from filename: {}".format(filename))
                        exit(-5)

                    # We allow for hahes instead of dates in our index name.
                    if not args['hashdates']:
                        es_index = "zeek_{}{}_{}".format(sysname, zeek_log_path, gmt_mydt.date())
                    else:
                        es_index = "zeek_{}{}_{}".format(sysname, zeek_log_path, random.getrandbits(hashbits))

                    es_index = es_index.replace(':', '_').replace("/", "_")

                # If we are not sending the data to stdout, we prepare the ES index or datastream.
                if not args['stdout']:
                    if putmapping == False:
                        sendmappings(args, es_index, mappings)
                        putmapping = True
                    if putpipeline == False and len(ingest_pipeline["processors"]) > 0:
                        sendpipeline(args, ingest_pipeline)
                        putpipeline = True
                    if args["datastream"] > 0 and putdatastream == False:
                        senddatastream(args, es_index, mappings)
                        putdatastream = True

                # We add the system name, if desired.
                if (len(args['name']) > 0):
                    j_data["zeek_log_system_name"] = args['name']

                # Here we are checking if the keys will filter the data in.
                if not filterkeys_field or (filterkeys_field and j_data[filterkeys_field] in filterkeys):
                    # This check below is for the Python filters.
                    filter_data = False
                    if filterfilter:
                        output = list(filter(filterfilter, [j_data]))
                        if len(output) == 0:
                            filter_data = True

                    if not filter_data:
                        # We log the keys, if so desired.
                        i = 0
                        for lkf in logkeyfields:
                            lkfd = logkeys_fds[i]
                            if lkf in j_data:
                                if isinstance(j_data[lkf], list):
                                    for z in j_data[lkf]:
                                        lkfd.write(z)
                                        lkfd.write("\n")
                                else:
                                    lkfd.write(j_data[lkf])
                                    lkfd.write("\n")
                            i += 1
                        items += 1

                        if not args['nobulk']:
                            i = dict(create=dict(_index=es_index))
                            if len(ingest_pipeline["processors"]) > 0:
                                i["create"]["pipeline"] = "zeekgeoip"
                            outstring += json.dumps(i)+"\n"
                        j_data["@timestamp"] = j_data["ts"]
                        # Here we only include the output fields identified via the command line.
                        if len(outputfields) > 0:
                            new_j_data = {}
                            for o in outputfields:
                                if o in j_data:
                                    new_j_data[o] = j_data[o]
                            j_data = new_j_data
                        outstring += json.dumps(j_data) + "\n"
                        n += 1

                # Here we output a set of lines to the ES server.
                if n >= args['lines']:
                    sendbulk(args, outstring, es_index, filename)
                    outstring = ""
                    n = 0

        # We send the last of the data to the ES server, if there is any left.
        if n != 0:
            sendbulk(args, outstring, es_index, filename)

# This deals with running as a script vs. cython.
if __name__ == "__main__":
    args = parseargs()
    if args.cython:
        import zeek2es
        zeek2es.main(**vars(args))
    else:
        main(**vars(args))