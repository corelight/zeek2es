import sys
import subprocess
import json
import csv
import io
import requests
import datetime
import re
import argparse
import random
# Making these available for lambda filter input.
import ipaddress
import os

# The number of bits to use in a random hash
hashbits = 128

class MyParser(argparse.ArgumentParser):
    def print_help(self):
        super().print_help()
        print("")
        print("To delete indices:\n\n\tcurl -X DELETE http://localhost:9200/zeek*?pretty\n")
        print("To delete data streams:\n\n\tcurl -X DELETE http://localhost:9200/_data_stream/zeek*?pretty\n")
        print("To delete index templates:\n\n\tcurl -X DELETE http://localhost:9200/_index_template/zeek*?pretty\n")
        print("To delete the lifecycle policy:\n\n\tcurl -X DELETE http://localhost:9200/_ilm/policy/zeek-lifecycle-policy?pretty\n")

def parseargs():
    parser = MyParser(description='Process Zeek ASCII logs into Elasticsearch.', formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('filename', 
                        help='The Zeek log in *.log or *.gz format.  Include the full path.')
    parser.add_argument('-i', '--esindex', help='The Elasticsearch index/data stream name.')
    parser.add_argument('-u', '--esurl', default="http://localhost:9200/", help='The Elasticsearch URL. (default: http://localhost:9200/)')
    parser.add_argument('-l', '--lines', default=10000, type=int, help='Lines to buffer for RESTful operations. (default: 10,000)')
    parser.add_argument('-n', '--name', default="", help='The name of the system to add to the index for uniqueness. (default: empty string)')
    parser.add_argument('-k', '--keywords', default="service", help='A comma delimited list of text fields to add a keyword subfield. (default: service)')
    parser.add_argument('-a', '--lambdafilter', default="", help='A lambda function, when eval\'d will filter your output JSON dict. (default: empty string)')
    parser.add_argument('-f', '--lambdafilterfile', default="", help='A lambda function file, when eval\'d will filter your output JSON dict. (default: empty string)')
    parser.add_argument('-y', '--outputfields', default="", help='A comma delimited list of fields to keep for the output.  Must include ts. (default: empty string)')
    parser.add_argument('-d', '--datastream', default=0, type=int, help='Instead of an index, use a data stream that will rollover at this many GB.  Recommended is 50 or less.  (default: 0 - disabled)')
    parser.add_argument('-g', '--ingestion', action="store_true", help='Use the ingestion pipeline to do things like geolocate IPs and split services.  Takes longer, but worth it.')
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

def main(**args):
    outputfields = []
    if (len(args['outputfields']) > 0):
        try:
            outputfields = args['outputfields'].split(",")
        except Exception as e:
            if not args['supresswarnings']:
                print("Your output fields did not comma split correctly.  Please try again. Exception: {}".format(e))
            exit(-8)

    keywords = []
    if (len(args['keywords']) > 0):
        try:
            keywords = args['keywords'].split(",")
        except Exception as e:
            if not args['supresswarnings']:
                print("Your keywords did not comma split correctly.  Please try again. Exception: {}".format(e))
            exit(-6)

    if args['esindex'] and args['stdout']:
        if not args['supresswarnings']:
            print("Cannot write to Elasticsearch and stdout at the same time.")
        exit(-1)

    if args['nobulk'] and not args['stdout']:
        if not args['supresswarnings']:
            print("The nobulk option can only be used with the stdout option.")
        exit(-2)

    if not args['timestamp'] and args['origtime']:
        if not args['supresswarnings']:
            print("The origtime option can only be used with the timestamp option.")
        exit(-3)

    if len(args['lambdafilter']) > 0 and len(args['lambdafilterfile']) > 0:
        if not args['supresswarnings']:
            print("The lambdafilter option cannot be used with the lambdafilterfile option.")
        exit(-7)

    lambdafilter = None
    if len(args['lambdafilter']) > 0:
        lambdafilter = eval(args['lambdafilter'])

    if len(args['lambdafilterfile']) > 0:
        with open(args['lambdafilterfile'], "r") as lff:
            lambdafilter = eval(lff.read())

    filename = args['filename']
                    
    if filename.split(".")[-1].lower() == "gz":
        # This works on Linux and MacOs
        zcat_name = ["gzip", "-d", "-c"]
    else:
        zcat_name = ["cat"]

    ingest_pipeline = {"description": "Zeek Log Ingestion Pipeline.", "processors": [ ]}

    if args['ingestion']:
        ingest_pipeline["processors"] += [{"dot_expander": {"field": "*"}}]
        ingest_pipeline["processors"] += [{"split": {"field": "service", "separator": ",", "ignore_missing": True, "ignore_failure": True}}]
        ingest_pipeline["processors"] += [{"geoip": {"field": "id.orig_h", "target_field": "geoip_orig", "ignore_missing": True}}]
        ingest_pipeline["processors"] += [{"geoip": {"field": "id.resp_h", "target_field": "geoip_resp", "ignore_missing": True}}]

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

        if not args['esindex']:
            sysname = ""
            if (len(args['name']) > 0):
                sysname = "{}_".format(args['name'])
            if not args['hashdates']:
                es_index = "zeek_"+sysname+"{}_{}".format(zeek_log_path, log_date.date())
            else:
                es_index = "zeek_"+sysname+"{}_{}".format(zeek_log_path, random.getrandbits(hashbits))
        else:
            es_index = args['esindex']

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
                    # Special cases
                    if fields[i] in keywords:
                        mappings["mappings"]["properties"][fields[i]] = {"type": "text", "fields": { "keyword": { "type": "keyword" }}}
                    else:
                        mappings["mappings"]["properties"][fields[i]] = {"type": "text"}

            # Put index template for data stream

            if args["datastream"] > 0:
                lifecycle_policy = {"policy": {"phases": {"hot": {"actions": {"rollover": {"max_primary_shard_size": "{}GB".format(args['datastream'])}}}}}}
                res = requests.put(args['esurl']+"_ilm/policy/zeek-lifecycle-policy", headers={'Content-Type': 'application/json'},
                                    data=json.dumps(lifecycle_policy).encode('UTF-8'))
                index_template = {"index_patterns": [es_index], "data_stream": {}, "composed_of": [], "priority": 500, 
                                    "template": {"settings": {"index.lifecycle.name": "zeek-lifecycle-policy"}, "mappings": mappings["mappings"]}}
                res = requests.put(args['esurl']+"_index_template/"+es_index, headers={'Content-Type': 'application/json'},
                                    data=json.dumps(index_template).encode('UTF-8'))

            # Put data

            putmapping = False
            putpipeline = False
            n = 0
            items = 0
            outstring = ""
            ofl = len(outputfields)
            for row in read_tsv:
                d = dict(zeek_log_filename=filename, zeek_log_path=zeek_log_path)
                if (len(args['name']) > 0):
                    d["zeek_log_system_name"] = args['name']
                i = 0
                added_val = False
                for col in row:
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

                if added_val and "ts" in d:
                    filter_data = False
                    if lambdafilter:
                        output = list(filter(lambdafilter, [d]))
                        if len(output) == 0:
                            filter_data = True

                    if not filter_data:
                        if not args['nobulk']:
                            i = dict(create=dict(_index=es_index))
                            if len(ingest_pipeline["processors"]) > 0:
                                i["create"]["pipeline"] = "zeekgeoip"
                            outstring += json.dumps(i)+"\n"
                        d["@timestamp"] = d["ts"]
                        outstring += json.dumps(d)+"\n"
                        n += 1
                        items += 1
                        if not args['stdout']:
                            if putmapping == False:
                                res = requests.put(args['esurl']+es_index, headers={'Content-Type': 'application/json'},
                                                    data=json.dumps(mappings).encode('UTF-8'))
                                putmapping = True
                            if putpipeline == False and len(ingest_pipeline["processors"]) > 0:
                                res = requests.put(args['esurl']+"_ingest/pipeline/zeekgeoip", headers={'Content-Type': 'application/json'},
                                                    data=json.dumps(ingest_pipeline).encode('UTF-8'))
                                putpipeline = True

                if n >= args['lines']:
                    if not args['stdout']:
                        res = requests.put(args['esurl']+'/_bulk', headers={'Content-Type': 'application/json'},
                                            data=outstring.encode('UTF-8'))
                        if not res.ok:
                            if not args['supresswarnings']:
                                print("WARNING! PUT did not return OK! Your index {} is incomplete.  Filename: {} Response: {} {}".format(es_index, filename, res, res.text))
                    else:
                        print(outstring)
                    outstring = ""
                    n = 0

            if n != 0:
                # One last time
                if not args['stdout']:
                    res = requests.put(args['esurl']+'/_bulk', headers={'Content-Type': 'application/json'},
                                        data=outstring.encode('UTF-8'))
                    if not res.ok:
                        if not args['supresswarnings']:
                            print("WARNING! PUT did not return OK! Your index {} is incomplete.  Filename: {} Response: {} {}".format(es_index, filename, res, res.text))
                else:
                    print(outstring)
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

        while True:
            line = j_in.readline()
            
            if not line:
                break

            j_data = json.loads(line)

            if "ts" in j_data:
                gmt_mydt = datetime.datetime.utcfromtimestamp(float(j_data["ts"]))

                if not args['timestamp']:
                    j_data["ts"] = "{}T{}".format(gmt_mydt.date(), gmt_mydt.time())
                else:
                    if args['origtime']:
                        j_data["ts"] = gmt_mydt.timestamp()
                    else:
                        # ES uses ms
                        j_data["ts"] = gmt_mydt.timestamp()*1000

                if es_index == "":
                    sysname = ""

                    if (len(args['name']) > 0):
                        sysname = "{}_".format(args['name'])

                    try:
                        zeek_log_path = re.search(".*\/([^\._]+).*", filename).group(1).lower()
                    except:
                        print("Log path cannot be found from filename: {}".format(filename))
                        exit(-5)

                    if not args['hashdates']:
                        es_index = "zeek_{}{}_{}".format(sysname, zeek_log_path, gmt_mydt.date())
                    else:
                        es_index = "zeek_{}{}_{}".format(sysname, zeek_log_path, random.getrandbits(hashbits))

                    es_index = es_index.replace(':', '_').replace("/", "_")

                if not args['stdout']:
                    if putmapping == False:
                        res = requests.put(args['esurl']+es_index, headers={'Content-Type': 'application/json'},
                                            data=json.dumps(mappings).encode('UTF-8'))
                        putmapping = True
                    if putpipeline == False and len(ingest_pipeline["processors"]) > 0:
                        res = requests.put(args['esurl']+"_ingest/pipeline/zeekgeoip", headers={'Content-Type': 'application/json'},
                                            data=json.dumps(ingest_pipeline).encode('UTF-8'))
                        putpipeline = True
                    if args["datastream"] > 0 and putdatastream == False:
                        lifecycle_policy = {"policy": {"phases": {"hot": {"actions": {"rollover": {"max_primary_shard_size": "{}GB".format(args['datastream'])}}}}}}
                        res = requests.put(args['esurl']+"_ilm/policy/zeek-lifecycle-policy", headers={'Content-Type': 'application/json'},
                                            data=json.dumps(lifecycle_policy).encode('UTF-8'))
                        index_template = {"index_patterns": [es_index], "data_stream": {}, "composed_of": [], "priority": 500, 
                                            "template": {"settings": {"index.lifecycle.name": "zeek-lifecycle-policy"}, "mappings": mappings["mappings"]}}
                        res = requests.put(args['esurl']+"_index_template/"+es_index, headers={'Content-Type': 'application/json'},
                                            data=json.dumps(index_template).encode('UTF-8'))
                        putdatastream = True

                if (len(args['name']) > 0):
                    j_data["zeek_log_system_name"] = args['name']

                filter_data = False
                if lambdafilter:
                    output = list(filter(lambdafilter, [j_data]))
                    if len(output) == 0:
                        filter_data = True

                if not filter_data:
                    items += 1

                    if not args['nobulk']:
                        i = dict(create=dict(_index=es_index))
                        if len(ingest_pipeline["processors"]) > 0:
                            i["create"]["pipeline"] = "zeekgeoip"
                        outstring += json.dumps(i)+"\n"
                    j_data["@timestamp"] = j_data["ts"]
                    if len(outputfields) > 0:
                        new_j_data = {}
                        for o in outputfields:
                            if o in j_data:
                                new_j_data[o] = j_data[o]
                        j_data = new_j_data
                    outstring += json.dumps(j_data) + "\n"
                    n += 1

                if n >= args['lines']:
                    if not args['stdout']:
                        res = requests.put(args['esurl']+es_index+'/_bulk', headers={'Content-Type': 'application/json'},
                                            data=outstring.encode('UTF-8'))
                        if not res.ok:
                            if not args['supresswarnings']:
                                print("WARNING! PUT did not return OK! Your index {} is incomplete.  Filename: {} Response: {} {}".format(es_index, filename, res, res.text))
                    else:
                        print(outstring)
                    outstring = ""
                    n = 0

        if n != 0:
            # One last time
            if not args['stdout']:
                res = requests.put(args['esurl']+es_index+'/_bulk', headers={'Content-Type': 'application/json'},
                                    data=outstring.encode('UTF-8'))
                if not res.ok:
                    if not args['supresswarnings']:
                        print("WARNING! PUT did not return OK! Your index {} is incomplete.  Filename: {} Response: {} {}".format(es_index, filename, res, res.text))
            else:
                print(outstring)

if __name__ == "__main__":
    args = parseargs()
    if args.cython:
        import zeek2es
        zeek2es.main(**vars(args))
    else:
        main(**vars(args))