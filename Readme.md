# zeek2es.py

This Python application translates Zeek's ASCII TSV and JSON
logs into [ElasticSearch's bulk load JSON format](https://www.elastic.co/guide/en/elasticsearch/reference/current/getting-started.html#add-multiple-documents).

![Kibana](images/kibana.png)

IP Addresses can be Geolocated with the `-g` command line option:

![Kibana](images/kibana-map.png)

This application will "just work" when Zeek log formats change.  The logic reads
the field names and associated types to set up the mappings correctly in
ElasticSearch.

This application will recognize gzip or uncompressed logs.  This application assumes 
you have ElasticSearch set up on your localhost at the default port.
If you do not have ElasticSearch you can output the JSON to stdout with the `-s -b` command line options
to process with the [jq application](https://stedolan.github.io/jq).

This program will output date and times in GMT time zone.  You can change the input with the `-m`
command line option with any timezone listed by the following Python program:

```
import pytz
print(pytz.all_timezones)
```

No other Python libraries are needed to run this application.

## Command Line:

```
python zeek2es.py your_zeek_log.gz -i your_es_index_name
```

This script can be run in parallel on all connection logs, 10 at a time, with the following command:

```
find /some/dir -name “conn*.log.gz” | parallel -j 10 python zeek2es.py {1} :::: -
```

If you have the jq command installed you can perform searches across all your logs for a common
field like connection uid, even without ElasticSearch:

```
find /usr/local/var/logs -name "*.log.gz" -exec python ~/Source/zeek2es/zeek2es.py {} -s -b -z \; | jq -c '. | select(.uid=="CLbPij1vThLvQ2qDKh")'
```

You can use much more complex jq queries than this if you are familiar with jq.

If you want to remove all of your Zeek data from ElasticSearch, this command will do it for you:

```
curl -X DELETE http://localhost:9200/zeek*
```

Since the indices have the date appended to them, you could
delete Dec 31, 2021 with the following command:

```
curl -X DELETE http://localhost:9200/zeek_*_2021-12-31
```

You could delete all conn.log entries with this command:

```
curl -X DELETE http://localhost:9200/zeek_conn_*
```

## Command Line Options:

```
$ python zeek2es.py -h
usage: zeek2es.py [-h] [-i ESINDEX] [-u ESURL] [-l LINES] [-n NAME] [-m TIMEZONE] [-g] [-j] [-r] [-t] [-s] [-b] [-z] filename

Process Zeek ASCII logs into Elasticsearch.

positional arguments:
  filename              The Zeek log in *.log or *.gz format. Include the full path.

optional arguments:
  -h, --help            show this help message and exit
  -i ESINDEX, --esindex ESINDEX
                        The Elasticsearch index name.
  -u ESURL, --esurl ESURL
                        The Elasticsearch URL. (default: http://localhost:9200/)
  -l LINES, --lines LINES
                        Lines to buffer for RESTful operations. (default: 10,000)
  -n NAME, --name NAME  The name of the system to add to the index for uniqueness. (default: empty string)
  -m TIMEZONE, --timezone TIMEZONE
                        The time zone of the Zeek logs. (default: GMT)
  -g, --geolocate       Geolocate IP addresses upon ES ingestion.
  -j, --jsonlogs        Assume input logs are JSON.
  -r, --origtime        Keep the numerical time format, not milliseconds as ES needs.
  -t, --timestamp       Keep the time in timestamp format.
  -s, --stdout          Print JSON to stdout instead of sending to Elasticsearch directly.
  -b, --nobulk          Remove the ES bulk JSON header. Requires --stdout.
  -z, --supresswarnings
                        Supress any type of warning. Die silently.
```

## Requirements:

- A Unix-like environment (MacOs works!)
- Python

## Notes:

### JSON Log Input

Since Zeek JSON logs do not have type information like the ASCII TSV versions, only limited type information 
can be provided to ElasticSearch.  You will notice this most for Zeek "addr" log fields that 
are not id$orig_h and id$resp_h, since the type information is not available to translate the field into 
ElasticSearch's "ip" type.  Since address fields will not be of type "ip", you will not be able to use 
subnet searches, for example, like you could for the TSV logs.  Saving Zeek logs in ASCII TSV 
format provides for greater long term flexibility.