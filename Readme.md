# zeek2es.py

This Python application translates Zeek's ASCII TSV
logs into [ElasticSearch's bulk load JSON format](https://www.elastic.co/guide/en/elasticsearch/reference/current/getting-started.html#add-multiple-documents).
For JSON logs, see Elastic's File Beats application.

This application will recognize gzip or uncompressed logs.

This application assumes you have Elasticsearch set up on your
localhost at the default port.

Run this program on a system with the same timezone that was logged
by Zeek originally, as `zeek-cut -d -u` translates the timestamps into 
UTC for Elasticsearch.

## Command Line:

```
python zeek2es.py your_zeek_log.gz -e your_es_index_name
```

This script can be run in parallel on all connection logs, 10 at a time, with the following command:

```
find /some/dir -name “conn*.log.gz” | parallel -j 10 python zeek2es.py {1} :::: -
```

## Command Line Options:

```
$ python zeek2es.py -h
usage: zeek2es.py [-h] [-i ESINDEX] [-u ESURL] [-l LINES] [-n NAME] [-c] [-s] [-b] filename

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
                        Lines to buffer for RESTful operations. (default: 50,000)
  -n NAME, --name NAME  The name of the system to add to the index for uniqueness. (default: empty string)
  -c, --checkindex      Check for the ES index first, and if it exists exit this program.
  -s, --stdout          Print JSON to stdout instead of sending to Elasticsearch directly.
  -b, --nobulk          Remove the ES bulk JSON header. Requires --stdout.
```

## Requirements:

- A Unix-like environment (MacOs works!)
- Python
- zeek-cut in your path