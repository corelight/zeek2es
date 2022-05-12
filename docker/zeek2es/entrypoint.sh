#!/bin/bash

fswatch -m poll_monitor --event Created -r /logs | parallel -j 3 python3 /zeek2es/zeek2es.py {} --compress -g -l 5000 -d 25 -u https://es01:9200 --user elastic --passwd elastic :::: - 