import sys
import subprocess
import json

filename = sys.argv[1]

zcat_process = subprocess.Popen(['cat', filename], 
                                stdout=subprocess.PIPE)

head_process = subprocess.Popen(['head'], 
                                stdin=zcat_process.stdout,
                                stdout=subprocess.PIPE)

grep_process = subprocess.Popen(['grep', '#fields'], 
                                stdin=head_process.stdout,
                                stdout=subprocess.PIPE)

fields = grep_process.communicate()[0].decode('UTF-8').strip().split('\t')[1:]

jq_string = "split(\"\\n\") | map(split(\"\\t\")) | .[0:-1] | map( {"
i = 0
for field in fields:
    jq_string += " \"" + str(field) + "\": .[" + str(i) + "],"
    i += 1

jq_string = jq_string[:-1]
jq_string += " }\n )"

zcat_process = subprocess.Popen(['cat', filename], 
                                stdout=subprocess.PIPE)

zeek_cut_process = subprocess.Popen(['zeek-cut', '-d'], 
                                    stdin=zcat_process.stdout,
                                    stdout=subprocess.PIPE)

jq_process = subprocess.Popen(['jq', '--raw-input', '--slurp', '-c', jq_string], 
                                stdin=zeek_cut_process.stdout, stdout=subprocess.PIPE)

json_data = json.loads(jq_process.communicate()[0])

for j in json_data:
    print("{ \"create\": { } }")
    print(j)