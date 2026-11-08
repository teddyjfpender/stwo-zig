import json,sys
r=json.load(open(sys.argv[1]))
r["output_directory"]=sys.argv[3]
r["workers"]=16
json.dump(r,open(sys.argv[2],"w"))
