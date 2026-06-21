import csv
from pathlib import Path
import sys
from enum import Enum
import os
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

class ResponseStatus(Enum):
    UNHANDLEDERROR = -1
    GOOD = 0 # unused
    REFUSED = 1
    SERVFAIL = 2
    TIMEOUT = 3
    NXDOMAIN = 4
    NOROUTE = 5
    NORECURSION = 6
    NOANSWER = 7
    NOTXTRESPONSE = 8

class ResolverEval(Enum):
    ERROR = -1
    NOQMIN = 0
    QMIN = 1
    PARTIAL = 2

schema = pa.schema([
    pa.field("resolver_ip", pa.string()),
    pa.field("status", pa.int16()),
    pa.field("res", pa.map_(pa.string(), pa.int32())),
    pa.field("requesting_ip", pa.list_(pa.string()))
])


class ResolverLine:    
    def __init__(self, ip):
        self.ip:str = ip
        self.qmin:ResolverEval = ResolverEval.ERROR
        self.responses:dict[str, int] = {}
        self.requestingIPs = set()

    def addResponse(self, response):
        for k,v in response:
            if k in self.responses:
                self.responses[k] += int(v)
            else:
                self.responses[k] = int(v)
    
    def addRequestingIP(self, ip):
        for rIP in ip:
            self.requestingIPs.add(rIP)
    
    def evaluateQMIN(self):
        for key in self.responses.keys():
            # we dont need to if the response was an error as qmin is
            # only evaluated on successful responses
            # if there are none the error stays
            if key.upper() not in ResponseStatus.__members__:
                if "|" in key:
                    if self.qmin is ResolverEval.ERROR:
                        self.qmin = ResolverEval.QMIN
                    elif self.qmin is ResolverEval.NOQMIN:
                        self.qmin = ResolverEval.PARTIAL
                else:
                    if self.qmin is ResolverEval.ERROR:
                        self.qmin = ResolverEval.NOQMIN
                    elif self.qmin is ResolverEval.QMIN:
                        self.qmin = ResolverEval.PARTIAL

    def asArray(self):
        self.evaluateQMIN()

        return [
            self.ip,
            self.qmin.value,
            self.responses,
            self.requestingIPs
        ]

if __name__ == '__main__':
    files: [str] = []

    outputDir = "./../../data/processed/qmin/"

    # handle provided output dir
    
    if os.path.isfile(sys.argv[1]):
        if len(sys.argv[1:]) <= 1:
            print("Please provide more than one file!")
            sys.exit(1)
        for path in sys.argv[1:]:
            if not Path(path).exists():
                print(f'Given file does not exist: {path}')
                sys.exit(1)
            if not path.endswith(".parquet"):
                print(f'Given file is not a csv file: {path}')
                sys.exit(1)
            files.append(path)
    elif os.path.isdir(sys.argv[1]):
        files = [(r+"/"+f) for r, d, files in os.walk(sys.argv[1]) for f in files if f.endswith('.csv')]
    else:
        print("invalid arguments")
        sys.exit(1)
    
    comb:[str, ResolverLine] = {}

    for f in files:
        table = pq.read_table(f)
        df_table = table.to_pandas()

        for row in df_table.itertuples(index=False):
            if row.resolver_ip not in comb.keys():
                comb[row.resolver_ip] = ResolverLine(row.resolver_ip)
            comb[row.resolver_ip].addResponse(row.res)
            comb[row.resolver_ip].addRequestingIP(row.requesting_ip)
    
    out1 = []
    out2 = []
    out3 = []
    out4 = []
    for value in comb.values():
        res = value.asArray()
        out1.append(res[0])
        out2.append(res[1])
        out3.append(res[2])
        out4.append(res[3])
    
    table = pa.Table.from_arrays([out1, out2, out3, out4], schema=schema)
    pq.write_table(table, outputDir + "/combined_resolver.parquet")