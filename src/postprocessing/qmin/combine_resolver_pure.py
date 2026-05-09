import csv
from pathlib import Path
import sys
from enum import Enum
import os

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


class ResolverLine:    
    def __init__(self, ip):
        self.ip:str = ip
        self.qmin:ResolverEval = ResolverEval.ERROR
        self.responses:dict[str, int] = {}

    def addResponse(self, response):
        # remove leading/trailing brackets and split
        responses = response[1:-1].split(";")

        for res in responses:
            res = res.split(":")
            if res[0] in self.responses:
                self.responses[res[0]] += int(res[1])
            else:
                self.responses[res[0]] = int(res[1])
    
    def evaluateQMIN(self):
        for key in self.responses.keys():
            # we dont need to if the response was an error as qmin is
            # only evaluated on successful responses
            # if there are none the error stays
            if key.upper() not in ResponseStatus:
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
        outStr = "["
        for key, value in self.responses.items():
            if outStr != "[":
                outStr += ";"
            outStr += key + ":" + str(value)
        outStr += "]"

        return [
            self.ip,
            str(self.qmin.value),
            outStr
        ]

def getCSVinDir(dir):
    files:[str] = []




if __name__ == '__main__':
    files: [str] = []

    outputDir = "./../../data/processed/qmin/"

    # handle prvided output dir
    
    if os.path.isfile(sys.argv[1]):
        if len(sys.argv[1:]) <= 1:
            print("Please provide more than one file!")
            sys.exit(1)
        for path in sys.argv[1:]:
            if not Path(path).exists():
                print(f'Given file does not exist: {path}')
                sys.exit(1)
            if not path.endswith(".csv"):
                printf(f'Given file is not a csv file: {path}')
                sys.exit(1)
            files.append(path)
    elif os.path.isdir(sys.argv[1]):
        files = [(r+"/"+f) for r, d, files in os.walk(sys.argv[1]) for f in files if f.endswith('.csv')]
    else:
        print("invalid arguments")
        sys.exit(1)
    
    comb:[str, ResolverLine] = {}

    for f in files:
        with open(f, 'r') as file:
            csvfile = csv.DictReader(file)
            for row in csvfile:
                if row["ip"] not in comb.keys():
                    comb[row["ip"]] = ResolverLine(row["ip"])
                comb[row["ip"]].addResponse(row["response"])
            file.close()

    with open(outputDir + "/combined_resolver.csv", 'w') as outfile:
                writer = csv.writer(outfile)
                writer.writerow(["ip", "qmin", "response"])
                for value in comb.values():
                    value.evaluateQMIN()
                    writer.writerow(value.asArray())
                outfile.close

    
