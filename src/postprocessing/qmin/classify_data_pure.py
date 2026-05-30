
import csv
from pathlib import Path
import sys
from enum import Enum
from datetime import datetime
import graphviz

class ResponseStatus(Enum):
    UNHANDLEDERROR = -1
    GOOD = 0
    REFUSED = 1
    SERVFAIL = 2
    TIMEOUT = 3
    NXDOMAIN = 4
    NOROUTE = 5
    NORECURSION = 6
    NOANSWER = 7
    NOTXTRESPONSE = 8

# all types (except ERROR) will contain another split for Resolver that sometimes answered (with the respective type) and sometimes gave an error
class ResolverEval(Enum):
    ERROR = -1
    NOQMIN = 0
    QMIN = 1
    PARTIAL = 2

graph = graphviz.Digraph()

def classify():
    # setup empty dict structure to hold classified data
    result = {key: None for key in ResolverEval}

    for key in ResolverEval:
        graph.edge("root", str(key))
        if key == ResolverEval.ERROR:
            continue
        result[key] = {"allGood": [], "someError": []}
        graph.edge(str(key), str(key) + "allGood")
        graph.edge(str(key), str(key) + "someError")
    result[ResolverEval.ERROR] = []
    
    num_rows = 0
    with open(sys.argv[1], newline='') as file:
        csvfile = csv.DictReader(file)
        for row in csvfile:
            num_rows += 1
            responses = stringToDict(row['response'])

            someError = False
            for key in responses.keys():
                if key in ResponseStatus:
                    someError = True
            if int(row['qmin']) == -1:
                result[ResolverEval.ERROR].append(row.values())
            else:
                result[ResolverEval(int(row['qmin']))]["someError" if someError else "allGood"].append(row.values())
        
        file.close()
        #print(result[ResolverEval.QMIN]["allGood"])
    graph.node("root", "Resolver\n" + str(num_rows))
    return result


def stringToDict(input):
    input = input[1:-1]

    res = {}

    top = input.split(";")
    for line in top:
        resType = line.split(":")

        if "*idToken*" in resType[0]:
            res[resType[0]] = int(resType[1])
        else:
            # some resolver return blocked in form of a TXt message
            # now skip
            # TODO: handle
            try:
                res[ResponseStatus[resType[0].upper()]] = int(resType[1])
            except:
                res[ResponseStatus.UNHANDLEDERROR] = 1
    return res

def makeDirctory(path):
    try:
        path.mkdir()
    except FileExistsError:
        print(f"Directory '{path}' already exists.")
        return
    except PermissionError:
        print(f"Permission denied: Unable to create '{path}'.")
        return
    except Exception as e:
        print(f"An error occurred while creating output directory: {e}")
        return

def writeClassifiedResolver(resolver, outDir, parent=None):
    makeDirctory(outDir)

    for key, value in resolver.items():
        if isinstance(value, dict):
            writeClassifiedResolver(value, outDir / str(key), key)
        if isinstance(value, list):
            with open(outDir / (str(key)+".csv"), 'w') as outfile:
                writer = csv.writer(outfile)
                writer.writerow(["resolverIP", "requestingIPs", "qmin", "response"])
                writer.writerows(value)
                outfile.close
                graph.node((str(parent) if (parent != None) else "") + str(key), str(key) + "\n" + str(len(value)))

if __name__ == '__main__':

    if not Path(sys.argv[1]).exists():
        print("File does not exist!")
        sys.exit(1)
    
    outputDir = "./../../data/processed/qmin/"
    if 2 < len(sys.argv):
        if not Path(sys.argv[2]).exists():
            print("Provided output directory does not exist")
            sys.exit(1)
        outputDir = sys.argv[2]
    
    outputDir = Path(outputDir + "classify_" + datetime.now().strftime("%Y-%m-%d_%H-%M"))


    classifiedResolver = classify()

    writeClassifiedResolver(classifiedResolver, outputDir)
    graph.render(outputDir / "graph", format="svg", cleanup=True)


    
