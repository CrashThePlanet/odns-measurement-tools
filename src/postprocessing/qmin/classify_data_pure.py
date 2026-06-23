
import csv
from pathlib import Path
import sys
from enum import Enum
from datetime import datetime
import graphviz

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

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

# schema for parquet file(s)
schema = pa.schema([
    pa.field("resolver_ip", pa.string()),
    pa.field("status", pa.int16()),
    pa.field("res", pa.map_(pa.string(), pa.int32())),
    pa.field("requesting_ip", pa.list_(pa.string()))
])

# output graph to show distribution
graph = graphviz.Digraph()

def classify():
    # setup empty dict structure to hold classified data
    result = {key: None for key in ResolverEval}

    # sub-dicts for each depending if some requests to a resolver failed or if all went through
    for key in ResolverEval:
        graph.edge("root", str(key))
        if key == ResolverEval.ERROR:
            continue
        result[key] = {"allGood": [], "someError": []}
        # set edges for graph
        # the nodes will be defined later so they can include the total count
        # edges can be defined with the nodes existing yet
        graph.edge(str(key), str(key) + "allGood")
        graph.edge(str(key), str(key) + "someError")
    result[ResolverEval.ERROR] = []

    # read file to be classified
    table = pq.read_table(sys.argv[1])
    df_table = table.to_pandas()

    for row in df_table.itertuples(index=False):
        someError = False
        # check if at least one of the requests failed
        for res in row.res:
            if res[0].upper() in ResponseStatus.__members__:
                someError = True
        # add to sub-dicts depending on status and if all requests qere good
        if int(row.status) == -1:
            result[ResolverEval.ERROR].append(row)
        else:
            result[ResolverEval(int(row.status))]["someError" if someError else "allGood"].append(row)
    # set root node for output graph with total number of resolver
    graph.node("root", "Resolver\n" + str(df_table.shape[0]))
    return result

# simply create and directory of catch fail
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

# write the classifcation to a directory
# structure follows the the graph (or vise-versa)
# recursive function
def writeClassifiedResolver(resolver, outDir, parent=None):
    makeDirctory(outDir)

    for key, value in resolver.items():
        # value of type dict means, that this is and directory
        # therefore make directory and giv contents to recursion
        if isinstance(value, dict):
            writeClassifiedResolver(value, outDir / str(key), key)
        # value of type list means it is a file
        # therefore create Dataframe from list of resolver scans and write to parquet file in given directory
        if isinstance(value, list):
            df = pd.DataFrame(value, columns=["resolver_ip", "status", "res", "requesting_ip"])
            df.to_parquet(outDir / (str(key)+".parquet"), schema=schema)
            # define node for graph with resolver count
            # the internal name of the node includes the name of the parent to differntiate between e.g. the "allGood" of QMIN resolver
            # and the "allGood" node of the NOQMIN resolver
            graph.node((str(parent) if (parent != None) else "") + str(key), str(key) + "\n" + str(len(value)))

if __name__ == '__main__':
    if not Path(sys.argv[1]).exists():
        print("File does not exist!")
        sys.exit(1)
    
    #default output directory
    # going fro mthe roor of the project it should by odns-measurement-tools/src/data/processed/qmin
    outputDir = "./../../data/processed/qmin/"
    # if there is a third argument, check if directory exitsts
    if 2 < len(sys.argv):
        if not Path(sys.argv[2]).exists():
            print("Provided output directory does not exist")
            sys.exit(1)
        outputDir = sys.argv[2]
    
    # create output path for this classification run
    # structure is: "classify_*YEAR*-*MONTH*-*DAY*_*HOUR*-*MINUTES*"
    outputDir = Path(outputDir + "classify_" + datetime.now().strftime("%Y-%m-%d_%H-%M"))

    # run classification, write for folder structure and render graph
    classifiedResolver = classify()

    writeClassifiedResolver(classifiedResolver, outputDir)
    graph.render(outputDir / "graph", format="svg", cleanup=True)


    
