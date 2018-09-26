import sys
import os
import numpy as np
import shutil
import cPickle as pkl
from sklearn.externals import joblib
from neo4jrestclient.client import GraphDatabase

# Suppress Neo4j warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def mimicry(sample_dir,neo4j_db,mal_fn,name,a,clf,metadata_fn):
   
    # Get attack api's needed to be inserted for existence attack
    for root, dirs, files in os.walk(sample_dir):

        for filename in files:
            
            # Ignore metadata
            if filename == 'metadata.pkl':
                    continue

            # Read in sequence data
            fn = os.path.join(root,filename)
            existence_name = os.path.basename(fn)
            #print s

            # If file is empty
            if os.stat(fn).st_size == 0:
                continue
            if name == existence_name:
                with open(fn, 'rb') as fr:
                    existence_line = fr.readlines()
                    existence_line =  eval(existence_line[0])
                    #print line
                l_line = len(existence_line)
                #print l

    with open(metadata_fn,'rb') as fr:
        # Window Size
        windowSize = pkl.load(fr)
        # Number of samples per label
        labelCount = pkl.load(fr)
        # Number of samples per data file (so we can determine folds properly)
        fileMap = pkl.load(fr)

    count = fileMap[name]

    # Get sequence data from malware
    seq = np.array([])
    with open(mal_fn, 'rb') as fr:
        for i in range(count):
            s,l = pkl.load(fr)
            
            if len(seq) == 0:
                seq = s
            else:
                seq = np.append(seq,s)

    print 'orig len: {0}'.format(len(seq))
    
    # If no sequences, return
    if len(seq) == 0:
        return False,0,0,0,0,0,0

    mw_label = l
    len_of_mw = np.count_nonzero(seq)
    # Query mimicry path
    index = np.arange(2)[None,:] + np.arange(len(seq)-1)[:,None]
    # For each pair of API calls...
    pair_no = 0
    api_array = []


    #TODO
    # Steps:
    #    1. Loop through original malware sequences
    #    2. Perform Mimicry (i.e., between each pair of api calls in the
    #       original malware sample, search for an API call which exists
    #       between them in the Neo4j graph).
    #           - While you are doing this, instead of simply checking
    #             for *any* API call in the Neo4j graph, check if one of
    #             the API calls in the existence attack (i.e., l above)
    #             connects the two original malware API calls
    #    3. As you do this, make sure you insert *all* api calls which
    #       need to be added from the existence attack (i.e., l above)
    #           - If you are unable to find any existence attack api calls
    #             in between the two original malware api calls, see if a
    #             direct connection connects the two original calls.
    #           - If you still cannot find a connection, search (randomly)
    #             for an API call which already exists in the original
    #             sequence to connect them.
    #           - Hope we don't fail after that. -if so, then we have to do
    #             multiple rounds of attack existence, attack mimicry, etc.
    #               - for now, just print out the sample hashes of which get to here

    # To search for direct connections (or otherwise), see my email I sent today (09/25/2018)
    i = 0
    e_number = 0

    # Loop through api call pairs (from sequences) to find mimicry path
    for e,p in enumerate(seq[index]):
        pair_no = pair_no + 1
        p1 = p[0]
        p2 = p[1]
    
        # If api calls are just padding calls, we're done
        if p1 == 0 or p2 == 0:
            break

        # Loop through existence attack api calls and find path between malware api call pairs which pass through the attack api calls
        if l_line > e_number:  
#           print 'enumber: {0}'.format(e_number)
            
            q = "MATCH (n:NODE {{name: '{0}'}}) MATCH (m:NODE {{name: '{1}'}}) MATCH (k:NODE {{name: '{2}'}})".format(p1,p2,existence_line[e_number])
            q += "MATCH path=(n)-[:EDGE]->(k)-[:EDGE]->(m)"
            q += "RETURN extract(node in nodes(path) | node.name) as nodes"
            
            # Search for the path
            result = neo4j_db.query(q)
            # If we found a path, add the new attack api call between the malware api call pairs and continue searching for next attack api call to insert
            if len(result) > 0:
                for r in result:
                    keep_api = []
                    for blah in r[0]:
                        blah = int(blah)
                        keep_api.append(blah)
                e_number += 1
           
           
                # Insert new attack api call(s)
                if i == 0:
                    api_array.extend(keep_api)
                    i = i+1
                # Prevents overlap with api calls we've already added
                else:
                    api_array.extend(keep_api[1:])

            # If we didn't find a direct path through the attack api call, search for path through api call which already exists in malware sequence
            else :
                q = "MATCH (n:NODE {{name: '{0}'}}) MATCH (m:NODE {{name: '{1}'}})".format(p1,p2)
                q += "MATCH path=(n)-[:EDGE]->(m)"
                q += "RETURN extract(node in nodes(path) | node.name) as nodes"
                
                # Search for path 
                result = neo4j_db.query(q)

                # If we found a path
                if len(result) > 0:
                    for r in result:
                        keep_api = []
                        for blah in r[0]:
                            blah = int(blah)
                            keep_api.append(blah)

                    # Add new api call
                    if i == 0:
                        api_array.extend(keep_api)
                        i = i+1
                    else:
                        api_array.extend(keep_api[1:])

#           print 'api_array: {0}'.format(len(api_array))

        # If we've finished inserting all new attack api calls (for existence), now just find paths through api calls which already exist in malware api call sequence
        else:
#           print 'FINISHED with finding attack'
            
            q = "MATCH (n:NODE {{name: '{0}'}}) MATCH (m:NODE {{name: '{1}'}})".format(p1,p2)
            q += "MATCH path=(n)-[:EDGE]->(m)"
            q += "RETURN extract(node in nodes(path) | node.name) as nodes"

            # Search for path
            result = neo4j_db.query(q)

            # If we found a path
            if len(result) > 0:
                for r in result:
                    keep_api = []
                    for blah in r[0]:
                        blah = int(blah)
                        keep_api.append(blah)

                if i == 0:
                    api_array.extend(keep_api)
                    i = i+1
                else:
                    api_array.extend(keep_api[1:])

#               print 'api_array: {0}'.format(len(api_array))

            #TODO - add in case where we can search for a path through another existing api call in the malware sequence

            # Else, we can't find a new path so we fail at attacking both sequence & existence models
            else:
                print 'Error, failed to find attack'
                return

    #print api_array
   # api_array = eval(api_array)
   # print api_array

               
               #print x
    x = [0]*a
    # Create new existence features from new malware
    for i in api_array:
        x[i] = 1
       # print x[i]

    # Classify new existence feature
    pred = clf.predict([x])[0]
    
    # If classified as benign, we succeed
    if pred == 0:
        print '\tSucceess'
    # Else, we've failed. We shouldn't get here
    else:
        print '\tError, only inserted api calls which already existed or are in the attack and still is classified as malicious'


def usage():
    print 'usage:  python neo4j-mode.py /data/arsa/api-existence-attacks /home/evan/arsa/model-api-existence/model.pkl /data/arsa/api-sequences-all-classification-32-filtered/ api.txt /data/arsa/api-sequences-all-classification-32-filtered/metadata.pkl'
    sys.exit(2)

def _main():
    if len(sys.argv) != 6:
        usage()

    sample_dir = sys.argv[1]
    modelfn = sys.argv[2]
    mal_dir = sys.argv[3]
    api_file = sys.argv[4]
    metadata_fn = sys.argv[5]

    #count = 0
    neo4j_db = GraphDatabase('http://localhost:7474', username='neo4j', password='change123me!@#')
   
   # Load model
    #print 'Loading model'
    clf = joblib.load(modelfn)
   
    a = 0
    with open(api_file, 'rb') as fr:
        lines = fr.readlines()
        a = len(lines)
    
# Load malwares

    say = 0
    for root, dirs, files in os.walk(mal_dir):  
        for filename in files:
            # Ignore metadata
            if filename == 'metadata.pkl':
                continue
            # Read in sequence data
            mal_fn = os.path.join(root,filename)
            name = os.path.basename(mal_fn)[:-4]
            #print name

            # If file is empty
            if os.stat(mal_fn).st_size == 0:
                continue
            if say < 10:
                print 'Finding attack for {0}'.format(mal_fn)
                mimicry(sample_dir,neo4j_db,mal_fn,name,a,clf,metadata_fn)
            say = say+1
            
            
# Simdilik burda dursun

      # x = np.array([0]*a)
                # Deduplicate sequence integers
               # k = set(k)

                # Remove 0's from feature vector (these are padding integers)
               # k -= {0}

        
               # for i in k:
                  #  x[i-1] = 1
   

                #print name


if __name__ == '__main__':
    _main()
