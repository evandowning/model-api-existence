import sys
import os
import cPickle as pkl
import numpy as np
from multiprocessing import Pool

from sklearn.ensemble import RandomForestClassifier
from sklearn.datasets import make_classification
from sklearn.metrics import accuracy_score

# Extracts features
def extract(fn,a):
    # Read sequence
    with open(fn, 'rb') as fr:
        s,l = pkl.load(fr)

    x = np.array([0]*a)
    # Deduplicate sequence integers
    s = set(s)
    # Create feature vector for existence
    for i in s:
        x[i] = 1
    
    # For classes 'benign' and 'malicious'
    if l > 0:
        l = 1

    return x,l

def extract_wrapper(args):
    return extract(*args)

# Iterates over each sample file to extract features
def existence(sample_dir,api_file):
    # Get number of API calls
    a = 0
    with open(api_file, 'rb') as fr:
        lines = fr.readlines()
        a = len(lines)

    fileList = list()

    # For each malware sample
    for root, dirs, files in os.walk(sample_dir):  
        #TODO - figure out how to make this 150k without running out of memory
        for filename in files[:1000]:
            # Ignore metadata
            if filename == 'metadata.pkl':
                continue

            # Read in sequence data
            sample_fn = os.path.join(root,filename)

            # If file is empty
            if os.stat(sample_fn).st_size == 0:
                continue

            fileList.append((sample_fn,a))

    X = np.array([])
    y = np.array([], dtype=np.int64)

    # Extract features in parallel
    pool = Pool(20)
    results = pool.imap_unordered(extract_wrapper, fileList)
    for e,r in enumerate(results):
        x,l = r

        # Append x data
        if len(X) == 0:
            X = x
        else:
            X = np.vstack((X,x))

        # Append y data
        y = np.append(y,[l])

        sys.stdout.write('Extracting sample: {0}/{1}\r'.format(e+1,len(fileList)))
        sys.stdout.flush()

    pool.close()
    pool.join()

    sys.stdout.write('\n')
    sys.stdout.flush()


    return X,y
    
def usage():
    print 'usage: python api_existence.py sequences/ api.txt'
    sys.exit(2)

def _main():
    if len(sys.argv) != 3:
        usage()

    sample_dir = sys.argv[1]
    api_file = sys.argv[2]

    # Extract features
    x,y = existence(sample_dir,api_file) 

    # Train random forest
    clf = RandomForestClassifier(max_depth=32, random_state=0)
    clf.fit(x, y)

    # Print out "n most important features"
    # https://stackoverflow.com/questions/6910641/how-do-i-get-indices-of-n-maximum-values-in-a-numpy-array
    n = 10
    imp = clf.feature_importances_
    index = imp.argsort()[-n:][::-1]
    # Print important API calls
    for i in index:
        print 'Call: {0}    Importance: {1}'.format(i,imp[i])

    # Run predictions
    predicted = clf.predict(x)
    accuracy = accuracy_score(y, predicted)

    print ''
    print 'Accuracy: {0:.3}'.format(accuracy)

if __name__ == '__main__':
    _main()
