import sys
import os
import cPickle as pkl
import numpy as np
from multiprocessing import Pool
import random

from sklearn.ensemble import RandomForestClassifier
from sklearn.datasets import make_classification
from sklearn.metrics import accuracy_score
from sklearn.model_selection import KFold
from sklearn.externals import joblib


# Extracts features
def extract(fn,a):
    # Read sequence
    with open(fn, 'rb') as fr:
        s,l = pkl.load(fr)

    x = np.array([0]*a)
    # Deduplicate sequence integers
    s = set(s)

    # Remove 0's from feature vector (these are padding integers)
    s -= {0}

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

    # Get number of API calls
    a = 0
    with open(api_file, 'rb') as fr:
        lines = fr.readlines()
        a = len(lines)

    # Create Random Forest
    # https://stackoverflow.com/questions/42757892/how-to-use-warm-start#42763502
    clf = RandomForestClassifier(warm_start=True,n_estimators=10)

    fileList = list()

    # For each malware sample
    for root, dirs, files in os.walk(sample_dir):  
        for filename in files:
            # Ignore metadata
            if filename == 'metadata.pkl':
                continue

            # Read in sequence data
            sample_fn = os.path.join(root,filename)

            # If file is empty
            if os.stat(sample_fn).st_size == 0:
                continue

            fileList.append((sample_fn,a))

    print 'Number of samples: {0}'.format(len(fileList))

    # Split dataset
    random.shuffle(fileList)
    t = int(len(fileList)*0.9)
    train = fileList[:t]
    test = fileList[t:]

    e = 0

    # Iteratively train over portions of samples
    print 'Running training'
    m = 100 # Fit m samples at a time
    for i in range(0,len(train),m):
        X = np.array([])
        y = np.array([], dtype=np.int64)

        # Extract features in parallel
        pool = Pool(20)
        results = pool.imap_unordered(extract_wrapper, train[i:i+m])
        for r in results:
            x,l = r

            # Append x data
            if len(X) == 0:
                X = x
            else:
                X = np.vstack((X,x))

            # Append y data
            y = np.append(y,[l])

            sys.stdout.write('\tExtracting sample: {0}/{1}\r'.format(e+1,len(train)))
            sys.stdout.flush()

            e += 1

        pool.close()
        pool.join()

        sys.stdout.write('\n')
        sys.stdout.flush()

        # Train random forest
        clf.fit(X,y)

    # Print out "n most important features"
    # https://stackoverflow.com/questions/6910641/how-do-i-get-indices-of-n-maximum-values-in-a-numpy-array
    n = 10
    imp = clf.feature_importances_
    index = imp.argsort()[-n:][::-1]
    # Print important API calls
    for i in index:
        print 'Call: {0}    Importance: {1}'.format(i,imp[i])

    # Run predictions
    print 'Running predictions'
    X = np.array([])
    y = np.array([], dtype=np.int64)

    #NOTE: I pretend that we can fit this whole test dataset into memory
    # Extract features in parallel
    pool = Pool(20)
    results = pool.imap_unordered(extract_wrapper, test)
    for e,r in enumerate(results):
        x,l = r

        # Append x data
        if len(X) == 0:
            X = x
        else:
            X = np.vstack((X,x))

        # Append y data
        y = np.append(y,[l])

        sys.stdout.write('\tExtracting sample: {0}/{1}\r'.format(e+1,len(test)))
        sys.stdout.flush()

    pool.close()
    pool.join()

    sys.stdout.write('\n')
    sys.stdout.flush()

    predicted = clf.predict(X)
    accuracy = accuracy_score(y, predicted)
    joblib.dump(clf, 'model.pkl') 
    print ''
    print 'Validation Accuracy: {0:.3}'.format(accuracy)

if __name__ == '__main__':
    _main()
