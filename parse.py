# Puts data into a CSV file so it can be read in faster
import sys
import os
import cPickle as pkl
from multiprocessing import Pool
import numpy as np

# Parses each malware file
def parse(fn, fileMap, a):
    # Get chunk number
    s = os.path.basename(fn)
    count = fileMap[s[:-4]]

    seq = np.array([])

    l = None

    # Read sequence
    with open(fn, 'rb') as fr:
        for i in range(count):
            n,l = pkl.load(fr)
            if len(seq) == 0:
                seq = n
            else:
                seq = np.append(seq,n)

    x = np.array([0]*a)
    # Deduplicate sequence integers
    s = set(seq)

    # Remove 0's from feature vector (these are padding integers)
    s -= {0}

    # Create feature vector for existence
    # -1 because 0 is used as a padding character for sequences
    for i in s:
        x[i-1] = 1

    # For classes 'benign' and 'malicious'
    if l > 0:
        l = 1

    return x,l

def parse_wrapper(args):
    return parse(*args)

def usage():
    print 'usage: python parser.py sequences/ api.txt out.csv'
    sys.exit(2)

def _main():
    if len(sys.argv) != 4:
        usage()

    sample_dir = sys.argv[1]
    api_file = sys.argv[2]
    outfile = sys.argv[3]

    # If outfile already exists, remove it
    if os.path.exists(outfile):
        os.remove(outfile)

    # Get number of API calls
    a = 0
    with open(api_file, 'rb') as fr:
        lines = fr.readlines()
        a = len(lines)

    # Read in metadata
    metadata_fn = os.path.join(sample_dir,'metadata.pkl')
    with open(metadata_fn,'rb') as fr:
    # Window Size
        windowSize = pkl.load(fr)
        # Number of samples per label
        labelCount = pkl.load(fr)
        # Number of samples per data file (so we can determine folds properly)
        fileMap = pkl.load(fr)

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

            fileList.append((sample_fn,fileMap,a))

    pool = Pool(20)
    results = pool.imap_unordered(parse_wrapper, fileList)

    # Consolidate all features to single CSV file
    with open(outfile, 'a') as fa:
        for e,r in enumerate(results):
            x,l = r

            # Append data to CSV file
            fa.write('{0}'.format(','.join(map(str,x))))
            fa.write(',{0}\n'.format(l))

            sys.stdout.write('\tExtracting sample: {0}/{1}\r'.format(e+1,len(fileList)))
            sys.stdout.flush()

    sys.stdout.write('\n')
    sys.stdout.flush()

    pool.close()
    pool.join()

if __name__ == '__main__':
    _main()