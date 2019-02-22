# Produces images of api sequences
import sys
import os
import numpy as np
import png
from struct import unpack
from multiprocessing import Pool

# Extract API existence data and convert them to pixels
def extract(data,width):
    fn = data[0]
    label = data[-1]

    # Read in sample's sequence
    seq = data[1:-1]
    seq = map(int, seq)

    # Pad array if it's not divisible by width
    r = len(seq) % width
    if r != 0:
        seq.extend([0]*(width-r))

    # Reshape numpy array
    rv = np.reshape(np.array(seq), (-1,width))
    rv = rv.astype(np.int8)

    return fn,rv,label

def extract_wrapper(args):
    return extract(*args)

def usage():
    print 'usage: python color.py data.csv images/ image.labels errors.txt'
    sys.exit(2)

def _main():
    if len(sys.argv) != 5:
        usage()

    feature_csv = sys.argv[1]
    output_folder = sys.argv[2]
    output_labels = sys.argv[3]
    output_errors = sys.argv[4]

    #TODO - make these parameters
    # Width of image
    width = 496

    # Grayscale (1 channel)
    fmt_str = 'L;1'

    # If output folder doesn't exist, create it
    if not os.path.exists(output_folder):
        os.mkdir(output_folder)

    data = list()

    # Read in data
    print 'Reading in data'
    with open(feature_csv,'r') as fr:
        for e,line in enumerate(fr):
            line = line.strip('\n')
            data.append(line.split(','))

            # Only do first 10k samples
            if e == 10000:
                break


    #TODO - make these parameters
    # Create argument pools
    args = [(d,width) for d in data]

    # Extract images
    pool = Pool(20)
    results = pool.imap_unordered(extract_wrapper, args)

    # Write labels
    with open(output_labels,'w') as fo, open(output_errors,'w') as fe:
        for e,r in enumerate(results):
            sys.stdout.write('Extracting sample\'s traces: {0}/{1}\r'.format(e+1,len(args)))
            sys.stdout.flush()

            fn,data,label = r

            # Write existence to image file
            out_path = os.path.join(output_folder,fn+'.png')
            png.from_array(data, fmt_str).save(out_path)

            # Write label
            fo.write('{0} {1}\n'.format(fn,label))

    pool.close()
    pool.join()

    sys.stdout.write('\n')
    sys.stdout.flush()

if __name__ == '__main__':
    _main()
