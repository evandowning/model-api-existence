import sys
import os
import math
import numpy as np
import cPickle as pkl
from subprocess import call
import itertools
from multiprocessing import Pool

from sklearn import tree
from sklearn.tree import _tree
from sklearn.externals import joblib

# NOTE: to defeat a random forest, we must defeat a majority
#       of the decision trees in that forest:
# http://scikit-learn.org/stable/modules/generated/sklearn.ensemble.RandomForestClassifier.html#sklearn.ensemble.RandomForestClassifier.predict

#TODO
# Finds attack across multiple trees
def find_attack(trees, benign_paths):
    for t in benign_paths:
        print len(t)

# Produces attack for each sample
def attack_all(fn, fileMap, clf, benign_paths, num_trees, half, a, api_list, output_dir):
    # Get chunk number
    s = os.path.basename(fn)
    count = fileMap[s[:-4]]

    seq = np.array([])

    l = None

    print 'Reading in sequence'

    # Read sequence
    with open(fn, 'rb') as fr:
        for i in range(count):
            n,l = pkl.load(fr)
            if len(seq) == 0:
                seq = n
            else:
                seq = np.append(seq,n)

    print 'done'

    # If sample is benign, ignore it
    if l == 0:
        return None
    # Else, change label to be malicious (instead of malware class)
    else:
        l = 1

    x = np.array([0]*a)
    # Deduplicate sequence integers
    s = set(seq)

    # Remove 0's from feature vector (these are padding integers)
    s -= {0}

    # Create list of API calls to check against
    # If any path traverses to the left, it means the API call
    # shouldn't exist, violating our constraint of not removing
    # any API calls.
    check = list()

    # Create feature vector for existence
    # -1 because 0 is used as a padding character for sequences
    for i in s:
        # NOTE: "i" should be the same value as "api_list[i-1]"
        x[i-1] = 1
        check.append([str(api_list[i-1]),'left'])

    # Evaluate features
    pred = clf.predict([x])[0]

    if pred == 0:
        print '    Already classified as benign'
        return None

    print 'Removing irrelevant benign paths'

#   print check
    remove = dict()

    # Remove all benign paths which involve removing some API call which
    # already exists in the malware.
    for e1,t in enumerate(benign_paths):
        count = 0
        print 'number of paths: {0}'.format(len(t))

        r = list()

        # For each benign path in tree
        for e2,p in enumerate(t):
            if any(p[i:i+2] in check for i in range(0,len(p),2)):
                count += 1
                r.append(e2)

        remove[e1] = r
        print 'removing: {0} paths'.format(count)
        print ''

    # Remove paths
    for k,v in remove.iteritems():
        # Remove in reverse order so indices are correct
        for i in v[::-1]:
            del benign_paths[k][i]

    print 'done'
    print ''

    #TODO
    # Find overlap in benign paths across trees
    attack = find_attack(clf.estimators_, benign_paths)

def attack_all_wrapper(args):
    return attack_all(*args)

# Prints out decision tree logic in if-else statement form
def recursive_print(left, right, threshold, features, node, value, depth=0):
    indent = "\t" * depth
    if(threshold[node] != -2):
        print indent, "if ( " + str(features[node]) + " <= " + str(threshold[node])  + " class:" + str(np.argmax(value[node])) +  "  ) { " 
        if left[node] != -1:
            recursive_print (left, right, threshold, features, left[node], value, depth+1)
            print indent, '} else { '
            if right[node] != -1:
                recursive_print (left, right, threshold, features, right[node], value, depth+1)
            print indent, ' } '
    else:
        print indent,"return "  + str(value[node])

# Print decision tree
def print_tree(tree_in_clf, api_list, fn, outfn):
    # Print tree logic to stdout
    # https://www.kdnuggets.com/2017/05/simplifying-decision-tree-interpretation-decision-rules-python.html
#   recursive_print(left, right, tree_in_clf.tree_.threshold, tree_in_clf.tree_.feature, node, tree_in_clf.tree_.value)

    print 'Writing tree to {0} and {1}'.format(fn, outfn)

    # https://stats.stackexchange.com/questions/118016/how-can-you-print-the-decision-tree-of-a-randomforestclassifier
    # Write tree information to dot file
    with open(fn, 'w') as fw:
        tree.export_graphviz(tree_in_clf, out_file = fw, class_names = ['benign', 'malicious'], feature_names = api_list)

    # Convert dot file to png file
    call(['dot', '-Tpng', fn, '-o', outfn, '-Gdpi=300'])

# Pythonic way of traversing tree & keeping track of path
# Based on https://eddmann.com/posts/depth-first-search-and-breadth-first-search-in-python/
def get_paths(t,start):
    # Initialize path
    queue = [(start, [start])]

    while queue:
        # Get current node/path
        (node, path) = queue.pop(0)

        # Get left and right children of node
        left = t.children_left[node]
        right = t.children_right[node]

        # If leaf node, yield path
        if (left == -1) and (right == -1):
            yield path
        else:
            # If a left child exists
            if left != -1:
                queue.append((left, path + ['left',left]))
            # If a right child exists
            if right != -1:
                queue.append((right, path + ['right',right]))

# Extracts benign paths of single tree
def parse_tree(tree_,feature_names):
    threshold = tree_.threshold
    features = tree_.feature

    #TODO - number of samples and values do not match
    value = tree_.value
    samples = tree_.n_node_samples
#   print value, samples

    # Get all paths in decision tree
    paths = list(get_paths(tree_,0))

#   print '    Number of paths: ', str(len(paths))

    rules = list()

    # Extract rulesets for benign paths
    for p in paths:
        # Get last node in path (the class)
        c = p[-1]

        # If the class is benign
        if np.argmax(value[c]) == 0:
            f = list()

            for n in p:
                if n == 'left' or n == 'right':
                    f.append(n)
                    continue

                if threshold[n] != -2:
                    f.append(str(feature_names[features[n]]))

            rules.append(f)

    return rules

# Returns list of rulesets for benign paths
def create_rules(clf, api_list):
    rules = list()

    #TODO - remove limit on number of trees searched
    # Iterate over each tree in random forest
    for e, tree_in_clf in enumerate(clf.estimators_):
        print 'Scanning tree {0}'.format(e)

        # Create ruleset for tree
        rv = parse_tree(tree_in_clf.tree_,api_list)
        rules.append(rv)

#       # Print tree to file
#       fn = 'tree_' + str(e) + '.dot' 
#       outfn = 'tree_' + str(e) + '.png'
#       print_tree(tree_in_clf, api_list, fn, outfn)

        if e == 4:
            break

    return rules

def usage():
    print 'usage: python attack.py sequences/ api.txt model.pkl output/'
    sys.exit(2)

def _main():
    if len(sys.argv) != 5:
        usage()

    # Get parameter
    sample_dir = sys.argv[1]
    api_file = sys.argv[2]
    modelfn = sys.argv[3]
    output_dir = sys.argv[4]

    # If output_dir doesn't exist yet
    if not os.path.exists(output_dir):
        os.mkdir(output_dir)

    # Get number of API calls
    a = 0
    api_list = list()
    with open(api_file, 'rb') as fr:
        for e,line in enumerate(fr):
            line = line.strip('\n')
            api_list.append('{0} {1}'.format(e+1,line))
            a += 1

    # Load model
    print 'Loading model'
    clf = joblib.load(modelfn)

    # Extract benign paths for each tree
    benign_paths = create_rules(clf, api_list)

#   num_trees = len(clf.estimators_)
    num_trees = len(benign_paths)
    # If evenly divisible
    if num_trees % 2 == 0:
        half = num_trees/2 + 1
    else:
        half = int(math.ceil(num_trees/2.0))

    print ''
    print 'Must find attacks for at least {0}/{1} trees'.format(half,num_trees)
    print ''

    # Read in metadata
    metadata_fn = os.path.join(sample_dir,'metadata.pkl')
    with open(metadata_fn,'rb') as fr:
    # Window Size
        windowSize = pkl.load(fr)
        # Number of samples per label
        labelCount = pkl.load(fr)
        # Number of samples per data file (so we can determine folds properly)
        fileMap = pkl.load(fr)

    args = list()

    # Get malware files to find attacks for
    for root, dirs, files in os.walk(sample_dir):
        for filename in files:
            # Ignore metadata
            if filename == 'metadata.pkl':
                continue

            # Read in sequence data
            fn = os.path.join(root,filename)

            # If file is empty
            if os.stat(fn).st_size == 0:
                continue

            args.append((fn,fileMap,clf,benign_paths,num_trees,half,a,api_list,output_dir))

            #TODO - testing just one sample
            break

    #TODO -testing sequential
    for a in args:
        r = attack_all(*a)

if __name__ == '__main__':
    _main()
