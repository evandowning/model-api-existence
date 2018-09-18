import sys
import os
import numpy as np
import cPickle as pkl
from subprocess import call

from sklearn import tree
from sklearn.tree import _tree
from sklearn.externals import joblib

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
#   recursive_print(left, right, threshold, features, node, value)

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

# Creates ruleset of single tree
def parse_tree(tree_,feature_names):
    # print tree_
    # print tree_.children_left[0]
    # print tree_.children_left
    # print tree_.children_right[0]
    # print tree_.children_right
    # print '----'
    # print tree_.feature
    # print tree_.value

    rules = list()

    threshold = tree_.threshold
    features = tree_.feature

    #TODO - number of samples and values do not match
    value = tree_.value
    samples = tree_.n_node_samples
#   print value, samples

    # Get all paths in decision tree
    paths = list(get_paths(tree_,0))

    print 'number of paths: ', str(len(paths))
#   for e,p in enumerate(paths):
#       print 'path {0}'.format(e)
#       for n in p:
#           if n == 'left' or n == 'right':
#               print '\t', n
#               continue

#           # the leaf node (i.e., class)
#           if threshold[n] == -2:
#               print '\tclass:' + str(np.argmax(value[n]))
#           else:
#               print '\t' + str(feature_names[features[n]])

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
    trees = list()
    rules = list()

    # Iterate over each tree in random forest
    for e, tree_in_clf in enumerate(clf.estimators_):
        # Create ruleset for tree
        rv = parse_tree(tree_in_clf.tree_,api_list)
        trees.append(tree_in_clf)
        rules.append(rv)

#       # Print tree to file
#       fn = 'tree_' + str(e) + '.dot' 
#       outfn = 'tree_' + str(e) + '.png'
#       print_tree(tree_in_clf, api_list, fn, outfn)

    return trees,rules

def usage():
    print 'usage: python attack.py sequences/ api.txt model.pkl'
    sys.exit(2)

def _main():
    if len(sys.argv) != 4:
        usage()

    # Get parameter
    sample_dir = sys.argv[1]
    api_file = sys.argv[2]
    modelfn = sys.argv[3]

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
    trees, rules = create_rules(clf, api_list)

    #TODO
    # Evaluate each benign path on each malware sample
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

            print fn
            # Evaluate features
            pred = clf.predict([x])[0]
            print pred

            if pred == 0:
                print '\tAlready classified as benign'
                continue

            # Get decision path for this sample
            # https://stackoverflow.com/questions/48869343/decision-path-for-a-random-forest-classifier
#           print clf.decision_path([x])
#           (node_indicator, _) = clf.decision_path([x])
#           print node_indicator

#           node_index = node_indicator.indices[node_indicator.indptr[0]:
#                                   node_indicator.indptr[1]]
#           print node_index
#           print len(node_index)


            # http://scikit-learn.org/stable/auto_examples/tree/plot_unveil_tree_structure.html#
            # https://stackoverflow.com/questions/48880557/print-the-decision-path-of-a-specific-sample-in-a-random-forest-classifier
            for estimator in trees:
                node_indicator = estimator.decision_path([x])
#               print node_indicator

                leave_id = estimator.apply([x])

                node_index = node_indicator.indices[node_indicator.indptr[0]:
                                        node_indicator.indptr[1]]
#               print node_index

                features = estimator.tree_.feature
                value = estimator.tree_.value
                for n in node_index:
                    # If a leaf node is reached, a decision is made
                    if leave_id[0] == n:
                        print 'leaf node: ', str(np.argmax(value[n]))
                        break
                    print '\t', str(api_list[features[n]])
                print ''
            break

if __name__ == '__main__':
    _main()
