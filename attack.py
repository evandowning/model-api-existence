from sklearn.externals import joblib
from sklearn.ensemble import RandomForestClassifier
import sys
import os
import cPickle as pkl
import numpy as np
from sklearn import tree
from subprocess import call


def parse_tree(tree_):
    # print tree_
    # print tree_.children_left[0]
    # print tree_.children_left
    # print tree_.children_right[0]
    # print tree_.children_right
    # print '----'
    # print tree_.feature
    # print tree_.value

    left = tree_.children_left
    right = tree_.children_right

    threshold = tree_.threshold
    #TODO- Our sapmle number and total of value number doesn't mach
    value = tree_.value
    node = 0 ## root is located at index 0 in the array
    features = tree_.feature

    recursive_parse(left, right, threshold, features, node, value)

    

    #https://www.kdnuggets.com/2017/05/simplifying-decision-tree-interpretation-decision-rules-python.html
def recursive_parse(left, right, threshold, features, node, value, depth=0):
    indent = "\t" * depth
    if(threshold[node] != -2):
        print indent, "if ( " + str(features[node]) + " <= " + str(threshold[node])  + " class:" + str(np.argmax(value[node])) +  "  ) { " 
        if left[node] != -1:
            recursive_parse (left, right, threshold, features, left[node], value, depth+1)
            print indent, '} else { '
            if right[node] != -1:
                recursive_parse (left, right, threshold, features, right[node], value, depth+1)
            print indent, ' } '
        
    else:
        print indent,"return "  + str(value[node])
                                                                                                                                                        



def find_tree(clf,api_list):
    #https://stats.stackexchange.com/questions/118016/how-can-you-print-the-decision-tree-of-a-randomforestclassifier
    i_tree = 0

    #TODO - figure out which tree is being chosen?
    # Or, since it's an ensemble, do you have to attack multiple trees (i.e., all 10?)

    # Iterate over each tree in random forest
    for tree_in_clf in clf.estimators_:
        #TODO
        # Traverse tree to find shorest path to 0 from malware input

        fn = 'tree_' + str(i_tree) + '.dot' 
        outfn = 'tree_' + str(i_tree) + '.png'
        print 'Parsing tree: {0}...'.format(i_tree)
        parse_tree(tree_in_clf.tree_)

        print 'Writing tree: {0}...'.format(i_tree)

        # Write tree information to dot file
        with open(fn, 'w') as my_file:
            #fn.get._state_()
            my_file = tree.export_graphviz(tree_in_clf, out_file = my_file, class_names = ['benign', 'malicious'], feature_names = api_list)
            #my_file.get._state_()
        # Convert dot file to png file
        #call(['dot', '-Tpng', fn, '-o', outfn, '-Gdpi=600'])

        i_tree = i_tree + 1
        quit()


def usage():
    print 'usage: python attack.py sequences/'
    sys.exit(2)

def _main():
    if len(sys.argv) != 3:
        usage()

    sample_dir = sys.argv[1]
    api_file = sys.argv[2]

    # Get number of API calls
    api_list = []
    a = 0
    with open(api_file, 'rb') as fr:
        for line in fr:
            api_list.append(str(a))
            a = a+1
    #print api_list
    #quit()


    clf = joblib.load('model.pkl')
    print clf

    find_tree(clf,api_list)
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

if __name__ == '__main__':
    _main()
