from sklearn.externals import joblib
from sklearn.ensemble import RandomForestClassifier
import sys
import os
import cPickle as pkl
from sklearn import tree
from subprocess import call


def find_tree(clf):
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

        print 'Writing tree: {0}...'.format(i_tree)
        print tree_in_clf.tree_
        print tree_in_clf.tree_.children_left[0]
        print tree_in_clf.tree_.children_left
        print tree_in_clf.tree_.children_right[0]
        print tree_in_clf.tree_.children_right

        # Write tree information to dot file
        with open(fn, 'w') as my_file:
            #fn.get._state_()
            my_file = tree.export_graphviz(tree_in_clf, out_file = my_file)
            #my_file.get._state_()
        # Convert dot file to png file
        #call(['dot', '-Tpng', fn, '-o', outfn, '-Gdpi=600'])

        i_tree = i_tree + 1



def usage():
    print 'usage: python attack.py sequences/'
    sys.exit(2)

def _main():
    if len(sys.argv) != 2:
        usage()

    sample_dir = sys.argv[1]

    clf = joblib.load('model.pkl')
    print clf

    find_tree(clf)

if __name__ == '__main__':
    _main()
