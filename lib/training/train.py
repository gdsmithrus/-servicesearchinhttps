import numpy as np
from sklearn import tree

from lib.common.stream import readFileCSVFormat

def trainModel(filename):
    print "Generation model"
    train = readFileCSVFormat(filename)

    target = np.array([x[38] for x in train])

    train = np.array([x[0:38] for x in train])
    print "Train: ", train
    print "Target: ", target
    rf = tree.DecisionTreeClassifier()
    rf.fit(train, target)
    print "Service: \"Name\" -> \"Connect to server name\""
    return rf