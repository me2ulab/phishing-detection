from dbn.tensorflow import SupervisedDBNClassification
import numpy as np
import pandas as pd
classifier=SupervisedDBNClassification(hidden_layers_structure=[256,256],learning_rate_rbm=0.05,learning_rate=0.1,n_epochs_rbm=10,
                                      n_iter_backprop=100,batch_size=32,activation_function='relu',dropout_p=0.2)
