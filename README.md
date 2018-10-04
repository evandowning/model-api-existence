# model-api-existence
Creates ML models of existence of API calls

The API integers printed out by api_existence.py and attack.py are the zero-indexed
line numbers in api.txt

## Usage
```
# Parse data into CSV file
$ time python parse.py /data/arsa/api-sequences-all-classification-32-filtered/ api.txt data.csv

# Model data & save model to file
$ python api_existence.py data.csv model.pkl

# Brute-force attack model
$ python attack.py /data/arsa/api-sequences-all-classification-32-filtered/ api.txt model.pkl /data/arsa/api-existence-attacks/

# Optimized attack
$ python attack2.py /data/arsa/api-sequences-all-classification-32-filtered/ api.txt model.pkl /data/arsa/api-existence-attacks/

# Attack sequence and existence models
$ python neo4j-mode.py /data/arsa/api-existence-attacks /home/evan/arsa/model-api-existence/model.pkl /data/arsa/api-sequences-all-classification-32-filtered/ api.txt /data/arsa/api-sequences-all-classification-32-filtered/metadata.pkl
```
