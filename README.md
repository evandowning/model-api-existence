# model-api-existence
Creates ML models of existence of API calls

The API integers printed out by api_existence.py and attack.py are the zero-indexed
line numbers in api.txt

## Requirements
  * Debian 9 64-bit

## Install dependencies
```
$ ./setup.sh
```

## Usage
```
# Parse data into CSV file
$ python3 parse.py api-sequence-features/ api.txt data.csv

# Model data & save model to file
$ python3 api_existence.py data.csv model.pkl

# Evaluate model
$ python3 evaluation.py data.csv labels.txt model.pkl predictions.csv
```

## Create images of sequences
```
$ python3 color.py
```
