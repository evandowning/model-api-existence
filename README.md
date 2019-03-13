# model-api-existence
Creates ML models of existence of API calls

The API integers printed out by api_existence.py and attack.py are the zero-indexed
line numbers in api.txt

## Requirements
  * Debian 9 64-bit

## Clone repo
```
$ git clone --recurse-submodules git@github.com:evandowning/model-api-existence.git
```

## Install dependencies
```
$ ./setup.sh
```

## Usage
```
# Extract sequences from nvmtrace dumps (https://github.com/evandowning/nvmtrace/tree/kvm)
# Parse data into CSV file
$ cd cuckoo-headless/extract_raw
$ python2.7 extract-existence.py

# Model data & save model to file
$ python3 api_existence.py data.csv model.pkl

# Evaluate model
$ python3 evaluation.py data.csv labels.txt model.pkl predictions.csv
```

## Create images of existence data
```
$ python3 color.py
```
