# model-api-existence
Creates ML models of existence of API calls

The API integers printed out by api_existence.py are the line numbers (not zero-indexed) in api.txt

## Usage
```
# Parse data into CSV file
$ time python parse.py /data/arsa/api-sequences-all-classification-32-filtered api.txt data.csv

# Model data & save model to file
$ python api_existence.py data.csv model.pkl
```
