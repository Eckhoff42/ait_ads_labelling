# Automatic labeler AIT-ADS

A simple python script to label the datasets from [AIT_ADS](https://zenodo.org/records/8263181).
Any alert happening in the time scope of an attack (as specified in the label file) is labeled as that attack.
Multiple attacks happening at once have multiple labels.

The the label is an extra `Label` list in each jason object.
```json
{
  ...,
  "AMiner": {"ID": "10.35.35.206"},
  "Label": ["dirb"]
}
```
A false positive will have an empty list as a label
```json
{
  ...,
  "AMiner": {"ID": "10.35.35.206"},
  "Label": []
}
```

## How to run
1. Download and extract the AIT-ADS dataset from here: https://zenodo.org/records/8263181
2. Make sure to also download the the `labels.csv` file
3. Run the command line tool
```bash
usage: labeler.py [options]

options:
  -h, --help            
    show this help message and exit
  --scenario {russellmitchell,fox,harrison,santos,shaw,wardbeck,wheeler,wilson,all}
    The name of the scenario.
  --label_filename LABEL_FILENAME
    the csv file containing infomation about the attacks
  --dataset_dir DATASET_DIR
    the directory containing the datasets
  --output_dir OUTPUT_DIR
    the directory to output the labeled datasets
```