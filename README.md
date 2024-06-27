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

## Label distribution
| russellmitchell | fox | harrison | santos | shaw | wardbeck | wheeler | wilson |
| --------------- | --- | -------- | ------ | ---- | -------- | ------- | ------ |
| network_scans | 0 | 0 | 0 | 0 | 9 | 0 | 20 | 25 |
| service_scans | 200 | 130 | 60 | 33 | 2 | 107 | 141 | 196 |
| dirb | 63 | 4481 | 4534 | 63 | 63 | 63 | 4533 | 4535 |
| wpscan | 3187 | 4816 | 4861 | 3293 | 787 | 797 | 6653 | 3212 |
| webshell | 2 | 2 | 2 | 3 | 2 | 3 | 2 | 2 |
| cracking | 4 | 5 | 5 | 4 | 106 | 4 | 0 | 3 |
| reverse_shell | 3 | 1 | 1 | 13 | 2 | 0 | 8 | 8 |
| privilege_escalation | 18 | 7 | 45 | 35 | 35 | 28 | 28 | 9 |
| service_stop | 2 | 2 | 2 | 3 | 2 | 2 | 2 | 2 |
| dnsteal | 0 | 7 | 3 | 1 | 0 | 6 | 5 | 5 |
| ['webshell', 'cracking'] | 1 | 0 | 1 | 1 | 1 | 1 | 0 | 1 |
| ['wpscan', 'dirb'] | 0 | 38 | 0 | 0 | 38 | 38 | 0 | 0 |
| ['reverse_shell', 'privilege_escalation'] | 0 | 0 | 0 | 12 | 0 | 0 | 7 | 7 |
| ['network_scans', 'service_scans'] | 0 | 0 | 0 | 0 | 0 | 0 | 20 | 25 |
| ['service_scans', 'dirb'] | 0 | 0 | 0 | 0 | 0 | 0 | 12 | 38 |