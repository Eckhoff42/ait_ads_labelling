# Automatic labeler AIT-ADS

A python script to label the datasets from [AIT_ADS](https://zenodo.org/records/8263181).
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
  -h, --help            show this help message and exit
  -s --scenario {russellmitchell,fox,harrison,santos,shaw,wardbeck,wheeler,wilson,all}
    The name of the scenario. 
    Default: 'all'
  -lf --label_filename LABEL_FILENAME
    the csv file containing infomation about the attacks. 
    Default: 'labels.csv'
  -dd --dataset_dir DATASET_DIR
    the directory containing the datasets. 
    Default: 'ait_ads'
  -od --output_dir OUTPUT_DIR
    the directory to output the labeled datasets. 
    Default: 'labeled'
```

## file structure
```bash 
.
├── README.md
├── ait_ads             # default AIT_ADS dataset location 
    ├── fox_aminer.json # example
├── analyzer.py         # analyze labeled files
├── labeled             # default labeled files location
│   ├── labeled_fox_aminer.json # example
├── labeler.py          # Create labeled files from ait_ads and labels.csv
├── labels.csv          # default label csv file location
```

## Distributions
### Label distribution (Aminer)
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

### Label distribution (Wazuh)
| russellmitchell | fox | harrison | santos | shaw | wardbeck | wheeler | wilson |
| --------------- | --- | -------- | ------ | ---- | -------- | ------- | ------ |
| network_scans | 8 | 323 | 300 | 104 | 3 | 3 | 643 | 190 |
| service_scans | 167 | 140 | 769 | 90 | 1 | 56 | 167 | 390 |
| dirb | 4459 | 406083 | 411477 | 4459 | 4459 | 4459 | 413009 | 424361 |
| wpscan | 3172 | 4985 | 4848 | 3274 | 933 | 910 | 6670 | 3247 |
| webshell | 4 | 0 | 31 | 13 | 0 | 13 | 8 | 40 |
| cracking | 10 | 554 | 1251 | 773 | 647 | 752 | 0 | 1284 |
| reverse_shell | 0 | 0 | 19 | 6 | 3 | 6 | 26 | 20 |
| privilege_escalation | 6 | 10 | 49 | 22 | 19 | 13 | 25 | 22 |
| service_stop | 0 | 0 | 20 | 0 | 0 | 0 | 0 | 0 |
| dnsteal | 711 | 381 | 3236 | 831 | 105 | 17 | 461 | 2861 |
| ['wpscan', 'dirb'] | 0 | 236 | 0 | 0 | 204 | 160 | 0 | 11 |
| ['network_scans', 'service_scans'] | 0 | 0 | 4 | 0 | 0 | 0 | 0 | 0 |
| ['service_stop', 'dnsteal'] | 0 | 0 | 16 | 0 | 0 | 0 | 0 | 0 |
| ['reverse_shell', 'privilege_escalation'] | 0 | 0 | 0 | 3 | 0 | 0 | 2 | 3 |
| ['service_scans', 'dirb'] | 0 | 0 | 0 | 0 | 0 | 0 | 26 | 219 |

### Message distribution for Scenario Fox (Aminer)
```json
"service_stop": {
    "New value combination(s) detected": 2
},
"dnsteal": {
    "Value entropy anomaly detected": 6,
    "Frequency anomaly detected": 1
},
"service_scans": {
    "New path(es) detected": 106,
    "New value(s) detected": 24
},
"wpscan": {
    "New value(s) detected": 4748,
    "New path(es) detected": 36,
    "New character(s) detected": 32
},
"dirb": {
    "New value(s) detected": 721,
    "New character(s) detected": 2457,
    "New path(es) detected": 1300,
    "Frequency anomaly detected": 3
},
"webshell": {
    "Value entropy anomaly detected": 2
},
"cracking": {
    "Value entropy anomaly detected": 1,
    "Frequency anomaly detected": 3,
    "Statistical data report": 1
},
"reverse_shell": {
    "Value entropy anomaly detected": 1
},
"privilege_escalation": {
    "New path(es) detected": 3,
    "New value combination(s) detected": 4
}
```

### Message distribution for Scenario Fox (Wazuh)
```json
"dnsteal": {
    "Dovecot Authentication Success.": 336,
    "IDS event.": 17,
    "Suricata: Alert - ET INFO Observed DNS Query to .cloud TLD": 1,
    "Suricata: Alert - SURICATA TLS invalid handshake message": 8,
    "Suricata: Alert - SURICATA TLS invalid record/traffic": 8,
    "CMS (WordPress or Joomla) login attempt.": 1,
    "ClamAV database update": 10
},
"network_scans": {
    "Dovecot Authentication Success.": 123,
    "Suricata: Alert - SURICATA TLS invalid record/traffic": 50,
    "IDS event.": 98,
    "Suricata: Alert - SURICATA TLS invalid handshake message": 50,
    "Multiple IDS alerts for same id.": 1,
    "Multiple IDS events from same source ip.": 1
},
"service_scans": {
    "Dovecot Authentication Success.": 6,
    "sshd: insecure connection attempt (scan).": 7,
    "Web server 400 error code.": 37,
    "Apache: Attempt to access forbidden file or directory.": 24,
    "Suricata: Alert - SURICATA SMTP no server welcome message": 2,
    "First time this IDS alert is generated.": 9,
    "Suricata: Alert - SURICATA SMTP invalid reply": 2,
    "Multiple web server 400 error codes from same source ip.": 2,
    "IDS event.": 21,
    "Suricata: Alert - SURICATA TLS invalid SSLv2 header": 2,
    "Suricata: Alert - SURICATA TLS invalid record/traffic": 2,
    "Suricata: Alert - ET SCAN Possible Nmap User-Agent Observed": 24,
    "Multiple IDS alerts for same id.": 1,
    "Multiple IDS events from same source ip.": 1
},
"wpscan": {
    "Web server 400 error code.": 4589,
    "Multiple web server 400 error codes from same source ip.": 353,
    "Apache: Attempt to access forbidden directory index.": 1,
    "Web server 500 error code (Internal Error).": 9,
    "Apache: Attempt to access forbidden file or directory.": 10,
    "Dovecot Authentication Success.": 12,
    "Suspicious URL access.": 10,
    "Common web attack.": 1
},
"dirb": {
    "Web server 400 error code.": 375637,
    "Multiple web server 400 error codes from same source ip.": 28946,
    "Suspicious URL access.": 456,
    "Common web attack.": 182,
    "Apache: Attempt to access forbidden file or directory.": 547,
    "Apache: Attempt to access forbidden directory index.": 82,
    "Dovecot Authentication Success.": 216,
    "Web server 500 error code (Internal Error).": 5,
    "IDS event.": 4,
    "Suricata: Alert - SURICATA TLS invalid handshake message": 2,
    "Suricata: Alert - SURICATA TLS invalid record/traffic": 2,
    "ClamAV database update": 4
},
"cracking": {
    "Dovecot Authentication Success.": 162,
    "Suricata: Alert - SURICATA HTTP unable to match response to request": 2,
    "IDS event.": 183,
    "Suricata: Alert - SURICATA TLS invalid handshake message": 94,
    "Suricata: Alert - SURICATA TLS invalid record/traffic": 94,
    "Multiple IDS alerts for same id.": 5,
    "ClamAV database update": 6,
    "Multiple IDS events from same source ip.": 1,
    "First time this IDS alert is generated.": 1,
    "PAM: User login failed.": 1,
    "Dovecot Invalid User Login Attempt.": 3,
    "syslog: User authentication failure.": 2
},
"privilege_escalation": {
    "User successfully changed UID.": 1,
    "PAM: Login session opened.": 4,
    "Successful sudo to ROOT executed.": 3,
    "PAM: Login session closed.": 2
}
```