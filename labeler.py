from argparse import ArgumentParser
from datetime import datetime
import json
import os
import pandas as pd

scenario_options = [
    "russellmitchell",
    "fox",
    "harrison",
    "santos",
    "shaw",
    "wardbeck",
    "wheeler",
    "wilson",
    "all",
]

noise_messages = [
    "Web server 400 error code.",
    "IDS event.",
    "Dovecot Authentication Success.",
    "Multiple web server 400 error codes from same source ip.",
    "Suricata: Alert - SURICATA TLS invalid record/traffic",
    "Suricata: Alert - SURICATA TLS invalid handshake message",
    "Suricata: Alert - ET INFO Observed DNS Query to .biz TLD",
    "ClamAV database update",
    "Multiple IDS alerts for same id.",
    "Suricata: Alert - ET POLICY GNU/Linux APT User-Agent Outbound likely related to package management",
    "Multiple IDS events from same source ip.",
    "Multiple IDS alerts for same id (ignoring now this id).",
    "Dovecot Invalid User Login Attempt.",
    "PAM: User login failed.",
    "First time this IDS alert is generated.",
    "Suricata: Alert - ET INFO Observed DNS Query to .cloud TLD",
    "syslog: User authentication failure.",
    "CMS (WordPress or Joomla) login attempt.",
    "Suricata: Alert - SURICATA HTTP unable to match response to request",
    "Apache: Attempt to access forbidden directory index.",
    "Multiple IDS events from same source ip (ignoring now this srcip and id).",
    "PAM: Login session opened.",
    "Auditd: SELinux permission check.",
    "PAM: Login session closed.",
    "Suricata: Alert - ET DNS Query for .to TLD",
    "Web server 500 error code (Internal Error).",
    "Suricata: Alert - ET DNS Query for .cc TLD",
    "Suricata: Alert - ET HUNTING Possible COVID-19 Domain in SSL Certificate M2",
    "sshd: authentication success.",
    "Suricata: Alert - SURICATA HTTP gzip decompression failed",
    "Suricata: Alert - ET HUNTING Suspicious Domain Request for Possible COVID-19 Domain M1",
    "Successful sudo to ROOT executed.",
    "Suricata: Alert - ET HUNTING Suspicious TLS SNI Request for Possible COVID-19 Domain M1",
    "Suricata: Alert - ET INFO DNS Query for Suspicious .ga Domain",
    "Suricata: Alert - ET INFO Suspicious Domain (*.ga) in TLS SNI",
    "Suricata: Alert - SURICATA TLS invalid SSLv2 header",
    "Suricata: Alert - SURICATA SMTP no server welcome message",
    "Suricata: Alert - SURICATA SMTP invalid reply",
    "First time user executed sudo.",
    "Suricata: Alert - SURICATA HTTP invalid response chunk len",
    "Suricata: Alert - ET INFO TLS Handshake Failure",
    "Suricata: Alert - ET INFO Session Traversal Utilities for NAT (STUN Binding Request)",
    "Suricata: Alert - SURICATA TLS invalid record type",
    "User successfully changed UID.",
    "Suricata: Alert - SURICATA TLS certificate invalid der",
    "Suricata: Alert - SURICATA DNS Unsolicited response",
]


def check_sequence(filename):
    """
    Check the attack times in the labels csv file to see if two attacks are happening at the same time in the same scenario.
    """
    with open(filename, "r") as file:
        previous_end = 0
        previous_attack = ""
        for line in file:
            scenario, attack, start, end = line.strip().split(",")
            if scenario == "scenario":
                continue
            if previous_end > int(start[:-2]):
                print(
                    f"{scenario:8} Sequence error: {previous_attack} and {attack:20} {start} {end}"
                )
            else:
                previous_attack = attack
                previous_end = int(end[:-2])


def get_attack_times(filename: str, scenario_name: str, start_offset=0, end_offset=0):
    """
    Read the csv file containing information about attack start and end times.

    Returns:
        a list of tuples `<attack name, start time and end time>` for a given scenario.
    """
    attack_times = []
    with open(filename, "r") as file:
        for line in file:
            scenario, attack, start, end = line.strip().split(",")
            if scenario == scenario_name:
                attack_times.append(
                    (attack, int(start[:-2]) + start_offset, int(end[:-2]) + end_offset)
                )
    return attack_times


def label_aminer(filename, attack_times, dataset_dir, output_dir):
    output_file = open(output_dir + "/labeled_" + filename, "w")

    with open(dataset_dir + "/" + filename, "r", encoding="utf-8") as file:
        for line in file:
            obj = json.loads(line)

            detection_time = int(obj["LogData"]["DetectionTimestamp"][0])

            possible_labels = []
            for attack, start, end in attack_times:
                if start <= detection_time < end:
                    possible_labels.append(attack)

            if len(possible_labels) == 0:
                possible_labels.append("benign")
            elif len(possible_labels) == 1:
                obj["Label"] = possible_labels
            else:
                print("🚨 Multiple labels for object", obj)
                exit(1)

            output_file.write(json.dumps(obj) + "\n")
    output_file.close()


def label_wazuh(filename, attack_times, dataset_dir, output_dir):
    output_file = open(output_dir + "/labeled_" + filename, "w")
    with open(dataset_dir + "/" + filename, "r", encoding="utf-8") as file:
        for line in file:
            obj = json.loads(line)

            if arguments.remove_noise:
                if obj["rule"]["description"] in noise_messages:
                    continue

            # get the detection time as epoch time
            detection_time = obj["@timestamp"]
            detection_time = int(
                datetime.fromisoformat(
                    detection_time.replace("Z", "+00:00")
                ).timestamp()
            )

            obj["Label"] = []
            for attack, start, end in attack_times:
                if start <= detection_time < end:
                    obj["Label"].append(attack)

            output_file.write(json.dumps(obj) + "\n")
    output_file.close()


"""
def find_correct_label(labels: list, alert_obj):
    if "webshell" in labels and "cracking" in labels:
        try:
            if "/intranet-access.log" in alert_obj["LogData"]["LogResources"][0]:
                return "webshell"
            else:
                return "cracking"
        except KeyError:
            print("🚨 Failed while resolving webshell vs cracking with labels", labels)

    elif "wpscan" in labels and "dirb" in labels:
        try:
            if (
                "WPScan" in alert_obj["LogData"]["LogResources"][0]
                or "wp-content" in alert_obj["LogData"]["LogResources"][0]
            ):
                return "wpscan"
            else:
                return "dirb"
        except KeyError:
            print("🚨 Failed while resolving wpscan vs dirb with labels", labels)

    elif "reverse_shell" in labels and "privilege_escalation" in labels:
        return "privilege_escalation"

    elif "network_scans" in labels and "service_scans" in labels:
        if "imap-login" in alert_obj["LogData"]["RawLogData"][0]:
            return "service_scans"
        elif "exim4" in alert_obj["LogData"]["LogResources"][0]:
            return "service_scans"
        else:
            return "network_scans"

    elif "service_scans" in labels and "dirb" in labels:
        return "dirb"

    else:
        print("🚨 Failed to resolve labels", labels)
        SystemExit(1)
"""


def full_convert(
    scenario_name, label_filename, dataset_dir, output_dir, start_offset, end_offset
):
    """
    Label both the aminer and wazuh files for a specific scenario. Outputs are saved to files in the `output_dir` directory.
    """
    aminer_filename = scenario_name + "_aminer.json"
    wazuh_filename = scenario_name + "_wazuh.json"
    label_filename = label_filename
    attack_times = get_attack_times(
        label_filename, scenario_name, start_offset, end_offset
    )

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    sucess = True
    try:
        label_aminer(aminer_filename, attack_times, dataset_dir, output_dir)
        print(
            "✅ Created new file:",
            output_dir + "/labeled_" + scenario_name + "_aminer.json",
        )
    except Exception as e:
        print("❌ Failed labeling the file", aminer_filename)
        print(e)
        sucess = False

    try:
        label_wazuh(wazuh_filename, attack_times, dataset_dir, output_dir)
        print(
            "✅ Created new file:",
            output_dir + "/labeled_" + scenario_name + "_wazuh.json",
        )
    except Exception as e:
        print("❌ Failed labeling the file", wazuh_filename)
        print(e)
        sucess = False

    if sucess:
        print("✅ Parsing complete for scenario", scenario_name)
    else:
        print("❌ Parsing failed for scenario", scenario_name)


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument(
        "-s",
        "--scenario",
        help="The name of the scenario. Default: 'all'",
        choices=scenario_options,
        default="all",
    )
    parser.add_argument(
        "-lf",
        "--label_filename",
        help=f"the csv file containing infomation about the attacks. Default: 'labels.csv'",
        default="labels.csv",
    )
    parser.add_argument(
        "-dd",
        "--dataset_dir",
        help="the directory containing the datasets. Default: '.'",
        default="ait_ads",
    )
    parser.add_argument(
        "-od",
        "--output_dir",
        help="the directory to output the labeled datasets. Default: 'labeled'",
        default="labeled",
    )
    parser.add_argument(
        "-so",
        "--start_offset",
        help="number of seconds offset to add to the start time of the attacks. Default: 0",
        type=int,
        default=0,
    )
    parser.add_argument(
        "-eo",
        "--end_offset",
        help="number of seconds offset to add to the end time of the attacks. Default: 0",
        type=int,
        default=0,
    )
    parser.add_argument(
        "-rn",
        "--remove_noise",
        help="If flag is set: remove alerts from the wazuh dataset that should not be there. Default: False",
        action="store_true",
        default=False,
    )

    arguments = parser.parse_args()

    if arguments.scenario != "all":
        full_convert(
            arguments.scenario,
            arguments.label_filename,
            arguments.dataset_dir,
            arguments.output_dir,
            arguments.start_offset,
            arguments.end_offset,
        )
    else:
        for scenario in scenario_options[:-1]:
            print("⌛ Parsing scenario: ", scenario)
            full_convert(
                scenario,
                arguments.label_filename,
                arguments.dataset_dir,
                arguments.output_dir,
                arguments.start_offset,
                arguments.end_offset,
            )
