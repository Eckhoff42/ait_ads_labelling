from argparse import ArgumentParser
from datetime import datetime
import json
import os

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

            ## assumes only one attack can happen at a specific time
            obj["Label"] = []
            for attack, start, end in attack_times:
                if start <= detection_time <= end:
                    obj["Label"].append(attack)

            output_file.write(json.dumps(obj) + "\n")
    output_file.close()


def label_wazuh(filename, attack_times, dataset_dir, output_dir):
    output_file = open(output_dir + "/labeled_" + filename, "w")
    with open(dataset_dir + "/" + filename, "r", encoding="utf-8") as file:
        for line in file:
            obj = json.loads(line)

            # get the detection time as epoch time
            detection_time = obj["@timestamp"]
            detection_time = int(
                datetime.fromisoformat(
                    detection_time.replace("Z", "+00:00")
                ).timestamp()
            )

            # assumes only one attack can happen at a specific time
            obj["Label"] = []
            for attack, start, end in attack_times:
                if start <= detection_time <= end:
                    obj["Label"].append(attack)

            output_file.write(json.dumps(obj) + "\n")
    output_file.close()


def full_convert(scenario_name, label_filename, dataset_dir, output_dir):
    """
    Label both the aminer and wazuh files for a specific scenario. Outputs are saved to files in the `output_dir` directory.
    """
    aminer_filename = scenario_name + "_aminer.json"
    wazuh_filename = scenario_name + "_wazuh.json"
    label_filename = label_filename
    attack_times = get_attack_times(label_filename, scenario_name)

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

    arguments = parser.parse_args()

    if arguments.scenario != "all":
        full_convert(
            arguments.scenario,
            arguments.label_filename,
            arguments.dataset_dir,
            arguments.output_dir,
        )
    else:
        for scenario in scenario_options[:-1]:
            print("⌛ Parsing scenario: ", scenario)
            full_convert(
                scenario,
                arguments.label_filename,
                arguments.dataset_dir,
                arguments.output_dir,
            )
