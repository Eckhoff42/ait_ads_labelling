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
    with open(filename, "r") as file:
        previous_end = 0
        previous_scenario = ""
        for line in file:
            scenario, attack, start, end = line.strip().split(",")
            if scenario == "scenario":
                continue
            if previous_scenario == scenario:
                if previous_end > int(start[:-2]):
                    print("")
                    print(
                        "Sequence error:",
                        scenario,
                        attack,
                        start,
                        end,
                    )
            else:
                previous_scenario = scenario
                previous_end = int(end[:-2])


def get_attack_times(filename: str, scenario_name: str):
    """
    Read the csv file containing information about attack start and end times. return a list of tuples `<attack name, start time and end time>` for a given scenario.
    """
    attack_times = []
    with open(filename, "r") as file:
        for line in file:
            scenario, attack, start, end = line.strip().split(",")
            if scenario == scenario_name:
                attack_times.append((attack, int(start[:-2]), int(end[:-2])))
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
    except:
        print("❌ Failed labeling the file", aminer_filename)
        sucess = False

    try:
        label_wazuh(wazuh_filename, attack_times, dataset_dir, output_dir)
        print(
            "✅ Created new file:",
            output_dir + "/labeled_" + scenario_name + "_wazuh.json",
        )
    except:
        print("❌ Failed labeling the file", wazuh_filename)
        sucess = False

    if sucess:
        print("✅ Parsing complete for scenario", scenario_name)
    else:
        print("❌ Parsing failed for scenario", scenario_name)


if __name__ == "__main__":

    parser = ArgumentParser()
    parser.add_argument(
        "--scenario",
        help="The name of the scenario",
        choices=scenario_options,
        default="all",
    )
    parser.add_argument(
        "--label_filename",
        help="the csv file containing infomation about the attacks",
        default="labels.csv",
    )
    parser.add_argument(
        "--dataset_dir", help="the directory containing the datasets", default="."
    )
    parser.add_argument(
        "--output_dir",
        help="the directory to output the labeled datasets",
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
