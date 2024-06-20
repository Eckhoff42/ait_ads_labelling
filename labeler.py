from datetime import datetime
import json

scenario_name = "shaw"
alert_filename_aminer = "shaw_aminer_test.json"
alert_filename_wazuh = "shaw_wazuh.json"
label_filename = "labels.csv"


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


def get_attack_times(filename, scenario_name):
    attack_times = []
    with open(filename, "r") as file:
        for line in file:
            scenario, attack, start, end = line.strip().split(",")
            if scenario == scenario_name:
                attack_times.append((attack, int(start[:-2]), int(end[:-2])))
    return attack_times


def label_aminer(filename, attack_times):
    output_file = open("labeled_" + filename, "w")
    with open(filename, "r", encoding="utf-8") as file:
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


def label_wazuh(filename, attack_times):
    output_file = open("labeled_" + filename, "w")
    with open(filename, "r", encoding="utf-8") as file:
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
                    print("HIT!", attack)
                    obj["Label"].append(attack)

            output_file.write(json.dumps(obj) + "\n")
    output_file.close()


if __name__ == "__main__":
    # check_sequence(label_filename)
    attack_times = get_attack_times(label_filename, scenario_name)
    # label_aminer(alert_filename_aminer, attack_times)
    label_wazuh(alert_filename_wazuh, attack_times)
