from labeler import get_attack_times, scenario_options
import json


def count_attack_freqencies(dataset_name, attack_times):
    """
    Count the frequency of each attack a given marked dataset.

    Returns:
        a dictionary with the attack as the key and the frequency as the value.
    """

    attack_freqency = {}
    for attack, _, _ in attack_times:
        attack_freqency[attack] = 0
    attack_freqency["benign"] = 0

    with open(dataset_name, "r", encoding="utf-8") as file:
        for line in file:
            obj = json.loads(line)
            attack_freqency[obj["Label"]] += 1
    return attack_freqency


def print_attack_frequencies(attack_frequencies):
    """
    Print the attack frequencies for all scenarios in a md table format.
    """
    # print the heading of the md table
    print("| attack", end=" ")
    for scenario in scenario_options:
        if scenario == "all":
            print("|")
            break
        print("|", scenario, end=" ")
    print("| ----- ", end=" ")
    for scenario in scenario_options:
        if scenario == "all":
            print("|")
            break
        print("|", "-" * len(scenario), end=" ")

    # print the values of all attacks
    all_attacks = []
    for i in attack_frequencies:
        for attack in i.keys():
            if attack not in all_attacks:
                all_attacks.append(attack)

    for attack in all_attacks:
        print("|", attack, "|", end=" ")
        for i in attack_frequencies:
            if attack in i:
                print(i[attack], end=" ")
            else:
                print(0, end=" ")
            print("|", end=" ")
        print("")


def count_attack_messages(dataset_name, alarm_type="Aminer"):
    """
    Count the number of message types for each labeled attack in a dataset.

    Returns:
        A nested dictionary on the from: attack -> message -> frequency
    """
    attack_message_counts = {}

    with open(dataset_name, "r", encoding="utf-8") as file:
        for line in file:
            obj = json.loads(line)
            labels = obj["Label"]
            if alarm_type == "Aminer":
                try:
                    message = obj["AnalysisComponent"]["Message"]
                except KeyError:
                    message = "no message found"
            else:
                try:
                    message = obj["rule"]["description"]
                except KeyError:
                    message = "no message found"

            for l in labels:
                if l not in attack_message_counts:
                    attack_message_counts[l] = {}
                if message not in attack_message_counts[l]:
                    attack_message_counts[l][message] = 1
                else:
                    attack_message_counts[l][message] += 1

    return attack_message_counts


def print_attack_message_counts(attack_message_count):
    """
    Print the attack message counts for one scenarios in json format.
    the JSON is in the format
    {
        attack: {
            message1: frequency,
            message2: frequency,
            ...
        }
    }
    """

    print(json.dumps(attack_message_count, indent=4))


if __name__ == "__main__":
    labelfile = "labels.csv"

    attack_frequencies = []
    for scenario in scenario_options:
        if scenario == "all":
            continue
        print("Analyzing scenario:", scenario)
        dataset_name = "labeled/labeled_" + scenario + "_aminer.json"
        attack_times = get_attack_times(labelfile, scenario)
        attack_frequencies.append(count_attack_freqencies(dataset_name, attack_times))

    print_attack_frequencies(attack_frequencies)

    attack_frequencies = []
    for scenario in scenario_options:
        if scenario == "all":
            continue
        print("Analyzing scenario:", scenario)
        dataset_name = "labeled/labeled_" + scenario + "_wazuh.json"
        attack_times = get_attack_times(labelfile, scenario)
        attack_frequencies.append(count_attack_freqencies(dataset_name, attack_times))

    print_attack_frequencies(attack_frequencies)

    # for scenario in scenario_options:
    #     if scenario == "all":
    #         continue
    #     print("\nAnalyzing scenario:", scenario)
    #     dataset_name = "labeled/labeled_" + scenario + "_wazuh.json"
    #     attack_message_counts = count_attack_messages(dataset_name, alarm_type="Wazuh")
    #     print_attack_message_counts(attack_message_counts)
