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

    with open(dataset_name, "r", encoding="utf-8") as file:
        for line in file:
            obj = json.loads(line)
            labels = obj["Label"]
            for l in labels:
                attack_freqency[l] += 1
            if len(labels) > 1:
                if str(labels) not in attack_freqency.keys():
                    attack_freqency[str(labels)] = 1
                else:
                    attack_freqency[str(labels)] += 1
    return attack_freqency


def print_attack_frequencies(attack_frequencies):
    """
    Print the attack frequencies for all scenarios in a md table format.
    """
    # print the heading of the md table
    for scenario in scenario_options:
        if scenario == "all":
            print("|")
            break
        print("|", scenario, end=" ")
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


if __name__ == "__main__":
    labelfile = "labels.csv"

    attack_frequencies = []
    for scenario in scenario_options:
        if scenario == "all":
            continue
        print("Analyzing scenario:", scenario)
        dataset_name = "labeled/labeled_" + scenario + "_wazuh.json"
        attack_times = get_attack_times(labelfile, scenario)
        attack_frequencies.append(count_attack_freqencies(dataset_name, attack_times))

    print_attack_frequencies(attack_frequencies)
