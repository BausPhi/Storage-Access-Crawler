import random
import os
import urllib.request


def sort_rank(val):
    return int(val.split(",")[0])


def read_websites(path):
    websites = []
    with open(path, 'r') as file:
        for line in file:
            website = line.strip()
            websites.append(website + "\n")
    return websites


def sample_websites(websites):
    section_1 = websites[:25000]
    section_2 = websites[25000:100000]
    section_3 = websites[100000:500000]
    section_4 = websites[500000:]

    sample_sizes = [25000, 25000, 25000, 25000]
    sampled_section_1 = random.sample(section_1, sample_sizes[0])
    sampled_section_2 = random.sample(section_2, sample_sizes[1])
    sampled_section_3 = random.sample(section_3, sample_sizes[2])
    sampled_section_4 = random.sample(section_4, sample_sizes[3])

    result = sampled_section_1 + sampled_section_2 + sampled_section_3 + sampled_section_4
    result.sort(key=sort_rank)

    return result


def main(sample_path):
    # Set working directory to file directory
    abspath = os.path.abspath(__file__)
    dname = os.path.dirname(abspath)
    os.chdir(dname)

    # Make directory for tranco ranking
    tranco_path = 'tranco.csv'
    url = 'https://tranco-list.eu/download/4Q39X/full'
    if not os.path.isfile(tranco_path):
        print("Starting download of Tranco ranking!")
        urllib.request.urlretrieve(url, tranco_path)
        print("Tranco ranking successfully downloaded!")
    else:
        print("Tranco ranking already downloaded!")

    websites = read_websites(sample_path)
    sampled_websites = sample_websites(websites)
    with open("sampled.csv", "w") as fd:
        fd.writelines(sampled_websites)


file_path = 'tranco.csv'


if __name__ == '__main__':
    main(file_path)
