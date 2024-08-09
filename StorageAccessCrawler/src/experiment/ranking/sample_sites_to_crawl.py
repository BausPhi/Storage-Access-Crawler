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


def sample_websites(websites, sizes):
    top_10k = websites[:10000]
    next_90k = websites[10000:100000]
    rest = websites[100000:]

    sampled_top_10k = random.sample(top_10k, sizes[0])
    sampled_next_90k = random.sample(next_90k, sizes[1])
    sampled_rest = random.sample(rest, sizes[2])

    result = sampled_top_10k + sampled_next_90k + sampled_rest
    result.sort(key=sort_rank)

    return result


def main(sample_path, sizes):
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
    sampled_websites = sample_websites(websites, sizes)
    with open("sampled.csv", "w") as fd:
        fd.writelines(sampled_websites)


sample_sizes = [5000, 3000, 2000]
file_path = 'tranco.csv'

# Run the main function
if __name__ == '__main__':
    main(file_path, sample_sizes)
