import argparse
import sys

from database import Task


def add_tranco_sites(job: str, ranking_file: str):
    with open(ranking_file, 'r') as file:
        sites = file.readlines()
        for index, line in enumerate(sites):
            site_name = line.split(',')[1].strip()
            add_site(site_name, f"https://{site_name}/", index, job)
            if index > 4998:
                break


def add_site(site, url, rank, job):
    Task.create(job=job, site=site, url=url, landing_page=url, rank=rank)


def main(job: str, ranking_file: str):
    add_tranco_sites(job, ranking_file)
    return 0


if __name__ == "__main__":
    # Preparing command line argument parser
    args_parser = argparse.ArgumentParser()
    args_parser.add_argument("-j", "--job", type=str, required=True, help="unique job id for crawl")
    args_parser.add_argument("-r", "--ranking", type=str, required=True, help="ranking file for crawl")

    # Parse command line arguments
    args = vars(args_parser.parse_args())
    sys.exit(main(args.get('job'), args.get('ranking')))
