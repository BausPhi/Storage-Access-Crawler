import argparse
import sys

from database import Task


def add_site(site, url, rank, job):
    Task.create(job=job, site=site, url=url, landing_page=url, rank=rank)


def main(job: str):
    add_site('storage-access-api-demo-site-b.glitch.me', 'https://storage-access-api-demo-site-b.glitch.me/', 1, job)
    return 0


if __name__ == "__main__":
    # Preparing command line argument parser
    args_parser = argparse.ArgumentParser()
    args_parser.add_argument("-j", "--job", type=str, required=True, help="unique job id for crawl")

    # Parse command line arguments
    args = vars(args_parser.parse_args())
    sys.exit(main(args.get('job')))
