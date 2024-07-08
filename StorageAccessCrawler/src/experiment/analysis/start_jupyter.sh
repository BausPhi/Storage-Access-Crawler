#!/bin/bash

# Can only be executed in the docker container
export PYTHONPATH=/pycrawler
cd /pycrawler/experiment || exit
jupyter lab --ip 0.0.0.0 --port 8888