#!/bin/bash

# Make sure to launch browser guis such that we can see them in VNC
export DISPLAY=:99

# Make sure we use the correct config file
export PYTHONPATH=/pycrawler

# Go to pycrawler directory
cd /pycrawler/ || echo "Script can only be run in the docker container" && exit

# Check if website sample was created
if [ ! -f "./experiment/ranking/sampled.csv" ]; then
    echo "Please first run the sample python script (experiment/ranking/sample_sites_to_crawl.py) to sample websites from the Tranco ranking!"
    echo "If the sample should persist across multiple crawls, run it outside of the container!"
fi

# Populate DB with URLs to crawl
python3 ./experiment/experiment_storage_access_api.py -j storageaccessapi -r ./experiment/ranking/sampled.csv

echo "Experiment storageaccessapi starting"

echo "This might take a while. You can watch the experiment via VNC or the logs in /pycrawler/logs"

# now launch the actual experiment
python3 main.py -m StorageAccessApi -j storageaccessapi -c 30

echo "Experiment storageaccessapi completed"
echo "You can inspect the raw results in the database"
