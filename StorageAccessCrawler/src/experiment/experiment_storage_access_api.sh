#!/bin/bash

# Make sure to launch browser guis such that we can see them in VNC
export DISPLAY=:99

# Make sure we use the correct config file
export PYTHONPATH=/pycrawler

# Go to pycrawler directory
cd /pycrawler/

# Populate DB with URLs to crawl
python3 ./experiment/experiment_storage_access_api.py -j storageaccessapi

echo "Experiment storageaccessapi starting"

echo "This might take a while. You can watch the experiment via VNC or the logs in /pycrawler/logs"

# now launch the actual experiment
python3 main.py -m StorageAccessApi -j storageaccessapi -c 1

echo "Experiment storageaccessapi completed"
echo "You can inspect the raw results in the database"
