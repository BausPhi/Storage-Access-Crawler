# Storage-Access-Crawler

Storage-Access-Crawler is a web crawler that is implemented as part of my master thesis 
`Escaping the Cookie Prison: An in-depth Analysis of Storage Access API Usage on the Web` and can be used to collect 
data about the usage of the Storage Access API on the web.

The crawler is based on the crawling framework implemented by Rautenstrauch et al. for their paper 
`To Auth or Not To Auth? A Comparative Analysis of the Pre- and Post-Login Security Landscape` which was released on 
[IEEE S&P 2024](https://www.computer.org/csdl/proceedings-article/sp/2024/313000a094/1Ub232sRVao).

The **storageaccessapi** module is responsible for collecting data about the usage of the StorageAccessAPI.

---

## Crawler Setup

This section contains a detailed step-by-step explanation for setting up and running the crawler.

### 1. Cloning the Repository

Clone the code to your machine using the following command:

```shell
git clone https://github.com/BausPhi/Storage-Access-Crawler`
```

### 2. Create Credentials

The crawler consists of a Postgresql database that stores all the data collected during the crawl.
Furthermore, the crawling environment also runs a VNC server in which the crawling process can be followed.
To connect to these services, a password is needed. These passwords are provided via the `src/secrets` folder.
In the folder two files need to be created:
- `db_password.txt`: Password for the database
- `vnc_password.txt`: Password for the VNC server

### 3. Create a Website Dataset for Crawling

Before running the crawler a dataset also needs to be created and stored in `src/experiment/ranking/sampled.csv`. 
The dataset needs to follow this format:

```
<crawling rank>,<site>
```

The **crawling rank** decides the order in which the sites are crawled. 

We also provide a sampling script under `src/experiment/ranking/sample_sites_to_crawl.py` which automatically downloads a given Tranco ranking and samples 100.000 random sites from it. 
By default it downloads the ranking used in my master's thesis: https://tranco-list.eu/download/4Q39X/full

### 4. Starting the Docker container

To run the crawler, you first need to start the docker container in which the crawler will be executed. 
The container will contain all dependencies that the crawler needs to run. 
Running the crawler outside of the container is not recommended.

```shell
./src/restart.sh
```

### 5. Running the Crawler
After starting the crawler container connect to it:
```shell
docker exec -it storageaccesscrawler-pycrawler-1 /bin/bash
```

Start the crawler with the sites sampled in `sampled.csv`:
```shell 
./experiment/experiment_storage_access_api.sh
```
The script will run the crawler until all sites were visited. All the collected data will be stored in the database.

### 6. Connect to the VNC Server
To inspect the crawling process one can connect to the VNC server. 
The required password to connect to the server will be the one that was previously stored in `src/secrets/vcn_password.txt`.
To connect to the server every common VNC viewer can be used.

---

## Data Analysis

After crawling, the collected data can be inspected in the database or analyzed via Jupyter.

### Data Inspection
To connect to the database and inspect the data use the following command:
```shell
psql -h 127.0.0.1 -p 55433 -U postgres
```
The password that was previously stored in `src/secrets/db_password.txt` is required to connect.

### Data Analysis
To analyze the data, the crawling environment contains a Jupyter server:
```shell
./experiment/analysis/start_jupyter.sh
```
A demo analysis notebook (`saa_analysis.ipynb`) can be found in the `experiment` folder. 
The demo file shows how to load the collected data from the database to analyze it.

