docker container rm storageaccesscrawler-db-1 -f
docker container rm storageaccesscrawler-pycrawler-1 -f
docker container prune -f
docker compose up -d --build