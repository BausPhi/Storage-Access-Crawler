docker container rm storageaccesscrawler_db_1 -f
docker container rm storageaccesscrawler_pycrawler_1 -f
docker container prune -f
docker-compose up -d --build