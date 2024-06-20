docker container rm pythoncrawler_db_1 -f
docker container rm pythoncrawler_pycrawler_1 -f
docker container prune -f
docker-compose up -d --build