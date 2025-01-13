# Fail2ban Geo map for Grafana


This a containerized app which gathers data about bans, attemps and fails from fail2ban.log and stores the data in PostgreSQL for retrival to Grafana dasboard.
It uses docker-compose to build and deploy containers and allow Grafana to connect to PostgreSQL endpoint.
Data model for this log seems to better fit NoSQL like MongoDB but MongoDB connection in Grafana is only available in Grafana Enterprise.


# How to use
Clone this repo
```
git clone https://github.com/ryba3310/Fail2ban_map
```
Run docker-compose to setup containres
```
docker-compose up -d
```
Setup PostgresSQL  connetion in Grafana and Import dashbaord with with JSON file


# TODO

- ✅ Basic functionality for testing and development

- ✅ Setup PostgreSQL and populate with data

- ✅ Get geo-location data through APi

- ✅️ Use psycopg2 module for DB client

- ✅️  Add access to log file through docker

- ✅️  Add Grafana user with read-only rights

- ✅️  Setup dashboard in Grafana

- ✅️  Check DB if ip metadata is already inserted and abort API request

- ✅️  Add option to recheck all metadata for all ips in DB

- ⚠️  Add GitHub actions CI/CD pipeline

- ✅️  Use python generator

- ✅️  Parse and add more granuality to parsed data

- ✅️  Seperate diffrent jails

- ⚠️  Switch to SQLAlchemy ORM model

- ✅️  Prepare Dockerfile and docker-compose file

- ⚠️  Get core functionality and tidy up code
