# Fail2ban Geo map for Grafana


This a containerized app which gathers data about bans, attemps and fails from fail2ban.log and stores the data in PostgreSQL for retrival to Grafana dasboard.


# How to use
Clone this repo
```
git clone https://github.com/ryba3310/Fail2ban_map
```
Run docker-compose to setup containres
```
docker-compose up -d
```
Setup MongoDB connetion in Grafana and Import dashbaord with with JSON file


# TODO

- ✅ Basic functionality for testing and development

- ✅ Setup PostgreSQL and populate with data

- ✅ Get geo-location data through APi

- ✅️ Use psycopg2 module for DB client

- ⚠️ Set path globbing for fail2ban log files

- ⚠️ Setup dashboard in Grafana

- ⚠️ Parse and add more granuality to parsed data

- ⚠️ Seperate diffrent jails

- ⚠️ Switch to SQLAlchemy ORM model

- ⚠️ Find and delete unbanned records from DB

- ⚠️ Prepare Dockerfile and docker-compose file

- ⚠️ Get core functionality and tidy up code