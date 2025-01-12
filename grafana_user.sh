#!/bin/bash

docker exec postgres psql postgres -c "CREATE ROLE grafana WITH LOGIN PASSWORD 'password';"
docker exec postgres psql postgres -c "GRANT CONNECT ON DATABASE postgres TO grafana;"
docker exec postgres psql postgres -c "GRANT USAGE ON SCHEMA public TO grafana;"
docker exec postgres psql postgres -c "GRANT SELECT ON ALL TABLES IN SCHEMA public TO grafana;"
docker exec postgres psql postgres -c "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO grafana;"