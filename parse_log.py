import os
import requests
import time
import psycopg2
from datetime import datetime
import re


LOG_PATH = '/home/admin/fail2ban_map/fail2ban.log'
IP_API = 'http://ip-api.com/json/'

try:
    conn = psycopg2.connect(dbname='postgres', host='localhost', user='root', password='password')
    cur = conn.cursor()
    cur.execute('CREATE TABLE IF NOT EXISTS test4 (id SERIAL, ip VARCHAR(15) NOT NULL, banned BOOLEAN DEFAULT true NOT NULL, country VARCHAR(50) NOT NULL, region_name VARCHAR(50),\
        city VARCHAR(30), lat VARCHAR(10) NOT NULL, lon VARCHAR(10) NOT NULL, isp VARCHAR(100), org VARCHAR(100), asn VARCHAR(255), date TIMESTAMP, jail VARCHAR(20), PRIMARY KEY(id))')
except psycopg2.OperationalError as err:
    print('Couldn\'t connect to database, exiting...' )
    exit(1)


def get_ip_data(ip):
    host_metadata = requests.get(f'{IP_API}{ip}')
    return host_metadata.json()

def insert_host(host_metadata, attempt_data):
    print('Inserting:')
    print(host_metadata)
    try:
        cur.execute('INSERT INTO test4 (ip, banned, country, region_name, city, lat, lon, isp, org, asn, date, jail) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)\
            ON CONFLICT (id) DO UPDATE SET banned = excluded.banned, date = excluded.date',\
            (attempt_data[0], attempt_data[3], host_metadata['country'], host_metadata['regionName'], host_metadata['city'], host_metadata['lat'], host_metadata['lon'], host_metadata['isp'], \
            host_metadata['org'], host_metadata['as'], attempt_data[1], attempt_data[2]))
        conn.commit()
    except Exception as err:
        print('Cannot insert')
        print(err)

def check_if_inserted(attempt_data):
    cur.execute('SELECT ip FROM test4 WHERE date >= %s', (attempt_data[1],))
    record = cur.fetchone()
    if record == None:
        return False
    return True

def follow_generator(log_file):
    """Generator which first reads all the lines then simulates tail -f behaviour"""
    while True:
        line = log_file.readline()
        if not line:
            time.sleep(0.1)
        yield line

def get_ip_timestamp(line):
    line = ' '.join(line.split()).split(' ')
    ip = line[7]
    timestamp = line[0] + ' ' + line[1][0:8]
    jail = line[5]
    return [ip, timestamp, jail]

def parse_line(line):
    """Only look for Bans and Attemps(Notice) in log and save host and timestamp"""
    ip_timestamp = []
    if 'Found' in line:
        ip_timestamp = get_ip_timestamp(line)
        ip_timestamp.append('false')
    elif 'Ban' in line:
        ip_timestamp = get_ip_timestamp(line)
        ip_timestamp.append('true')
    else:
        return None
    
    return tuple(ip_timestamp)

if __name__ == '__main__':
    with open(LOG_PATH) as log_file:
        lines = follow_generator(log_file)
        rate_limit = 0  # Rate limit value set by ip-api for free access is set to 45 reqests per minute
        for line in lines:
            attempt_data = parse_line(line)
            if not attempt_data:
                continue
            print(attempt_data)
            if check_if_inserted(attempt_data):
                print('Inserted: ', attempt_data)
                continue
            host_metadata = get_ip_data(attempt_data[0])
            insert_host(host_metadata, attempt_data)
            rate_limit += 1
            if rate_limit > 40:
                time.sleep(60)
                rate_limit = 0
    cur.close()
    conn.close()
