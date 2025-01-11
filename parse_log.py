import os
import requests
import time
import psycopg2
import re


LOG_PATH = '/home/admin/fail2ban_map/fail2ban.log'
IP_API = 'http://ip-api.com/json/'

conn = psycopg2.connect(dbname='postgres', host='localhost', user='root', password='password')
cur = conn.cursor()
cur.execute('CREATE TABLE IF NOT EXISTS test2 (ip varchar(15) NOT NULL, banned boolean DEFAULT true NOT NULL, country varchar(50) NOT NULL,\
    region_name varchar(50), city varchar(30), lat varchar(10) NOT NULL, lon varchar(10) NOT NULL, isp varchar(100), org varchar(100), asn varchar(100), PRIMARY KEY(ip))')



def get_ip_data(ips):
    hosts_data = []
    rate_limit = 0  # Rate limit value set by ip-api for free access is set to 45 reqests per minute
    for ip in ips:
       host_data = requests.get(f'{IP_API}{ip}')
       rate_limit += 1
       if rate_limit > 40:
           time.sleep(60)
           rate_limit = 0

       data = host_data.json()
       print('Inserting')
       print(data)
       cur.execute('INSERT INTO test2 (ip, banned, country, region_name, city, lat, lon, isp, org, asn) VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)', \
           (ip, 'true', data['country'], data['regionName'], data['city'], data['lat'], data['lon'], data['isp'], data['org'], data['as']))
       conn.commit()


def read_log():
    with open(LOG_PATH) as log_file:
        bans = []
        for line in log_file:
            if 'Ban' in line:
                ip = ' '.join(line.split()).split(' ')[7]
                bans.append(ip)

        print(bans)
        return bans

if __name__ == '__main__':
    banned_ips = read_log()
    hosts_data = get_ip_data(banned_ips)
    print(hosts_data)
    cur.close()
    conn.close()
