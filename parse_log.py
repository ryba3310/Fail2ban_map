from signal import signal, SIGINT
import requests
import time
import psycopg2


LOG_PATH = '/app/fail2ban.log'
IP_API = 'http://ip-api.com/json/'

try:
    conn = psycopg2.connect(dbname='postgres', host='postgres', user='root', password='password')
    cur = conn.cursor()
    cur.execute('CREATE TABLE IF NOT EXISTS f2b (id SERIAL, ip VARCHAR(15) NOT NULL, banned BOOLEAN DEFAULT true NOT NULL, country VARCHAR(255) NOT NULL, region_name VARCHAR(255),\
        city VARCHAR(255), lat VARCHAR(10) NOT NULL, lon VARCHAR(10) NOT NULL, isp VARCHAR(255), org VARCHAR(255), asn VARCHAR(255), date TIMESTAMP, jail VARCHAR(20), attempts_num INT NOT NULL DEFAULT 1, PRIMARY KEY(id))')
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
        cur.execute('INSERT INTO f2b (ip, banned, country, region_name, city, lat, lon, isp, org, asn, date, jail, attempts_num) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)\
            ON CONFLICT (id) DO UPDATE SET banned = excluded.banned, date = excluded.date',\
            (attempt_data[0], attempt_data[3], host_metadata['country'], host_metadata['regionName'], host_metadata['city'], host_metadata['lat'], host_metadata['lon'], host_metadata['isp'], \
            host_metadata['org'], host_metadata['as'], attempt_data[1], attempt_data[2], '1'))
        conn.commit()
    except Exception as err:
        print('Cannot insert')
        print(err)

def check_if_inserted(attempt_data):
    cur.execute('SELECT ip FROM f2b WHERE date >= %s', (attempt_data[1],))
    record = cur.fetchone()
    if record == None:
        return False
    # Update attempt count if host read from log is already inserted
    cur.execute('UPDATE f2b SET attempts_num = attempts_num + 1 WHERE date < %s AND ip = %s', (attempt_data[1], attempt_data[0]))
    return True

def follow_generator(log_file):
    """Generator which first reads all the lines then simulates tail -f behaviour"""
    while True:
        line = log_file.readline()
        if not line:
            time.sleep(0.1)
        yield line

def get_ip_timestamp_jail(line):
    line = ' '.join(line.split()).split(' ')
    ip = line[7]
    timestamp = line[0] + ' ' + line[1][0:8]
    jail = line[5]
    return [ip, timestamp, jail]

def parse_line(line):
    """Only look for Bans and Attemps(Notice) in log and save host and timestamp"""
    ip_timestamp_jail = []
    if 'Found' in line:
        ip_timestamp_jail = get_ip_timestamp_jail(line)
        ip_timestamp_jail.append('false')
    elif 'Ban' in line:
        ip_timestamp_jail = get_ip_timestamp_jail(line)
        ip_timestamp_jail.append('true')
    else:
        return None
    # tuple = (ip_addr, timestamp, jail_name, banned(boolean))
    return tuple(ip_timestamp_jail)

def handle_SIGINT(sig, frame):
    print('Gracefully closing...')
    cur.close()
    conn.close()
    exit(0)

if __name__ == '__main__':
    with open(LOG_PATH) as log_file:
        lines = follow_generator(log_file)
        rate_limit = 0  # Rate limit value set by ip-api for free access is set to 45 reqests per minute
        signal(SIGINT, handle_SIGINT)
        for line in lines:
            attempt_data = parse_line(line)
            if not attempt_data:
                continue
            if check_if_inserted(attempt_data):
                continue
            host_metadata = get_ip_data(attempt_data[0])
            insert_host(host_metadata, attempt_data)
            rate_limit += 1
            if rate_limit > 40:
                time.sleep(60)
                rate_limit = 0
    cur.close()
    conn.close()
