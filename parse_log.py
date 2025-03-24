from signal import signal, SIGINT
from json.decoder import JSONDecodeError
from collections import namedtuple
from orm_helpers import *
import requests
import time


LOG_PATH = '/app/fail2ban.log'
IP_API = 'http://ip-api.com/json/'


def get_ip_data(ip):
    try:
        host_metadata = requests.get(f'{IP_API}{ip}')
        return host_metadata.json()
    except JSONDecodeError as e:
        print('\t[get_ip_data] Exeeded requests per minute limit')
        return None


def insert_host(host_metadata, attempt_data):
    print('Inserting:')
    print(host_metadata, end=' ')
    print(" Date: " + attempt_data[1])

    try:
        client = (Client.insert(ip=attempt_data.ip, country=host_metadata['country'], region_name=host_metadata['region'],
                               city=host_metadata['city'], lat=host_metadata['lat'], lon=host_metadata['lon'],
                               isp=host_metadata['isp'], org=host_metadata['org'], asn=host_metadata['as'], date=attempt_data.timestamp)
                    .on_conflict(conflict_target=[Client.ip], update={Client.lat: host_metadata['lat']})
                      .execute())
        attempt = Attempt.insert(client=client, attempted_at=attempt_data.timestamp).execute()
        if attempt_data.banned:
            ban = Ban.insert(client=client, jail=attempt_data.jail, banned_at=attempt_data.timestamp).execute()
            print(ban)
    except IntegrityError as err:
        print('\t[insert_host]Couldn\'t insert data...\n')


def follow_generator(log_file):
    """Generator which first reads all the lines then simulates tail -f behaviour"""
    while True:
        line = log_file.readline()
        if not line:
            time.sleep(0.1)
        yield line


def parse_line(line):
    """Only look for Bans and Attempts(Notice) in log and save host and timestamp"""
    banned = False
    Attempt_data = namedtuple('Attempt_data', ['ip', 'timestamp', 'jail', 'banned'])
    if 'Ban' in line:
        banned = True
    if 'Found' in line or banned:
        line = ' '.join(line.split()).split(' ')
        ip = line[7]
        timestamp = line[0] + ' ' + line[1][0:8]
        jail = line[5]
        attempt_data = Attempt_data(ip, timestamp, jail, banned)
        return attempt_data

    return None


def handle_SIGINT(sig, frame):
    print('\nClosing db connection...')
    db.close()
    exit(0)


if __name__ == '__main__':
    with open(LOG_PATH) as log_file:
        lines = follow_generator(log_file)
        rate_limit = 0  # Rate limit value set by ip-api for free access is set to 45 reqests per minute
        signal(SIGINT, handle_SIGINT)
        for line in lines:
            print(line)
            attempt_data = parse_line(line)
            if not attempt_data:
                continue
            host_metadata = get_ip_data(attempt_data[0])
            rate_limit += 1
            if rate_limit > 40 or host_metadata == None:
                time.sleep(60)
                rate_limit = 0
                host_metadata = get_ip_data(attempt_data[0])
            insert_host(host_metadata, attempt_data)

