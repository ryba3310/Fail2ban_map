from signal import signal, SIGINT
from json.decoder import JSONDecodeError
from collections import namedtuple
from orm_helpers import *
from datetime import datetime
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
    print('\t[insert_host] Inserting:')
    print(host_metadata)
    print(f"\t[insert_host] Date: {attempt_data.timestamp}")

    try:
        client = (Client.insert(ip=attempt_data.ip, country=host_metadata['country'], region_name=host_metadata['region'],
                               city=host_metadata['city'], lat=host_metadata['lat'], lon=host_metadata['lon'],
                               isp=host_metadata['isp'], org=host_metadata['org'], asn=host_metadata['as'], date=attempt_data.timestamp)
                  .on_conflict(conflict_target=[Client.ip], update={Client.lat: host_metadata['lat'], Client.date: attempt_data.timestamp})
                      .execute())
        attempt = Attempt.insert(client=client, attempted_at=attempt_data.timestamp).execute()
        if attempt_data.banned:
            ban = Ban.insert(client=client, jail=attempt_data.jail, banned_at=attempt_data.timestamp).execute()
            print(f'\t[insert_host] Banned {attempt_data.ip}, at {attempt_data.timestamp} ')
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
        timestamp = datetime.fromisoformat((line[0] + ' ' + line[1][0:8]))
        jail = line[5]
        attempt_data = Attempt_data(ip, timestamp, jail, banned)
        return attempt_data

    return None


def handle_SIGINT(sig, frame):
    print('\nClosing db connection...')
    db.close()
    exit(0)


def is_inserted(attempt_data):
    """Check if ip record already exists to skip pulling data from API"""
    query = Client.select(Client.ip, Client.date).where((Client.ip == attempt_data.ip) & (Client.date >= attempt_data.timestamp))
    record_num = len(query)
    print(f'\t[is_inserted] Number of records found {record_num}')
    if record_num > 0:
        for record in query:
            print(f'\t[is_inserted] Record data: {record.ip}, {record.date}')
        print(f'\t[is_inserted] Found {record_num} records for {attempt_data.ip} with date: {attempt_data.timestamp}')
        return True
    print(f'\t[is_inserted] Found nothing for {attempt_data.ip} with date: {attempt_data.timestamp}')
    return False


if __name__ == '__main__':
    create_tables()
    with open(LOG_PATH) as log_file:
        lines = follow_generator(log_file)
        rate_limit = 0  # Rate limit value set by ip-api for free access is set to 45 reqests per minute
        signal(SIGINT, handle_SIGINT)
        for line in lines:
            # Check if we got proper line from follow_generator or just an empty read
            if len(line) < 1:
                continue
            attempt_data = parse_line(line)
            # If parsed line is not an attmpt nor a ban it returns None
            if not attempt_data:
                continue
            # Check if the ip is already inserted
            if is_inserted(attempt_data):
                continue
            host_metadata = get_ip_data(attempt_data[0])
            rate_limit += 1
            if rate_limit > 40 or host_metadata == None:
                time.sleep(60)
                rate_limit = 0
                host_metadata = get_ip_data(attempt_data[0])
            insert_host(host_metadata, attempt_data)

