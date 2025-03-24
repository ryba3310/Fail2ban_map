from signal import signal, SIGINT
from json.decoder import JSONDecodeError
from collections import namedtuple
import requests
import time
import psycopg2
from peewee import *
import os


LOG_PATH = '/app/fail2ban.log'
IP_API = 'http://ip-api.com/json/'
POSTGRES_USER = POSTGRES_DB = os.environ['POSTGRES_USER']    # Postgres Docker image sets db name as users name by default
POSTGRES_PASSWORD = os.environ['POSTGRES_PASSWORD']


try:
    db = PostgresqlDatabase(
    POSTGRES_DB,  # Required by Peewee.
    user=POSTGRES_USER,  # Will be passed directly to psycopg2.
    password=POSTGRES_PASSWORD,  # Ditto.
    host='localhost',  # Ditto
    port=5432)
except psycopg2.OperationalError as err:
    print('Couldn\'t connect to database, exiting...' )
    print(err)
    exit(1)


class BaseModel(Model):
    class Meta:
        database = db


class Client(BaseModel):
    ip = CharField(unique=True)
    country = CharField(max_length=255)
    region_name = CharField(max_length=255)
    city = CharField(max_length=255)
    lat = CharField(max_length=10)
    lon = CharField(max_length=10)
    isp = CharField(max_length=255)
    org = CharField(max_length=255)
    asn = CharField(max_length=255)
    date = DateTimeField()


class Attempt(BaseModel):
    client = ForeignKeyField(Client, backref='attempts')
    attempted_at = DateTimeField()


class Ban(BaseModel):
    client = ForeignKeyField(Client, backref='bans')
    jail = CharField(max_length=20)
    banned_at = DateTimeField()


def create_tables():
    with db:
        db.create_tables([Client, Attempt, Ban])


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
    ################# ORM
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
    """Only look for Bans and Attemps(Notice) in log and save host and timestamp"""

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

    cur.close()
    conn.close()
