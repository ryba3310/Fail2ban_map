from signal import signal, SIGINT
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
    host_metadata = requests.get(f'{IP_API}{ip}')
    return host_metadata.json()


def insert_host(host_metadata, attempt_data):
    print('Inserting:')
    print(host_metadata, end=' ')
    print(" Date: " + attempt_data[1])
    ################# ORM
    try:
        client = (Client.insert(ip=attempt_data[0], country=host_metadata['country'], region_name=host_metadata['region'],
                               city=host_metadata['city'], lat=host_metadata['lat'], lon=host_metadata['lon'],
                               isp=host_metadata['isp'], org=host_metadata['org'], asn=host_metadata['as'], date=attempt_data[1])
                  .on_conflict(conflict_target=[Client.ip], update={Client.lat: host_metadata['lat']})
                      .execute())
        attempt = Attempt.create(client=client, date=attempt_data[1])
    except IntegrityError as err:
        print('Client already inserted, updateing attempt...\n')
        #attempt = Attempt.create(client=client, date=attempt_data[1])
        #attempt = Attempt.update(client=client, date=date).where(Client.ip == attempt_data[0])
        #if attempt_data[3]:
        #    ban = Ban.create(client=client, jail=attempt_data[2], banned_at=attempt_data[1])
#    try:
#        cur.execute('INSERT INTO f2b (ip, banned, country, region_name, city, lat, lon, isp, org, asn, date, jail, attempts_num) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)\
#            ON CONFLICT (id) DO UPDATE SET banned = excluded.banned, date = excluded.date',\
#            (attempt_data[0], attempt_data[3], host_metadata['country'], host_metadata['regionName'], host_metadata['city'], host_metadata['lat'], host_metadata['lon'], host_metadata['isp'], \
#            host_metadata['org'], host_metadata['as'], attempt_data[1], attempt_data[2], '1'))
#        conn.commit()
#    except Exception as err:
#        print('Cannot insert')
#        print(err)

############### Fix function name
def check_if_inserted(attempt_data):
    ###############ORM
    cur.execute('SELECT ip FROM f2b WHERE date >= %s', (attempt_data[1],))
    record = cur.fetchone()
    if record == None:
        return False
    #################FIX and ORM
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
    ############# Return tuple
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
    ################# the var will be tuple from function call
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
            print(line)
            attempt_data = parse_line(line)
            if not attempt_data:
                continue
        #    if check_if_inserted(attempt_data):
        #        continue
            host_metadata = get_ip_data(attempt_data[0])
            insert_host(host_metadata, attempt_data)
            rate_limit += 1
            if rate_limit > 40:
                time.sleep(60)
                rate_limit = 0
    cur.close()
    conn.close()
