from peewee import *
import os


POSTGRES_USER = POSTGRES_DB = os.environ['POSTGRES_USER']    # Postgres Docker image sets db name as users name by default
POSTGRES_PASSWORD = os.environ['POSTGRES_PASSWORD']
POSTGRES_HOST = os.environ['POSTGRES_HOST']


try:
    db = PostgresqlDatabase(
    POSTGRES_DB,  # Required by Peewee.
    user=POSTGRES_USER,  # Will be passed directly to psycopg2.
    password=POSTGRES_PASSWORD,  # Ditto.
    host=POSTGRES_HOST,  # Ditto
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


