import configparser
import psycopg2
from psycopg2 import sql

# Create connection
def create_connection():
    # Create a ConfigParser instance
    config = configparser.ConfigParser()
    
    # Read the configuration file
    config.read('db.config')

    database = config.get('database', 'dbname')
    user = config.get('database', 'user')
    password = config.get('database', 'password')
    host = config.get('database', 'host')
    port = config.get('database', 'port')

    try:
        connection = psycopg2.connect(
            user=user,
            password=password,
            host=host, 
            port=port,
            database=database
        )
        return connection
    except (Exception, psycopg2.Error) as error:
        print("Error while connecting to PostgreSQL", error)
        return None

# Schema selection
def set_schema(cursor, schema_name):
    try:
        cursor.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema_name)))
    except (Exception, psycopg2.Error) as error:
        print("Error while setting schema", error)
