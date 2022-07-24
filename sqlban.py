import argparse
from multiprocessing import connection
import re
import sys
import sqlite3
import os
import json
import urllib.request
import urllib.parse
import urllib.error

from numpy import insert

# Constants
DB_FILE = "sqlban.db"

# Initialisation of the argument parser
parser = argparse.ArgumentParser()

parser.add_argument("-v", "--verbose",
                    action='store_true',
                    help="Activate verbose mode")
parser.add_argument("action", metavar="ACTION", help="The action to perform: check, insert, delete", choices=[
                    "check", "insert", "delete"])
parser.add_argument("ip", metavar="IP",
                    help="The IP address on which the action should be performed")
parser.add_argument("-a", "--attempts", metavar="ATTEMPTS",
                    help="The number of connection attempts", type=int)
parser.add_argument("-b","--bantime", metavar="BANTIME",
                    help="The ban time in seconds", type=int)
parser.add_argument("-j", "--jailname", metavar="JAILNAME", help="The name of the Fail2ban jail")

# Parsing all the arguments
args = parser.parse_args()

VERBOSE = args.verbose

ACTION = args.action


def valid_ip(ip):
    """Use RegExp to check if the IP is a valid form of IPv4
    """
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
        return True
    else:
        return False


if not valid_ip(args.ip):
    print("Invalid IP address")
    sys.exit(1)

IP = args.ip

ATTEMPTS = args.attempts

BANTIME = args.bantime

JAILNAME = args.jailname


def check_if_the_db_exists():
    """Check if the database exists
    """
    if VERBOSE:
        print("Checking if the database exists")

    # Connect to the database
    return os.path.exists(DB_FILE)


def get_country_from_ip(ip):
    """Get the country from the IP
    """
    if VERBOSE:
        print("Getting the country from IP {}".format(ip))

    api_url = "https://json.geoiplookup.io/{}".format(ip)
    response = urllib.request.urlopen(api_url)
    data = json.loads(response.read())
    return data["country"]


def initialise_database():
    """Initialise the database
    """
    if VERBOSE:
        print("Initialising the database")

    # Connect to the database
    connection = sqlite3.connect(DB_FILE)
    cursor = connection.cursor()
    cursor.execute("CREATE TABLE sqlban (id INTEGER PRIMARY KEY NOT NULL, ip TEXT NOT NULL, last_jail_name TEXT, connection_attempts_numbers INTEGER, ban_numbers INTEGER, cumulative_bantime INTEGER, country TEXT, region TEXT, isp TEXT);")
    connection.commit()
    connection.close()


def check_ip_in_db(ip):
    """Check if the IP is in the database
    """
    if VERBOSE:
        print("Checking if IP {} is in the database".format(ip))

    cursor.execute("SELECT * FROM sqlban WHERE ip = ?", (ip,))
    result = cursor.fetchone()
    if result is None:
        return False
    else:
        return True


def ip_lookup(ip):
    """Lookup the IP from the API
    """
    if VERBOSE:
        print("Retrieving IP information using the API")

    urllib.request.urlopen("https://json.geoiplookup.io/{}".format(ip))
    response = urllib.request.urlopen(
        "https://json.geoiplookup.io/{}".format(ip))
    data = json.loads(response.read())
    if VERBOSE:
        print("IP information: {}".format(data))
    return data


def insert_ip_in_db(ip):
    """Insert the IP in the database
    """
    if VERBOSE:
        print("Inserting IP {} in the database".format(ip))
    if check_ip_in_db(ip):
        print("IP {} is already in the database, increasing the attempts and ban numbers".format(ip))
        cursor.execute("UPDATE sqlban SET connection_attempts_numbers = connection_attempts_numbers + ?, ban_numbers = ban_numbers + 1, cumulative_bantime = cumulative_bantime + ? WHERE ip = ?", (ATTEMPTS, BANTIME, ip))
    else:
        print("IP {} is not in the database, inserting it".format(ip))
        data = ip_lookup(ip)
        country = data["country_name"]
        region = data["region"]
        isp = data["isp"]
        cursor.execute("INSERT INTO sqlban (ip, last_jail_name, connection_attempts_numbers, ban_numbers, cumulative_bantime, country, region, isp) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                       (ip, JAILNAME, ATTEMPTS, 1, BANTIME, country, region, isp))

def delete_ip_from_db(ip):
    """Delete the IP from the database
    """
    if VERBOSE:
        print("Deleting IP {} from the database".format(ip))
    cursor.execute("DELETE FROM sqlban WHERE ip = ?", (ip,))


# --- Main program ---

# Checking if the database exists
if not check_if_the_db_exists():
    initialise_database()

connection = sqlite3.connect(DB_FILE)
cursor = connection.cursor()

if ACTION == "check":
    print(check_ip_in_db(IP))
elif ACTION == "insert":
    if BANTIME is None or ATTEMPTS is None:
        if BANTIME is None:
            print("Bantime is not set")
        if ATTEMPTS is None:
            print("Attempts is not set")
        sys.exit(1)
    insert_ip_in_db(IP)
elif ACTION == "delete":
    delete_ip_from_db(IP)
else:
    print("Invalid action")
    connection.commit()
    connection.close()
    sys.exit(1)

connection.commit()
connection.close()
sys.exit(0)
