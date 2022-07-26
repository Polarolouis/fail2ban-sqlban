import argparse
import re
import sys
import sqlite3
import os
import json
import urllib.request
import urllib.parse
import urllib.error
import time

# Constants
DIRECTORY = "/data/scripts/sqlban/"
DB_FILE = DIRECTORY + "sqlban.db"

# Initialisation of the argument parser
parser = argparse.ArgumentParser()

parser.add_argument("-v", "--verbose",
                    action='store_true',
                    help="Activate verbose mode")
parser.add_argument("action", metavar="ACTION", help="The action to perform: check, insert, delete, unban", choices=[
                    "check", "insert", "delete", "unban"])
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

BANDATE = int(time.time())


def check_if_the_db_exists():
    """Check if the database exists
    """
    if VERBOSE:
        print("Checking if the database exists")

    # Connect to the database
    return os.path.exists(DB_FILE)


def initialise_database():
    """Initialise the database
    """
    if VERBOSE:
        print("Initialising the database")

    # Connect to the database
    connection = sqlite3.connect(DB_FILE)
    cursor = connection.cursor()
    cursor.execute("CREATE TABLE sqlban (id INTEGER PRIMARY KEY NOT NULL, ip TEXT NOT NULL, last_jail_name TEXT, first_ban_date INTEGER, last_ban_date INTEGER, is_currently_banned INTEGER, connection_attempts_numbers INTEGER, ban_numbers INTEGER, cumulative_bantime INTEGER, country TEXT, region TEXT, longitude REAL, latitude REAL, isp TEXT);")
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
        cursor.execute("UPDATE sqlban SET last_jail_name = ?, last_ban_date = ?, is_currently_banned = 1, connection_attempts_numbers = connection_attempts_numbers + ?, ban_numbers = ban_numbers + 1, cumulative_bantime = cumulative_bantime + ? WHERE ip = ?", (JAILNAME, BANDATE, ATTEMPTS, BANTIME, ip))
    else:
        print("IP {} is not in the database, inserting it".format(ip))
        data = ip_lookup(ip)
        country = data["country_name"]
        region = data["region"]
        isp = data["isp"]
        latitude = data["latitude"]
        longitude = data["longitude"]
        cursor.execute("INSERT INTO sqlban (ip, last_jail_name, first_ban_date, last_ban_date, is_currently_banned, connection_attempts_numbers, ban_numbers, cumulative_bantime, country, region, longitude, latitude, isp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                       (ip, JAILNAME, BANDATE, BANDATE, 1,ATTEMPTS, 1, BANTIME, country, region, longitude, latitude, isp))

def delete_ip_from_db(ip):
    """Delete the IP from the database
    """
    if VERBOSE:
        print("Deleting IP {} from the database".format(ip))
    cursor.execute("DELETE FROM sqlban WHERE ip = ?", (ip,))

def is_ip_banned(ip):
       cursor.execute("SELECT is_currently_banned FROM sqlban WHERE ip = ?", (ip,))
       result = cursor.fetchone()[0]
       if VERBOSE:
           print(f"Checking if {ip} is banned")
       if result == 0:
           if VERBOSE:
               print(f"{ip} is not banned")
           return False
       else:
           if VERBOSE:
               print(f"{ip} is banned")
           return True

def unban_ip_in_db(ip):
    """Marks the IP as unbanned in the database
    """
    if not check_ip_in_db(ip):
        print(f"Error: {ip} not registered in database")
        sys.exit(1)
    if not is_ip_banned(ip):
        print(f"{ip} is not banned, aborting")
        return
    if VERBOSE:
        print(f"Marking the IP {ip} as unbanned in the database")
    cursor.execute("UPDATE sqlban SET is_currently_banned = 0 WHERE ip = ?", (ip,))


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
elif ACTION == "unban":
    unban_ip_in_db(IP)
else:
    print("Invalid action")
    connection.commit()
    connection.close()
    sys.exit(1)

connection.commit()
connection.close()

st_db = os.stat(DB_FILE)

if st_db.st_uid != 0 or st_db.st_gid != 472:
    os.chown(DB_FILE, 0, 472)

sys.exit(0)
