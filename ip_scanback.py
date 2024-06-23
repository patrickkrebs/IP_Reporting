import requests
from ipwhois import IPWhois
import socket
import json
import logging
import os
import local_config  # Import the local_config module

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Function to get Whois information
def get_whois_info(ip):
    logging.debug(f"Performing Whois lookup for {ip}")
    try:
        obj = IPWhois(ip)
        whois_info = obj.lookup_rdap()
        logging.debug(f"Whois lookup successful for {ip}")
        return whois_info
    except Exception as e:
        logging.error(f"Whois lookup failed for {ip}: {e}")
        return str(e)

# Function to get Geolocation information from ipgeolocation.io
def get_geolocation_info(ip):
    logging.debug(f"Performing Geolocation lookup for {ip} with ipgeolocation.io")
    try:
        response = requests.get(f"https://ipgeolocation.io/ip-location/{ip}?key={local_config.IP_GEOLOCATION_API_KEY}")
        geolocation_info = response.json()
        logging.debug(f"Geolocation lookup successful for {ip} with ipgeolocation.io")
        return geolocation_info
    except Exception as e:
        logging.error(f"Geolocation lookup failed for {ip} with ipgeolocation.io: {e}")
        return str(e)

# Function to get Geolocation information from IPInfo
def get_ipinfo_geolocation(ip):
    logging.debug(f"Performing Geolocation lookup for {ip} with IPInfo")
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json?token={local_config.IPINFO_API_KEY}")
        geolocation_info = response.json()
        logging.debug(f"Geolocation lookup successful for {ip} with IPInfo")
        return geolocation_info
    except Exception as e:
        logging.error(f"Geolocation lookup failed for {ip} with IPInfo: {e}")
        return str(e)

# Function to get Reverse DNS information
def get_reverse_dns(ip):
    logging.debug(f"Performing Reverse DNS lookup for {ip}")
    try:
        reverse_dns = socket.gethostbyaddr(ip)
        logging.debug(f"Reverse DNS lookup successful for {ip}")
        return reverse_dns
    except Exception as e:
        logging.error(f"Reverse DNS lookup failed for {ip}: {e}")
        return str(e)

# Function to get reputation information from AbuseIPDB
def get_abuseipdb_reputation(ip):
    logging.debug(f"Checking IP reputation for {ip} with AbuseIPDB")
    headers = {
        'Key': local_config.ABUSEIPDB_API_KEY,
        'Accept': 'application/json'
    }
    try:
        response = requests.get(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}", headers=headers)
        reputation_info = response.json()
        logging.debug(f"Reputation check successful for {ip} with AbuseIPDB")
        return reputation_info
    except Exception as e:
        logging.error(f"Reputation check failed for {ip} with AbuseIPDB: {e}")
        return str(e)

# Function to read IP addresses from a file
def read_ip_list(filename):
    logging.debug(f"Reading IP addresses from {filename}")
    try:
        with open(filename, 'r') as file:
            ip_list = file.read().splitlines()
        logging.debug(f"Successfully read IP addresses from {filename}")
        return ip_list
    except Exception as e:
        logging.error(f"Failed to read IP addresses from {filename}: {e}")
        return []

# Function to write findings to a markdown file
def write_to_markdown(ip_info_list, filename='output/discovery.md'):
    logging.debug(f"Writing findings to {filename}")
    try:
        with open(filename, 'w') as file:
            for info in ip_info_list:
                file.write(f"## IP Address: {info['IP']}\n")
                file.write(f"### Whois Information\n")
                file.write(f"```\n{json.dumps(info['Whois'], indent=4)}\n```\n")
                file.write(f"### Geolocation Information (ipgeolocation.io)\n")
                file.write(f"```\n{json.dumps(info['Geolocation'], indent=4)}\n```\n")
                file.write(f"### Geolocation Information (IPInfo)\n")
                file.write(f"```\n{json.dumps(info['IPInfoGeolocation'], indent=4)}\n```\n")
                file.write(f"### Reverse DNS Information\n")
                file.write(f"```\n{info['Reverse DNS']}\n```\n")
                file.write(f"### Reputation Information (AbuseIPDB)\n")
                file.write(f"```\n{json.dumps(info['Reputation'], indent=4)}\n```\n")
                file.write("\n")
        logging.debug(f"Successfully wrote findings to {filename}")
    except Exception as e:
        logging.error(f"Failed to write findings to {filename}: {e}")

# Function to write findings to a JSON file
def write_to_json(ip_info_list, filename='output/discovery.json'):
    logging.debug(f"Writing findings to {filename}")
    try:
        with open(filename, 'w') as file:
            json.dump(ip_info_list, file, indent=4)
        logging.debug(f"Successfully wrote findings to {filename}")
    except Exception as e:
        logging.error(f"Failed to write findings to {filename}: {e}")

# Main function to gather all information
def get_ip_info(ip_list):
    logging.debug(f"Starting information gathering for IP list")
    ip_info_list = []

    for ip in ip_list:
        logging.debug(f"Gathering information for {ip}")
        info = {}
        info['IP'] = ip
        info['Whois'] = get_whois_info(ip)
        info['Geolocation'] = get_geolocation_info(ip)
        info['IPInfoGeolocation'] = get_ipinfo_geolocation(ip)
        info['Reverse DNS'] = get_reverse_dns(ip)
        info['Reputation'] = get_abuseipdb_reputation(ip)
        ip_info_list.append(info)
        logging.debug(f"Finished gathering information for {ip}")

    logging.debug(f"Completed information gathering for all IPs")
    return ip_info_list

# Ensure the output directory exists
output_dir = 'output'
if not os.path.exists(output_dir):
    logging.debug(f"Creating directory {output_dir}")
    os.makedirs(output_dir)

# Read IP addresses from ip_list.dat
ip_addresses = read_ip_list('ip_list.dat')

# Get information for each IP address
ip_information = get_ip_info(ip_addresses)

# Write the information to a markdown file
write_to_markdown(ip_information)

# Write the information to a JSON file
write_to_json(ip_information)

# Optionally, print the information
# print(json.dumps(ip_information, indent=4))