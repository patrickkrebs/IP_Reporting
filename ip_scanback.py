import requests
from ipwhois import IPWhois
import socket
import json
import local_config  # Import the local_config module

# Function to get Whois information
def get_whois_info(ip):
    try:
        obj = IPWhois(ip)
        whois_info = obj.lookup_rdap()
        return whois_info
    except Exception as e:
        return str(e)

# Function to get Geolocation information
def get_geolocation_info(ip):
    try:
        response = requests.get(f"https://ipgeolocation.io/ip-location/{ip}?key={local_config.IP_GEOLOCATION_API_KEY}")
        geolocation_info = response.json()
        return geolocation_info
    except Exception as e:
        return str(e)

# Function to get Reverse DNS information
def get_reverse_dns(ip):
    try:
        reverse_dns = socket.gethostbyaddr(ip)
        return reverse_dns
    except Exception as e:
        return str(e)

# Function to read IP addresses from a file
def read_ip_list(filename):
    with open(filename, 'r') as file:
        ip_list = file.read().splitlines()
    return ip_list

# Main function to gather all information
def get_ip_info(ip_list):
    ip_info_list = []

    for ip in ip_list:
        info = {}
        info['IP'] = ip
        info['Whois'] = get_whois_info(ip)
        info['Geolocation'] = get_geolocation_info(ip)
        info['Reverse DNS'] = get_reverse_dns(ip)
        ip_info_list.append(info)

    return ip_info_list

# Read IP addresses from ip_list.dat
ip_addresses = read_ip_list('ip_list.dat')

# Get information for each IP address
ip_information = get_ip_info(ip_addresses)

# Print the information
print(json.dumps(ip_information, indent=4))