import requests
from ipwhois import IPWhois
import socket
import json

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
        response = requests.get(f"https://ipgeolocation.io/ip-location/{ip}?key=YOUR_API_KEY")
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

# List of IP addresses to lookup
ip_addresses = ['8.8.8.8', '8.8.4.4']  # Replace with your list of IP addresses

# Get information for each IP address
ip_information = get_ip_info(ip_addresses)

# Print the information
print(json.dumps(ip_information, indent=4))