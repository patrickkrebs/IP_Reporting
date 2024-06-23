import json
import os


def parse_ip_data(ip_data):
    parsed_data = []

    for entry in ip_data:
        whois_objects = entry.get('Whois', {}).get('objects', {})
        contacts = []

        for obj in whois_objects.values():
            contact = obj.get('contact', {})
            address = contact.get('address', [{}])[0].get('value', 'N/A') if contact.get('address') else 'N/A'
            name = contact.get('name', 'N/A')
            phone = contact.get('phone', [{}])[0].get('value', 'N/A') if contact.get('phone') else 'N/A'
            abuse_email = next((email.get('value') for email in contact.get('email', []) if
                                email and email.get('type') and 'abuse' in email.get('type', '').lower()),
                               'N/A') if contact.get('email') else 'N/A'
            contacts.append({
                'Contact Name': name,
                'Contact Address': address,
                'Contact Phone': phone,
                'Abuse Email': abuse_email
            })

        ip_info = {
            'IP Address': entry.get('IP', 'N/A'),
            'Whois': {
                'ASN': entry.get('Whois', {}).get('asn', 'N/A'),
                'ASN Description': entry.get('Whois', {}).get('asn_description', 'N/A'),
                'Country': entry.get('Whois', {}).get('asn_country_code', 'N/A'),
                'Contacts': contacts
            },
            'Geolocation': {
                'City': entry.get('IPInfoGeolocation', {}).get('city', 'N/A'),
                'Region': entry.get('IPInfoGeolocation', {}).get('region', 'N/A'),
                'Country': entry.get('IPInfoGeolocation', {}).get('country', 'N/A'),
                'Organization': entry.get('IPInfoGeolocation', {}).get('org', 'N/A')
            },
            'Reputation': {
                'Abuse Confidence Score': entry.get('Reputation', {}).get('data', {}).get('abuseConfidenceScore',
                                                                                          'N/A'),
                'Total Reports': entry.get('Reputation', {}).get('data', {}).get('totalReports', 'N/A'),
                'Last Reported At': entry.get('Reputation', {}).get('data', {}).get('lastReportedAt', 'N/A')
            }
        }
        parsed_data.append(ip_info)

    return parsed_data


def format_markdown(parsed_data):
    markdown_lines = ["# IP Address Report\n"]
    for entry in parsed_data:
        markdown_lines.append(f"## IP Address: {entry['IP Address']}\n")
        markdown_lines.append("### Whois Information\n")
        markdown_lines.append(f"- **ASN**: {entry['Whois']['ASN']}")
        markdown_lines.append(f"- **ASN Description**: {entry['Whois']['ASN Description']}")
        markdown_lines.append(f"- **Country**: {entry['Whois']['Country']}")
        for contact in entry['Whois']['Contacts']:
            markdown_lines.append(f"  - **Contact Name**: {contact['Contact Name']}")
            markdown_lines.append(f"  - **Contact Address**: {contact['Contact Address']}")
            markdown_lines.append(f"  - **Contact Phone**: {contact['Contact Phone']}")
            markdown_lines.append(f"  - **Abuse Email**: {contact['Abuse Email']}")
        markdown_lines.append("\n### Geolocation Information\n")
        markdown_lines.append(f"- **City**: {entry['Geolocation']['City']}")
        markdown_lines.append(f"- **Region**: {entry['Geolocation']['Region']}")
        markdown_lines.append(f"- **Country**: {entry['Geolocation']['Country']}")
        markdown_lines.append(f"- **Organization**: {entry['Geolocation']['Organization']}")
        markdown_lines.append("\n### Reputation Information\n")
        markdown_lines.append(f"- **Abuse Confidence Score**: {entry['Reputation']['Abuse Confidence Score']}")
        markdown_lines.append(f"- **Total Reports**: {entry['Reputation']['Total Reports']}")
        markdown_lines.append(f"- **Last Reported At**: {entry['Reputation']['Last Reported At']}")
        markdown_lines.append("\n")

    return "\n".join(markdown_lines)


def save_to_file(content, filename):
    with open(filename, 'w') as file:
        file.write(content)


def main():
    # Load the JSON file
    with open('output/discovery.json', 'r') as file:
        ip_data = json.load(file)

    # Parse the IP data
    parsed_data = parse_ip_data(ip_data)

    # Format the data to markdown
    markdown_content = format_markdown(parsed_data)

    # Ensure the output directory exists
    output_dir = 'output'
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Save the formatted markdown to a file
    save_to_file(markdown_content, os.path.join(output_dir, 'parsed_discovery.md'))

    # Save the parsed JSON data to a file
    save_to_file(json.dumps(parsed_data, indent=4), os.path.join(output_dir, 'parsed_discovery.json'))


if __name__ == "__main__":
    main()