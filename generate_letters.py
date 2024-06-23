import os
import re
from datetime import datetime

def parse_markdown(file_path):
    with open(file_path, 'r') as file:
        content = file.read()

    ip_sections = re.split(r'## IP Address: ', content)[1:]
    ip_info_list = []

    for section in ip_sections:
        ip_info = {}
        lines = section.split('\n')
        ip_info['IP Address'] = lines[0].strip()
        whois_info = {}
        geolocation_info = {}
        reputation_info = {}
        contacts = []

        whois_section = re.search(r'### Whois Information\n(.*?)\n### Geolocation Information', section, re.DOTALL)
        if whois_section:
            whois_lines = whois_section.group(1).split('\n')
            current_contact = {}
            for line in whois_lines:
                if '- **ASN**' in line:
                    whois_info['ASN'] = line.split(': ')[1]
                if '- **ASN Description**' in line:
                    whois_info['ASN Description'] = line.split(': ')[1]
                if '- **Country**' in line:
                    whois_info['Country'] = line.split(': ')[1]
                if '  - **Contact Name**' in line:
                    if current_contact:  # Save previous contact if it exists
                        contacts.append(current_contact)
                    current_contact = {'Contact Name': line.split(': ')[1]}
                if '  - **Contact Address**' in line:
                    address = line.split(': ')[1].replace("\\n", "\n").split("\n")
                    current_contact['Contact Address'] = ', '.join([part for part in address if part and part != 'N/A'])
                if '  - **Contact Phone**' in line:
                    current_contact['Contact Phone'] = line.split(': ')[1]
                if '  - **Abuse Email**' in line:
                    current_contact['Abuse Email'] = line.split(': ')[1]
            if current_contact:  # Save the last contact
                contacts.append(current_contact)

        geolocation_section = re.search(r'### Geolocation Information\n(.*?)\n### Reputation Information', section, re.DOTALL)
        if geolocation_section:
            geolocation_lines = geolocation_section.group(1).split('\n')
            for line in geolocation_lines:
                if '- **City**' in line:
                    geolocation_info['City'] = line.split(': ')[1]
                if '- **Region**' in line:
                    geolocation_info['Region'] = line.split(': ')[1]
                if '- **Country**' in line:
                    geolocation_info['Country'] = line.split(': ')[1]
                if '- **Organization**' in line:
                    geolocation_info['Organization'] = line.split(': ')[1]

        reputation_section = re.search(r'### Reputation Information\n(.*)', section, re.DOTALL)
        if reputation_section:
            reputation_lines = reputation_section.group(1).split('\n')
            for line in reputation_lines:
                if '- **Abuse Confidence Score**' in line:
                    reputation_info['Abuse Confidence Score'] = line.split(': ')[1]
                if '- **Total Reports**' in line:
                    reputation_info['Total Reports'] = line.split(': ')[1]
                if '- **Last Reported At**' in line:
                    reputation_info['Last Reported At'] = line.split(': ')[1]

        ip_info['Whois'] = whois_info
        ip_info['Geolocation'] = geolocation_info
        ip_info['Reputation'] = reputation_info
        ip_info['Contacts'] = contacts
        ip_info_list.append(ip_info)

    return ip_info_list

def generate_letter(ip_info, user_name, user_email):
    today_date = datetime.now().strftime("%B %d, %Y")
    letters = []
    for info in ip_info:
        letter = f"""
{user_name}
Email Address: {user_email}
{today_date}

To Whom It May Concern,

I am writing to formally lodge a complaint regarding malicious activities originating from the IP address {info['IP Address']}.

This IP address, managed by {info['Whois']['ASN Description']} and located in {info['Whois']['Country']}, has been attacking my network at daily intervals over several years. The attacks have been persistent and disruptive, affecting the security and stability of my online environment.

According to the information gathered, this IP address has an abuse confidence score of {info['Reputation']['Abuse Confidence Score']} and has been reported {info['Reputation']['Total Reports']} times for malicious activities by others. The last reported attack was on {info['Reputation']['Last Reported At']}, as recorded by {info['Geolocation']['Organization']}.

The following contacts are associated with this IP address:
"""
        for contact in info['Contacts']:
            # Ensure full address is formatted correctly
            address_parts = contact.get('Contact Address', 'N/A').split("\n")
            contact_address = ', '.join([part for part in address_parts if part and part != 'N/A'])
            letter += f"""
- **Name**: {contact.get('Contact Name', 'N/A')}
  **Address**: {contact_address}
  **Phone**: {contact.get('Contact Phone', 'N/A')}
  **Abuse Email**: {contact.get('Abuse Email', 'N/A')}
"""

        letter += f"""
I kindly demand that immediate action be taken to identify and remove the user associated with this IP address, and to implement measures to restrict and monitor this IP address to prevent further malicious activities. Continued attacks will be logged and filed, and will serve as evidence in a class action suit should this behavior persist.

Please confirm receipt of this letter and inform me of the steps you will take to address this issue. I expect a prompt response outlining the actions you will implement to resolve this matter.

Thank you for your time and attention to this critical issue. I look forward to your response and to the resolution of this matter.

Sincerely,

{user_name}
"""
        letters.append((letter, [contact.get('Abuse Email', 'N/A') for contact in info['Contacts'] if contact.get('Abuse Email') != 'N/A']))
    return letters

def save_letters(letters, output_dir):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    for i, (letter, emails) in enumerate(letters):
        for email in emails:
            file_name = re.sub(r'[^a-zA-Z0-9]', '_', email)  # Sanitize email for use in file name
            with open(os.path.join(output_dir, f'complaint_letter_{file_name}.txt'), 'w') as file:
                file.write(letter)

def main():
    user_name = input("Enter your name: ")
    user_email = input("Enter your email address: ")

    ip_info_list = parse_markdown('output/parsed_discovery.md')
    letters = generate_letter(ip_info_list, user_name, user_email)
    save_letters(letters, 'letters_output')

if __name__ == "__main__":
    main()