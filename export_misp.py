import requests
import json

# Configuration MISP
MISP_URL = 'https://192.168.2.3'
MISP_KEY = 'vtdt6j2BMFRTJFxfJ2apXPlepvD9kYdndwhm8DG4'
MISP_VERIFY_CERT = False

# Configuration Snort
SNORT_RULES_FILE = '/home/user/misp-export/apt41.rules'

def get_apt41_iocs():
    headers = {
        'Authorization': MISP_KEY,
        'Accept': 'application/json',
        'Content-type': 'application/json'
    }
    url = f'{MISP_URL}/events/restSearch'
    query = {
        'tags': 'APT41',
        'returnFormat': 'json'
    }
    response = requests.post(url, headers=headers, data=json.dumps(query), verify=MISP_VERIFY_CERT)
    return response.json()

def format_iocs_to_snort(iocs):
    rules = []
    for event in iocs['response']:
        for attribute in event['Attribute']:
            if attribute['type'] == 'ip-dst':
                rules.append(f'alert ip {attribute["value"]} any -> any any (msg:"APT41 IP"; sid:{1000000 + len(rules)}; rev:1;)')
            elif attribute['type'] == 'domain':
                rules.append(f'alert udp $HOME_NET any -> {attribute["value"]} any (msg:"APT41 Domain"; sid:{1000000 + len(rules)}; rev:1;)')
    return rules

def save_rules_to_file(rules):
    with open(SNORT_RULES_FILE, 'w') as file:
        for rule in rules:
            file.write(rule + '\n')

if __name__ == '__main__':
    iocs = get_apt41_iocs()
    snort_rules = format_iocs_to_snort(iocs)
    save_rules_to_file(snort_rules)