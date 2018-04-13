from xml.etree import ElementTree as ET
import json
import argparse
from subprocess import check_output

parser = argparse.ArgumentParser(description='Scan IPs for vulnerability to ms08-067 and ms17-010')
input_group = parser.add_mutually_exclusive_group(required=True)
input_group.add_argument('--ip')
input_group.add_argument('--file')
args = parser.parse_args()

if args.ip: # If ips supplied as an argument
    ip_input = args.ip
else:
    ip_input = '-iL {0}'.format(args.file)

# Perhaps add an option for different ports? These are just the standard
# I think limiting ports is just an optimization; scripts should choose whatever is SMB
nmap_cmd = 'nmap -v -n -p137,139,445 --script=smb-vuln-ms08-067,smb-vuln-ms17-010 {ip_input} -oX -'.format(ip_input=ip_input)

out_xml = check_output(nmap_cmd.split(), encoding='utf-8')
root = ET.fromstring(out_xml)

results = {
    'ms08-067': [],
    'ms17-010': []
}

for host in root.findall('host'):
    for script in host.findall('./hostscript/script'):
        for elem in script.findall('./table/elem'):  # nmap's output has multiple 'elem' elements, instead of a state element or something
            if elem.get('key') == 'state' and elem.text.lower() == 'vulnerable':
                # This host is vulnerable to either ms08 or ms17, as determined by id in script
                # This might cause an issue if the address order isn't consistent (IP then MAC)
                results[script.get('id')[-8:]].append(host.find('address').get('addr'))

print(json.dumps(results))