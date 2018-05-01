from xml.etree import ElementTree as ET
import json
import argparse
from subprocess import check_output

def check_vulnerable(ip=None, ip_file=None):

    results = {
        'ms08-067': [],
        'ms17-010-psexec': [],
        'ms17-010-eternalblue': []
    }

    if ip is not None: # If ips supplied as an argument
        ip_input = ip
    elif ip_file is not None:
        ip_input = '-iL {0}'.format(ip_file)
    else:
        return results

    # Perhaps add an option for different ports? This port is used because its default for
    # most SMB and default in Metasploit
    # I think limiting ports is just an optimization; scripts should choose whatever is SMB
    nmap_cmd = 'nmap -v -n -p445 --script=smb-vuln-ms08-067,smb-vuln-ms17-010,smb-os-discovery {ip_input} -oX -'.format(ip_input=ip_input)

    out_xml = check_output(nmap_cmd.split())#, encoding='utf-8')
    root = ET.fromstring(out_xml)

    for host in root.findall('host'):
        for script in host.findall('./hostscript/script'):
            for elem in script.findall('./table/elem'):  # nmap's output has multiple 'elem' elements, instead of a state element or something
                if elem.get('key') == 'state' and elem.text.lower() == 'vulnerable':
                    # This host is vulnerable to either ms08 or ms17, as determined by id in script
                    # This might cause an issue if the address order isn't consistent (IP then MAC)
                    vuln = script.get('id')[-8:] # "ms17-010" or "ms08-067"
                    host_identifier = host.find('address').get('addr')

                    if vuln == 'ms17-010':
                        for os_elem in host.findall('./hostscript/script/elem'):
                            if os_elem.get('key') == 'os':
                                if os_elem.text.startswith('Windows 7 ') or os_elem.text.startswith('Windows Server 2008 R2 '):
                                    vuln += '-eternalblue'
                                else:
                                    vuln += '-psexec'

                    results[vuln].append(host_identifier)

    return results


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Scan IPs for vulnerability to ms08-067 and ms17-010')
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('--ip')
    input_group.add_argument('--file')
    args = parser.parse_args()

    print(json.dumps(check_vulnerable(args.ip, args.file)))
