from xml.etree import ElementTree as ET
import json
import argparse
from subprocess import check_output
import tempfile

def check_vulnerable(ip=None, ip_file=None, ip_list=None):

    results = {
        'ms08-067': [],
        'ms17-010-psexec': [],
        'ms17-010-eternalblue': []
    }

    pipe = None
    if ip is not None: # If ips supplied as an argument
        ip_input = ip
    elif ip_list is not None:
        pipe = tempfile.NamedTemporaryFile()
        pipe.write('\n'.join(ip_list).encode('utf-8'))
        pipe.flush()
        ip_input = '-iL {0}'.format(pipe.name)
    elif ip_file is not None:
        ip_input = '-iL {0}'.format(ip_file)
    else:
        return results

    # Perhaps add an option for different ports? This port is used because its default for
    # most SMB and default in Metasploit
    # I think limiting ports is just an optimization; scripts should choose whatever is SMB
    nmap_cmd = 'nmap -v -n -p445 --script=smb-vuln-ms08-067,smb-vuln-ms17-010,smb-os-discovery {ip_input} -oX -'.format(ip_input=ip_input)

    out_xml = check_output(nmap_cmd.split())#, encoding='utf-8')

    if pipe:
        pipe.close()

    root = ET.fromstring(out_xml)

    for host in root.findall('host'):
        for script in host.findall('./hostscript/script'):
            # nmap's output has multiple 'elem' elements, instead of a state element or something
            for elem in script.findall('./table/elem'):
                if elem.get('key') == 'state' and elem.text.lower() == 'vulnerable':
                    # This host is vulnerable to either ms08 or ms17, as determined by id in script
                    vuln = script.get('id')[-8:] # "ms17-010" or "ms08-067"
                    # This might cause an issue if the address order isn't consistent (IP then MAC)
                    # In the future, this could be changed to a tuple or something for port
                    host_identifier = host.find('address').get('addr')

                    if vuln == 'ms17-010':
                        for os_elem in host.findall('./hostscript/script/elem'):
                            if os_elem.get('key') == 'os':
                                # Win 7 & 2008 R2 use eternalblue, everything else uses psexec version
                                # Supposedly Win 8, 8.1, and 10 are vulnerable too, but eternalblue variant
                                # doesn't even support them
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
