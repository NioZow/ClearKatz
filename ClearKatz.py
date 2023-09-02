#!/usr/bin/env python3
import json, sys, os, argparse

class PrintColors:
	# Found printcolors.py on the Osintgram project (https://github.com/Datalux/Osintgram)
	def __init__(self):
		self.BLACK, self.RED, self.GREEN, self.YELLOW, self.BLUE, self.MAGENTA, self.CYAN, self.WHITE = range(8)
		self.has_colours = self.has_colours(sys.stdout)

	def has_colours(self, stream):
		if not (hasattr(stream, "isatty") and stream.isatty):
			return False
		try:
			import curses
			curses.setupterm()
			return curses.tigetnum("colors") > 2
		except:
			return False

	def printout(self, text, colour=None):
		colour = self.WHITE if colour == None else colour
		if self.has_colours:
			seq = "\x1b[1;%dm" % (30 + colour) + text + "\x1b[0m"
			sys.stdout.write(seq)
		else:
			sys.stdout.write(text)

class BeautifulPrint:
	# Found printcolors.py on the Osintgram project (https://github.com/Datalux/Osintgram)

	def print_w(self, text):
		pc.printout(text + "\n")

	def print_g(self, text):
		pc.printout("[+] ", pc.GREEN)
		pc.printout(text + "\n")

	def print_b(self, text):
		pc.printout("[*] ", pc.BLUE)
		pc.printout(text + "\n")

	def print_r(self, text):
		pc.printout("[-] ", pc.RED)
		pc.printout(text + "\n")

class ClearKatz:
	def __init__(self, json_path, bin_path):
		# Initialize basic data
		self.data = {"domain_info": {"fqdn": None, "alias": None}, "creds" : {}}
		self.isSilent = args.silent
		self.data['domain_info']["fqdn"] = args.domain.upper() if args.domain != None else self.data['domain_info']["fqdn"]

		if bin_path != None:
			json_path = self.convert_dump_to_json(bin_path)
		self.open_lsass_json(json_path)

		if bin_path != None:
			self.cleanup()

	def open_lsass_json(self, json_path):
		try:
			with open(json_path, "r") as f:
				lsass_json = json.loads(f.read())
				self.lsass_json = lsass_json[list(lsass_json.keys())[0]]['logon_sessions']
		except:
			bp.print_r("Failed to open json dump file, quitting!")
			exit()

	def convert_dump_to_json(self, bin_path):
		from pypykatz.__main__ import main as pypykatz_main
		
		dir_tmp = f"{os.path.dirname(os.path.realpath(__file__))}/tmp"
		if not(os.path.isdir(dir_tmp)):
			os.mkdir(dir_tmp)
		json_path = f"{dir_tmp}/{bin_path}.json"
		sys.argv = ["pypykatz", "lsa", "minidump", bin_path, "--json", "-o", json_path]

		try:
			pypykatz_main()
			bp.print_g("Successfully converted memory dump into json!")
		except:
			bp.print_r("Memory dump conversion failed")
		return json_path

	def cleanup(self):
		from shutil import rmtree
		rmtree(f"{os.path.dirname(os.path.realpath(__file__))}/tmp", ignore_errors=True)

	def show(self):
		tab = "    "
		if len(self.data['creds']) < 1:
			bp.print_r("No creds were found...")
			return

		creds = self.data['creds']

		bp.print_b("Domain information")
		bp.print_w(f"{tab}Domain Name: {self.data['domain_info']['fqdn']}")
		bp.print_w(f"{tab}Domain alias: {self.data['domain_info']['alias']}\n")

		for account_name in creds:
			bp.print_g(f"{account_name}")
			bp.print_w(f"{tab}Password: {creds[account_name]['PASSWORD']}")
			if args.raw:
				bp.print_w(f"{tab}Password (Raw): {creds[account_name]['PASSWORD_RAW']}")
			bp.print_w(f"{tab}NT: {creds[account_name]['NT']}")
			bp.print_w(f"{tab}AES256: {creds[account_name]['AES256']}\n")
		if args.dpapi:
			bp.print_b("DPAPI Keys (guid: masterkey):")
			for guid in self.data["dpapi"]:
				bp.print_w(f"{guid}: {self.data['dpapi'][guid]}")
		else:
			bp.print_b(f"Ignored {len(self.data['dpapi'])} arrays of DPAPI keys")

	def guess(self):
		# This code sucks i was tired when writing it
		creds = self.data['creds']
		all_accounts = list(creds.keys())
		unique_account, seen_before = {}, []
		for account in all_accounts:
			if account.split("@")[0] not in seen_before:
				unique_account[account.split("@")[0]] = []
				seen_before.append(account.split("@")[0])
			unique_account[account.split("@")[0]].append(account)


		deleted_ones = []
		for account in unique_account.keys():
			if len(unique_account[account]) == 1:
				pass
			else:
				# FIND THE LONGEST TO USE FOR DISPLAY
				couple = [0, ""]
				for k in range(len(unique_account[account])):
					length = len(unique_account[account][k])
					if length > couple[0]:
						couple = [length, unique_account[account][k]]
				kept = couple[1]
				deleted_ones.append(kept)
				unique_account[account].pop(unique_account[account].index(kept))

				# END FIND LONGEST FOR DISPLAY

				# Edit the values

				for k in unique_account[account]:
					self.data['creds'][kept]['PASSWORD'] = self.data['creds'][k]['PASSWORD'] if self.data['creds'][k]['PASSWORD'] != None else self.data['creds'][kept]['PASSWORD']
					self.data['creds'][kept]['PASSWORD_RAW'] = self.data['creds'][k]['PASSWORD_RAW'] if self.data['creds'][k]['PASSWORD_RAW'] != None else self.data['creds'][kept]['PASSWORD_RAW']
					self.data['creds'][kept]['NT'] = self.data['creds'][k]['NT'] if self.data['creds'][k]['NT'] != None else creds[kept]['NT']
					self.data['creds'][kept]['AES256'] = self.data['creds'][k]['AES256'] if self.data['creds'][k]['AES256'] != None else self.data['creds'][kept]['AES256']
					# Delete the other one
					self.data['creds'].pop(k)
					deleted_ones.append(k)

		for k in self.data['creds']:
			if (self.data['creds'][k]['PASSWORD'] == self.data['creds'][k]['PASSWORD_RAW']) and (self.data['creds'][k]['PASSWORD'] != None and self.data['creds'][k]['PASSWORD_RAW']):
				try:
					self.data['creds'][k]['PASSWORD'] = bytes.fromhex(self.data['creds'][k]['PASSWORD_RAW']).decode('utf-8')
				except:
					self.data['creds'][k]['PASSWORD'] = "Not an ASCII PASSWORD"


		bp.print_b(f"ClearKatz tried to guess which credentials were associated to ({deleted_ones}), to prevent that behaviour use the --no-guessing switch.\n")

	def export_json(self, json_path):
		for key in self.data['creds']:
			self.data['creds'][key]['USERNAME'] = key

		try:
			with open(json_path, "w") as outfile:
				json.dump(self.data['creds'], outfile)
			bp.print_g(f"Succesfully exported to {json_path}!")
		except:
			bp.print_r("Failed to export to JSON!")

	def start(self):
		keys1 = list(self.lsass_json.keys())

		self.data['domain_info']['alias'] = self.lsass_json[keys1[0]]['domainname'].upper()

		for key1 in keys1:
			for key in self.lsass_json[key1].keys():
				lsass_tmp = self.lsass_json[key1]
				if key == "kerberos_creds" and len(lsass_tmp['kerberos_creds']) > 0:
					self.kerberos_creds(list(lsass_tmp['kerberos_creds'])[0])

				elif key == "msv_creds" and len(lsass_tmp['msv_creds']) > 0:
					self.msv_creds(list(lsass_tmp['msv_creds'])[0])

				elif key == "dpapi_creds" and len(lsass_tmp['dpapi_creds']) > 0:
					self.dpapi_creds(lsass_tmp['dpapi_creds'][0]['key_guid'], lsass_tmp['dpapi_creds'][0]['masterkey'])

				elif key == "wdigest_creds" and len(lsass_tmp['wdigest_creds']) > 0:
					self.wdigest_creds(list(lsass_tmp['wdigest_creds'])[0])

				elif key == "credman_creds" and len(lsass_tmp["credman_creds"]) > 0:
					self.credman_creds(list(lsass_tmp['credman_creds'])[0])
		if not args.no_guessing:
			self.guess()

	def credman_creds(self, lsass_json):
		username = lsass_json['username'].upper()
		if username == "" or ord(username[0]) > 255 or lsass_json['domainname'] == "":
			if not self.isSilent:
				bp.print_r(f"No username or domain found, skipping... \n{lsass_json}")
			return

		domain = self.data['domain_info']['fqdn'] if (self.data['domain_info']['fqdn'] != None and lsass_json['domainname'] == self.data['domain_info']['alias']) else lsass_json['domainname'].upper()
		fullname = username + "@" + domain

		if self.data['creds'].get(fullname) == None:
			self.data['creds'][fullname] = {'AES256': None, 'NT': None, "PASSWORD": None, "PASSWORD_RAW":None}

		self.data['creds'][fullname]['PASSWORD'] = lsass_json['password'] if lsass_json['password'] not in ("", None) else self.data['creds'][fullname]['PASSWORD']
		self.data['creds'][fullname]['PASSWORD_RAW'] = lsass_json['password_raw'] if lsass_json['password_raw'] not in ("", None) else self.data['creds'][fullname]['PASSWORD_RAW']

	def wdigest_creds(self, lsass_json):
		username = lsass_json['username'].upper()
		if username == "" or ord(username[0]) > 255 or lsass_json['domainname'] == "":
			if not self.isSilent:
				bp.print_r(f"No username or domain found, skipping... \n{lsass_json}")
			return

		domain = self.data['domain_info']['fqdn'] if (self.data['domain_info']['fqdn'] != None and lsass_json['domainname'] == self.data['domain_info']['alias']) else lsass_json['domainname'].upper()
		fullname = username + "@" + domain

		if self.data['creds'].get(fullname) == None:
			self.data['creds'][fullname] = {'AES256': None, 'NT': None, "PASSWORD": None, "PASSWORD_RAW":None}

		self.data['creds'][fullname]['PASSWORD'] = lsass_json['password'] if lsass_json['password'] not in ("", None) else self.data['creds'][fullname]['PASSWORD']
		self.data['creds'][fullname]['PASSWORD_RAW'] = lsass_json['password_raw'] if lsass_json['password_raw'] not in ("", None) else self.data['creds'][fullname]['PASSWORD_RAW']
		return

	def msv_creds(self, lsass_json):
		username = lsass_json['username'].upper()
		if username == "" or ord(username[0]) > 255 or lsass_json['domainname'] == "":
			if not self.isSilent:
				bp.print_r(f"No username or domain found, skipping... \n{lsass_json}")
			return

		domain = self.data['domain_info']['fqdn'] if (self.data['domain_info']['fqdn'] != None and lsass_json['domainname'] == self.data['domain_info']['alias']) else lsass_json['domainname'].upper()

		fullname = username + "@" + domain

		if self.data['creds'].get(fullname) == None:
			self.data['creds'][fullname] = {'AES256': None, 'NT': None, "PASSWORD": None, "PASSWORD_RAW":None}

		self.data['creds'][fullname]['NT'] = lsass_json['NThash'] if lsass_json['NThash'] not in ("", None) else self.data['creds'][fullname]
		return

	def kerberos_creds(self, lsass_json):
		username = lsass_json['username'].upper()
		if username == "" or ord(username[0]) > 255 or lsass_json['domainname'] == "":
			if not self.isSilent:
				bp.print_r(f"No username or domain found, skipping... \n{lsass_json}")
			return

		domain = self.data['domain_info']['fqdn'] if (self.data['domain_info']['fqdn'] != None and lsass_json['domainname'] == self.data['domain_info']['alias']) else lsass_json['domainname'].upper()

		fullname = username + "@" + domain

		if self.data['creds'].get(fullname) == None:
			self.data['creds'][fullname] = {'AES256': None, 'NT': None, "PASSWORD": None, "PASSWORD_RAW":None}

		if len(lsass_json['tickets']) > 1:
			self.data['creds'][fullname]['AES256'] = lsass_json['tickets']['Key'] if lsass_json['tickets']['Key'] not in ("", None) else self.data['creds'][fullname]['AES256']

		self.data['creds'][fullname]['PASSWORD'] = lsass_json['password'] if lsass_json['password'] not in ("", None) else self.data['creds'][fullname]['PASSWORD']
		self.data['creds'][fullname]['PASSWORD_RAW'] = lsass_json['password_raw'] if lsass_json['password_raw'] not in ("", None) else self.data['creds'][fullname]['PASSWORD_RAW']
		return

	def dpapi_creds(self, guid, masterkey):
		if self.data.get("dpapi") == None:
			self.data["dpapi"] = {guid : masterkey}
		else:
			self.data["dpapi"][guid] = masterkey
		return

banner = """
   ______    __   github.com/NioZow      __ __           __
  / ____/   / /  ___   ____ _   _____   / //_/  ____ _  / /_ ____
 / /       / /  / _ \ / __ `/  / ___/  / ,<    / __ `/ / __//_  /
/ /___    / /  /  __// /_/ /  / /     / /| |  / /_/ / / /_   / /_
\____/   /_/   \___/ \__,_/  /_/     /_/ |_|  \__,_/  \__/  /___/
"""
version = "Version 0.1"

def main():
	pc.printout(banner, pc.YELLOW)
	pc.printout("\n	Version 1.0\n\n", pc.BLUE)
	katz = ClearKatz(json_path=args.import_json, bin_path=args.import_memory_dump)
	katz.start()
	katz.show()
	if args.json != None:
		katz.export_json(args.json)


parser = argparse.ArgumentParser(description='ClearKatz is a tool to see clearly the results of a LSASS dump. It uses pypykatz to read a LSASS dump and then filter the output to only get the most important.')
parser.add_argument('-i', '--import-json', type=str,help='LSASS json dump file location')
parser.add_argument('-m', '--import-memory-dump', type=str, help='LSASS dump file location')
parser.add_argument('-d', '--domain', help='Specify the domain name to make things even clearer')
parser.add_argument('-n', '--no-guessing', help='Prevent the tool from trying to guess with creds are linked', action='store_true')
parser.add_argument('-s', '--silent', help='Do not print when username or domain not found', action='store_true')
parser.add_argument('-r', '--raw', help='Display raw password', action='store_true')
parser.add_argument('-j', '--json', help='Export the creds to JSON')
parser.add_argument('--dpapi', help="Display DPAPI keys", action='store_true')
args = parser.parse_args()
pc, bp = PrintColors(), BeautifulPrint()


if len(sys.argv) == 1:
	parser.print_help()
	exit()
elif (args.import_json == None) and (args.import_memory_dump == None):
	bp.print_r("No memory dump or JSON file specified, quitting!")
	exit()
elif args.import_json and args.import_memory_dump:
	bp.print_r("Memory dump and JSON file specified, quitting!")
	exit()

if __name__ == "__main__":
	main()
