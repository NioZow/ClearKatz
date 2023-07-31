# ClearKatz
A tool to make LSASS memory dump more readable, using pypykatz.

# Installation

```
pip3 install -r requirements.txt
```

# Usage
```
./ClearKatz.py 
usage: ClearKatz.py [-h] [-i IMPORT_JSON] [-m IMPORT_MEMORY_DUMP] [-d DOMAIN] [-n] [-s] [-r] [-j JSON] [--dpapi]

ClearKatz is a tool to see clearly the results of a LSASS dump. It uses pypykatz to read a LSASS dump and then filter the output to only get the most important.

options:
  -h, --help            show this help message and exit
  -i IMPORT_JSON, --import-json IMPORT_JSON
                        LSASS json dump file location
  -m IMPORT_MEMORY_DUMP, --import-memory-dump IMPORT_MEMORY_DUMP
                        LSASS dump file location
  -d DOMAIN, --domain DOMAIN
                        Specify the domain name to make things even clearer
  -n, --no-guessing     Prevent the tool from trying to guess with creds are linked
  -s, --silent          Do not print when username or domain not found
  -r, --raw             Display raw password
  -j JSON, --json JSON  Export the creds to JSON
  --dpapi               Display DPAPI keys
```

# Demo
```
./ClearKatz.py -m dump.bin 

   ______    __   github.com/NioZow      __ __           __
  / ____/   / /  ___   ____ _   _____   / //_/  ____ _  / /_ ____
 / /       / /  / _ \ / __ `/  / ___/  / ,<    / __ `/ / __//_  /
/ /___    / /  /  __// /_/ /  / /     / /| |  / /_/ / / /_   / /_
\____/   /_/   \___/ \__,_/  /_/     /_/ |_|  \__,_/  \__/  /___/

	Version 1.0

INFO:pypykatz:Parsing file dump.bin
[+] Successfully converted memory dump into json!
[-] No username or domain found, skipping... 
{'cardinfo': None, 'credtype': 'kerberos', 'domainname': '', 'luid': 997, 'password': None, 'password_raw': '', 'pin': None, 'pin_raw': None, 'tickets': [], 'username': ''}
[*] ClearKatz tried to guess which credentials were associated to (['NOAH@DESKTOP-XYZ', 'NOAH@.']), to prevent that behaviour use the --no-guessing switch.

[*] Domain information
    Domain Name: None
    Domain alias: WORKGROUP

[+] DESKTOP-XYZ$@WORKGROUP
    Password: None
    NTLM: None
    AES256: None

[+] 192.168.56.1\NOAH@192.168.56.1
    Password: Password1!
    NTLM: None
    AES256: None

[+] NOAH@DESKTOP-XYZ
    Password: None
    NTLM: 7facdc498ed1680c4fd1448319a8c04f
    AES256: None

[*] Ignored 2 arrays of DPAPI keys
```