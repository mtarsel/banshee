banshee.py
=========

Set of security scripts to run on a Local Area Network. Features currently
include:

1. DNS Spoofing
2. DeAuthentication
3. ARP Poison √
4. SYN Flooding √
5. DeAuthentication Flooding
6. Sniff email address & password
7. Inject HTML/JS 
8. Grab Cookies

###Prerequisities
Linux

Tested with Python 2.7

###Installation
```bash
apt-get install python-nfqueue

pip install python-nmap

wget http://hg.secdev.org/scapy/raw-file/v1.2.0.2/scapy.py

sudo python scapy.py

sudo python banshee.py 
```
###License
GPL v2. See [License](./LICENSE)
