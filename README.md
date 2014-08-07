banshee.py
=========

Set of security scripts to run on a Local Area Network. Features currently
include:

1. DNS Spoofing (Testing)
2. DeAuthentication (Implementing)
3. ARP Poison √
4. SYN Flooding √
5. Sniff email address & password (not started)
6. Inject HTML/JS (not started)
7. Grab Cookies (not started)

###Prerequisities
Linux

Tested with Python 2.7

###Installation
```bash
sudo apt-get install python-nfqueue
sudo apt-get install python-scapy
sudo apt-get install python-twisted

pip install netaddr

pip install python-nmap

wget http://xael.org/norman/python/python-nmap/python-nmap-0.1.4.tar.gz
tar xvzf python-nmap-0.2.6.tar.gz
cd python-nmap-0.2.6
python setup.py install
```
or to get scapy version I used

```bash
wget http://hg.secdev.org/scapy/raw-file/v1.2.0.2/scapy.py
sudo python scapy.py
``
To run it:
```bash
sudo python banshee.py 
```
###Useful Links

https://docs.python.org/2/library/cmd.html

http://xael.org/norman/python/python-nmap/

http://danmcinerney.org/

http://www.secdev.org/projects/scapy/doc/

###License
GPL v2. See [License](./LICENSE)
