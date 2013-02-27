#!/usr/bin/python
'''
Created on May 14, 2012

@author: vsakode
'''
import sys;
import time;
import re;
import socket;
import os;
from signal import SIGTERM

def daemonize(stdout='/dev/null', stderr='/dev/null', stdin='/dev/null', pidfile='/var/run/ipaddr.pid' ):
    '''
        Fork to create a child and exit parent process
        Change the umask so that we aren't relying on the one set in the parent
        Create new session id and detach from the current session
        Change the working directory to somewhere that won't get unmounted
    '''
    try:
        pid = os.fork()
        if pid > 0: sys.exit(0) # Exit first parent.
    except OSError, e:
        sys.stderr.write("fork #1 failed: (%d) %s\n" % (e.errno, e.strerror))
        sys.exit(1)

    os.chdir("/")
    os.umask(0)
    os.setsid()

    try:
        pid = os.fork()
        if pid > 0: sys.exit(0) # Exit second parent.
    except OSError, e:
        sys.stderr.write("fork #2 failed: (%d) %s\n" % (e.errno, e.strerror))
        sys.exit(1)

    si = file(stdin, 'r')
    so = file(stdout, 'a+')
    se = file(stderr, 'a+', 0)
    pid = str(os.getpid())
    startmsg = "IPaddr daemon started with PID %s ... LOGFILE : /var/log/ipaddr.log"
    sys.stderr.write("%s\n" % startmsg % pid)
    sys.stderr.flush()
    sys.stdout.flush()
    if pidfile: 
        file(pidfile,'w+').write("%s\n" % pid)
    # Redirect standard file descriptors.
    os.dup2(si.fileno(), sys.stdin.fileno())
    os.dup2(so.fileno(), sys.stdout.fileno())
    os.dup2(se.fileno(), sys.stderr.fileno())

def startdaemon(pid,stdout,stderr,stdin,pidfile):
    """
    Start and Daemonize the script
    """
    if pid:
        mess = "[ERROR:] pid file '%s' exists... Daemon is already running\n"
        sys.stderr.write(mess % pidfile)
        sys.exit(1)
    daemonize()

def stopdaemon(pid, pidfile,action):
    """
    Stop daemon and check for restart condition
    """
    if not pid:
        mess = "[ERROR:] Daemon not running.... Unable to locate pid file %s\n"
        sys.stderr.write(mess % pidfile)
        sys.exit(1)
    try:
        while 1:
            os.kill(pid,SIGTERM)
            time.sleep(1)
    except OSError, err:
        err = str(err)
        if err.find("No such process") > 0:
            if os.path.exists(pidfile):
                os.remove(pidfile)
            #os.remove(pidfile)
                if 'stop' == action:
                    print "ipfind daemon stopped"
                    sys.exit(0)
                action = 'start'
                pid = None
                return pid, action
        else:
            print str(err)
            sys.exit(1)
     
                    
def daemonAction(stdout='/dev/null', stderr='/dev/null', stdin='/dev/null', pidfile='/var/run/ipaddr.pid' ):
    """
    Check for the argument passed to the daemon script and perform the action accordingly
    """
    if len(sys.argv) > 1:
        action = sys.argv[1]
        try:
            pf  = file(pidfile,'r')
            pid = int(pf.read().strip())
            pf.close()
        except IOError:
            pid = None
        
        if 'stop' == action or 'restart' == action:
            pid, action = stopdaemon(pid, pidfile,action)
            ## Check pid and action for restart condition
            print "Daemon stoppped. "
            print "Restarting ipfind daemon.........."
            time.sleep(1)
            
        if 'start' == action:
            startdaemon(pid,stdout,stderr,stdin,pidfile)
            return
        
        if 'status' == action:
            if not pid:
                print "Daemon is not running"
            else:
                print "Daemon running with pid = %s" %pid
                
    else:
        print "usage: %s start|stop|restart|status" % sys.argv[0]
        sys.exit(1)
    sys.exit(2)


def parseFile(infile):
    """
    Parses the log file for valid IP and verifies if the IP is Pingable or not
    """  
    token = file(infile,'rU')
    while True:
        newline = token.readline()
        if newline:
            ### Search for the IP patterns
            ipmatch = re.search(r'[0-9][0-9]?[0-9]?\.[0-9][0-9]?[0-9]?\.[0-9][0-9]?[0-9]?\.[0-9][0-9]?[0-9]?', newline)
            if ipmatch:
                try:
                    ### Validates the IP address
                    socket.inet_aton(ipmatch.group())
                    valid_ip = ipmatch.group() + "    [valid IP]"
                    yield (valid_ip)
                except socket.error:
                    invalid_ip = ipmatch.group() + "    [INVALID IP]"
                    yield (invalid_ip)
                    continue
        else:
            time.sleep(0.1)

def isReadable(infile):
    """
    test if the /var/log/messages is readable
    """
    try :
        token = open(infile, 'rU')
        token.close()
    except:
        print "%s exists but not readable..... check the permissions or Run as root" %(infile)  
        sys.exit()
    return True

def valid_ip_search():
    """
    Search valid IP addresses in /var/log/messages and store the result in /var/log/ipaddr.log
    """
    infile = "/var/log/messages"   
    if os.path.exists(infile) and isReadable(infile):
        dataout = "/var/log/ipaddr.log"
        fout = file(dataout,'a')
        for ipaddr in parseFile(infile):
            print >> fout, ipaddr
            fout.flush()
    else:
        print "/var/log/messages does not exists"
        
def main(): 
    """
    Check for the root login and execute the script
    """
    if os.getuid() == 0:
        daemonAction()  
        valid_ip_search()
    else:
        print "Login as root to run this daemon"    
    
if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass