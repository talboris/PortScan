#MULTIPROCESS Port Scanner , scanning 1-1014 ports with 4 processes using Scapy
# example of running the program "python scanner.py 192.68.X.X " 
from scapy.all import *
import sys
import multiprocessing as mp


ip= sys.argv[1]
print ":::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::\n\n\n\n\n\n\n"
print "-------------------------scaning the ...... %s-----------------------\n\n\n\n\n" %ip
print ":::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::\n\n\n\n\n\n\n\n\n"

#Before scanning the ports, the func tests whether host in online by sending ping command
def up7(ip):
    
    is_up = sr1(IP(dst=ip)/ICMP(),timeout=2)
    if is_up == None:
        return False
    else:
        return True
        
#func for the scanning
def scan(port):
    
            sporting = RandShort() #create rand port as source port, to stay invisible
            packet=sr1(IP(dst=ip)/TCP(sport = sporting,dport=port,flags = 'S'), timeout = 0.5)#sending SYN with IP packet, layered with TCP
            
            if str(type(packet))== "<type 'NoneType'>":
                print"closed port ------------> %d" %port
            elif packet.haslayer(TCP):  #in in resulsts there is TCP layer then
                print "has TCP layer"
                if packet.getlayer(TCP).flags==0x12:# cheching what flags are on in TCP layer , hex 12 is decimal 18 , means SYN and ACK flags together
                    sr1(IP(dst=ip)/TCP(sport = sporting,dport=port,flags='AR'), timeout=0.5) # resseting the port not to create DOS , sendinf ACK RESET flags
                    print "open port --------------------------------------------------------------------------------------> %d" %port
                    return port
    
        
        
if __name__ == '__main__':
    if up7(ip):
       
        pool = mp.Pool(processes=4) #creating process pool and 4 workers

        results = pool.map(scan,range (1,1024))# sending func and ports to pool by map func 


        
        #printing open ports
        for port in results:
            if port:
                print "\n"
                print "the port %d is open " %port     
    else:
        print "host is down"
        sys.exit(1)

        
