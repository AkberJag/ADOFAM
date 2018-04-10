import subprocess as sp
from scapy.all import *
import re
import time
import sys
from PyQt4 import QtCore, QtGui, uic, QtNetwork


# clear the ARP table
sp.call(['ip -s -s neigh flush all && clear'], shell=True)
time.sleep(3)
gateway_ip = ""
gateway_mac = ""
# find and print all interfaces
ifaces_names = []
ifaces_macs = []
ifaces = QtNetwork.QNetworkInterface.allInterfaces()
print '************************************'
for i in ifaces:
    ifaces_names.append(str(i.name()))
    ifaces_macs.append(str(i.hardwareAddress()))
    interface = ifaces_names
    interface_mac = ifaces_macs
    hname = str(i.name())
    print "* [*] {} \t".format(hname),
    print str(i.hardwareAddress()), " *"

print '************************************'
interface_choosen = raw_input("choose the interface (wlan recomented): ")
while interface_choosen not in ifaces_names:
    interface_choosen = raw_input("choose the interface (wlan recomented): ")
mymac = ifaces_macs[ifaces_names.index(interface_choosen)]
print "\nyour mac is:", mymac, "\n"


# find gateway mac and ip
route = sp.check_output(['route', '-n'], shell=False)
for _ in route.split('\n'):
    if "UG" in _:
        gateway_ip = re.split('[\s]+', _,)[1]
# arp_cap will collect all arp entries
arp_cmd = sp.check_output(['arp', '-a', '-n'], shell=False)

for _ in arp_cmd.split('\n'):
    if gateway_ip in _:
        # re= reqular exp, \s space
        gateway_mac = re.split('[\s]+', _)[3]
print "gateway ip is {} \ngateway mac is {}".format(gateway_ip, gateway_mac)

# ICMP ping
icmp_ping = ' -sP ' + gateway_ip + '/24'
print "\n[*] Sending ICMP ping...\n"
sp.check_output("nmap {} &> /dev/null".format(icmp_ping), shell=True)
print "[*] DONE"
print "[*] waiting for attacker "


# attacker identification
# from sniffing at the bottom
def arp_capture(pkt):

    # attacker will say he is the gateway by changing the MAC of gateway with his
    # and keep the ip as of the gatewayr
    # so check old and new mac with of code opcode (op) = is 'is-at'
    if ARP in pkt and pkt[ARP].op == 2 and pkt[ARP].psrc == gateway_ip and pkt[ARP].hwsrc != gateway_mac:
        print "\n\nattack detected \n[*]with MAC :", pkt[ARP].hwsrc
        # send the attacker mac to the function def
        find_attacker_ip(pkt[ARP].hwsrc)

# find attackers ip address from the arp table with the help of MAC


def find_attacker_ip(mac):
    arp_cmd = sp.check_output(['arp', '-a', '-n'])
    for line in arp_cmd.split('\n'):
        gateway_ip_splitted = '(' + gateway_ip + ')'
        if mac in line:
            attacker_ip = re.split('[()\s]+', line)[1]
            print "[*]attacker ip is:", attacker_ip


# sniff all packets and filter ARP
sniff(iface="wlan0", filter="arp", count=0, prn=arp_capture, store=0)
