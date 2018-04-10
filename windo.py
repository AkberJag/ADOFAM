import subprocess as sp
from scapy.all import *
import re
import time
import sys
from PyQt4 import QtCore, QtGui, uic, QtNetwork

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
#window
class mw(QtGui.QMainWindow):
    def __init__(self):
        QtGui.QMainWindow.__init__(self)
        uic.loadUi('mw.ui', self)
        live_hosts = []
        iface="wlan0"
        ip=gateway_ip
        arping = sp.Popen(['arp-scan','--interface',iface,ip+'/24'],stdout = sp.PIPE,shell=False)
        i=1
        for line in arping.stdout:
            if line.startswith(ip.split('.')[0]):
                ip = line.split()[0]
                mac= line.split()[1]
                self.tableWidget.setRowCount(i)
                self.tableWidget.setItem(i-1, 0, QtGui.QTableWidgetItem(mac))
                self.tableWidget.setItem(i-1,1,QtGui.QTableWidgetItem(ip))
                header = self.tableWidget.horizontalHeader()
                header.setResizeMode(0, QtGui.QHeaderView.Stretch)
                header.setResizeMode(1, QtGui.QHeaderView.ResizeToContents)
                header.setResizeMode(2, QtGui.QHeaderView.ResizeToContents)
                #live_hosts.append(ip)
                i=1+i

        self.show()


if __name__ == '__main__':
    app = QtGui.QApplication(sys.argv)
    window = mw()
    sys.exit(app.exec_())
