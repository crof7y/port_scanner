#!/usr/bin/python3

import nmap
import time
import os
bstart = '\033[1m'
gstart = '\033[2m'
red = '\033[91m'
blue = '\033[94m'
uline = '\033[4m'
fstop = '\033[0;0m'
purple = '\033[95m'

print(bstart + red + uline + '\n\tWelcome to The Vulnerability Assessment Port Scanner' + fstop)
print(gstart + '\tInput Host Addresses in the following format: 192.168.1.150 (example)' + fstop)
print(gstart + '\tInput Network Addresses in the following format: 192.168.1.1/24 (example)' + fstop)
time.sleep(1)
scan = nmap.PortScanner()
addressID = input(bstart + '\n\tInput Address to Scan: ' + fstop)
print(gstart + '\n\tInitializing Scan...' + fstop)
time.sleep(2)
print(gstart + '\n\tScanning.....This may take some time.' + fstop)
scan.scan(addressID, arguments = '-A -T4 -p 21-443,1433-1434')
for host in scan.all_hosts():
    print('\n\t\t------------------------------------------------------------------------------------------')
    print(blue + bstart + '\t\tHost: ' + fstop + '{0} ({1})'.format(host, scan[host].hostname()))
    print(blue + bstart + '\t\tState: ' + fstop + '{0}'.format(scan[host].state()))
    #if scan[host]['osmatch']:
    #    if scan[host]['osmatch'][0]['osclass'][0]['vendor'] == 'Microsoft':
    #        os = 'Windows'
    #        print(blue + bstart + '\t\tOS: ' +fstop +os)
    #    if scan[host]['osmatch'][0]['osclass'][0]['vendor'] == 'Linux':
    #        os = 'Linux'
    #        print(blue + bstart + '\t\tOS: ' +fstop +os)
    #else:
    #    print(blue + bstart +'\t\tOS: ' +fstop + 'Unknown')

    for protocol in scan[host].all_protocols():
        print(blue + bstart + '\t\tProtocol: ' + fstop + '{0}'.format(protocol))

        lport = scan[host][protocol].keys()
        sorted(lport)
        for port in lport:
            if port == 21 or port == 22 or port == 23 or port == 25 or port == 53 or port == 110 or port == 135 or port == 137 or port == 139 or port == 443 or port == 1433 or port == 1434:
                print(red+bstart+'\t\t\tport: '+str(port)+red+bstart+'\tstate: {0}'.format(scan[host][protocol][port]['state'])+fstop)
            else:
                print(purple+bstart+'\t\t\tport: '+str(port)+'\tstate: {0}'.format(scan[host][protocol][port]['state'])+fstop)

        print('\n')
        print(bstart + uline + '\t\t\tRecommended Actions:' +fstop+gstart+ ' close all open ports.' +fstop)
        print(bstart + uline + '\t\t\tTo Close Open Ports:' +fstop+gstart+ ' access firewall and create rules to close ports.' +fstop)
        if port == 21 or port == 22 or port == 23 or port == 25 or port == 53 or port == 110 or port == 135 or port == 137 or port == 139 or port == 443 or port == 1433 or port == 1434:
            print(gstart + '\t\t\tThe above ports in '+fstop+bstart+red+'RED'+fstop+gstart+' are extremely vulnerable to attack.' +fstop)
            print(gstart + '\t\t\tTo minimize vulnerability, ' +fstop+bstart+uline+red+ 'CLOSE THESE PORTS IMMEDIATELY:' +fstop)
        print('\n')

        for port in lport:
            if port == 21:
                print(bstart + red + '\t\t\tPort 21: ' +fstop+gstart+ 'FTP' + fstop)
            if port == 22:
                print(bstart + red + '\t\t\tPort 22: ' +fstop+gstart+ 'SSH' + fstop)
            if port == 23:
                print(bstart + red + '\t\t\tPort 23: ' +fstop+gstart+ 'Telnet' + fstop)
            if port == 25:
                print(bstart + red + '\t\t\tPort 25: ' +fstop+gstart+ 'SMTP' + fstop)
            if port == 53:
                print(bstart + red + '\t\t\tPort 53: ' +fstop+gstart+ 'DNS' + fstop)
            if port == 110:
                print(bstart + red + '\t\t\tPort 110: ' +fstop+gstart+ 'POP3' + fstop)
            if port == 135:
                print(bstart + red + '\t\t\tPort 135: ' +fstop+gstart+ 'Windows RPC' + fstop)
            if port == 137:
                print(bstart + red + '\t\t\tPort 137: ' +fstop+gstart+ 'Windows NetBIOS over TCP/IP' + fstop)
            if port == 139:
                print(bstart + red + '\t\t\tPort 139: ' +fstop+gstart+ 'Windows NetBIOS over TCP/IP' + fstop)
            if port == 443:
                print(bstart + red + '\t\t\tPort 443: ' +fstop+gstart+ 'HTTP/HTTPS' + fstop)
            if port == 1433:
                print(bstart + red + '\t\t\tPort 1433: ' +fstop+gstart+ 'Microsoft SQL Server' + fstop)
            if port == 1434:
                print(bstart + red + '\t\t\tPort 1434: ' +fstop+gstart+ 'Microsoft SQL Server' + fstop)
    print('\t\t------------------------------------------------------------------------------------------\n')
