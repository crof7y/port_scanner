#!/usr/bin/python3

import nmap
import time
import os


print('\n\tWelcome to The Vulnerability Assessment Port Scanner!')
print('\n\n\tInput Host Addresses in the following format: 192.168.1.150 (example)')
print('\tInput Network Addresses in the following format: 192.168.1.1/24 (example)')
time.sleep(1)
scan = nmap.PortScanner()
addressID = input('\n\tInput Address to Scan: ')
print('\n\tInitializing Scan...')
time.sleep(2)
print('\n\tScanning.....This may take some time.')
scan.scan(addressID, arguments = '-A -T4 -p 21-443,1433-1434')
for host in scan.all_hosts():
    print('\n\t\t------------------------------------------------------------------------------------------')
    print('\t\tHost: {0} ({1})'.format(host, scan[host].hostname()))
    print('\t\tState: {0}'.format(scan[host].state()))
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
        print('\t\tProtocol: {0}'.format(protocol))

        lport = scan[host][protocol].keys()
        sorted(lport)
        for port in lport:
            if port == 21 or port == 22 or port == 23 or port == 25 or port == 53 or port == 110 or port == 135 or port == 137 or port == 139 or port == 443 or port == 1433 or port == 1434:
                print('\t\t\tport: '+str(port)+'\tstate: {0}'.format(scan[host][protocol][port]['state']))
            else:
                print('\t\t\tport: '+str(port)+'\tstate: {0}'.format(scan[host][protocol][port]['state']))

        print('\n')
        print('\t\t\tRecommended Actions: close all open ports.')
        print('\t\t\tTo Close Open Ports: access firewall and create rules to close ports.')
        if port == 21 or port == 22 or port == 23 or port == 25 or port == 53 or port == 110 or port == 135 or port == 137 or port == 139 or port == 443 or port == 1433 or port == 1434:
            print('\n\t\t\tPorts 21, 22, 23, 25, 53, 110, 135, 137, 139, \n\t\t\t443, 1433 and 1434 are EXTREMELY vulnerable to attack.')
            print('\n\t\t\tTo minimize vulnerability, CLOSE THESE PORTS IMMEDIATELY:')
        print('\n')
        for port in lport:
            if port == 21:
                print('\t\t\tPort 21: FTP')
            if port == 22:
                print('\t\t\tPort 22: SSH')
            if port == 23:
                print('\t\t\tPort 23: Telnet')
            if port == 25:
                print('\t\t\tPort 25: SMTP')
            if port == 53:
                print('\t\t\tPort 53: DNS')
            if port == 110:
                print('\t\t\tPort 110: POP3')
            if port == 135:
                print('\t\t\tPort 135: Windows RPC')
            if port == 137:
                print('\t\t\tPort 137: Windows NetBIOS over TCP/IP')
            if port == 139:
                print('\t\t\tPort 139: Windows NetBIOS over TCP/IP')
            if port == 443:
                print('\t\t\tPort 443: HTTP/HTTPS')
            if port == 1433:
                print('\t\t\tPort 1433: Microsoft SQL Server')
            if port == 1434:
                print('\t\t\tPort 1434: Microsoft SQL Server')
    print('\t\t------------------------------------------------------------------------------------------\n')

input('Press ENTER to quit')
