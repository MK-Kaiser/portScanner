#!/usr/bin/env python3
import optparse
from socket import *

#simple function to scan target:port(s) and display received banner
def connScan(tgtHost, tgtPort):
    try:
        connSock = socket(AF_INET, SOCK_STREAM)
        connSock.connect((tgtHost, tgtPort))
        connSock.send(b'HEAD / HTTP/1.1\r\r\n\n')
        results = connSock.recv(100)
        print('[+]%d/tcp open'% tgtPort)
        print('[+] ' + str(results))
        connSock.close()
    except:
        print('[-]%d/tcp closed'% tgtPort)
#simple function to resolve hostname if required
def portScan(tgtHost, tgtPorts):
    try:
        tgtIP = gethostbyname(tgtHost)
    except:
        print("[-] Cannot Resolve '%s': Unknown host"% tgtHost)
        return

    try:
        tgtName = gethostbyaddr(tgtIP)
        print("\n[+] Scan results for: " + tgtName[0])
    except:
        print("\n[+] Scan results for: " + tgtIP)
#loop to iterate through list of ports to scan
    setdefaulttimeout(1)
    for tgtPort in tgtPorts:
        print("Scanning port " + tgtPort)
        connScan(tgtHost, int(tgtPort))
#argument parser to construct help menu and handle user supplied values
def main():
    parser = optparse.OptionParser('usage %prog -t' +\
        '<target host> -p <target port>')
    parser.add_option('-t', dest='tgtHost', type='string', \
        help='specify target host')
    parser.add_option('-p', dest='tgtPort', type='string', \
        help='specify target port[s] separated by comma')
    (options, args) = parser.parse_args()
    tgtHost = options.tgtHost
    tgtPorts = str(options.tgtPort).split(', ')
    if (tgtHost == None) | (tgtPorts[0] == None):
        print('[-] You must specify a target host and port[s]')
        exit(0)
    portScan(tgtHost, tgtPorts)
if __name__ == '__main__':
    main()
