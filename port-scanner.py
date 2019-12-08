#!/usr/bin/env python3
import argparse
from socket import *

#simple function to scan target:port(s) and display received banner
def connScan(tgtHost, tgtPort):
    try:
        connSock = socket(AF_INET, SOCK_STREAM)
        connSock.connect((tgtHost, tgtPort))
        if tgtPort == 80 or 443:
            connSock.send(b'HEAD / HTTP/1.1\r\r\n\n')
        else:
            connSock.send(b'connect request\r\n')

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
    parser = argparse.ArgumentParser(description='scan a host for running services')
    parser.add_argument('-u', '--url', dest='tgtHost', type=str, required=False, help='provide a target url, or address example: www.website.com')
    parser.add_argument('-v', '--version', dest='ver', required=False, action='store_true', help='display version number.')
    parser.add_argument('-p', '--ports', dest='tgtPort', required=False, type=str, help="provide port[s] example: '22, 80' or 22 ")
    args = parser.parse_args()
    tgtHost = args.tgtHost
    tgtPorts = str(args.tgtPort).split(', ')
    if args.ver:
        print("portScanner version 0.1")
        exit()

    if (tgtHost == None) | (tgtPorts[0] == None):
        print('[-] You must specify a target host and port[s]')
        exit(0)
    portScan(tgtHost, tgtPorts)



if __name__ == '__main__':
    main()
