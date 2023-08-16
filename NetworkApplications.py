#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import argparse
from ctypes import addressof
from logging import exception
import socket
import os
import sys
import struct
from tempfile import tempdir
import time
import base64
import select


def setupArgumentParser() -> argparse.Namespace:
        parser = argparse.ArgumentParser(
            description='A collection of Network Applications developed for SCC.203.')
        parser.set_defaults(func=ICMPPing, hostname='lancaster.ac.uk')
        subparsers = parser.add_subparsers(help='sub-command help')
        
        parser_p = subparsers.add_parser('ping', aliases=['p'], help='run ping')
        parser_p.set_defaults(timeout=4)
        parser_p.add_argument('hostname', type=str, help='host to ping towards')
        parser_p.add_argument('--count', '-c', nargs='?', type=int,
                              help='number of times to ping the host before stopping')
        parser_p.add_argument('--timeout', '-t', nargs='?',
                              type=int,
                              help='maximum timeout before considering request lost')
        parser_p.set_defaults(func=ICMPPing)

        parser_t = subparsers.add_parser('traceroute', aliases=['t'],
                                         help='run traceroute')
        parser_t.set_defaults(timeout=4, protocol='icmp')
        parser_t.add_argument('hostname', type=str, help='host to traceroute towards')
        parser_t.add_argument('--timeout', '-t', nargs='?', type=int,
                              help='maximum timeout before considering request lost')
        parser_t.add_argument('--protocol', '-p', nargs='?', type=str,
                              help='protocol to send request with (UDP/ICMP)')
        parser_t.set_defaults(func=Traceroute)

        parser_w = subparsers.add_parser('web', aliases=['w'], help='run web server')
        parser_w.set_defaults(port=8080)
        parser_w.add_argument('--port', '-p', type=int, nargs='?',
                              help='port number to start web server listening on')
        parser_w.set_defaults(func=WebServer)

        parser_x = subparsers.add_parser('proxy', aliases=['x'], help='run proxy')
        parser_x.set_defaults(port=8000)
        parser_x.add_argument('--port', '-p', type=int, nargs='?',
                              help='port number to start web server listening on')
        parser_x.set_defaults(func=Proxy)

        args = parser.parse_args()
        return args


class NetworkApplication:

    def checksum(self, dataToChecksum: str) -> str:
        csum = 0
        countTo = (len(dataToChecksum) // 2) * 2
        count = 0

        while count < countTo:
            thisVal = dataToChecksum[count+1] * 256 + dataToChecksum[count]
            csum = csum + thisVal
            csum = csum & 0xffffffff
            count = count + 2

        if countTo < len(dataToChecksum):
            csum = csum + dataToChecksum[len(dataToChecksum) - 1]
            csum = csum & 0xffffffff

        csum = (csum >> 16) + (csum & 0xffff)
        csum = csum + (csum >> 16)
        answer = ~csum
        answer = answer & 0xffff
        answer = answer >> 8 | (answer << 8 & 0xff00)

        answer = socket.htons(answer)

        return answer

    def printOneResult(self, destinationAddress: str, packetLength: int, time: float, ttl: int, destinationHostname=''):
        if destinationHostname:
            print("%d bytes from %s (%s): ttl=%d time=%.2f ms" % (packetLength, destinationHostname, destinationAddress, ttl, time))
        else:
            print("%d bytes from %s: ttl=%d time=%.2f ms" % (packetLength, destinationAddress, ttl, time))

    def printAdditionalDetails(self, packetLoss=0.0, minimumDelay=0.0, averageDelay=0.0, maximumDelay=0.0):
        print("%.2f%% packet loss" % (packetLoss))
        if minimumDelay > 0 and averageDelay > 0 and maximumDelay > 0:
            print("rtt min/avg/max = %.2f/%.2f/%.2f ms" % (minimumDelay, averageDelay, maximumDelay))


class ICMPPing(NetworkApplication):

    timeOfSending = time.time()
    ID_count = 0
    received = True

    def receiveOnePing(self, icmpSocket, destinationAddress, ID, timeout):
        # 1. Wait for the socket to receive a reply
        # 2. Once received, record time of receipt, otherwise, handle a timeout
        receivedPacket = None 
        returnAddress = None
        timeOfReceive = None
        while True:
            receivedPacket, returnAddress = icmpSocket.recvfrom(1024)
            timeOfReceive = time.time()
            if(receivedPacket == None):
                if((time.time() - self.timeOfSending) * 1000 > timeout):
                    self.received = False
                    break
            else:
                break
        if(self.received == True):
            # 3. Compare the time of receipt to time of sending, producing the total network delay
            delay = (timeOfReceive - self.timeOfSending) * 1000 #ms
            # 4. Unpack the packet header for useful information, including the ID
            newReceivedPacket = receivedPacket[20:28]
            ttl = struct.unpack("b", receivedPacket[8:9])
            ICMP_type, ICMP_code, ICMP_checksum, ICMP_identifier, ICMP_sequence_number = struct.unpack('!bbHHh', newReceivedPacket)
            # 5. Check that the ID matches between the request and reply
            if(ICMP_identifier != self.ID_count):
                # 6. Return total network delay
                print("Wrong Packet ID")
                return None, None
            # 6. Return total network delay
        return delay, ttl, receivedPacket
        

    def sendOnePing(self, icmpSocket, destinationAddress, ID):
        # 1. Build ICMP header
        ICMP_type = 8
        ICMP_code = 0
        ICMP_checksum = 0
        ICMP_identifier = self.ID_count
        ICMP_sequence_number = 1
        ICMP_packet = struct.pack('!bbHHh', ICMP_type, ICMP_code, ICMP_checksum, ICMP_identifier, ICMP_sequence_number)
        ICMP_data = struct.pack('d', time.time())
        ICMP_packet += ICMP_data
        # 2. Checksum ICMP packet using given function
        ICMP_checksum = self.checksum(ICMP_packet)
        ICMP_packet = struct.pack('!bbHHh', ICMP_type, ICMP_code, ICMP_checksum, ICMP_identifier, ICMP_sequence_number)
        ICMP_packet += ICMP_data
        # 3. Insert checksum into packetock = socket.socket(
        icmpSocket.sendto(ICMP_packet, (destinationAddress, 1))
        # 5. Record time of sending
        self.timeOfSending = time.time()
        return sys.getsizeof(ICMP_packet)

    def doOnePing(self, destinationAddress, timeout):
        # 1. Create ICMP socket
        sock = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP)
        # 2. Call sendOnePing function
        packetSize = self.sendOnePing(sock, destinationAddress, self.ID_count)
        # 3. Call receiveOnePing function
        delay, ttl, receivedPacket= self.receiveOnePing(sock, destinationAddress, self.ID_count, timeout)  
        packetSize = sys.getsizeof(receivedPacket)    
        self.ID_count = self.ID_count + 1
        # 4. Close ICMP socket
        # 5. Return total network delay
        return packetSize, delay, ttl
        

    def __init__(self, args):
        print('Ping to: %s...' % (args.hostname))
        # 1. Look up hostname, resolving it to an IP address
        #hostnameIP = socket.gethostname(args.hostname)
        hostnameIP = socket.gethostbyname(args.hostname)
        # 2. Call doOnePing function, approximately every second
        while(True):
        #for i in range(3):
            ttl = 255
            packetSize, delay, ttl= self.doOnePing(hostnameIP, ttl)
            # 3. Print out the returned delay (and other relevant details) using the printOneResult method
            if(delay == None):
                print("packet failed")
            #else:
            self.printOneResult(hostnameIP, packetSize, delay, ttl[0], args.hostname)
            time.sleep(1)

        # 4. Continue this process until stopped


class Traceroute(NetworkApplication):

    timeOfSending = time.time()
    ID_count = 0
    receive_count = 0
    received = True
    allDelays = []

    def receiveOnePing(self, icmpSocket, destinationAddress, ID, timeout):
        # 1. Wait for the socket to receive a reply
        # 2. Once received, record time of receipt, otherwise, handle a timeout
        receivedPacket = None 
        returnAddress = None
        timeOfReceive = None
        while True:
            receivedPacket, returnAddress = icmpSocket.recvfrom(1024)
            timeOfReceive = time.time()
            if(receivedPacket == None):
                if((time.time() - self.timeOfSending) * 1000 > timeout):
                    print("Too long timed out")
                    self.received = False
                    break
            else:
                break
        if(self.received == True):
            # 3. Compare the time of receipt to time of sending, producing the total network delay
            delay = (timeOfReceive - self.timeOfSending) * 1000 #ms
            # 4. Unpack the packet header for useful information, including the ID
            newReceivedPacket = receivedPacket[20:28]
            ttl = struct.unpack("b", receivedPacket[8:9])
            ICMP_type, ICMP_code, ICMP_checksum, ICMP_identifier, ICMP_sequence_number = struct.unpack('bbHHh', newReceivedPacket)

            # 6. Return total network delay
            if(ICMP_type == 3):
                if(ICMP_code == 0):
                    print("Destination network unreachable")
                elif(ICMP_code == 1):
                    print("Destination host unreachable")
                else:
                    print("unreachable")
                return None, ttl[0], None, None
        self.receive_count += 1
        return delay, ttl[0], receivedPacket, returnAddress
        

    def sendOnePing(self, icmpSocket, destinationAddress, ID, ttl):
        # 1. Build ICMP header
        ICMP_type = 8
        ICMP_code = 0
        ICMP_checksum = 0
        ICMP_identifier = self.ID_count
        ICMP_sequence_number = 1
        ICMP_packet = struct.pack('bbHHh', ICMP_type, ICMP_code, ICMP_checksum, ICMP_identifier, ICMP_sequence_number)
        ICMP_data = struct.pack('d', time.time())
        ICMP_packet += ICMP_data
        # 2. Checksum ICMP packet using given function
        ICMP_checksum = self.checksum(ICMP_packet)
        ICMP_packet = struct.pack('bbHHh', ICMP_type, ICMP_code, ICMP_checksum, ICMP_identifier, ICMP_sequence_number)
        ICMP_packet += ICMP_data
        # 3. Insert checksum into packetock = socket.socket(
        icmpSocket.sendto(ICMP_packet, (destinationAddress, 1))
        # 5. Record time of sending
        self.timeOfSending = time.time()
        return sys.getsizeof(ICMP_packet)

    def doOnePing(self, destinationAddress, timeout, ttl):
        # 1. Create ICMP socket
        sock = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP)
        sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        # 2. Call sendOnePing function
        packetSize = self.sendOnePing(sock, destinationAddress, self.ID_count, int(ttl))
        # 3. Call receiveOnePing function
        delay, ttl, receivedPacket, returnAddress= self.receiveOnePing(sock, destinationAddress, self.ID_count, timeout)  
        packetSize = sys.getsizeof(receivedPacket)    
        self.ID_count = self.ID_count + 1
        # 4. Close ICMP socket
        # 5. Return total network delay
        return packetSize, delay, ttl, returnAddress
        
    def doOnePingUDP(self, destinationAddress, timeout, ttl):

        pass
    def doThreePings(self, destinationAddress, timeout, ttl):
        delays = []
        ttls = []
        returnAddress = None
        returned = False
        packetSize = None
        for i in range(3):
            temppacketSize, delay, tempttl, tempreturnAddress= self.doOnePing(destinationAddress, timeout, ttl)
            if(delay != None):
                returned = True
                returnAddress = tempreturnAddress
                packetSize = temppacketSize
            delays.append(delay)
            ttls.append(tempttl)
        if(returned):
            try:
                print(ttl, ". ", returnAddress[0], " (", socket.gethostbyaddr(returnAddress[0])[0] , ") ", round(delays[0],3), " ms ", round(delays[1],3), " ms ", round(delays[2],3), " ms ")
            except:
                print(ttl, ". ", returnAddress[0], " (", returnAddress[0] , ") ", round(delays[0],3), " ms ", round(delays[1],3), " ms ", round(delays[2],3), " ms ")
            for i in range(3):
                if(delays[i] != None):
                    self.allDelays.append(delays[i])
            return returnAddress[0], ttls[0]
        else:
            print(" * * * ")
            return None, ttl


    def __init__(self, args):
        # Please ensure you print each result using the printOneResult method!
        print('Traceroute to: %s' % (args.hostname), end="")
        try:
            hostnameIP = socket.gethostbyname(args.hostname)
            maxTTL = 30
            print(", ", maxTTL, " hops max", ", 69 byte packets")
            for ttl in range(1, maxTTL):     
                returnAddress, ttl= self.doThreePings(hostnameIP, 4, ttl)

                if(returnAddress == hostnameIP or returnAddress == args.hostname):
                    self.printAdditionalDetails((self.ID_count - self.receive_count), sorted(self.allDelays)[0], (sum(self.allDelays)/len(self.allDelays)), sorted(self.allDelays)[len(self.allDelays) - 1])
                    break

        except Exception as e:
            print("\nerror occured")
            #print(e)




class WebServer(NetworkApplication):

    def handleRequest(tcpSocket):
        # 1. Receive request message from the client on connection socket
        # 2. Extract the path of the requested object from the message (second part of the HTTP header)
        # 3. Read the corresponding file from disk
        # 4. Store in temporary buffer
        # 5. Send the correct HTTP response error
        # 6. Send the content of the file to the socket
        # 7. Close the connection socket
        pass

    def __init__(self, args):
        print('Web Server starting on port: %i...' % (args.port))
        # 1. Create server socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # 2. Bind the server socket to server address and server port
        hostnameIP = socket.gethostbyname(args.hostname)
        sock.bind((args.hostnameIP, args.port))
        # 3. Continuously listen for connections to server socket
        
        # 4. When a connection is accepted, call handleRequest function, passing new connection socket (see https://docs.python.org/3/library/socket.html#socket.socket.accept)
        # 5. Close server socket


class Proxy(NetworkApplication):

    def handleRequest(self, tcpSocket):
        dataRecv = tcpSocket.recv(4096).decode()
        #split data
        data = dataRecv.split('\r\n')
        #check for GET
        print(data)
        requestType = data[0].split()[0]
        if requestType == "GET":
            #get path
            path = data[0].split()[1].replace('http://', '')
            if(path[len(path) - 1] == '/'):
                path = path[:-1]
            
            #see if it's cached
            try:
                cachePath = 'cachefile' + base64.urlsafe_b64encode(path.encode()).decode()
                with open(cachePath, 'rb') as file:
                    cachedData = file.read()
                print("cache found")
                tcpSocket.sendall(cachedData)
            except:
                print("cache not found")
                #get address
                hostnameIP = socket.gethostbyname(path)
                #new connection
                proxySock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                address = (hostnameIP, 80)
                proxySock.connect(address)
                #forward the request
                encodeData = dataRecv.encode()
                proxySock.sendall(encodeData)
                #receive from server
                
                #loop to get things from a large receive
                serverData = b''
                while True:
                    tempData = select.select([proxySock], [], [], 0.5)
                    if(tempData[0] == []):
                        break
                    else:
                        tempserverData = proxySock.recv(4096)
                    serverData += tempserverData
                
                #send back to client
                tcpSocket.sendall(serverData)

                #add to cache
                cachePath = 'cachefile' + base64.urlsafe_b64encode(path.encode()).decode()
                with open(cachePath, 'wb') as file:
                    file.write(serverData)

                
        else: 
            print("not GET request")
            hostnameIP = socket.gethostbyname(path)
            #new connection
            proxySock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            address = (hostnameIP, 80)
            proxySock.connect(address)
            #forward the request
            encodeData = dataRecv.encode()
            proxySock.sendall(encodeData)
            #receive from server                
            #loop to get things from a large receive
            serverData = b''
            while True:
                tempData = select.select([proxySock], [], [], 0.5)
                if(tempData[0] == []):
                    break
                else:
                    tempserverData = proxySock.recv(4096)
                serverData += tempserverData

            #send back to client
            tcpSocket.sendall(serverData)
            
        print(dataRecv)
        pass

    def __init__(self, args):
        print('Web Proxy starting on port: %i...' % (args.port))
        try:            
            # 1. Create server socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # 2. Bind the server socket to server address and server port
            sock.bind(("127.0.0.1", args.port))
            # 3. Continuously listen for connections to server socket
            while True:
                sock.listen()
                # 4. When a connection is accepted, call handleRequest function, passing new connection socket (see https://docs.python.org/3/library/socket.html#socket.socket.accept)
                try:
                    newSock, address = sock.accept()
                    self.handleRequest(newSock)
                except:
                    sock.close()
                # 5. Close server socket
        except:
            sock.close()



if __name__ == "__main__":
    args = setupArgumentParser()
    args.func(args)
