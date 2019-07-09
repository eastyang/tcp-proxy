#!/bin/python

import sys
import socket
import threading

def server_loop(local_host,local_port,remote_host,remote_port,receive_first):
    server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    try:
        server.bind((local_host,local_port))
    except:
        print "[!!] Failed to listen on %s:%d" % (local_host,local_port)
        print "[!!] Check for other listening sockets or correct permissions."
        sys.exit(0)
    
    print "[*] Listening on %s:%d" % (local_host,local_port)
    server.listen(5)
    while True:
        try:
            client_socket, addr = server.accept()
        except:
            print " Tcp_proxy.py exit!!"
            sys.exit(1)
        
        # print output local connection information
        print "[==>] Received incoming connection from %s:%d" % (addr[0], addr[1])
        # start up a thread to communicate with the process host
        proxy_thread = threading.Thread(target=proxy_handler, args=(client_socket,remote_host,remote_port,receive_first))
        proxy_thread.start()

def main():
    
    if len(sys.argv[1:]) != 5:
        print "Usage: ./tcp_proxy [localhost] [localport] [remotehost] [remoteport] [recerve_first]"
        print "Example: ./tcp_proxy 127.0.0.1 9000 10.12.132.1 9000 True"
        sys.exit(0)
        
    # setting local listening parameters
    local_host = sys.argv[1]
    local_port = int(sys.argv[2])
    
    # setting Remote Targets
    remote_host = sys.argv[3]
    remote_port = int(sys.argv[4])
    
    # tell the proxy to connect and receive data before sending it to the remote host
    receive_first = sys.argv[5]
    
    if "True" in receive_first:
        receive_first = True
    else:
        receive_first = False
    
    # setting monitor socker
    server_loop(local_host, local_port, remote_host, remote_port, receive_first)
    
def proxy_handler(client_socket, remote_host, remote_port, receive_first):
    
    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote_socket.connect((remote_host,remote_port))
    
    # if recerve_first is true, first receive data from a remote host
    if receive_first:
        remote_buffer = receive_from(remote_socket)
        hexdump(remote_buffer)
        
        # response processing sent to us
        remote_buffer = response_handler(remote_buffer)
        
        # if we have data that needs to be sent back to the local client, send it
        if len(remote_buffer):
            print "[<==] Sending %d bytes to localhost." % len(remote_buffer)
            client_socket.send(remote_buffer)
        
    # read data from local loops and send it to remote hosts and local hosts
    while True:
        local_buffer = receive_from(client_socket)     
        if len(local_buffer):
            print "[==>] Received %d bytes from localhost." % len(local_buffer)
            hexdump(local_buffer)
            # sent to us to request processing
            local_buffer = request_handler(local_buffer)
                
            # send data to remote host
            remote_socket.send(local_buffer)
            print "[==>] Sent to remote."
                
        remote_buffer = receive_from(remote_socket)
        if len(remote_buffer):
            print "[<==] Reveived %d bytes from remote." % len(remote_buffer)
            hexdump(remote_buffer)
            # send to response handler
            remote_buffer = response_handler(remote_buffer)
                
            client_socket.send(remote_buffer)
            print "[<==] Sent to localhost."
                
        if not len(local_buffer) or not len(remote_buffer):
            client_socket.close()
            remote_socket.close()
            print "[*] No more data. Closing connections."
            break
            

def hexdump(src,length=16):
    result = []
    digits = 4 if isinstance(src, unicode) else 2
    
    for i in xrange(0, len(src), length):
        s = src[i:i+length]
        hexa = b' '.join(["%0*X" % (digits, ord(x)) for x in s])
        text = b' '.join([x if 0x20 <= ord(x) < 0x7F else b'.' for x in s])
        result.append(b"%04X %-*s  %s" % (i, length*(digits + 1), hexa, text))
    print b'\n'.join(result)
    

def receive_from(connection):
    buffer = ""
    connection.settimeout(2)
    
    try:
        while True:
            data = connection.recv(4096)
            if not data:
                break
            buffer += data
    except:
        pass
    return buffer

def request_handler(buffer):
    return buffer

def response_handler(buffer):
    return buffer

main()
     
            


        
        





