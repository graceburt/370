from socket import *
import os
import sys
import struct
import time
import select
import binascii
ICMP_ECHO_REQUEST = 8

def checksum(str_):
    # In this function we make the checksum of our packet 
        #checksum is a digit representing the sum of the correct digits in a piece of stored or transmitted digital data, against which later comparisons can be made to detect errors in the data.
    
    str_ = bytearray(str_) #returns an array of bytes of the given size and initialization values 0 <= x < 256
    
    csum = 0
    countTo = (len(str_) // 2) * 2 

    for count in range(0, countTo, 2):
        thisVal = str_[count+1] * 256 + str_[count] #thisVal covers (iteration list array of bytes + 1 * 256) + iteration of list of array of bytes
        csum = csum + thisVal #creates csum using the iteration + current csum value (begins at 0)
        csum = csum & 0xffffffff #checking for overflow & if positive using '0xffffffff'

    if countTo < len(str_): #if length is less than length of array of bytes
        csum = csum + str_[-1] #setting csum to csum + bytearray at position -1 - the last element in the list
        csum = csum & 0xffffffff #checking for overflow & if positive using '0xffffffff'

    csum = (csum >> 16) + (csum & 0xffff) #shifts csum over to the right by 16 places and checks for overflow & positivity
    csum = csum + (csum >> 16) #adds csum from above to (csum from above shifted another 16 places)
    answer = ~csum #inverts csum
    answer = answer & 0xffff #checks for overflow & positivity
    answer = answer >> 8 | (answer << 8 & 0xff00) #shifts over right 8 bits OR shifts left 8 places and checks for overflow
    return answer

def receiveOnePing(mySocket, ID, timeout, destAddr):
    timeLeft = timeout #total time left before timeout
    while 1: #while true
        startedSelect = time.time() #marks start time, returns time in seconds (float)
        whatReady = select.select([mySocket], [], [], timeLeft) #3 params are 'waitable objs' 
        #.select() - rlist waits until ready for reading, wlist wait until ready for writing, xlist waits for 'exceptional condition', timeout is final param
        howLongInSelect = (time.time() - startedSelect) #how long wait til select
        if whatReady[0] == []: # Timeout 
            return "Request timed out."

        timeReceived = time.time() #time ping is recieved
        recPacket, addr = mySocket.recvfrom(1024) #recieves data from socket, return value is pair (bytes, address) where bytes represent datar recieved & add is add of socket sending data

        icmpHeader = recPacket[20:28] #header is bytes recieved from socket from position 20 - 28
        icmpType, code, mychecksum, packetID, sequence = struct.unpack("bbHHh", icmpHeader) #unpacks buffer (second param) according to str format (first param) returns tuple even if it contanis only 1 item - buffer's size in bytes must match the sze required by format
    
        if type != 8 and packetID == ID: #uses the function type() to return val of type obj & if packetId (returned id) is the same as the one we sent (ID)
            bytesInDouble = struct.calcsize("d") #returns size of the struct corresponds to format string (listed in param)
            timeSent = struct.unpack("d", recPacket[28:28 + bytesInDouble])[0] #unpacks buffer of recieved packet by format 'd', starts from position 28 on packet + size of struct ^^ @ list size 0
            return timeReceived - timeSent #returns time that has passed from sending - recieving 

        timeLeft = timeLeft - howLongInSelect #returns leftover time, if any
        
        if timeLeft <= 0:
            return "Request timed out."

def sendOnePing(mySocket, destAddr, ID):
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)

    myChecksum = 0
    # Make a dummy header with a 0 checksum.
    # struct -- Interpret strings as packed binary data
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    data = struct.pack("d", time.time())
    # Calculate the checksum on the data and the dummy header.
    myChecksum = checksum(header + data)

    # Get the right checksum, and put in the header
    if sys.platform == 'darwin':
        myChecksum = htons(myChecksum) & 0xffff # HTONS needs updating
    #Convert 16-bit integers from host to network byte order.
    else:
        myChecksum = htons(myChecksum) # HTONS needs updating

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    packet = header + data
    mySocket.sendto(packet, (destAddr, 1)) # AF_INET address must be tuple, not str
    #Both LISTS and TUPLES consist of a number of objects
    #which can be referenced by their position number within the object

def doOnePing(destAddr, timeout):         
    icmp = getprotobyname("icmp") 
    #Create Socket here
    mySocket = socket(AF_INET, SOCK_DGRAM, icmp) 

    myID = os.getpid() & 0xFFFF  #Return the current process i     
    sendOnePing(mySocket, destAddr, myID) 
    delay = receiveOnePing(mySocket, myID, timeout, destAddr)          

    mySocket.close()         
    return delay  

def ping(host, timeout=1):
    dest = gethostbyname(host) #names host destination
    print ("Pinging " + dest + " using Python:")
    print ("")
    #Send ping requests to a server separated by approximately one second
    while 1 :
        delay = doOnePing(dest, timeout)
        print (delay)
        time.sleep(1)# one second
    return delay

ping("127.0.0.1")