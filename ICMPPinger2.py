import os       # Needed for process ID
import sys      # Needed to check if sys.platform is darwin (kernel)
import struct   # Needed to unpack the struct that is the receieved packet
import time     # Needed for timing RTT
import select   # Needed for monitoring sockets
import socket   # Used for manipulating the socket
import argparse #used for handling arguments
ICMP_ECHO_REQUEST_RATE = 8      # Type must be set to 0
ap = argparse.ArgumentParser()
ap.add_argument("-d", "--destination",default="127.0.0.1"
 ,required=False,
	help="address that will be pinged")
ap.add_argument("-n", "--number",default=256
 ,required=False,
	help="number of ICMP pings that will be sent")
args = vars(ap.parse_args())
# This function returns the time delay between sending and receiving a single ping.
def perform_one_ping(destination_add, timeout):
    icmp_ping = socket.getprotobyname("icmp")                               # Translates protocol name into a constant to be passed as an (optional) argument to the socket function
    mySocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp_ping)    # Creates a new socket (family = AF_INET, socket type = raw, protocol number = icmp_ping)
    myID = os.getpid() & 0xFFFF                                             # Get the process id
    sendsingle_icmpping(mySocket, destination_add, myID)                        # Calls function to send a single ping
    delay = receivesingle_icmpping(mySocket, myID, timeout, destination_add)    # Calls function to receive a single ping (delay hold, # of bits, time, etc.)
    mySocket.close()           # Closes the socket
    return delay               # Returns the delay struct with data from the sent/received ping

# This function receives a single ping.
def receivesingle_icmpping(mySocket, ID, timeout, destAddr):
    global roundTrip_min, roundTrip_max, roundTrip_sum, roundTrip_cnt           # Variables to keep track of RTT and and number of trips
    timeRemain = timeout                                                        # Time remaining to receive packet
    while 1:                                                    # Loops until out of time
        startedSelect = time.time()                             # Get start time to receive ping
        arr = select.select([mySocket], [], [], timeRemain)     # Interface system call, waits until ready for reading, and gets timeout, returns a triple of list objects
        howLongInSelect = (time.time() - startedSelect)         # Gets total time it took to receive ping
        if arr[0] == []:                                        # Checks if the returned array is empty, it will be empty if the timeout was reached
            return "Request timed out."                         # Print message indicating it took too long
        timeReceived = time.time()                              # Gets the time that the ping is received
        received_Packet, addr = mySocket.recvfrom(1024)                                     # Bits from socket are stored in received_Packet, and the address of the socket stored in addr
        type, code, checksum, id, seq = struct.unpack('bbHHh', received_Packet[20:28])      # Unpack the struct from the packet, "bbHHh" is the variable type for each, ex: b = unsigned char, H = unsigned short, h = short
        if type != 0:                                                       # Type should be 0
            return 'expected type=0, but got {}'.format(type)
        if code != 0:                                                       # Code should be 0
            return 'expected code=0, but got {}'.format(code)
        if ID != id:                                                        # If the IDs do not match
            return 'expected id={}, but got {}'.format(ID, id)
        trans_time, = struct.unpack('d', received_Packet[28:])              # Gets the time the ping was sent
        roundTrip = (timeReceived - trans_time) * 1000                      # Calculates round trip time
        roundTrip_cnt += 1                                                  # Increase number of trips by 1
        roundTrip_sum += roundTrip                                          # Adds current RTT to sum
        roundTrip_min = min(roundTrip_min, roundTrip)                       # Gets the current minimum round trip time
        roundTrip_max = max(roundTrip_max, roundTrip)                       # Gets the current minimum round trip time
        ip_pkt_head = struct.unpack('!BBHHHBBH4s4s', received_Packet[:20])  # Unpacks the first 20 bits
        ttl = ip_pkt_head[5]                                                # Gets time to live of request
        saddr = socket.inet_ntoa(ip_pkt_head[8])                            # Gets the socket address
        length = len(received_Packet) - 20                                  # Gets the length of packet (not including time bits)
        return '{} bytes from {}: icmp_seq={} ttl={} time={:.3f} ms'.format(length, saddr, seq, ttl, roundTrip)     # Returns multiple variables
        timeRemain = timeRemain - howLongInSelect       # Gets the time remaining
        if timeRemain <= 0:                             # If the time reaches 0 it has taken too long
            return "Request timed out."


# The checksum function used to evaluate the checksum.
# The answer of the checksum calculation is returned.
def checksum(str):
    count_sum = 0                           # Set count sum to 0
    countTo = (len(str) / 2) * 2            # Get length in bits
    count = 0
    while count < countTo:      # While there are still bits to go through
        thisVal = str[count + 1] * 256 + str[count]          # Returns the current bit, Ord returns an integer that represents the unicode symbol
        count_sum = count_sum + thisVal                                 # Adds bit to the count sum
        count_sum = count_sum & 0xffffffff                              # Bitwise and operation to check for overflow
        count = count + 2                                               # Move to next bit
    if countTo < len(str):                                  # If more bits in the string
        count_sum = count_sum + str[len(str) - 1]      # Add the last bit
        count_sum = count_sum & 0xffffffff                  # Bitwise and operation to check for overflow
    count_sum = (count_sum >> 16) + (count_sum & 0xffff)    # Shifts the bits right 16 places and check for overflow
    count_sum = count_sum + (count_sum >> 16)               # Add to count sum and count sum shifted 16 right
    calc = ~count_sum                                       # Returns the complement of count sum
    calc = calc & 0xffff                                    # Check overflow and sign again
    calc = calc >> 8 | (calc << 8 & 0xff00)                 # Does a bitwise or on the first and last 8 bits?
    return calc                                     # Return count checkSum


# This function sends a single ping.
def sendsingle_icmpping(mySocket, destination_add, ID):
    count_checksum = 0
    pkt_head = struct.pack("bbHHh", ICMP_ECHO_REQUEST_RATE, 0, count_checksum, ID, 1)       # Pack the struct that is the packet head
    data = struct.pack("d", time.time())                                                    # Pack the time into a struct
    count_checksum = checksum(pkt_head + data)                                              # Get the checksum
    if sys.platform == 'darwin':            # Check the platform of the system (like the kernel)
        count_checksum = socket.htons(count_checksum) & 0xffff          # Convert 16-bit positive integers from host to network byte order with and get last 8 bits
    else:
        count_checksum = socket.htons(count_checksum)                   # Convert 16-bit positive integers from host to network byte order
    pkt_head = struct.pack("bbHHh", ICMP_ECHO_REQUEST_RATE, 0, count_checksum, ID, 1)       # Pack the struct with the new checksum
    packet = pkt_head + data                                                                # Add bits to form packet
    mySocket.sendto(packet, (destination_add, 1))                                           # Send the packet to destination




# This function displays the ping statistics.
def icmp_ping(host, timeout=1):
    global roundTrip_min, roundTrip_max, roundTrip_sum, roundTrip_cnt           # Define RTT variables
    roundTrip_min = float('+inf')       # Sets min to negative infinity
    roundTrip_max = float('-inf')       # Sets max to positive infinity
    roundTrip_sum = 0
    roundTrip_cnt = 0
    count = 0
    dest = socket.gethostbyname(host)               # Sets destination to the host name
    print("Pinging " + dest + " using Python:")     # Print statement indicating destination of ping
    for i in range (0,int(args["number"])):
        count += 1
        # calls function to send ping
        print (perform_one_ping(dest, timeout))
        time.sleep(1)                           # Wait one second
    # Stops when the user hits the interrupt key
    if count != 0:
        # Print and format statistics
        print '--- {} ping statistics ---'.format(host)
        print '{} packets transmitted, {} packets received, {:.1f}% packet loss'.format(count, roundTrip_cnt,
                                                                                        100.0 - roundTrip_cnt * 100.0 / count)
        if roundTrip_cnt != 0:
            print 'round-trip min/avg/max {:.3f}/{:.3f}/{:.3f} ms'.format(roundTrip_min, roundTrip_sum / roundTrip_cnt, roundTrip_max)

icmp_ping(args["destination"])         # Calls ping routine with destination google
