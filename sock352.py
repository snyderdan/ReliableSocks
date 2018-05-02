# sock352.py

# (C) 2018 by R. P. Martin, under the GPL license, version 2.

# this is the skeleton code that defines the methods for the sock352 socket library,
# which implements a reliable, ordered packet stream using go-back-N.
#
# Note that simultaneous close() is required, does not support half-open connections ---
# that is outstanding data if one side closes a connection and continues to send data,
# or if one side does not close a connection the protocol will fail.
import heapq
import socket as ip
import random
import binascii
import threading
import time
import struct as st

# The first byte of every packet must have this value
from collections import deque

MESSAGE_TYPE = 0x44

# this defines the sock352 packet format.
# ! = big endian, b = byte, L = long, H = half word
HEADER_FMT = '!bbLLH'

# this are the flags for the packet header
SYN = 0x01  # synchronize
ACK = 0x02  # ACK is valid
DATA = 0x04  # Data is valid
FIN = 0x08  # FIN = remote side called close

# max size of the data payload is 63 KB
MAX_SIZE = (63 * 1024)

# max size of the packet with the headers
MAX_PKT = ((16 + 16 + 16) + (MAX_SIZE))

# these are the socket states
STATE_INIT = 1
STATE_SYNSENT = 2
STATE_LISTEN = 3
STATE_SYNRECV = 4
STATE_ESTABLISHED = 5
STATE_CLOSING = 6
STATE_CLOSED = 7
STATE_REMOTE_CLOSED = 8


# function to print. Higher debug levels are more detail
# highly recommended
def dbg_print(level, string):
    global sock352_dbg_level
    if sock352_dbg_level >= level:
        print(string)

# this is the thread object that re-transmits the packets
class sock352Thread(threading.Thread):
    def __init__(self, threadID, name, delay):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.delay = float(delay)

    def run(self):
        dbg_print(3, ("sock352: timeout thread starting %s delay %.3f " % (self.name, self.delay)))
        scan_for_timeouts(self.delay)
        dbg_print(3, ("sock352: timeout thread %s Exiting " % (self.name)))
        return

        # Example timeout thread function


# every <delay> seconds it wakes up and re-transmits packets that
# have been sent, but not received. A received packet with a matching ack
# is removed from the list of outstanding packets.

def scan_for_timeouts(delay):
    global list_of_outstanding_packets

    time.sleep(delay)

    # there is a global socket list, although only 1 socket is supported for now
    while (True):

        time.sleep(delay)
        # example
        for packet in list_of_outstanding_packets:

            current_time = time.time()
            time_diff = float(current_time) - float(packet.time_sent)

            dbg_print(5, "sock352: packet timeout diff %.3f %f %f " % (time_diff, current_time, skbuf.time_sent))
            if (time_diff > delay):
                dbg_print(3, "sock352: packet timeout, retransmitting")
                # your transmit code here ...


    return


# This class holds the data of a packet gets sent over the channel
#
class Packet:
    def __init__(self):
        self.sender = None
        self.type = MESSAGE_TYPE  # ID of sock352 packet
        self.cntl = 0  # control bits/flags
        self.seq = 0  # sequence number
        self.ack = 0  # acknowledgement number
        self.size = 0  # size of the data payload
        self.data = b''  # data

    # unpack a binary byte array into the Python fields of the packet
    def unpack(self, bytes):
        # check that the data length is at least the size of a packet header
        data_len = (len(bytes) - st.calcsize('!bbLLH'))
        if data_len >= 0:
            new_format = HEADER_FMT + str(data_len) + 's'
            values = st.unpack(new_format, bytes)
            self.type = values[0]
            self.cntl = values[1]
            self.seq = values[2]
            self.ack = values[3]
            self.size = values[4]
            self.data = values[5]
            # you dont have to have to implement the the dbg_print function, but its highly recommended
            dbg_print(1, ("sock352: unpacked:0x%x cntl:0x%x seq:0x%x ack:0x%x size:0x%x data:x%s" % (
            self.type, self.cntl, self.seq, self.ack, self.size, binascii.hexlify(self.data))))
        else:
            dbg_print(2, (
            "sock352 error: bytes to packet unpacker are too short len %d %d " % (len(bytes), st.calcsize('!bbLLH'))))

        return

    # returns a byte array from the Python fields in a packet
    def pack(self):
        if (self.data == None):
            data_len = 0
        else:
            data_len = len(self.data)
        if (data_len == 0):
            bytes = st.pack('!bbLLH', self.type, self.cntl, self.seq, self.ack, self.size)
        else:
            new_format = HEADER_FMT + str(data_len) + 's'  # create a new string '!bbLLH30s'
            dbg_print(5, (
            "cs352 pack: %d %d %d %d %d %s " % (self.type, self.cntl, self.seq, self.ack, self.size, self.data)))
            bytes = st.pack(new_format, self.type, self.cntl, self.seq, self.ack, self.size, self.data)
        return bytes

    # this converts the fields in the packet into hexadecimal numbers
    def toHexFields(self):
        if (self.data == None):
            retstr = (
            "type:x%x cntl:x%x seq:x%x ack:x%x sizex:%x" % (self.type, self.cntl, self.seq, self.ack, self.size))
        else:
            retstr = ("type:x%x cntl:x%x seq:x%x ack:x%x size:x%x data:x%s" % (
            self.type, self.cntl, self.seq, self.ack, self.size, binascii.hexlify(self.data)))
        return retstr

    # this converts the whole packet into a single hexidecimal byte string (one hex digit per byte)
    def toHex(self):
        if (self.data == None):
            retstr = ("%x%x%x%xx%x" % (self.type, self.cntl, self.seq, self.ack, self.size))
        else:
            retstr = (
            "%x%x%x%x%xx%s" % (self.type, self.cntl, self.seq, self.ack, self.size, binascii.hexlify(self.data)))
        return retstr

    def __cmp__(self, other):
        return cmp(self.seq, other.seq)


class Receiver(threading.Thread):
    """This class handles receiving all packets, sending ACKs back, and handling FIN packets"""
    def __init__(self, connection, outstanding):
        threading.Thread.__init__(self)
        self.daemon = True
        self.packet_queue = []
        self.data_buffer = deque()
        self.data_buffer_lock = threading.Lock()
        self.connection = connection
        self.next_seq = 0
        self.running = False
        self.outstanding = outstanding

    def get_data(self, nbytes):
        while len(self.data_buffer) == 0:
            # sleep while we wait for data to fill buffer
            pass

        dbg_print(10, "full buffer: %s" % str(self.data_buffer))
        data = self.data_buffer.popleft()
        if len(data) > nbytes:
            data, remaining = data[:nbytes], data[nbytes:]
            self.data_buffer.appendleft(remaining)
            dbg_print(10, "returning data: %s" % data)
        return data

    def stop(self):
        while len(self.outstanding) > 0:
            pass
        self.running = False

    def run(self):
        self.running = True
        while self.running:
            raw_data, address = self.connection.recvfrom(MAX_PKT)
            packet = Packet()
            packet.sender = address
            packet.unpack(raw_data)
            dbg_print(10, "Got %d" % packet.seq)
            # if the packet is an ACK
            if packet.cntl == ACK:
                # remove the outstanding packet from the outstanding set
                self.outstanding.remove(packet.ack)
            # if it's a FIN packet
            elif packet.cntl & FIN == FIN:
                pass
            # must be a DATA packet
            else:
                dbg_print(10, "Got data in packet: %s" % packet.data)
                # push packet onto heap
                heapq.heappush(self.packet_queue, packet)
                # send ack packet for the received packet
                ackpack = Packet()
                ackpack.cntl = ACK
                ackpack.ack = packet.seq
                self.connection.sendto(ackpack.pack(), address)

            # go through packet queue
            while len(self.packet_queue) > 0 and self.packet_queue[0].seq == self.next_seq:
                # if the next sequential packet is available, add it's data to the data buffer
                packet = heapq.heappop(self.packet_queue)
                self.data_buffer.append(packet.data)
                self.next_seq += 1



        # the main socket class
# you must fill in all the methods
# it must work against the class client and servers
# with various drop rates

class Socket:
    def __init__(self):
        # ... your code here ...
        self.socket = None
        self.debug_level = 0
        self.drop_prob = 0
        self.target_address = None
        self.outstanding = set()
        self.sequence = random.randint(0, 10000)
        self.seed = None
        self.receiver = None

    #
    # 0 == no debugging, greater numbers are more detail.
    # You do not need to implement the body of this method,
    # but it must be in the library.
    def set_debug_level(self, level):
        self.debug_level = level

        # Set the % likelihood to drop a packet

    #
    # you do not need to implement the body of this method,
    # but it must be in the library,
    def set_drop_prob(self, probability):
        self.drop_prob = probability

        # Set the seed for the random number generator to get

    # a consistent set of random numbers
    #
    # You do not need to implement the body of this method,
    # but it must be in the library.
    def set_random_seed(self, seed):
        self.seed = seed
        random.seed(seed)

    def bind(self, address):
        # AF_INET is for internet, and SOCK_DGRAM indicates UDP
        self.socket = ip.socket(ip.AF_INET, ip.SOCK_DGRAM)
        self.receiver = Receiver(self.socket, self.outstanding)
        self.socket.bind(address)

    # You must implement this method
    def connect(self, address):
        self.target_address = address
        self.socket = ip.socket(ip.AF_INET, ip.SOCK_DGRAM)
        syncpack = Packet()
        syncpack.cntl = SYN
        syncpack.seq = self.sequence
        self.socket.sendto(syncpack.pack(), address)
        self.sequence += 1
        # now we must wait for a response
        raw_data, address = self.socket.recvfrom(MAX_PKT)
        packet = Packet()
        packet.sender = address
        packet.unpack(raw_data)
        if packet.cntl != (SYN | ACK):
            raise RuntimeError("Did not receive an acknowledgement to SYNC packet")

        self.receiver = Receiver(self.socket, self.outstanding)
        self.receiver.next_seq = packet.seq + 1
        self.receiver.start()

    def accept(self):
        # do some nonsense to get the address, then start the receiver
        raw_data, address = self.socket.recvfrom(MAX_PKT)
        self.target_address = address
        packet = Packet()
        packet.sender = address
        packet.unpack(raw_data)
        if packet.cntl != SYN:
            raise RuntimeError("Did not receive SYN packet upon opening connection")

        # received sync, acknowledge and respond
        ackpack = Packet()
        ackpack.cntl = ACK | SYN
        ackpack.seq = self.sequence
        ackpack.ack = packet.seq
        self.socket.sendto(ackpack.pack(), self.target_address)
        # start receiver now that we have an address and a sequence number to start
        self.sequence += 1
        self.receiver.next_seq = packet.seq + 1
        self.receiver.start()
        return address

        # send a message up to MAX_DATA

    # You must implement this method
    def sendto(self, buffer):
        # so...what if no one implements dropping packets?
        # read: someone's not going to implement dropping packets
        if random.random() > self.drop_prob:
            packet = Packet()
            packet.cntl = DATA
            packet.seq = self.sequence
            packet.data = buffer
            self.sequence += 1
            self.outstanding.add(packet.seq)
            dbg_print(10, "Sending %d" % packet.seq)
            self.socket.sendto(packet.pack(), self.target_address)

        # receive a message up to MAX_DATA

    # You must implement this method
    def recvfrom(self, nbytes):
        return self.receiver.get_data(nbytes)

    # close the socket and make sure all outstanding
    # data is delivered
    # You must implement this method
    def close(self):
        self.receiver.stop()
        self.socket.close()


# Example how to start a start the timeout thread
sock352_dbg_level = 0
#
# dbg_print(3, "starting timeout thread")
#
# # create the thread
# thread1 = sock352Thread(1, "Thread-1", 0.25)
#
# # you must make it a daemon thread so that the thread will
# # exit when the main thread does.
# thread1.daemon = True
#
# # run the thread
# thread1.start()

