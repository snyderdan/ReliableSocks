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


# This class holds the data of a packet gets sent over the channel
#
class Packet:
    def __init__(self):
        self.sender = None
        self.time_sent = None
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

    def __hash__(self):
        return hash(self.seq)

    def __cmp__(self, other):
        if isinstance(other, Packet):
            return cmp(self.seq, other.seq)
        elif isinstance(other, int):
            return cmp(self.seq, other)
        else:
            raise RuntimeError("Invalid type '%s' to compare to Packet" % str(type(other)))


outstanding_lock = threading.Lock()


class Receiver(threading.Thread):
    """This class handles receiving all packets, handling ACKs, sending ACKs,
    and passing data and FIN packets to the socket class."""
    def __init__(self, connection, outstanding, timediffs, dropprob):
        threading.Thread.__init__(self)
        self.daemon = True
        self.packet_queue = []
        self.connection = connection
        self.next_seq = 0
        self.running = False
        self.outstanding = outstanding
        self.timediffs = timediffs
        self.dropprob = dropprob

    def get_packet(self):
        while len(self.packet_queue) == 0 or self.packet_queue[0].seq != self.next_seq:
            # wait for next packet in sequence
            pass
        # return most recent packet
        self.next_seq += 1
        return heapq.heappop(self.packet_queue)

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
                # remove the outstanding packet from outstanding and log time to acknowledgement
                outstanding_lock.acquire()
                try:
                    acked = self.outstanding.pop(packet.ack)
                    self.timediffs.append(time.clock() - acked.time_sent)
                except Exception:
                    # do nothing if we already got an ACK for this packet
                    pass
                outstanding_lock.release()
            # must be a DATA or FIN packet -- processed by socket
            else:
                if packet.cntl == DATA:
                    dbg_print(10, "Got data in packet: %s" % packet.data)
                if packet.seq >= self.next_seq:
                    # push packet onto heap unless we have already processed the packet
                    heapq.heappush(self.packet_queue, packet)
                else:
                    print("Already saw: %d" % packet.seq)

                # send ack packet for the received packet, even if we've seen it already
                # they may not have gotten the last ACK for it.
                if random.random() > self.dropprob:
                    ackpack = Packet()
                    ackpack.cntl = ACK
                    ackpack.ack = packet.seq
                    self.connection.sendto(ackpack.pack(), address)


class Retransmitter(threading.Thread):
    def __init__(self, connection, outstanding, timediffs, dropprob, address):
        threading.Thread.__init__(self)
        self.daemon = True
        self.connection = connection
        self.outstanding = outstanding
        self.timediffs = timediffs
        self.dropprob = dropprob
        self.running = False
        self.address = address

    def stop(self):
        self.running = False

    def run(self):
        self.running = True
        while self.running:
            # run every 20ms
            time.sleep(0.02)
            cnt = len(self.timediffs)
            if cnt == 0:
                continue

            avg = sum(self.timediffs[:cnt]) / cnt
            outstanding_lock.acquire()
            for pkt in self.outstanding.values():
                if (time.clock() - pkt.time_sent) > 10 * avg:
                    # resend packet if it's 10 times above average for ACKs
                    pkt.time_sent = time.clock()
                    print("sending %d again to %s" % (pkt.seq, str(self.address)))
                    self.connection.sendto(pkt.pack(), self.address)
            outstanding_lock.release()


class Socket:
    def __init__(self):
        # ... your code here ...
        self.socket = None
        self.debug_level = 0
        self.drop_prob = 0
        self.target_address = None
        self.outstanding = dict()
        self.timediffs = []
        self.data_buffer = ""
        self.sequence = random.randint(0, 10000)
        self.seed = None
        self.receiver = None
        self.retransmitter = None

    def next_sequence(self):
        self.sequence += 1
        return self.sequence

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
        self.receiver = Receiver(self.socket, self.outstanding, self.timediffs, self.drop_prob)
        # bind to address
        self.socket.bind(address)

    def connect(self, address):
        # create socket
        self.target_address = address
        self.socket = ip.socket(ip.AF_INET, ip.SOCK_DGRAM)
        # create SYNC packet to send to server
        syncpack = Packet()
        syncpack.cntl = SYN
        syncpack.seq = self.next_sequence()
        # send packet
        self.socket.sendto(syncpack.pack(), address)
        # now we must wait for a SYNC ACK response
        raw_data, address = self.socket.recvfrom(MAX_PKT)
        # read packet received
        packet = Packet()
        packet.sender = address
        packet.unpack(raw_data)

        if packet.cntl != (SYN | ACK) or packet.ack != syncpack.seq:
            # raise an error if the server did not accept our sync
            raise RuntimeError("Did not receive an acknowledgement to SYNC packet")
        # start receiver thread with sequence number
        self.receiver = Receiver(self.socket, self.outstanding, self.timediffs, self.drop_prob)
        self.retransmitter = Retransmitter(self.socket, self.outstanding, self.timediffs, self.drop_prob,
                                           self.target_address)
        self.receiver.next_seq = packet.seq + 1
        self.receiver.start()
        self.retransmitter.start()

    def accept(self):
        # wait for SYNC packet
        raw_data, address = self.socket.recvfrom(MAX_PKT)
        self.target_address = address
        # parse packet
        packet = Packet()
        packet.sender = address
        packet.unpack(raw_data)
        if packet.cntl != SYN:
            # raise error if it is not a sync packet
            raise RuntimeError("Did not receive SYN packet upon opening connection")

        # received sync, acknowledge and respond
        ackpack = Packet()
        ackpack.cntl = ACK | SYN
        ackpack.seq = self.next_sequence()
        ackpack.ack = packet.seq
        # send ACK SYNC packet
        self.socket.sendto(ackpack.pack(), self.target_address)
        self.retransmitter = Retransmitter(self.socket, self.outstanding, self.timediffs, self.drop_prob,
                                           self.target_address)
        # start receiver now that we have an address and a sequence number to start
        self.receiver.next_seq = packet.seq + 1
        self.receiver.start()
        self.retransmitter.start()
        return address

        # send a message up to MAX_DATA

    # You must implement this method
    def sendto(self, buffer):
        # create packet to send
        packet = Packet()
        packet.cntl = DATA
        packet.seq = self.next_sequence()
        packet.data = buffer
        packet.time_sent = time.clock()
        # add it to the outstanding set
        self.outstanding[packet.seq] = packet
        # so...what if no one implements dropping packets?
        if random.random() > self.drop_prob:
            dbg_print(10, "Sending %d" % packet.seq)
            # actually send packet
            self.socket.sendto(packet.pack(), self.target_address)

    def recvfrom(self, nbytes):
        if len(self.data_buffer):
            data = self.data_buffer
            if len(self.data_buffer) > nbytes:
                data = data[:nbytes]
                self.data_buffer = data[nbytes:]
            else:
                self.data_buffer = ""
            return data
        else:
            packet = self.receiver.get_packet()
            if packet.cntl == DATA:
                data = packet.data
                if len(data) > nbytes:
                    data, remaining = data[:nbytes], data[nbytes:]
                    self.data_buffer += remaining
                return data
            elif packet.cntl == FIN:
                pass
            else:
                raise RuntimeError("Bad packet control byte: 0x%X" % packet.cntl)


    # close the socket and make sure all outstanding
    # data is delivered
    # You must implement this method
    def close(self):
        self.receiver.stop()
        self.retransmitter.stop()
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

