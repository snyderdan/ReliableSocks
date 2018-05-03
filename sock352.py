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


class Average:
    def __init__(self):
        self.size = 20
        self.total = 0
        self.samples = deque()

    def adjust(self, time):
        if len(self.samples) == self.size:
            # if we are at capacity, remove top element
            self.total -= self.samples.popleft()
        # add current time, and add it to sample list
        self.total += time
        self.samples.append(time)

    def get(self):
        if len(self.samples) == 0:
            return 0
        return self.total / len(self.samples)


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
            dbg_print(10, ("sock352: unpacked:0x%x cntl:0x%x seq:0x%x ack:0x%x size:0x%x data:x%s" % (
                self.type, self.cntl, self.seq, self.ack, self.size, binascii.hexlify(self.data))))
        else:
            dbg_print(2, (
                "sock352 error: bytes to packet unpacker are too short len %d %d " % (
                len(bytes), st.calcsize('!bbLLH'))))

        return

    # returns a byte array from the Python fields in a packet
    def pack(self):
        if self.data is None:
            data_len = 0
        else:
            data_len = len(self.data)
            self.size = data_len

        dbg_print(10,
                  "cs352 pack: 0x%x cntl:0x%x seq:0x%x ack:0x%x size:0x%x data:x%s" %
                  (self.type, self.cntl, self.seq, self.ack, self.size, self.data))

        if data_len == 0:
            bytes = st.pack('!bbLLH', self.type, self.cntl, self.seq, self.ack, self.size)
        else:
            new_format = HEADER_FMT + str(data_len) + 's'  # create a new string '!bbLLH30s'
            bytes = st.pack(new_format, self.type, self.cntl, self.seq, self.ack, self.size, self.data)
        return bytes

    # this converts the fields in the packet into hexadecimal numbers
    def toHexFields(self):
        if self.data is None:
            retstr = (
                "type:x%x cntl:x%x seq:x%x ack:x%x sizex:%x" % (self.type, self.cntl, self.seq, self.ack, self.size))
        else:
            retstr = ("type:x%x cntl:x%x seq:x%x ack:x%x size:x%x data:x%s" % (
                self.type, self.cntl, self.seq, self.ack, self.size, binascii.hexlify(self.data)))
        return retstr

    # this converts the whole packet into a single hexidecimal byte string (one hex digit per byte)
    def toHex(self):
        if self.data is None:
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


class Transmitter:
    """Class responsible for sending packets.
       It sets the times and sequence numbers of packets.
       It also is responsible for dropping packets. ALL packets should transmit through here.
    """

    def __init__(self, target, socket):
        self.sequence = random.randrange(0, 100000)
        self.target = target
        self.socket = socket

    def next_sequence(self):
        self.sequence += 1
        return self.sequence

    def transmit(self, packet, dropprob=0):
        """Does actual sending of packet -- only modifies time sent"""
        packet.time_sent = time.clock()
        if random.random() > dropprob:
            dbg_print(9, "Sending seq: %x" % packet.seq)
            self.socket.sendto(packet.pack(), self.target)
        else:
            dbg_print(9, "Dropping seq: %x" % packet.seq)

    def send(self, packet, dropprob=0):
        packet.seq = self.next_sequence()
        self.transmit(packet, dropprob)


class Receiver(threading.Thread):
    """This class strictly receives packets and passes them to the Socket class for processing.
       ALL packets should be received via this class.
    """

    def __init__(self, owner_sock):
        threading.Thread.__init__(self)
        self.daemon = True
        self.running = False
        self.packet_queue = deque()
        self.connection = owner_sock.socket
        self.owner = owner_sock

    def stop(self):
        self.running = False

    def run(self):
        self.running = True
        while self.running:
            # read raw data
            raw_data, address = self.connection.recvfrom(MAX_PKT)
            # create packet object and add it to queue
            packet = Packet()
            packet.sender = address
            packet.unpack(raw_data)
            self.owner.process_packet(packet)


class Socket(threading.Thread):
    """Class provides reliable interface to UDP socket. The thread portion that is started
       upon connection is what provides reliability. The thread handles ACKs, sends ACKs,
       provides ordering to packets, and handles FIN packets"""

    def __init__(self):
        threading.Thread.__init__(self)
        self.daemon = True
        self.running = False
        self.drop_prob = 0
        self.debug_level = 0
        self.data_buffer = ""
        self.socket = None
        self.receiver = None
        self.transmitter = None
        self.outstanding = dict()
        self.packet_heap = list()
        self.next_sequential = 0
        self.received_seqs = set()
        self.finish_sequence = None
        self.avg_response = Average()

    def process_packet(self, packet):
        """Processes a received packet"""
        if packet.cntl & SYN == SYN:
            # if it's a sync packet, place it on the heap with no ACK
            heapq.heappush(self.packet_heap, packet)
            self.next_sequential = packet.seq

        elif packet.cntl == DATA:
            if packet.seq not in self.received_seqs:
                # if we have not received it before, add it to the heap
                heapq.heappush(self.packet_heap, packet)
            # add it to the list of received sequences
            self.received_seqs.add(packet.seq)
            # send ACK packet
            ackpack = Packet()
            ackpack.cntl = ACK
            ackpack.ack = packet.seq
            dbg_print(9, "Sending ack for %x" % packet.seq)
            self.transmitter.transmit(ackpack, self.drop_prob)

        elif packet.cntl == ACK:
            dbg_print(9, "Got ack %x" % packet.ack)
            dbg_print(9, self.outstanding)
            if packet.ack in self.outstanding:
                # if this is an ACK for an outstanding packet, remove the outstanding packet
                dbg_print(9, "Removing %x from outstanding" % packet.ack)
                pkt = self.outstanding.pop(packet.ack)
                self.avg_response.adjust(time.clock() - pkt.time_sent)
            self.received_seqs.add(packet.seq)

        elif packet.cntl & FIN == FIN:
            # we received a FIN -- stop running
            print("Got fin")
            self.finish_sequence = packet.seq
            self.running = False

        else:
            raise RuntimeError("Bad packet cntl field: 0x%x" % packet.cntl)

    def _handle_outstanding(self):
        average = self.avg_response.get()
        threshold = average * 10  # threshold is 10 times average
        if average == 0:
            # if there is no average, default to 500ms
            threshold = 0.5

        for pkt in self.outstanding.values():
            if (time.clock() - pkt.time_sent) > threshold:
                # use transmit since sequence number is already set
                dbg_print(9, "Retransmitting: %x" % pkt.seq)
                self.transmitter.transmit(pkt, self.drop_prob)

    def run(self):
        self.running = True
        while self.running:
            time.sleep(0.02)
            # handle any outstanding packets
            self._handle_outstanding()
        # we end up here after receiving a FIN packet
        while len(self.outstanding) > 0:
            # while there are still outstanding packets, handle them
            self._handle_outstanding()
        # transmit FIN ACK packet
        finpack = Packet()
        finpack.cntl = FIN | ACK
        finpack.ack = self.finish_sequence
        self.transmitter.send(finpack)
        self.receiver.stop()
        self.socket.shutdown(ip.SHUT_RDWR)
        self.socket.close()

    # _data_wait and _sequence_check separated from get_sequential_packet for ease of profiling
    def _data_wait(self):
        start_wait = time.clock()
        while self.running and len(self.packet_heap) == 0:
            # wait while there aren't any packets to read, and we can still receive packets
            pass
        # print(time.clock() - start_wait)

    def _sequence_check(self):
        while self.packet_heap[0].seq != self.next_sequential:
            # wait until the next sequential packet is available
            pass
            # print("%x, %x" % (self.next_sequential, self.packet_heap[0].seq))
            # if self.next_sequential in self.received_seqs:
                # if the next sequence has been received but is not on the heap, it must have been an ACK
            #    self.next_sequential += 1
            # time.sleep(1)

    def get_sequential_packet(self):
        self._data_wait()
        if not self.running and len(self.packet_heap) == 0:
            # if the thread is no longer alive, we know that all outstanding data is settled by both parties
            # if there aren't anymore packets on the heap, then we're done
            return None

        self._sequence_check()

        self.next_sequential += 1
        packet = heapq.heappop(self.packet_heap)
        return packet

    def set_debug_level(self, level):
        global sock352_dbg_level
        sock352_dbg_level = level
        self.debug_level = level

    def set_drop_prob(self, probability):
        self.drop_prob = probability

    def set_random_seed(self, seed):
        self.seed = seed
        # random.seed(seed)

    def bind(self, address):
        # AF_INET is for internet, and SOCK_DGRAM indicates UDP
        self.socket = ip.socket(ip.AF_INET, ip.SOCK_DGRAM)
        # bind to address
        self.socket.bind(address)

    def connect(self, address):
        # create socket
        self.socket = ip.socket(ip.AF_INET, ip.SOCK_DGRAM)
        # create transmitter and receiver objects
        self.transmitter = Transmitter(address, self.socket)
        self.receiver = Receiver(self)
        self.receiver.start()
        self.running = True
        self.start()
        # create SYNC packet to send to server
        syncpack = Packet()
        syncpack.cntl = SYN
        # send packet
        self.transmitter.send(syncpack)
        # now we must wait for a SYNC ACK response
        packet = self.get_sequential_packet()

        if packet.cntl != (SYN | ACK) or packet.ack != syncpack.seq:
            # raise an error if the server did not accept our sync
            raise RuntimeError("Did not receive an acknowledgement to SYNC packet")
        # otherwise, we're established

    def accept(self):
        # create new receiver and begin listening for new connection
        self.receiver = Receiver(self)
        self.receiver.start()
        self.running = True
        packet = self.get_sequential_packet()

        if packet.cntl != SYN:
            # raise error if it is not a sync packet
            raise RuntimeError("Did not receive SYN packet upon opening connection")

        # create transmitter now that we have address and set next sequential packet number
        self.transmitter = Transmitter(packet.sender, self.socket)
        # start socket reliability thread now that we have both a transmitter and receiver
        self.start()

        # received sync, acknowledge and sync with client
        ackpack = Packet()
        ackpack.cntl = ACK | SYN
        ackpack.ack = packet.seq
        # send ACK SYNC packet
        self.transmitter.send(ackpack)
        return packet.sender

    def sendto(self, buffer):
        # create packet to send
        packet = Packet()
        packet.cntl = DATA
        packet.data = buffer
        # add it to the outstanding set
        self.transmitter.send(packet, self.drop_prob)
        self.outstanding[packet.seq] = packet
        return len(buffer)

    def recvfrom(self, nbytes):
        if len(self.data_buffer) > 0:
            # if there's data in buffer, use it
            data = self.data_buffer
        else:
            # otherwise, read in next sequential packet
            packet = self.get_sequential_packet()
            # if no packet is present then socket is closed => return empty string
            if packet is None:
                return ""
            # otherwise, read data from packet
            data = packet.data
        # split data depending on how many bytes are read, and store any remaining for later read
        data, remaining = data[:nbytes], data[nbytes:]
        self.data_buffer = remaining
        return data

    def close(self):
        while len(self.outstanding) > 0:
            # clear outstanding buffer
            pass

        # create FIN packet
        finpack = Packet()
        finpack.cntl = FIN
        # transmit to other end
        self.transmitter.send(finpack)

        while self.running:
            # we will continue to run until we receive a FIN packet
            # since we cleared the outstanding queue already, we don't have to worry about the main thread taking down
            # the socket after it receives a FIN packet and exits the main loop
            pass


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
