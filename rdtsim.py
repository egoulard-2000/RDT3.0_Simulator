'''
Name: Emile Goulard
Date: 5/4/2023
'''

## Python version of:
##
## ****************************************************************************
## ALTERNATING BIT AND GO-BACK-N NETWORK SIMULATOR: VERSION 1.1  J.F.Kurose
##
## This code should be used for PA2, unidirectional data-transfer protocols
## from A to B.
## Network properties:
##   - one-way network delay averages 5.0 time units (longer if there
##     are other messages in the channel for GBN), but can be larger
##   - packets can be corrupted (either the header or the data portion)
##     or lost, according to user-defined probabilities
##   - packets will be delivered in the order in which they were sent
##     (although some can be lost).
## ****************************************************************************

import argparse
from copy import deepcopy
from enum import Enum, auto
import queue
import random
import sys
import time

###############################################################################

# A Msg is the data unit passed from layer 5 (teacher's code) to layer 4
# (student's code).  It contains the data (bytes) to be delivered to layer 5
# via the student's transport-level protocol entities.
#
class Msg:
    MSG_SIZE = 20

    def __init__(self, data):
        self.data = data                # type: bytes[MSG_SIZE]

    def __str__(self):
        return 'Msg(data=%s)' % (self.data)

# A Pkt is the data unit passed from layer 4 (student's code) to layer 3
# (teacher's code).  Note the pre-defined packet structure, which all students
# must follow.
#
class Pkt:
    def __init__(self, seqnum, acknum, checksum, payload):
        self.seqnum = seqnum            # type: integer
        self.acknum = acknum            # type: integer
        self.checksum = checksum        # type: integer
        self.payload = payload          # type: bytes[Msg.MSG_SIZE]

    def __str__(self):
        return ('Pkt(seqnum=%s, acknum=%s, checksum=%s, payload=%s)'
                % (self.seqnum, self.acknum, self.checksum, self.payload))

###############################################################################

class EntityA:
    # The following method will be called once (only) before any other
    # EntityA methods are called.  You can use it to do any initialization.
    #
    # seqnum_limit is "the number of distinct seqnum values that your protocol
    # may use."  The seqnums and acknums in all layer3 Pkts must be between
    # zero and seqnum_limit-1, inclusive.  E.g., if seqnum_limit is 16, then
    # all seqnums must be in the range 0-15.

    ''' 
    Notes 3/20/23

    - 'start_timer' function acts as a timeout under rdt chart. It means the packet or acknowledgement could be lost between entities.
    - class 'Msg' is the message to send in bytes
    - Don't use global variables!

    '''
    def __init__(self, seqnum_limit):
        self.seqnum_limit = seqnum_limit
        self.seqnum = self.seqnum_limit - 1
        self.windowQueue = queue.Queue()
        self.windowSize = seqnum_limit // 2
        self.packetQueue = queue.Queue()
        self.timerActive = False
        self.timeIncrement = 30

    # Called from layer 5, passed the data to be sent to other side.
    # The argument `message` is a Msg containing the data to be sent.
    def output(self, message):
        self.packetQueue.put(message)
        if self.windowQueue.qsize() >= self.windowSize:
            return

        if self.packetQueue.qsize() < 1:
            return

        # Must be the packets within window or in the packet queue
        for p in range(min(self.packetQueue.qsize(), self.windowSize - self.windowQueue.qsize())):
            # Formulate the Seqnum, AckNum, and Checksum based on current window size
            create_windowSize = self.windowSize - (self.windowSize - self.windowQueue.qsize())
            create_seqnum = (self.get_valid_acknum() + create_windowSize) % self.seqnum_limit
            create_acknum = (create_seqnum - 1) % self.seqnum_limit
            self.incomingPacket = self.packetQueue.get()

            create_checksum = form_checksum(create_seqnum, create_acknum, self.incomingPacket.data)
            deliver_packet = Pkt(create_seqnum, create_acknum, create_checksum, self.incomingPacket.data)
            self.windowQueue.put(deliver_packet)
            to_layer3(self, deliver_packet) # Send packet

            if not self.timerActive:
                start_timer(self, self.timeIncrement) # Start Timer Increment
                self.timerActive = True

    # Called from layer 3, when a packet arrives for layer 4 at EntityA.
    # The argument `packet` is a Pkt containing the newly arrived packet.
    def input(self, packet):
        # Corrupted? isACK(packet, 0)?
        if corrupted(packet):
            return

        # Find most recent acked packet in queue
        ACKed_packet = False
        for p in range(self.windowQueue.qsize()):
            if packet.acknum == (self.get_valid_acknum() + p) % self.seqnum_limit:
                ACKed_packet = True
                break

        if not ACKed_packet:
            return
        
        # Start removing packets in queue already acked
        for p in range(self.windowQueue.qsize()):
            self.windowQueue.get()
            packet_ACKed = self.get_valid_acknum() + p
            if packet.acknum == (packet_ACKed % self.seqnum_limit):
                break

        # Stop Timer for a bit
        if self.timerActive:
            stop_timer(self)
            self.timerActive = False

        self.seqnum = packet.acknum

        if self.windowQueue.qsize() >= self.windowSize:
            return

        if self.packetQueue.qsize() < 1:
            return

        # Must be the packets within window or in the packet queue
        for p in range(min(self.packetQueue.qsize(), self.windowSize - self.windowQueue.qsize())):
            # Formulate the Seqnum, AckNum, and Checksum based on current window size
            create_windowSize = self.windowSize - (self.windowSize - self.windowQueue.qsize())
            create_seqnum = (self.get_valid_acknum() + create_windowSize) % self.seqnum_limit
            create_acknum = (create_seqnum - 1) % self.seqnum_limit

            create_checksum = form_checksum(create_seqnum, create_acknum, self.incomingPacket.data)
            deliver_packet = Pkt(create_seqnum, create_acknum, create_checksum, self.incomingPacket.data)
            self.windowQueue.put(deliver_packet)
            to_layer3(self, deliver_packet) # Send packet

            if not self.timerActive:
                start_timer(self, self.timeIncrement) # Start Timer Increment
                self.timerActive = True

    # Called when A's timer goes off.
    def timer_interrupt(self):
        # Send back packets in window queue
        for p in range(self.windowQueue.qsize()):
            deliver_packet = self.windowQueue.get()
            self.windowQueue.put(deliver_packet)
            to_layer3(self, deliver_packet)
            
            if not self.timerActive:
                start_timer(self, self.timeIncrement)
                self.timerActive = True

        self.timerActive = True
        start_timer(self, self.timeIncrement) # Start Timer Increment

    # Check if valid acknum
    def get_valid_acknum(self):
        return (self.seqnum + 1) % self.seqnum_limit # Use Modulo for alternating-bit pattern

class EntityB:
    # The following method will be called once (only) before any other
    # EntityB methods are called.  You can use it to do any initialization.
    #
    # See comment for the meaning of seqnum_limit.
    def __init__(self, seqnum_limit):
        self.acknum_limit = seqnum_limit
        self.windowSize = seqnum_limit // 2
        self.acknum = self.acknum_limit - 1
        self.timerIncrement = 30

    # Called from layer 3, when a packet arrives for layer 4 at EntityB.
    # The argument `packet` is a Pkt containing the newly arrived packet.
    def input(self, packet):
        if corrupted(packet):
            checksum = form_checksum(self.get_seqnum(), self.acknum, packet.payload)
            packet = Pkt(self.get_seqnum(), self.acknum, checksum, packet.payload)
            to_layer3(self, packet)
            return

        if self.get_seqnum() != packet.seqnum:
            checksum = form_checksum(self.get_seqnum(), self.acknum, packet.payload)
            packet = Pkt(self.get_seqnum(), self.acknum, checksum, packet.payload)
            to_layer3(self, packet)
            return
        
        send_message = Msg(packet.payload)
        to_layer5(self, send_message)

        # Send ACK Packet and Increment Acknum
        self.acknum = (self.acknum + 1) % self.acknum_limit
        checksum = form_checksum(self.get_seqnum(), self.acknum, packet.payload)
        packet = Pkt(self.get_seqnum(), self.acknum, checksum, packet.payload)
        to_layer3(self, packet)

    # Called when B's timer goes off.
    def timer_interrupt(self):
        # Don't Implement
        pass

    # Check if valid acknum
    def get_seqnum(self):
        return (self.acknum + 1) % self.acknum_limit # Use Modulo for alternating-bit pattern

###############################################################################

# Forms a Checksum
def form_checksum(seqnum, acknum, packet_load):
    return seqnum + acknum + sum(packet_load)
    
# Checks if a packet is corrupted
def corrupted(packet):
    current_checksum = packet.seqnum + packet.acknum + sum(packet.payload)
    return current_checksum != packet.checksum or len(packet.payload) != Msg.MSG_SIZE or packet.payload is None

def start_timer(calling_entity, increment):
    the_sim.start_timer(calling_entity, increment)

def stop_timer(calling_entity):
    the_sim.stop_timer(calling_entity)

def to_layer3(calling_entity, packet):
    the_sim.to_layer3(calling_entity, packet)

def to_layer5(calling_entity, message):
    the_sim.to_layer5(calling_entity, message)

def get_time(calling_entity):
    return the_sim.get_time(calling_entity)

# Added on 3/20.
# We don't want things always printing out.
# The Trace allows for holding the tracing value that was set on the command line via the -v option
def debug(x):
     if TRACE > 1:
        print(x)

def error(x):
    if TRACE > 0:
        print(x)

###############################################################################

## ****************************************************************************
## ***************** NETWORK SIMULATION CODE STARTS BELOW *********************
##
## The code below simulates the layer 3 and below network environment:
##   - simulates the tranmission and delivery (possibly with bit-level
##     corruption and packet loss) of packets across the layer 3/4 interface
##   - handles the starting/stopping of a timer, and generates timer
##     interrupts (resulting in calling student's timer handler).
##   - generates message to be sent (passed from later 5 to 4)
##
## THERE IS NO REASON THAT ANY STUDENT SHOULD HAVE TO READ OR UNDERSTAND
## THE CODE BELOW.  YOU SHOULD NOT TOUCH OR REFERENCE (in your code) ANY
## OF THE DATA STRUCTURES BELOW.  If you're interested in how I designed
## the simulator, you're welcome to look at the code - but again, you should
## not have to, and you definitely should not have to modify.
##
## ****************************************************************************

class EventType(Enum):
    TIMER_INTERRUPT = auto()
    FROM_LAYER5 = auto()
    FROM_LAYER3 = auto()

class Event:
    def __init__(self, ev_time, ev_type, ev_entity, packet=None):
        self.ev_time = ev_time      # float
        self.ev_type = ev_type      # EventType
        self.ev_entity = ev_entity  # EntityA or EntityB
        self.packet = packet        # Pkt or None



class Simulator:
    def __init__(self, options, cbA=None, cbB=None):
        self.n_sim                = 0
        self.n_sim_max            = options.num_msgs
        self.time                 = 0.000
        self.interarrival_time    = options.interarrival_time
        self.loss_prob            = options.loss_prob
        self.corrupt_prob         = options.corrupt_prob
        self.seqnum_limit         = options.seqnum_limit
        self.n_to_layer3_A        = 0
        self.n_to_layer3_B        = 0
        self.n_lost               = 0
        self.n_corrupt            = 0
        self.n_to_layer5_A        = 0
        self.n_to_layer5_B        = 0

        if options.random_seed:
            self.random_seed      = options.random_seed
        else:
            self.random_seed      = time.time_ns()
        random.seed(self.random_seed)

        if self.seqnum_limit < 2:
            self.seqnum_limit_n_bits = 0
        else:
            # How many bits to represent integers in [0, seqnum_limit-1]?
            self.seqnum_limit_n_bits = (self.seqnum_limit-1).bit_length()

        self.trace                = options.trace
        self.to_layer5_callback_A = cbA
        self.to_layer5_callback_B = cbB

        self.entity_A             = EntityA(self.seqnum_limit)
        self.entity_B             = EntityB(self.seqnum_limit)
        self.event_list           = []

    def get_stats(self):
        stats = {'n_sim'             : self.n_sim,
                 'n_sim_max'         : self.n_sim_max,
                 'time'              : self.time,
                 'interarrival_time' : self.interarrival_time,
                 'loss_prob'         : self.loss_prob,
                 'corrupt_prob'      : self.corrupt_prob,
                 'seqnum_limit'      : self.seqnum_limit,
                 'random_seed'       : self.random_seed,
                 'n_to_layer3_A'     : self.n_to_layer3_A,
                 'n_to_layer3_B'     : self.n_to_layer3_B,
                 'n_lost'            : self.n_lost,
                 'n_corrupt'         : self.n_corrupt,
                 'n_to_layer5_A'     : self.n_to_layer5_A,
                 'n_to_layer5_B'     : self.n_to_layer5_B
        }
        return stats

    def run(self):
        if self.trace>0:
            print('\n===== SIMULATION BEGINS')

        self._generate_next_arrival()

        while (self.event_list
               and self.n_sim < self.n_sim_max):
            ev = self.event_list.pop(0)
            if self.trace>2:
                print(f'\nEVENT time: {ev.ev_time}, ', end='')
                if ev.ev_type == EventType.TIMER_INTERRUPT:
                    print(f'timer_interrupt, ', end='')
                elif ev.ev_type == EventType.FROM_LAYER5:
                    print(f'from_layer5, ', end='')
                elif ev.ev_type == EventType.FROM_LAYER3:
                    print(f'from_layer3, ', end='')
                else:
                    print(f'unknown_type, ', end='')
                print(f'entity: {ev.ev_entity}')

            self.time = ev.ev_time

            if ev.ev_type == EventType.FROM_LAYER5:
                self._generate_next_arrival()
                j = self.n_sim % 26
                m = bytes([97+j for i in range(Msg.MSG_SIZE)])
                if self.trace>2:
                    print(f'          MAINLOOP: data given to student: {m}')
                self.n_sim += 1
                ev.ev_entity.output(Msg(m))

            elif ev.ev_type == EventType.FROM_LAYER3:
                ev.ev_entity.input(deepcopy(ev.packet))

            elif ev.ev_type == EventType.TIMER_INTERRUPT:
                ev.ev_entity.timer_interrupt()

            else:
                print('INTERNAL ERROR: unknown event type; event ignored.')

        if self.trace>0:
            print('===== SIMULATION ENDS')

    def _insert_event(self, event):
        if self.trace>2:
            print(f'            INSERTEVENT: time is {self.time}')
            print(f'            INSERTEVENT: future time will be {event.ev_time}')
        # Python 3.10+: use the bisect module:
        # insort(self.event_list, event, key=lambda e: e.ev_time)
        i = 0
        while (i < len(self.event_list)
               and self.event_list[i].ev_time < event.ev_time):
            i += 1
        self.event_list.insert(i, event)

    def _generate_next_arrival(self):
        if self.trace>2:
            print('          GENERATE NEXT ARRIVAL: creating new arrival')

        x = self.interarrival_time * 2.0 * random.random()
        ev = Event(self.time+x, EventType.FROM_LAYER5, self.entity_A)
        self._insert_event(ev)

    #####

    def _valid_entity(self, e, method_name):
        if (e is self.entity_A
            or e is self.entity_B):
            return True
        print(f'''WARNING: entity in call to `{method_name}` is invalid!
  Invalid entity: {e}
  Call ignored.''')
        return False

    def _valid_increment(self, i, method_name):
        if ((type(i) is int or type(i) is float)
            and i >= 0.0):
            return True
        print(f'''WARNING: increment in call to `{method_name}` is invalid!
  Invalid increment: {i}
  Call ignored.''')
        return False

    def _valid_message(self, m, method_name):
        if (type(m) is Msg
            and type(m.data) is bytes
            and len(m.data) == Msg.MSG_SIZE):
            return True
        print(f'''WARNING: message in call to `{method_name}` is invalid!
  Invalid message: {m}
  Call ignored.''')
        return False

    def _valid_packet(self, p, method_name):
        if (type(p) is Pkt
            and type(p.seqnum) is int
            and 0 <= p.seqnum < self.seqnum_limit
            and type(p.acknum) is int
            and 0 <= p.acknum < self.seqnum_limit
            and type(p.checksum) is int
            and type(p.payload) is bytes
            and len(p.payload) == Msg.MSG_SIZE):
            return True
        # Issue special warnings for invalid seqnums and acknums.
        if (type(p.seqnum) is int
            and not (0 <= p.seqnum < self.seqnum_limit)):
            print(f'''WARNING: seqnum in call to `{method_name}` is invalid!
  Invalid packet: {p}
  Call ignored.''')
        elif (type(p.acknum) is int
              and not (0 <= p.acknum < self.seqnum_limit)):
            print(f'''WARNING: acknum in call to `{method_name}` is invalid!
  Invalid packet: {p}
  Call ignored.''')
        else:
            print(f'''WARNING: packet in call to `{method_name}` is invalid!
  Invalid packet: {p}
  Call ignored.''')
        return False

    #####

    def start_timer(self, entity, increment):
        if not self._valid_entity(entity, 'start_timer'):
            return
        if not self._valid_increment(increment, 'start_timer'):
            return

        if self.trace>2:
            print(f'          START TIMER: starting timer at {self.time}')

        for e in self.event_list:
            if (e.ev_type == EventType.TIMER_INTERRUPT
                and e.ev_entity is entity):
                print('WARNING: attempt to start a timer that is already started!')
                return

        ev = Event(self.time+increment, EventType.TIMER_INTERRUPT, entity)
        self._insert_event(ev)

    def stop_timer(self, entity):
        if not self._valid_entity(entity, 'stop_timer'):
            return

        if self.trace>2:
            print(f'          STOP TIMER: stopping timer at {self.time}')

        i = 0
        while i < len(self.event_list):
            if (self.event_list[i].ev_type == EventType.TIMER_INTERRUPT
                and self.event_list[i].ev_entity is entity):
                break
            i += 1
        if i < len(self.event_list):
            self.event_list.pop(i)
        else:
            print('WARNING: unable to stop timer; it was not running.')

    def to_layer3(self, entity, packet):
        if not self._valid_entity(entity, 'to_layer3'):
            return
        if not self._valid_packet(packet, 'to_layer3'):
            return

        if entity is self.entity_A:
            receiver = self.entity_B
            self.n_to_layer3_A += 1
        else:
            receiver = self.entity_A
            self.n_to_layer3_B += 1

        # Simulate losses.
        if random.random() < self.loss_prob:
            self.n_lost += 1
            if self.trace>0:
                print('          TO_LAYER3: packet being lost')
            return

        seqnum = packet.seqnum
        acknum = packet.acknum
        checksum = packet.checksum
        payload = packet.payload

        # Simulate corruption.
        if random.random() < self.corrupt_prob:
            self.n_corrupt += 1
            x = random.random()
            if (x < 0.75
                or self.seqnum_limit_n_bits == 0):
                payload = b'Z' + payload[1:]
            elif x < 0.875:
                # Flip a random bit in the seqnum.
                # The result might be greater than seqnum_limit if seqnum_limit
                # is not a power of two.  This is OK.
                # Recall that randrange(x) returns an int in [0, x).
                seqnum ^= 2**random.randrange(self.seqnum_limit_n_bits)
                # Kurose's simulator simply did:
                # seqnum = 999999
            else:
                # Flip a random bit in the acknum.
                acknum ^= 2**random.randrange(self.seqnum_limit_n_bits)
                # Kurose's simulator simply did:
                # acknum = 999999
            if self.trace>0:
                print('          TO_LAYER3: packet being corrupted')

        # Compute the arrival time of packet at the other end.
        # Medium cannot reorder, so make sure packet arrives between 1 and 9
        # time units after the latest arrival time of packets
        # currently in the medium on their way to the destination.
        last_time = self.time
        for e in self.event_list:
            if (e.ev_type == EventType.FROM_LAYER3
                and e.ev_entity is receiver):
                last_time = e.ev_time
        arrival_time = last_time + 1.0 + 8.0*random.random()

        p = Pkt(seqnum, acknum, checksum, payload)
        ev = Event(arrival_time, EventType.FROM_LAYER3, receiver, p)
        if self.trace>2:
            print('          TO_LAYER3: scheduling arrival on other side')
        self._insert_event(ev)

    def to_layer5(self, entity, message):
        if not self._valid_entity(entity, 'to_layer5'):
            return
        if not self._valid_message(message, 'to_layer5'):
            return

        if entity is self.entity_A:
            self.n_to_layer5_A += 1
            callback = self.to_layer5_callback_A
        else:
            self.n_to_layer5_B += 1
            callback = self.to_layer5_callback_B

        if self.trace>2:
            print(f'          TO_LAYER5: data received: {message.data}')
        if callback:
            callback(message.data)

    def get_time(self, entity):
        if not self._valid_entity(entity, 'get_time'):
            return
        return self.time

###############################################################################

TRACE = 0

the_sim = None

def report_config():
    stats = the_sim.get_stats()
    print(f'''SIMULATION CONFIGURATION
--------------------------------------
(-n) # layer5 msgs to be provided:      {stats['n_sim_max']}
(-d) avg layer5 msg interarrival time:  {stats['interarrival_time']}
(-z) transport protocol seqnum limit:   {stats['seqnum_limit']}
(-l) layer3 packet loss prob:           {stats['loss_prob']}
(-c) layer3 packet corruption prob:     {stats['corrupt_prob']}
(-s) simulation random seed:            {stats['random_seed']}
--------------------------------------''')

def report_results():
    stats = the_sim.get_stats()
    time = stats['time']
    if time > 0.0:
        tput = stats['n_to_layer5_B']/time
    else:
        tput = 0.0
    print(f'''\nSIMULATION SUMMARY
--------------------------------
# layer5 msgs provided to A:      {stats['n_sim']}
# elapsed time units:             {stats['time']}

# layer3 packets sent by A:       {stats['n_to_layer3_A']}
# layer3 packets sent by B:       {stats['n_to_layer3_B']}
# layer3 packets lost:            {stats['n_lost']}
# layer3 packets corrupted:       {stats['n_corrupt']}
# layer5 msgs delivered by A:     {stats['n_to_layer5_A']}
# layer5 msgs delivered by B:     {stats['n_to_layer5_B']}
# layer5 msgs by B/elapsed time:  {tput}
--------------------------------''')

def main(options, cb_A=None, cb_B=None):
    global TRACE
    TRACE = options.trace

    global the_sim
    the_sim = Simulator(options, cb_A, cb_B)
    report_config()
    the_sim.run()

#####

if __name__ == '__main__':
    desc = 'Run a simulation of a reliable data transport protocol.'
    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument('-n', type=int, default=10,
                        dest='num_msgs',
                        help=('number of messages to simulate'
                              ' [int, default: %(default)s]'))
    parser.add_argument('-d', type=float, default=10.0,
                        dest='interarrival_time',
                        help=('average time between messages'
                              ' [float, default: %(default)s]'))
    parser.add_argument('-z', type=int, default=16,
                        dest='seqnum_limit',
                        help=('seqnum limit for data transport protocol; '
                              'all packet seqnums must be >=0 and <limit'
                              ' [int, default: %(default)s]'))
    parser.add_argument('-l', type=float, default=0.0,
                        dest='loss_prob',
                        help=('packet loss probability'
                              ' [float, default: %(default)s]'))
    parser.add_argument('-c', type=float, default=0.0,
                        dest='corrupt_prob',
                        help=('packet corruption probability'
                              ' [float, default: %(default)s]'))
    parser.add_argument('-s', type=int,
                        dest='random_seed',
                        help=('seed for random number generator'
                              ' [int, default: %(default)s]'))
    parser.add_argument('-v', type=int, default=0,
                        dest='trace',
                        help=('level of event tracing'
                              ' [int, default: %(default)s]'))
    options = parser.parse_args()

    main(options)
    report_results()
    sys.exit(0)

###############################################################################

## End of program.
