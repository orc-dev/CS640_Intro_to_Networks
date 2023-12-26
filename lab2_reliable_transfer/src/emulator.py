"""
File Name:    emulator.py
Author:       Xin Cai
Email:        xcai72@wisc.edu
Date:         Nov.4 2023

Description:  This program creates a network emulator that facilitates packet 
              exchange between senders and receivers, incorporating routing 
              and queuing policies. It also includes mechanisms to simulate 
              random packet drops and emulate bandwidth-delay scenarios. 
              Additionally, all packet loss events are logged to a file.

Arguments:
              -p, --port        the port of the emulator
              -q, --queue_size  the size of each of the three queues
              -f, --filename    the filename of the static forwarding table
              -l, --log         the filename of log

command:      python3 emulator.py -p <port> -q <queue_size> -f <filename> -l <log>

Course:       CS 640
Instructor:   Prof. Paul Barford
Assignment:   2. Network Emulator and Reliable Transfer
Due Date:     Nov.17 2023
"""

import argparse
import socket
import queue
import struct
import logging
import time
import random
import signal
from collections import namedtuple
from enum import Enum

# definition of namedtuples
IP_Header  = namedtuple('IP_Header', [
    'priority', 
    'src_ipv4', 
    'src_port', 
    'des_ipv4', 
    'des_port', 
    'udp_lenB'])

UDP_Header = namedtuple('UDP_Header', [
    'p_type', 
    'seq_no', 
    'msg_lenB'])

# global variables
HOST_NAME        = None    # host name of current machine
HOST_IPV4        = None    # ip address associated with the host
args             = None    # user specified arguments
f_table          = None    # forwarding table
emu_qs           = None    # emulator queues system
emulator_running = None    # global flag controls the running of the emulator

# debugging usage
idling    = False
last_msg  = None

# enum for packet loss reasons
class LossReason(Enum):
    NO_ENTRY   = 'No forwarding entry found'
    QUEUE_FULL = 'Priority queue was full  '
    LOSS_EVENT = 'Loss event occurred      '

# enum for packet type
class PacketType(Enum):
    ACK     = b'A'
    DATA    = b'D'
    END     = b'E'
    REQUEST = b'R'


def parse_args():
    """
    Parse command-line arguments, storing them in the global variable `args`
    """
    # init argument parser
    parser = argparse.ArgumentParser(description='emulator.py usage')

    # define the required arguments
    parser.add_argument('-p', '--port',       type=int, required=True)
    parser.add_argument('-q', '--queue_size', type=int, required=True)
    parser.add_argument('-f', '--filename',   type=str, required=True)
    parser.add_argument('-l', '--log',        type=str, required=True)
    
    # parse argument and initialize global variables
    global args, emu_qs, HOST_NAME, HOST_IPV4
    args      = parser.parse_args()
    emu_qs    = [ None, queue.Queue(), queue.Queue(), queue.Queue()]
    HOST_NAME = socket.gethostname()
    HOST_IPV4 = socket.gethostbyname(HOST_NAME)
    

def load_forwarding_table():
    """
    Load forwarding table from the given file.

    Note:
        The emulator reads this file once it starts running and then only
        refers to its version of the file in memory for every packet. The 
        emulator ignores lines in the table that do not correspond to its 
        own hostname and port.
    """
    global f_table
    f_table = []
    
    # open and read table file
    with open(args.filename, 'r') as file:
        for line in file:
            value = line.strip().split(' ')
            
            # ignore records that don't match the emulator's hostname and port
            if value[0] != HOST_NAME or int(value[1]) != args.port:
                continue

            # construct and append current entry
            entry = {
                'emu_ipv4': socket.gethostbyname(value[0]),
                'emu_port': int(value[1]),
                'des_ipv4': socket.gethostbyname(value[2]),
                'des_port': int(value[3]),
                'nxt_ipv4': socket.gethostbyname(value[4]),
                'nxt_port': int(value[5]),
                'delay_ns': int(value[6]) * 1000_000,
                'loss_prob': float(value[7])
            }
            f_table.append(entry)
    

def setup_logging():
    """
    Setup logging configurations
    """
    logging.basicConfig(
        filename=args.log,
        filemode='w',       
        level=logging.WARNING,
        format='%(asctime)s | %(name)s | %(levelname)s | %(message)s'
    )


def log_packet_loss(reason, ip_header):
    """
    Log packet loss information with the following contents:
    | reason | src_addr | des_addr | priority | payload size |
    """
    # construct the log message
    log_message = (
        f'reason: {reason.value} | '
        f'src_addr: {ip_header.src_ipv4}:{ip_header.src_port} | '
        f'des_addr: {ip_header.des_ipv4}:{ip_header.des_port} | '
        f'priority: {ip_header.priority} | '
        f'payload size: {ip_header.udp_lenB}'
    )
    # logging message
    logging.getLogger('packet_loss').warning(log_message)


def parse_IP_header(ip_packet):
    """
    Parses an IP header from input IP packet

    Args:
        ip_packet (bytes): The IP packet to be parsed.

    Returns:
        tuple: A tuple containing the following elements:
            - ip_header (IP_Header)
            - udp_header (UDP_Header)
            - b_message (binary message)
    
    Note:
        The IP_Header structure (field and bytes):
        | priority | src_ipv4 | src_port | des_ipv4 | des_port | udp_lenB | 
        |    1     |    4     |    2     |    4     |    2     |    4     | 

    """
    # header format and size
    H_FORMAT = '=BIHIHI'
    H_LENGTH = struct.calcsize(H_FORMAT)

    # unpack the header binary data into an IP_Header namedtuple
    ip_header = IP_Header(*struct.unpack(H_FORMAT, ip_packet[:H_LENGTH]))

    # convert ip_header fields to the host-byte-order format
    ip_header = ip_header._replace(
        src_ipv4 = socket.inet_ntoa(struct.pack('!I', ip_header.src_ipv4)),
        des_ipv4 = socket.inet_ntoa(struct.pack('!I', ip_header.des_ipv4)),
        src_port = socket.ntohs(ip_header.src_port),
        des_port = socket.ntohs(ip_header.des_port),
        udp_lenB = socket.ntohl(ip_header.udp_lenB)
    )
    # parse UDP packet
    udp_packet = ip_packet[H_LENGTH : H_LENGTH + ip_header.udp_lenB]
    udp_header, b_message = parse_UDP_header(udp_packet, ip_header.udp_lenB)

    return ip_header, udp_header, b_message


def parse_UDP_header(udp_packet, udp_lenB):
    """
    Parses an UDP header from input UDP packet

    Args:
        udp_packet (bytes): The UDP packet to be parsed.
        udp_lenB (int): the length of udp_packet specified by the ip_header

    Returns:
        tuple: A tuple containing the following elements:
            udp_header (UDP_Header): an UDP_Header namedtuple
            b_message (bytes): the UDP payload
    
    Note:
        The UDP_Header structure (field and bytes):
        | p_type | seq_no | msg_lenB |
        |   1    |   4    |     4    |

    """
    # header format and size
    H_FORMAT = '=cII'
    H_LENGTH = struct.calcsize(H_FORMAT)

    # unpack the header binary data into an UDP_Header namedtuple
    udp_header = UDP_Header(*struct.unpack(H_FORMAT, udp_packet[:H_LENGTH]))

    # convert udp_header fields to host-byte-order format
    udp_header = udp_header._replace(
        seq_no   = socket.ntohl(udp_header.seq_no),
        msg_lenB = socket.ntohl(udp_header.msg_lenB),
    )
    # check lengths
    if udp_lenB != len(udp_packet):
        print(f'Error: ({udp_lenB}) != udp packet size ({len(udp_packet)}).')

    if (udp_header.p_type == PacketType.DATA and 
        udp_header.msg_lenB != udp_lenB - H_LENGTH):
        print(f'Error: payload size inconsistency in DATA packet.')

    # extract UDP payload
    b_message = udp_packet[H_LENGTH : udp_lenB]
    return udp_header, b_message


def routing(ip_header):
    """
    Determine the forwarding table index based on given IP header.

    Args:
        ip_header (IPHeader): the packet's IP header for forwarding decision

    Returns:
        fid (int): the index of the matching entry in the forwarding table, 
                   or -1 if no match is found.

    Logging event:
        If no matching entry is found, drop the packet and log this event.
    """
    # lookup forwarding table
    for fid, entry in enumerate(f_table):
        # if match
        if (ip_header.des_ipv4 == entry['des_ipv4'] and
            ip_header.des_port == entry['des_port']):
            # return the current forwarding table's row index
            return fid
    
    # otherwise, drop the packet and log
    log_packet_loss(LossReason.NO_ENTRY, ip_header)
    return -1


def queueing(fid, ip_header, udp_header, ip_packet):
    """
    Queue a packet based on priority and log packet loss if the queue is full.

    Args:
        fid (int): the forwarding table index for the packet
        ip_header (IP_Header): the IP header of the processing packet
        udp_header (UDP_Header): the UDP header of the processing packet
        ip_packet (bytes): the IP packet
    
    Logging event:
        If the queue if full and the packet if not of type END,
        drop the packet and log this event.
    """
    # check next hop existing or not
    if fid < 0: return
    
    # access the queue with corresponding priority
    q = emu_qs[ip_header.priority]

    # check queue state and packet type
    if (udp_header.p_type != PacketType.END.value 
        and q.qsize() >= args.queue_size):
        # queue if full
        log_packet_loss(LossReason.QUEUE_FULL, ip_header)
    else:
        q.put((fid, ip_header, udp_header, ip_packet))
        #_verify_queue_status()
    

def loss_event_sim(fid, debug=False):
    """
    Return a boolean value representing a loss event occurs.
    """
    r_num = random.random() * 100
    event = r_num < f_table[fid]['loss_prob']

    if debug:
        print(f'fid             {fid}')
        print(f'given loss prob {f_table[fid]["loss_prob"]}')
        print(f'r_num           {r_num}')
        print(f'event happen    {event}')

    return event


def sending(emu_socket, curr_task):
    """
    Send the current packet to the next hop or 
    drop the packet if a loss event occurs.

    Args:
        emu_socket (socket): the emulator socket for sending packets
        curr_task (tuple): a tuple containing necessay elements

    Logging event:
        If a simulated loss event occurs, drop the packet and log this event.
    """
    if curr_task is None: return

    # expand current task
    fid, ip_header, udp_header, ip_packet = curr_task

    # simulate loss event
    if udp_header.p_type != PacketType.END.value and loss_event_sim(fid):
        # drop current packet and log
        log_packet_loss(LossReason.LOSS_EVENT, ip_header)
    else:
        # send the current IP packet to next hop
        next_hop = (f_table[fid]['nxt_ipv4'], f_table[fid]['nxt_port'])
        emu_socket.sendto(ip_packet, next_hop)


def run_emulator():
    """
    Run the emulator according to the lab specifications.
    """
    global emulator_running
    emulator_running = True

    # create a socket and set it as non-blocking
    emu_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    emu_socket.setblocking(False)
    emu_socket.bind(('0.0.0.0', args.port))

    # init timing variables
    time_delay_ns = 0
    time_start_ns = 0
    current_task  = None

    # working loop
    while emulator_running:
        try:
            # receive and parse
            ip_packet, _ = emu_socket.recvfrom(8192)
            ip_header, udp_header, _ = parse_IP_header(ip_packet)
            
            # routing and queueing
            fid = routing(ip_header)
            queueing(fid, ip_header, udp_header, ip_packet)
            
        except BlockingIOError:
            pass
        
        # waiting for the delay to expire
        if (time.time_ns() - time_start_ns) < time_delay_ns: 
            continue
        
        # send current task
        sending(emu_socket, current_task)
        # fetch next one
        current_task = next((emu_qs[i].get() 
                             for i in [1,2,3] if emu_qs[i].qsize() > 0), None)
        
        # configure delay settings for new packet
        if current_task is not None:
            # extend to tuple (fid, ip_header, udp_header, ip_packet)
            fid, _, _, _  = current_task
            time_delay_ns = f_table[fid]['delay_ns']
            time_start_ns = time.time_ns()
            #_verify_queue_status()

    # graceful termination with notification
    emu_socket.close()
    print(f"The emulator on host '{socket.gethostname()}'"
          f" and port '{args.port}' has been terminated.")
    

def _verify_queue_status():
    """
    This function display the wrokiing/idling status of the emulator,
    and shows the qsize of each queue.
    """
    global idling, last_msg

    task_nums = sum(q.qsize() for q in emu_qs[1:4])

    if (task_nums == 0 and not idling):
        print(f'Emulator idling...')
        idling = True

    elif task_nums:
        idling = False
        curr_msg = (f'Emulator working: queue sizes '
                    f'({emu_qs[1].qsize()}), '
                    f'({emu_qs[2].qsize()}), '
                    f'({emu_qs[3].qsize()})')

        print(curr_msg)


def _verify_args():
    """
    Verify and print the values of command-line arguments.
    """
    print(f'{"-" * 30}')
    print(f'Arguments and Global Variables')
    print(f'{"-" * 30}')
    print(f'port:       {args.port}')
    print(f'queue_size: {args.queue_size}')
    print(f'filename:   {args.filename}')
    print(f'log:        {args.log}')
    print(f'HOST_NAME:  {HOST_NAME}')
    print(f'HOST_IPV4:  {HOST_IPV4}')


def _verify_forwarding_table():
    """
    Print the forwarding table in a structured format.
    """
    # meta dimension data
    size  = len(f_table[0])
    gap   = 4
    col   = [key for key in f_table[0].keys()]
    width = [0] * size;
    
    # update width by reading column names
    for i, col_name in enumerate(col):
        width[i] = max(width[i], len(col_name) + gap)
    
    # update width by reading each entry
    for entry in f_table:
        for i, val in enumerate(entry.values()):
            width[i] = max(width[i], len(str(val)) + gap)

    # static str components
    title = 'STATIC FORWARDING TABLE'
    GAP_HEAD = ' ' * ((sum(width) - len(title)) // 2)
    SEP_LINE = '-' * sum(width)

    # display title
    print(f"\n{GAP_HEAD}{title}")

    # display header
    print(SEP_LINE)
    for i, col_name in enumerate(col):
        print(f"{col_name:{width[i]}}", end='')
    print()
    print(SEP_LINE)

    # display table contents
    for entry in f_table:
        for i, value in enumerate(entry.values()):
            print(f"{str(value):{width[i]}}", end='')
        print()
    print(SEP_LINE)


def _verify_loss_event_sim():
    loss_event_sim(0, True)
    loss = 0
    total = 1000
    for i in range(total):
        if loss_event_sim(0, False):
            loss += 1

    print(f'loss event: {loss} out of {total}, rate = {loss/total}')


def _verify_packet_creation_and_parsing():
    """
    Conduct basic testing for packet creation and parsing.
    """
    # udp fields
    chunk  = b'this is a testing udp payload'
    seq_no = 15
    
    p_type = PacketType.END.value
    seq_no   = socket.htonl(seq_no);
    msg_byte = socket.htonl(len(chunk));

    # construct udp_packet
    udp_header = struct.pack('=cII', p_type, seq_no, msg_byte)
    udp_packet = udp_header + chunk

    # ip field
    src_ipv4 = '192.168.1.6'
    src_port = 3000
    des_ipv4 = '192.168.1.78'
    des_port = 4000
    priority = 2

    src_ipnl = struct.unpack('!I', socket.inet_aton(src_ipv4))[0]
    src_port = socket.htons(src_port)
    des_ipnl = struct.unpack('!I', socket.inet_aton(des_ipv4))[0]
    des_port = socket.htons(des_port)
    udp_lenB = socket.htonl(len(udp_packet))

    # pack ip fields to create ip header
    ip_fields = (priority, src_ipnl, src_port, des_ipnl, des_port, udp_lenB)
    ip_header = struct.pack('=BIHIHI', *ip_fields)
    ip_packet = ip_header + udp_packet

    # unpack test
    _ip_header, _udp_header, _b_message = parse_IP_header(ip_packet)
    
    # selection output
    if (len(udp_header) != 9): 
        print(f'Error: udp_header size({len(udp_header)}) != 9')

    if (len(ip_header) != 17): 
        print(f'Error: ip_header size({len(ip_header)}) != 17')

    if not isinstance(_ip_header.priority, int):
        print(f'Error: ip_header.priority is not "int"')

    if not isinstance(_udp_header.p_type, bytes):
        print(f'Error: ip_header.p_type is not "bytes"')


# control function
def signal_handler(sig, frame):
    """
    Set the emulator flag to terminate (False) with notification.
    """
    global emulator_running
    emulator_running = False
    print('\nCtrl + C received. Stopping the emulator...')
    

def main():
    """
    Perform required setup tasks and run this emulator.
    """
    # initialize and configure emulator settings
    parse_args()
    load_forwarding_table()
    setup_logging()
    signal.signal(signal.SIGINT, signal_handler)

    # verification and message display
    _verify_forwarding_table()
    _verify_packet_creation_and_parsing()
    
    # run emulator
    run_emulator()           


if __name__ == '__main__':
    main()
