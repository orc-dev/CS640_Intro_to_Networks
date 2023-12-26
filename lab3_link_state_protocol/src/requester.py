"""
File Name:    requester.py
Author:       Xin Cai
Email:        xcai72@wisc.edu
Date:         Dec.11 2023

Description:  This script runs an instance of requester host, sending requests
              to senders, receiving packets and build a request file. After
              receiving each DATA packet, it sends a ACK packet to the sender.

Arguments:
              -p, --port        : requester's waiting port
              -o, --file_option : name of the request file
              -f, --f_hostname  : hostname of emulator
              -e, --f_port      : port of emulator
              -w, --window      : window size

command:      python3 requester.py -p <port> -o <file option> 
                                   -f <f_hostname> -e <f_port> -w <window>
              
Course:       CS 640
Instructor:   Prof. Paul Barford
Assignment:   3. Link State Routing
Due Date:     Dec.11 2023
"""
import sys
import argparse
import socket
import struct
import queue
import os
import time
from collections import namedtuple
from enum import Enum
from datetime import datetime

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

AddressPair = namedtuple('AddressPair', [
    'ipv4', 
    'port'])

# lightweight class organizes HelloMessage relating fields
class HelloManager:
    def __init__(self):
        self.packet      = None
        self.lastsent_ns = 0
        self.RESENT_NS   = int(1e8)
        self.TIMEOUT_NS  = int(1e9)
        self.lastrecv_ns = {}

# global variables
current_dir   = None    # path to current directory
HOST_IPV4     = None    # ip address associated with current machines
args          = None    # user input arguments
tracker       = None    # tracker table
emu_addr      = None    # emulator address for forwarding packet
msg_buffer    = None    # mapping: provider -> list of messages, index = seq_no
rcv_buffer    = None    # mapping: provider -> {'packets','bytes','start_time'}
task_queue    = None    # a queue of task tuple
task_complete = None    # status of finishing accept all packets from provider
HELLO         = None    # an instancce of HelloManager for this emulator

# enum for packet type
class PacketType(Enum):
    ACK     = b'A'
    DATA    = b'D'
    END     = b'E'
    REQUEST = b'R'
    HELLO   = b'H'


def _verify_args():
    """
    Print the values of command-line arguments.
    """
    print(f'port:          {args.port}')
    print(f'request_file:  {args.request_file}')
    print(f'emu_hostname:  {args.emu_hostname}')
    print(f'emu_port:      {args.emu_port}')
    print(f'window_size:   {args.window_size}')


def _verify_tracker():
    """
    Print the tracker table in a structured format.
    """
    # meta data
    GAP       = 4
    col_names = ['File_names', 'ID', 'Sender_hostname', 'Sender_port'];
    col_width = [len(x) + GAP for x in col_names]
    
    # read each field in each entry to update col_width
    for requestable in tracker:
        col_width[0] = max(col_width[0], len(requestable) + GAP)

        for provider, fid in tracker[requestable].items():
            col_width[1] = max(col_width[1], len(str(fid)) + GAP)
            col_width[2] = max(col_width[2], len(provider.ipv4) + GAP)
            col_width[3] = max(col_width[3], len(str(provider.port)) + GAP)
    
    # # define some basic tabular elements
    SEP_LINE  = '-' * sum(col_width)
    WHITE_SPS = ' ' * col_width[0]

    # # print the table title
    title = 'TRACKER TABLE'
    GAP_HEAD = ' ' * ((sum(col_width) - len(title)) // 2)
    print(f'\n{GAP_HEAD}{title}')

    # print table header
    print(SEP_LINE)
    for i, col_name in enumerate(col_names):
        print(f'{col_name:{col_width[i]}}', end='')
    print()
    print(SEP_LINE)

    # helper to print field
    print_field = lambda val, id: print(f'{str(val):{col_width[id]}}', end='')

    # print each section
    for requestable in tracker:
        print(f'{requestable:{col_width[0]}}')

        # print id and senders' addresses
        for provider in tracker[requestable]:
            print(WHITE_SPS, end='')
            print_field(tracker[requestable][provider], 1)
            print_field(provider.ipv4, 2)
            print_field(provider.port, 3)
            print()

    print(SEP_LINE)


def parse_args():
    """
    Parse command-line arguments, storing them in the global variable `args`
    """
    # init argument parser
    parser = argparse.ArgumentParser(description='requester.py usage')

    # define the required arguments
    parser.add_argument('-p', '--port',         type=int, required=True)
    parser.add_argument('-o', '--request_file', type=str, required=True)
    parser.add_argument('-f', '--emu_hostname', type=str, required=True)
    parser.add_argument('-e', '--emu_port',     type=int, required=True)
    parser.add_argument('-w', '--window_size',  type=int, required=True)

    # parse argument and init global variables
    global HOST_IPV4, current_dir, args, task_queue, emu_addr, HELLO

    HOST_IPV4   = socket.gethostbyname(socket.gethostname())
    current_dir = os.path.dirname(os.path.abspath(__file__))
    args        = parser.parse_args()
    task_queue  = queue.Queue()
    emu_addr    = (socket.gethostbyname(args.emu_hostname), args.emu_port)

    HELLO = HelloManager()
    emu_addrPair = AddressPair(emu_addr[0], emu_addr[1])
    HELLO.packet = create_packet(PacketType.HELLO, 0, bytes(), 0, emu_addrPair)
    

def load_tracker():
    """
    Load the tracker file to create a dictionary of tracking data.

    Note:
        1. filename: tracker.txt
        2. the requester can access it directly
        3. columens: Filename | ID | Sender_hostname | Sender_port
    """
    # build path for tracker file in current directory
    TRACKER_FILE = os.path.join(current_dir, 'tracker.txt')
    
    # init global variabes
    global tracker, msg_buffer, rcv_buffer, task_complete
    tracker       = {}
    msg_buffer    = {}
    rcv_buffer    = {}
    task_complete = [True]

    # open and read tracker file
    with open(TRACKER_FILE, 'r') as file:
        for line in file:
            # split line
            field = line.strip().split(' ')

            # extract fields
            requestable = field[0]
            section_id  = int(field[1])
            provider    = AddressPair(
                ipv4=socket.gethostbyname(field[2]), 
                port=int(field[3])
            )
            # create inner dict
            if requestable not in tracker:
                tracker[requestable] = {}
            
            tracker[requestable][provider] = section_id

    # check if request file is in tracker
    if args.request_file not in tracker:
        print('Error: request file is not in the tracker.')
        sys.exit()

    # initialize packet_buffer
    for provider in tracker[args.request_file]:
        msg_buffer[provider] = [ ]
        rcv_buffer[provider] = {
            'packets' : 0,
            'bytes': 0,
            'start_time': None,
        }
        task_complete.append(False)


def parse_IP_header(ip_packet):
    """
    Parses an IP header from input IP packet

    Args:
        ip_packet (bytes): The IP packet to be parsed.

    Returns:
        tuple: A tuple containing the following elements:
            - ip_header (IP_Header): an IP_Header namedtuple
            - udp_packet (bytes): the UDP packet
    
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
    # if udp_lenB != len(udp_packet):
    #     print(f'Error: ({udp_lenB}) != udp packet size ({len(udp_packet)}).')

    # if (udp_header.p_type == PacketType.DATA and 
    #     udp_header.msg_lenB != udp_lenB - H_LENGTH):
    #     print(f'Error: payload size inconsistency in DATA packet.')

    # extract UDP payload
    b_message = udp_packet[H_LENGTH : udp_lenB]
    return udp_header, b_message


def safe_msg_insert(provider, index, chunk, recv_datetime):
    """
    Safely inserts a message chunk into the message buffer for 
    a specific provider; then updates receipts of this provider.

    Parameters:
    - provider (AddressPair): The address of provider
    - index (int): The index (seq_no) at which to insert the message chunk
    - chunk (byte): The message chunk to be inserted
    - recv_datetime (datetime): timestamp of packet receiving

    """
    global msg_buffer, rcv_buffer
    msg_list = msg_buffer[provider]
    receipts = rcv_buffer[provider]

    # append the list if index is greater than the current length
    while index >= len(msg_list):
        msg_list.append(None)
    
    if msg_list[index] is None:
        msg_list[index] = chunk

        # update receipts
        receipts['packets']   += 1
        receipts['bytes']     += len(chunk)
        receipts['start_time'] = receipts['start_time'] or recv_datetime
        

def create_packet(packet_type, seq_no, chunk, length, des_addr):
    """
    Create and return a network packet with specified fields.

    Parameters:
        packet_type: Type of the packet
        seq_no: Sequence number for the packet
        chunk: Data payload to be included in the packet
        length: payload length in byte * (not for R packet)
        des_addr: Destination address (IP and port)

    Returns:
        ip_packet: A network packet ready to be transmitted.
    """
    # prepare udp fields in network byte order
    p_type   = packet_type.value
    seq_no   = socket.htonl(seq_no);
    msg_lenB = socket.htonl(length);

    # construct udp_packet
    udp_header = struct.pack('=cII', p_type, seq_no, msg_lenB)
    udp_packet = udp_header + chunk

    # prepare ip packet fields
    priority = 1    # all the packets sent by requester have priority 1
    src_ipnl = struct.unpack('!I', socket.inet_aton(HOST_IPV4))[0]
    src_port = socket.htons(args.port)
    des_ipnl = struct.unpack('!I', socket.inet_aton(des_addr.ipv4))[0]
    des_port = socket.htons(des_addr.port)
    udp_lenB = socket.htonl(len(udp_packet))

    # pack ip fields to create ip header
    ip_fields = (priority, src_ipnl, src_port, des_ipnl, des_port, udp_lenB)
    ip_header = struct.pack('=BIHIHI', *ip_fields)
    ip_packet = ip_header + udp_packet
    
    return ip_packet


def send_request_packet(rq_socket, provider):
    """
    Create a request packet and send it to the provider.
    """
    # create request packet
    req_packet = create_packet(
        packet_type=PacketType.REQUEST, 
        seq_no=0, 
        chunk=args.request_file.encode('utf-8'),
        length=args.window_size,
        des_addr=provider
    )
    # send packet to emulator
    rq_socket.sendto(req_packet, emu_addr)


def send_ack_packet(provider, seq_no, rq_socket):
    """
    Create a acknowledgment packet and send it to the provider.
    """
    # create ack packet
    ack_packet = create_packet(
        packet_type=PacketType.ACK, 
        seq_no=seq_no, 
        chunk=bytes(),
        length=0,
        des_addr=provider
    )
    # send packet to emulator
    rq_socket.sendto(ack_packet, emu_addr)


def display_summary(provider, recv_datetime):
    """
    Display the summary for the provider after receiving the END packet
    """
    global rcv_buffer
    receipts = rcv_buffer[provider]
    
    # update receipts
    receipts['start_time'] = receipts['start_time'] or recv_datetime

    # caclulations
    duration_sec = (recv_datetime - receipts['start_time']).total_seconds()
    average_rate = (receipts['packets'] / duration_sec)
    duration     = (duration_sec * 1000)

    # display summary
    print(f'Summary')
    print(f'sender addr:                    {provider.ipv4}:{provider.port}')
    print(f'Total Data packets (unique):    {receipts["packets"]}')
    print(f'Total Data bytes (unique):      {receipts["bytes"]}')
    print(f'Average packets/second:         {average_rate:.2f}')
    print(f'Duration of the test:           {duration:.2f} ms')
    print()


def process_packet(rq_socket, provider, udp_header, b_message, recv_datetime):
    """
    Process an packet by examing its header. If the packet is an END packet, 
    it sets the 'task_complete' flag. If it's a DATA packet, the function 
    safely inserts the message into the buffer and sends an ACK packet.

    Parameters:
        rq_socket: The socket used for sending acknowledgment packets.
        ip_header: The IP header of the incoming packet.
        udp_packet: The UDP packet to be processed.
    """
    global task_complete

    # if is the END packet
    if udp_header.p_type == PacketType.END.value:
        display_summary(provider, recv_datetime)
        section_id = tracker[args.request_file][provider]
        task_complete[section_id] = True
        return

     # if is a DATA packet
    if udp_header.p_type == PacketType.DATA.value:
        safe_msg_insert(provider, udp_header.seq_no, b_message, recv_datetime)
        send_ack_packet(provider, udp_header.seq_no, rq_socket)


def get_task_with_validation(ip_packet, recv_datetime):
    """
    Retrieves a task from the given IP packet, validating its 
    destination, provider, and packet type.

    Parameters:
    - ip_packet (bytes): The IP packet from which to extract the task
    - recv_datetime (datetime): timestamp of packet receiving

    Returns:
    - tuple or None: A tuple containing the provider, UDP packet, 
        and receive timestamp if the task is valid. Otherwise, None.
    
    """
    # check destination
    ip_header, udp_header, b_message = parse_IP_header(ip_packet)
    if (ip_header.des_ipv4 != HOST_IPV4 or
        ip_header.des_port != args.port):
        return None
    
    # check provider
    provider = AddressPair(ip_header.src_ipv4, ip_header.src_port)
    if provider not in tracker[args.request_file]: 
        return None
    
    # check packet type
    if (udp_header.p_type != PacketType.DATA.value and
        udp_header.p_type != PacketType.END.value):
        return None
    
    # return task
    return (provider, udp_header, b_message, recv_datetime)


def request_and_receive_packet():
    """
    Set up a socket, send request packets to providers, and receive/process 
    incoming packets.

    This function creates a non-blocking socket, binds it to a specified port, 
    sends request packets to all providers with the requested file data, and 
    then enters a main loop to receive and process incoming packets. 
    
    Packets intended for this host are put in a queue for processing. The 
    function continues checking for new packets and processes them until the 
    task is marked as complete.
    """
    # create a socket, set to non-blocking and bind
    rq_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rq_socket.setblocking(False)
    rq_socket.bind(('0.0.0.0', args.port))

    # send hello message to stable connection with emulator
    start_time_ns = time.time_ns()
    while time.time_ns() - start_time_ns < int(3e8):
        send_hello_packet(rq_socket)

    # send request packets to all providers with file data
    for provider in tracker[args.request_file]:
        send_request_packet(rq_socket, provider)
    
    # working loop
    while not all(task_complete):
        send_hello_packet(rq_socket)

        try:
            # receive and validate packet
            ip_packet, _ = rq_socket.recvfrom(8192)
            task = get_task_with_validation(ip_packet, datetime.now())

            if task is not None: 
                task_queue.put(task)

            continue  # immediately look for new one
        except BlockingIOError:
            pass
        
        # processing the next packet in task queue
        if task_queue.qsize() > 0:
            process_packet(rq_socket, *task_queue.get())
    
    # close socket
    rq_socket.close()
   

def write_messages_to_file():
    """
    Write received message chunks to a file, preserving the order 
    based on section ID and sequence number.

    This function sorts the providers by their file section ID and 
    sequentially writes the message chunks from the message buffer 
    to an output file, preserving their order as per the section ID 
    and sequence number.

    The function overwrites the existing file if it exists.
    """
    # build a path in current directory with request filename
    request_output = os.path.join(current_dir, args.request_file)

    # sorted providers by their file section id
    id_map = tracker[args.request_file]
    sorted_providers = sorted(id_map, key=lambda provider: id_map[provider])

    # write chunks to file, ordered by section ID and seq_no
    with open(request_output, 'wb') as out_f:
        for provider in sorted_providers:
            for chunk in msg_buffer[provider]:
                if chunk is not None:
                    out_f.write(chunk)
    

def send_hello_packet(sd_socket):
    """
    Send HelloMessages to immediate neighbors periodically.
    """
    global HELLO
    # check timeout condition
    if (time.time_ns() - HELLO.lastsent_ns) >= HELLO.RESENT_NS:
        sd_socket.sendto(HELLO.packet, emu_addr)
        HELLO.lastsent_ns = time.time_ns()

def main():
    """
    Perform required setup tasks and run this requester.
    """
    parse_args()
    load_tracker()
    
    _verify_args()
    _verify_tracker()
    
    request_and_receive_packet()
    write_messages_to_file()


if __name__ == '__main__':
    main()