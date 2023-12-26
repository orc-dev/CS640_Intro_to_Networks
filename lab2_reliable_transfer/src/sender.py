"""
File Name:    sender.py
Author:       Xin Cai
Email:        xcai72@wisc.edu
Date:         Nov.7 2023

Description:  This script runs an instance of a sender host, which receives 
              requests from a requester and sends the requested file to the 
              requester via a reliable transmission mechanism. It incorporates 
              features such as windowed packet transmission, acknowledgment 
              handling, and retransmission.

Arguments:
              -p, --port            the port of the sender
              -g, --requester_port  requester port
              -r, --rate            sending rate per second
              -q, --seq_no          starting sequence number
              -l, --length          size of payload in byte
              -f, --f_hostname      hostname for next emulator
              -e, --f_port          port for next emulator
              -i, --priority        priority level of packet
              -t, --timeout         timeout for resend packet

command:      python3 sender.py -p <port> -g <requester port> -r <rate> 
                                -q <seq_no> -l <length> -f <f_hostname> 
                                -e <f_port> -i <priority> -t <timeout>

Course:       CS 640
Instructor:   Prof. Paul Barford
Assignment:   2. Network Emulator and Reliable Transfer
Due Date:     Nov.17 2023
"""
import os
import argparse
import socket
import struct
import time
from collections import namedtuple
from enum import Enum
from itertools import count
import matplotlib.pyplot as plt

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

# global variables
HOST_IPV4      = None   # host's dot-notation ip address
WAITING_NS     = None   # waiting time for sending next packet (in nanoseconds)
TIMEOUT_NS     = None   # timeout (in nanoseconds)
args           = None   # user speficied arguments
emu_addr       = None   # address of emulator
requester      = None   # address of requester
window_size    = None   # window size
request_file   = None   # name of the request file
windows_buffer = None   # list of dictionaries, each representing a window
wid            = 0      # index of current window
last_sent_ns   = 0      # timestamp of last sent operation
total_num_pcks = 0      # total number of data packets
total_transmit = 0      # total number of transmissions
end_packet     = None   # end_packet for requester

# debug
packet_records = []

# enum for packet type
class PacketType(Enum):
    ACK     = b'A'
    DATA    = b'D'
    END     = b'E'
    REQUEST = b'R'


def _verify_args():
    """
    Print the values of command-line arguments.
    """
    print(f'{"-" * 30}')
    print(f'Arguments and Global Variables')
    print(f'{"-" * 30}')
    print(f'port:            {args.port}')
    print(f'requester_port:  {args.requester_port}')
    print(f'rate_hz:         {args.rate_hz}')
    print(f'seq_no:          {args.seq_no}')
    print(f'msg_maxlen:      {args.msg_maxlen}')
    print(f'emu_hostname:    {args.emu_hostname}')
    print(f'emu_port:        {args.emu_port}')
    print(f'priority:        {args.priority}')
    print(f'timeout_ms:      {args.timeout_ms}')
    print('-' * 40)
    print(f'emu_addr:        {emu_addr}')
    print(f'HOST_IPV4:       {HOST_IPV4}')
    print(f'WAITING_NS:      {WAITING_NS} ns')
    print(f'TIMEOUT_NS:      {TIMEOUT_NS} ns')


def parse_args():
    """
    Parse command-line arguments, storing them in the global variable `args`
    """
    # init argument parser
    parser = argparse.ArgumentParser(description='sender.py usage')

    # define the required arguments
    parser.add_argument('-p', '--port',           type=int, required=True)
    parser.add_argument('-g', '--requester_port', type=int,              )
    parser.add_argument('-r', '--rate_hz',        type=int, required=True)
    parser.add_argument('-q', '--seq_no',         type=int,              )
    parser.add_argument('-l', '--msg_maxlen',     type=int, required=True)
    parser.add_argument('-f', '--emu_hostname',   type=str, required=True)
    parser.add_argument('-e', '--emu_port',       type=int, required=True)
    parser.add_argument('-i', '--priority',       type=int, required=True)
    parser.add_argument('-t', '--timeout_ms',     type=int, required=True)

    # parse argument and update global variables
    global args, emu_addr, HOST_IPV4, WAITING_NS, TIMEOUT_NS
    args       = parser.parse_args()
    emu_addr   = (socket.gethostbyname(args.emu_hostname), args.emu_port)
    HOST_IPV4  = socket.gethostbyname(socket.gethostname())
    WAITING_NS = (1e9) / args.rate_hz
    TIMEOUT_NS = (1e6) * args.timeout_ms
    

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


def packet_matches(ip_header, udp_header, expected_type):
    """
    This function check input packet
    1. match destination
    2. match packet type
    3. match source (if requester has setup)
    """
    if (ip_header.des_ipv4 != HOST_IPV4 or
        ip_header.des_port != args.port):
        return False

    if (udp_header.p_type != expected_type.value):
        return False
    
    if (expected_type == PacketType.REQUEST and requester is None):
        return True
    
    if (ip_header.src_ipv4 != requester.ipv4 or
        ip_header.src_port != requester.port):
        return False

    return True


def accept_request(sd_socket):
    # global variables
    global requester, window_size, request_file
    curr_dir = os.path.dirname(os.path.abspath(__file__))
    
    # this loop is to wait and accept a request
    while True:
        try:
            # receive and parse packet
            ip_packet, _ = sd_socket.recvfrom(1024)
            ip_header, udp_header, rq_file = parse_IP_header(ip_packet)
            
            if packet_matches(ip_header, udp_header, PacketType.REQUEST):
                # update request-relating global variables
                requester = AddressPair(ip_header.src_ipv4, ip_header.src_port)
                window_size  = udp_header.msg_lenB
                request_file = os.path.join(curr_dir, rq_file.decode('utf-8'))
                return

        except BlockingIOError:
            pass
        

def _verify_request():
    print(f'requester    {requester}')
    print(f'window_size  {window_size}')
    print(f'request_file {request_file}')


def _verify_windows_buffer():
    # seperate line
    SEP_LINE = '-' * 45

    # for each window
    for i, window in enumerate(windows_buffer):
        print(f'{SEP_LINE} Window[{i}]')

        # display each packet-management-unit
        for seq_no, packet in window.items():
            print(f'seq_no         {seq_no}')

            for key, value in packet.items():
                if key == 'data_packet':
                    print(f'{key:{15}}{value[26:30]}')
                else:
                    print(f'{key:{15}}{value}')
            print()


def create_packet(packet_type, seq_no, chunk):
    """
    Create and return a network packet with specified fields.

    Parameters:
        packet_type: Type of the packet
        seq_no: Sequence number for the packet
        chunk: Data payload to be included in the packet

    Returns:
        ip_packet: A network packet ready to be transmitted.
    """
    # prepare udp fields in network byte order
    p_type   = packet_type.value
    seq_no   = socket.htonl(seq_no);
    msg_lenB = socket.htonl(len(chunk));

    # construct udp_packet
    udp_header = struct.pack('=cII', p_type, seq_no, msg_lenB)
    udp_packet = udp_header + chunk

    # prepare ip packet fields
    priority = args.priority
    src_ipnl = struct.unpack('!I', socket.inet_aton(HOST_IPV4))[0]
    src_port = socket.htons(args.port)
    des_ipnl = struct.unpack('!I', socket.inet_aton(requester.ipv4))[0]
    des_port = socket.htons(requester.port)
    udp_lenB = socket.htonl(len(udp_packet))

    # pack ip fields to create ip header
    ip_fields = (priority, src_ipnl, src_port, des_ipnl, des_port, udp_lenB)
    ip_header = struct.pack('=BIHIHI', *ip_fields)
    ip_packet = ip_header + udp_packet
    
    return ip_packet


def create_packets_from_file():
    # init windows_buffer
    global windows_buffer
    windows_buffer = [{}]

    # init a seq_no generator
    sequence = count(start=1)

    # read the request file
    with open(request_file, 'rb') as file:
        while True:
            chunk = file.read(args.msg_maxlen)

            if not chunk: 
                break  # end of file
            
            # if current window is full, create a new window
            if len(windows_buffer[-1]) == window_size:
                windows_buffer.append({})

            # create a wrapped DATA packet and append it to buffer
            seq_no = next(sequence)
            packet = create_packet(PacketType.DATA, seq_no, chunk)

            windows_buffer[-1][seq_no] = {
                'data_packet' : packet,
                'ack'         : False,
                'resend_left' : 6,
                'last_sent_ns': 0,
            }
    # create the END packet
    global end_packet, total_num_pcks
    seq_no = next(sequence)
    end_packet = create_packet(PacketType.END, seq_no, bytes())
    total_num_pcks = seq_no - 1;
    

def process_ack_packet(ip_packet):
    # parse parcket
    ip_header, udp_header, _ = parse_IP_header(ip_packet)
       
    # check if an ACK packet is intended sent for this host    
    if not packet_matches(ip_header, udp_header, PacketType.ACK):
        return
    
    # update ACK status for DATA packet with specific seq_no
    for i in range(wid, -1, -1):
        if udp_header.seq_no in windows_buffer[i]:
            windows_buffer[i][udp_header.seq_no]['ack'] = True
            break


def _verify_current_window():
    """
    Print out the info of current window
    """
    print(f'Finish sending window-[{wid}]')
    curr_window = windows_buffer[wid]

    for seq_no in sorted(curr_window.keys()):
        resend_time = 5 - curr_window[seq_no]['resend_left']
        print(f"seq_no: {seq_no:3}", end="\t")
        print(f"resend_times: {resend_time:2}", end="\t")
        print(f"ack: {curr_window[seq_no]['ack']}")
    print()


def send_data_packet(sd_socket):
    global last_sent_ns, windows_buffer, wid, total_transmit
    curr_window = windows_buffer[wid]

    done_counter = 0
    # process packets in current window
    for seq_no, packet in curr_window.items():
        # packet was sent (with ack received) or ran out of retries
        if packet['ack'] or packet['resend_left'] < 0: 
            done_counter += 1
            continue
        
        # within timeout, waiting for ack...
        if time.time_ns() - packet['last_sent_ns'] < TIMEOUT_NS:
            continue
        
        # abandon the packet
        if (packet['resend_left'] == 0):
            packet['resend_left'] -= 1
            print(f'Warning: packet with seq_no ({seq_no}) has been abandoned.')
            continue

        # the time elapsed is within the required waiting time
        if time.time_ns() - last_sent_ns < WAITING_NS:
            continue

        # send DATA packet
        sd_socket.sendto(packet['data_packet'], emu_addr)
        last_sent_ns = time.time_ns()
        total_transmit += 1

        # update packet fields
        packet['last_sent_ns'] = last_sent_ns
        packet['resend_left'] -= 1

        packet_records.append((seq_no, last_sent_ns))
        return

    # check if tasks in this window are all completed
    if done_counter == len(curr_window):
        _verify_current_window()
        wid += 1


def send_end_packet(sd_socket):
    # wait if needed
    time_wait_sec = (last_sent_ns + WAITING_NS - time.time_ns()) / 1e9;
    time.sleep(max(0, time_wait_sec))
    
    # send end packet
    sd_socket.sendto(end_packet, emu_addr)

    # print out the observed packets lost rate:
    num_retransmit = total_transmit - total_num_pcks
    pcks_loss_rate = num_retransmit / total_transmit
    
    print(f'number of retransmisson:      {num_retransmit}');
    print(f'total number of transmission: {total_transmit}');
    print(f'observed packets loss rate:   {pcks_loss_rate * 100:.2f}%');
    

def _write_sending_time_data():
    curr_dir = os.path.dirname(os.path.abspath(__file__))
    output_f = os.path.join(curr_dir, 'sending_time_data.txt')

    with open(output_f, 'w') as file:
        for seq_no, sending_time_ns in packet_records:
            file.write(f"{seq_no} {sending_time_ns}\n")


def main():
    """
    Perform required setup tasks and run this sender.
    """
    parse_args()
   
    # create a socket
    sd_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sd_socket.setblocking(False)
    sd_socket.bind(('0.0.0.0', args.port))

    # check and verify request
    accept_request(sd_socket)
    _verify_request()

    # load request file in buffer
    create_packets_from_file()
    
    # working loop
    while wid < len(windows_buffer):
        try:
            # receive and process ACK packets
            ip_packet, _ = sd_socket.recvfrom(8192)
            process_ack_packet(ip_packet)
            
        except BlockingIOError:
            pass
        # process packets in each window
        send_data_packet(sd_socket)
    
    # send END packet
    send_end_packet(sd_socket)
    sd_socket.close()
    
    #_verify_windows_buffer()
    #_write_sending_time_data()

if __name__ == '__main__':
    main()