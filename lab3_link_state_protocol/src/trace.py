"""
File Name:    trace.py
Author:       Xin Cai
Email:        xcai72@wisc.edu
Date:         Nov.21 2023

Description:  A node external to a specified network designed to validate the
              correct implementation of the shortest path algorithm. By 
              specifying a source node and a destination node within the 
              network, this application monitors and records the actual 
              routing path taken by the network.

Arguments:
              -a, --port       : emulator port
              -b, --src_host   : source hostname 
              -c, --src_port   : source port
              -d, --des_host   : destination hostname
              -e, --des_port   : destination port
              -f, --debug_flag : debug flag

command:      python3 trace.py 
                -a <routetrace port> 
                -b <source hostname> 
                -c <source port> 
                -d <destination hostname> 
                -e <destination port> 
                -f <debug option>

Course:       CS 640
Instructor:   Prof. Paul Barford
Assignment:   3. Link State Routing
Due Date:     Dec.11 2023
"""
import argparse
import socket
import struct
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

AddressPair = namedtuple('AddressPair', [
    'ipv4', 
    'port'])

# enum for packet type
class PacketType(Enum):
    ACK     = b'A'    # acknowledge packet type
    DATA    = b'D'    # data packet type
    END     = b'E'    # end packet type
    REQUEST = b'R'    # request packet type
    HELLO   = b'H'    # hello message packet type
    LSA     = b'L'    # link state message packet type
    TRACE   = b'T'    # routetrace packet type
    ERROR   = b'e'    # error packet type

# global variables
args     = None       # command arguments from user
HOST     = None       # Host address(ipv4, port)
SRC      = None       # the source address of the trace task
DES      = None       # the destination address of the trace task
path_buf = None       # a buffer stores node info on shortest path

def parse_args():
    """
    Parse command-line arguments, storing them in the global variable `args`
    """
    # init argument parser
    parser = argparse.ArgumentParser(description='trace.py usage')

    # define the required arguments
    parser.add_argument('-a', '--port',          type=int, required=True)
    parser.add_argument('-b', '--src_hostname',  type=str, required=True)
    parser.add_argument('-c', '--src_port',      type=int, required=True)
    parser.add_argument('-d', '--des_hostname',  type=str, required=True)
    parser.add_argument('-e', '--des_port',      type=int, required=True)
    parser.add_argument('-f', '--debug_flag',    type=int, required=True)
    
    # parse argument and initialize global variables
    global args, HOST, SRC, DES
    args = parser.parse_args()
    HOST = AddressPair(socket.gethostbyname(socket.gethostname()), args.port)
    SRC  = AddressPair(socket.gethostbyname(args.src_hostname), args.src_port)
    DES  = AddressPair(socket.gethostbyname(args.des_hostname), args.des_port)


def _show_args():
    """
    Display the values of command-line arguments.
    """
    SEP_LINE = '-' * 30
    print(SEP_LINE)
    print(f'Arguments and Global Variables')
    print(SEP_LINE)
    print(f'host name: {socket.gethostname()}')
    print(f'HOST addr: {HOST.ipv4}:{HOST.port}')
    print(f'.SRC addr: {SRC.ipv4}:{SRC.port}')
    print(f'.DES addr: {DES.ipv4}:{DES.port}')
    print(f'debug opt: {args.debug_flag}')
    

def create_packet(packet_type, seq_no, chunk, msg_lenB, prio, des_addr, TTL):
    """
    Create and return a network packet with specified fields.

    Parameters:
        ...
        TTL: time_to_live field, if TTL is negative, ignore it;
             otherwise, TTL is encoded in the 'udp_lenB' tag

    Returns:
        ip_packet: A network packet ready to be transmitted.
    """
    # prepare udp fields in network byte order
    p_type   = packet_type.value
    seq_no   = socket.htonl(seq_no)
    msg_lenB = socket.htonl(msg_lenB)

    # construct udp_packet
    udp_header = struct.pack('=cII', p_type, seq_no, msg_lenB)
    udp_packet = udp_header + chunk

    # prepare ip packet fields
    priority = prio
    src_ipnl = struct.unpack('!I', socket.inet_aton(HOST.ipv4))[0]
    src_port = socket.htons(HOST.port)
    des_ipnl = struct.unpack('!I', socket.inet_aton(des_addr.ipv4))[0]
    des_port = socket.htons(des_addr.port)
    udp_lenB = socket.htonl(TTL) if TTL >= 0 else socket.htonl(len(udp_packet))
    
    # pack ip fields to create ip header
    ip_fields = (priority, src_ipnl, src_port, des_ipnl, des_port, udp_lenB)
    ip_header = struct.pack('=BIHIHI', *ip_fields)
    ip_packet = ip_header + udp_packet

    return ip_packet


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
    udp_packet = ip_packet[H_LENGTH:]
    udp_header, b_message = parse_UDP_header(udp_packet)

    return ip_header, udp_header, b_message


def parse_UDP_header(udp_packet):
    """
    Parses an UDP header from input UDP packet

    Args:
        udp_packet (bytes): The UDP packet to be parsed.
        
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
    # extract UDP payload
    b_message = udp_packet[H_LENGTH:]
    return udp_header, b_message


def send_trace_packet(tr_socket, ttl_val):
    """
    Send trace packet to source node in the network
    """
    # check condition
    trace_packet = create_packet(
        packet_type=PacketType.TRACE,
        seq_no=0,
        chunk=bytes(),
        msg_lenB=0,
        prio=0,
        des_addr=DES,
        TTL=ttl_val
    )
    tr_socket.sendto(trace_packet, SRC)
    debug_message(ttl_val)
    

def debug_message(ttl_val=None, send_flag=True, ip_header=None):
    """
    Display debug message if debug flag is assert.
    """
    if not args.debug_flag:
        return
    
    SEP_LINE = '-' * 58
    s = ''    # empty string
    p = '| '  # line prefix char

    # done with debug message
    if ttl_val is None:
        print(f'{p}{SEP_LINE}')
        print()
        return

    if send_flag and ttl_val == 0:
        print()
        print(f'> DEBUG MESSAGES')
        print(f'{p}{SEP_LINE}')
        print(f'{p} Dir. | TTL |{s:7}Src_Addr{s:7}|{s:7}Des_Addr')
        print(f'{p}{SEP_LINE}')

    dir = 'send'
    src = SRC
    des = DES

    if not send_flag:
        dir = 'recv'
        src = AddressPair(ip_header.src_ipv4, ip_header.src_port)
        des = AddressPair(ip_header.des_ipv4, ip_header.des_port)

    record = (f'{p} {dir} |{ttl_val:3}  |'
              f' {f"{src.ipv4}:{src.port}":20} |'
              f' {f"{des.ipv4}:{des.port}":20}')
    print(record)
   

def build_path_table(ttl_val=None, response=None):
    """
    Build and/or display the table
    """
    global path_buf
    
    if ttl_val is None:
        SEP_LINE = '-' * 30
        # display table header
        print()
        print(f'{"":6}SHORTEST PATH TABLE')
        print(SEP_LINE)
        print(f' Hop |{"":6}IPv4{"":7}| Port')
        print(SEP_LINE)

        # display table content
        if path_buf:
            print('\n'.join(path_buf))
        else:
            print(f'{"":7}- empty table -')
        
        print(SEP_LINE)
        return

    # init path buffer
    if ttl_val == 0:
        path_buf = []
    
    # append new record
    new_ttl = ttl_val + 1
    record = f'  {new_ttl:2} | {response.ipv4:16}|{response.port:5}'
    path_buf.append(record)


def _test_display():
    """
    Perform a simple test on format of `build_path_table()`
    """
    addrs = [
        AddressPair("192.177.0.1",     4010),
        AddressPair("192.177.100.121", 4020),
        AddressPair("192.177.0.43",    4030),
        AddressPair("192.177.64.0",    4040),
        AddressPair("192.177.0.107",   4050),
        AddressPair("192.177.0.1",     4010),
        AddressPair("192.177.100.21",  4020),
        AddressPair("192.177.0.43",    4030),
        AddressPair("192.177.64.0",    4040),
        AddressPair("192.177.0.107",   4050),
        AddressPair("192.177.0.1",     4010),
        AddressPair("192.177.100.21",  4020),
        AddressPair("192.177.0.43",    4030),
        AddressPair("192.177.64.0",    4040),
        AddressPair("192.177.0.107",   4050),
    ]
    for i in range(5):
        build_path_table(i, addrs[i])


def main():
    parse_args()
    _show_args()
    #_test_display()
    
    # create socket
    tr_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tr_socket.setblocking(False)
    tr_socket.bind(('0.0.0.0', HOST.port))

    # first sending
    ttl_val = 0
    send_trace_packet(tr_socket, ttl_val)

    # prepare strings
    host_str = f'{HOST.ipv4}:{HOST.port}'
    term_msg = f'routetrace({host_str}) terminates unexpectedly.'
    
    while True:
        try:
            ip_packet, prev = tr_socket.recvfrom(8192)
            ip_header, udp_header, b_message = parse_IP_header(ip_packet)

            recv_TTL  = ip_header.udp_lenB
            responder = AddressPair(*prev)

            # check packet type
            if udp_header.p_type == PacketType.ERROR.value:
                term_msg = b_message.decode('utf-8')
                break

            if udp_header.p_type != PacketType.TRACE.value:
                continue
            
            if recv_TTL != 0:
                print(f'ERROR: received TRACE packet with TTL = {recv_TTL}')
            
            build_path_table(ttl_val, responder)
            debug_message(recv_TTL, False, ip_header)

            if responder == DES:
                term_msg = f'routetrace({host_str}) task completed.'
                break
            else:
                ttl_val += 1
                send_trace_packet(tr_socket, ttl_val)

        except BlockingIOError:
            pass
    
    # termination
    tr_socket.close()
    debug_message()
    build_path_table()
    print(term_msg)


if __name__ == '__main__':
    main()
