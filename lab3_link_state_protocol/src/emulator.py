"""
File Name:    emulator.py
Author:       Xin Cai
Email:        xcai72@wisc.edu
Date:         Nov.18 2023

Description:  This program implements a simple version of the Link State 
              Protocol on the emulators, which dynamicall transmits any
              local topology change to the whole network and forward packets
              along the shortest path.

Arguments:
              -p, --port     : emulator port
              -f, --filename : topology filename

command:      python3 emulator.py -p <port> -f <filename>

Course:       CS 640
Instructor:   Prof. Paul Barford
Assignment:   3. Link State Routing
Due Date:     Dec.11 2023
"""
import argparse
import socket
import queue
import struct
import time
import signal
import os
from collections import namedtuple
from enum import Enum
from datetime import datetime
from functools import reduce
from operator import or_

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

# lightweight class storing seq_no and LSA
class LinkState:
    def __init__(self, seq_no, lsa):
        self.seq_no = seq_no   # largest sequence number for the link state
        self.lsa    = lsa      # binary representation of the link state

    def __str__(self):
        return f"LinkState({self.seq_no}, {bin(self.lsa)})"

# lightweight class storing the cost and next_hop id of
# the shortest path from current node to some destination node
class Path:
    def __init__(self, cost, nxt_id):
        self.cost   = cost
        self.nxt_id = nxt_id

# lightweight class organizes HelloMessage relating fields
class HelloManager:
    def __init__(self):
        self.packet      = None
        self.lastsent_ns = 0
        self.RESENT_NS   = int(1e8)
        self.TIMEOUT_NS  = int(1e9)
        self.lastrecv_ns = {}

# lightweight class logs link state updating info
class LinkStateLog:
    def __init__(self):
        self.id      = None
        self.old_seq = None
        self.old_lsa = None
        self.new_seq = None
        self.new_lsa = None
        self.place   = None
        
    def update_seq(self, old, new, place):
        self.old_seq = old
        self.new_seq = new
        self.place   = place

    def update_lsa(self, id, old, new):
        self.id      = id
        self.old_lsa = old
        self.new_lsa = new


# global variables
HOST         = None    # host address pair
args         = None    # user specified arguments
topo_tb      = None    # initial topology of network: node -> neighbors
addr_tb      = None    # sorted list containing node address of the network
host_id      = None    # node id of host
nid_tb       = None    # node address -> nid
LSA_TB       = None    # nid -> LinkState
FWD_TB       = None    # forward table
task_q       = None    # task queue for normal tasks
emu_running  = None    # global flag controls the running of the emulator
TOTAL_NODES  = None    # total number of node in this network
HELLO        = None    # an instancce of HelloManager for this emulator
confirmed    = None    # data structure used in forward search
LSA_LOG      = None    # link state log
TTL_INIT     = 32      # inital TTL for LSA packet
FLOOD_REQ_ID = None    # sender's node ID for an LSA packet with seq_no zero
print_count  = 0       # forward table printing counter

def parse_args():
    """
    Parse command-line arguments, storing them in the global variable `args`
    """
    # init argument parser
    parser = argparse.ArgumentParser(description='emulator.py usage')

    # define the required arguments
    parser.add_argument('-p', '--port',       type=int, required=True)
    parser.add_argument('-f', '--filename',   type=str, required=True)
    
    # parse argument and initialize global variables
    global args, task_q, LSA_LOG, HOST, HELLO
    args    = parser.parse_args()
    task_q  = queue.Queue()
    LSA_LOG = LinkStateLog()

    HOST  = AddressPair(socket.gethostbyname(socket.gethostname()), args.port)
    HELLO = HelloManager()
    HELLO.packet = create_packet(
        packet_type=PacketType.HELLO,
        seq_no=0,
        chunk=bytes(),
        msg_lenB=0,
        prio=0,
        des=HOST,
        TTL=-1,
        src=HOST
    )


def _show_args():
    """
    Verify and print the values of command-line arguments.
    """
    print(f'{"-" * 30}')
    print(f'Arguments and Global Variables')
    print(f'{"-" * 30}')
    print(f'file name:   {args.filename}')
    print(f'host name:   {socket.gethostname()}')
    print(f'HOST.ipv4:   {HOST.ipv4}')
    print(f'HOST.port:   {HOST.port}')


def _print_lsa_log():
    """
    Output the reason for the update of the forward table.
    """
    debug = False
    if not debug: return

    if LSA_LOG.id == None:
        print(f'Cause of updates: Default topology setup completed.')
    else:
        old_list = get_active_nid_list(LSA_LOG.old_lsa)
        new_list = get_active_nid_list(LSA_LOG.new_lsa)
        print(f'Cause of updates: '
              f'LSA changed at \'{LSA_LOG.place}\' node {LSA_LOG.id} '
              f'replace No.{LSA_LOG.old_seq} {old_list} '
              f'with No.{LSA_LOG.new_seq} {new_list}\n')


def read_topology():
    """
    Reads the specified topology file to gather information about the current
    status of all nodes and links within the network. Subsequently, constructs
    data structures to represent the link states and related information.
    """
    global topo_tb, addr_tb, host_id, nid_tb, LSA_TB, TOTAL_NODES
    topo_tb = {}    # key:   node_addr  -> list of address of neighbors
    addr_tb = []    # index: nid        -> node_addr
    nid_tb  = {}    # key:   node_addr  -> nid
    LSA_TB  = []    # index: nid        -> LinkState

    # build path for tolology file in current directory
    current_dir = os.path.dirname(os.path.abspath(__file__))
    topology_fp = os.path.join(current_dir, args.filename)
    
    # open and read topology file
    with open(topology_fp, 'r') as file:
        for line in file:
            addrs = line.strip().split(' ')
            head  = None

            for i, addr in enumerate(addrs):
                item = addr.strip().split(',')
                node = AddressPair(ipv4=item[0], port=int(item[1]))

                if i == 0:
                    head = node
                    addr_tb.append(head)
                    topo_tb[head] = []
                else:
                    topo_tb[head].append(node)

    # sort neibs for each node
    for node, neibs in topo_tb.items():
        topo_tb[node] = sorted(neibs)
    
    # sort nodes, and build nid_tb
    addr_tb.sort()
    for i, node in enumerate(addr_tb):
        nid_tb[node] = i
    
    # update host_id and total nodes in network
    host_id     = nid_tb[HOST]
    TOTAL_NODES = len(addr_tb)

    # build the HELLO.lastrecv_ns
    for neib in topo_tb[HOST]:
        HELLO.lastrecv_ns[neib] = 0

    # build LSA_TB, newly emerged node must init seq_no with -1 .......... [!!]
    for node in addr_tb:
        lsa = reduce(or_, (1 << nid_tb[x] for x in topo_tb[node]), 0)
        LSA_TB.append(LinkState(seq_no=-1, lsa=lsa))


def _display_topo():
    """
    Print the topology table in a structured format.
    """
    # display addr_tb
    print()
    print('-' * 30)
    print('Assigned Numbers for Each Node')
    print('-' * 30)
    print(f' No.|   IPv4 Address   | port')
    print('-' * 30)

    for i, node in enumerate(addr_tb):
        print(f' {i:2} |  {node.ipv4:15} |{node.port:5}')
    
    # display topo_tb with nid
    m = '|'
    print(f'\n> INITIAL NETWORK TOPOLOGY:\n{m}')
    print(f'{m}  - each node is represented by its assigned number')
    print(f'{m}  - the host node is indicated by the \'*\' symbol')
    print(f'{m}')
    for node, neibs in topo_tb.items():
        prefix = f'{m} *' if node == HOST else f'{m}  '
        neib_id_list = list(map(lambda x: nid_tb[x], neibs))
        print(f'{prefix}{nid_tb[node]:2} -> {neib_id_list}')


def create_packet(packet_type, seq_no, chunk, msg_lenB, prio, des, TTL, src):
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
    seq_no   = socket.htonl(seq_no);
    msg_lenB = socket.htonl(msg_lenB);

    # construct udp_packet
    udp_header = struct.pack('=cII', p_type, seq_no, msg_lenB)
    udp_packet = udp_header + chunk

    # prepare ip packet fields
    priority = prio
    src_ipnl = struct.unpack('!I', socket.inet_aton(src.ipv4))[0]
    src_port = socket.htons(src.port)
    des_ipnl = struct.unpack('!I', socket.inet_aton(des.ipv4))[0]
    des_port = socket.htons(des.port)
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


def send_hello_packet(emu_socket):
    """
    Send HelloMessages to immediate neighbors periodically.
    """
    # check timeout condition
    if time.time_ns() - HELLO.lastsent_ns < HELLO.RESENT_NS:
        return
    
    # send HelloMessages to all neighbors
    for neib in topo_tb[HOST]:
        emu_socket.sendto(HELLO.packet, neib)
    
    # update last sent timestamp
    HELLO.lastsent_ns = time.time_ns()


def process_hello_packet(ip_header):
    """
    Updates most recent timestamp of HelloMessages from the neighbor node
    """
    global HELLO
    # check source in neighbor list
    neib = AddressPair(ip_header.src_ipv4, ip_header.src_port)
    if neib in HELLO.lastrecv_ns:
        HELLO.lastrecv_ns[neib] = time.time_ns()


def flood_lsa_packet(emu_socket, link_state, des, TTL, prev=None):
    """
    Flooding LSA packet to the network.
    """
    # create LSA packet
    lsa_packet = create_packet(
        packet_type=PacketType.LSA,
        seq_no=link_state.seq_no,
        chunk=bytes(),
        msg_lenB=link_state.lsa,
        prio=0,
        des=des,
        TTL=TTL,
        src=HOST
    )
    # flood LSA packet ................................................... [!!]
    for neib in topo_tb[HOST]:
        if neib != prev and neib != des:
            emu_socket.sendto(lsa_packet, neib)


def process_local_lsa(emu_socket):
    """
    Checks the timestamps of HelloMessages received from neighbors, updates
    the local link state, and floods the updated link state if a new change 
    is detected.
    """
    global LSA_TB, FLOOD_REQ_ID
    local_copy   = LSA_TB[host_id]
    new_gene_lsa = 0;

    # compute the most recent local link states
    for neib, timestamp in HELLO.lastrecv_ns.items():
        if time.time_ns() - timestamp < HELLO.TIMEOUT_NS:
            new_gene_lsa |= (1 << nid_tb[neib])

    # initiate local LSA flooding on changes or system start ............. [!!]
    if new_gene_lsa != local_copy.lsa or local_copy.seq_no == -1:
        # update local LSA
        LSA_LOG.update_seq(local_copy.seq_no, local_copy.seq_no + 1, 'host')
        LSA_LOG.update_lsa(host_id, local_copy.lsa, new_gene_lsa)
        local_copy.seq_no += 1
        local_copy.lsa = new_gene_lsa
        
        # update forwarding table
        build_forward_table()

        _print_flood_msg(local_copy)
        flood_lsa_packet(emu_socket, local_copy, HOST, TTL_INIT)

    # Initiate local LSA flooding upon external request .................. [!!]
    if FLOOD_REQ_ID is not None:
        _print_flood_msg(local_copy)
        flood_lsa_packet(emu_socket, local_copy, HOST, TTL_INIT)
        FLOOD_REQ_ID = None


def _print_flood_msg(local_copy):
    debug = False
    if not debug: return
   
    seq_no   = local_copy.seq_no
    nid_list = get_active_nid_list(local_copy.lsa)
    suffix   = 'internally initiated'

    if FLOOD_REQ_ID is not None:
        suffix = f'req_id={FLOOD_REQ_ID}'

    print(f'LSA flooding: No.{seq_no} {nid_list}, {suffix}')
   

def process_lsa_packet(emu_socket, ip_header, udp_header, prev):
    """
    Processes a received LinkStateMessage:
     - Updates the local copy if the seq_no is 0 or greater than the local copy
     - Updates forward table if a change of link state is detected
     - Floods the message if the Time-To-Live (TTL) > 0
    """
    global LSA_TB, FLOOD_REQ_ID

    if prev not in nid_tb:
        print(f'ERROR: prev_node {prev} not in network')
        return
    
    # LSA packet's ip_header.des stores the address of flooding origin ... [!!]
    flood_origin = AddressPair(ip_header.des_ipv4, ip_header.des_port)
    TTL          = ip_header.udp_lenB
    seq_no       = udp_header.seq_no
    new_recv_lsa = udp_header.msg_lenB

    # check flood origin
    if flood_origin not in nid_tb:
        print(f'ERROR: flood origin {flood_origin} not in network')
        return
    
    if flood_origin == HOST:
        print(f'ERROR: found self echo <<< seq_no:{seq_no}, '
              f'TTL:{TTL}, lsa:{get_active_nid_list(new_recv_lsa)}')
        return

    # access local copy LSA associated with the src node
    local_copy = LSA_TB[nid_tb[flood_origin]]

    # flood termination check
    if seq_no > 0 and local_copy.seq_no >= seq_no:
        return
    
    # A seq_no of 0 signals the need to flood the local copy LSA ......... [!!]
    if seq_no == 0 and local_copy.seq_no != 0:
        LSA_TB[host_id].seq_no += 1
        FLOOD_REQ_ID = nid_tb[flood_origin]
        #print(f'Recv \'ZERO_seq_no_packet\' from nid({FLOOD_REQ_ID})')
    
    # update seq_no
    LSA_LOG.update_seq(local_copy.seq_no, seq_no, 'external')
    local_copy.seq_no = seq_no

    # check link state
    if (local_copy.lsa != new_recv_lsa):
        LSA_LOG.update_lsa(nid_tb[flood_origin], local_copy.lsa, new_recv_lsa)
        local_copy.lsa = new_recv_lsa
        build_forward_table()

    # flood LSA_packet with TTL is 0
    if TTL > 0:
       flood_lsa_packet(emu_socket, local_copy, flood_origin, TTL - 1, prev)


def process_trace_packet(emu_socket, ip_header):
    """
    Checks TTL and forward new trace packet to next node.
    """
    # extract Link State info
    trc = AddressPair(ip_header.src_ipv4, ip_header.src_port)
    des = AddressPair(ip_header.des_ipv4, ip_header.des_port)
    TTL = ip_header.udp_lenB

    # check trace destination
    if des not in FWD_TB and des != HOST:
        error_message = f'ERROR: {des} not found in current forward table'
        b_message = error_message.encode('utf-8')
        print(error_message)

        error_packet = create_packet(
            packet_type=PacketType.ERROR,
            seq_no=0,
            chunk=b_message,
            msg_lenB=len(b_message),
            prio=0,
            des=des,
            TTL=0,
            src=HOST
        )
        emu_socket.sendto(error_packet, trc)
        return

    # determine where to send
    next_hop = trc if TTL == 0 else FWD_TB[des]
    next_TTL = TTL if TTL == 0 else TTL - 1

    # forward trace packet
    trace_packet = create_packet(
        packet_type=PacketType.TRACE,
        seq_no=0,
        chunk=bytes(),
        msg_lenB=0,
        prio=0,
        des=des,
        TTL=next_TTL,
        src=trc
    )
    emu_socket.sendto(trace_packet, next_hop)


def process_user_packet(ip_header, ip_packet):
    """
    Checks and puts a valid user packet in the task queue.
    """
    # get addresses of destination and next hop
    des = AddressPair(ip_header.des_ipv4, ip_header.des_port)

    if des == HOST:
        print(f'ERROR: drop user packet with des -> emu {host_id}')
        return
    
    if des not in FWD_TB:
        print(f'ERROR: drop user packet with {des} not in farward table')
        return
    
    # put packet in task queue
    task_q.put((ip_packet, FWD_TB[des]))
    

def forward_packet(emu_socket, ip_packet, prev):
    """
    Dispatch packets according to packet type.
    """
    # parse packet
    ip_header, udp_header, _ = parse_IP_header(ip_packet)
    
    # dispatch different type of packets
    match(udp_header.p_type):
        case PacketType.HELLO.value: 
            process_hello_packet(ip_header)

        case PacketType.LSA.value:   
            process_lsa_packet(emu_socket, ip_header, udp_header, prev)

        case PacketType.TRACE.value: 
            process_trace_packet(emu_socket, ip_header)

        case (PacketType.REQUEST.value |
              PacketType.DATA.value |
              PacketType.ACK.value |
              PacketType.END.value):  
            process_user_packet(ip_header, ip_packet)

        case _:
            print(f"ERROR: detected unrecognized type {udp_header.p_type}.")


def get_active_nid_list(lsa):
    """
    Convert the binary encoded `lsa` to a list of addresses of active neighbors
    """
    return [i for i in range(TOTAL_NODES) if (lsa & (1 << i))]
    

def build_forward_table():
    """
    Builds the latest forward table based on current LSAs, where the 
    underlying algorithm is Dijkstra's shortest path algorithm.
    Since all link costs are 1's for this project, we simplify it to
    the naive BFS algorithm for implementation of the forward search.
    """
    # init forward table and temporary queue
    global confirmed, FWD_TB
    confirmed = { host_id: Path(cost=0, nxt_id=None) }
    tentative = queue.Queue()

    for nid in get_active_nid_list(LSA_TB[host_id].lsa):
        tentative.put((nid, Path(cost=1, nxt_id=nid)))
    
    # implement forward search via naive BFS since all link costs are 1
    while tentative.qsize() > 0:
        des_id, path = tentative.get()

        if des_id in confirmed: 
            continue  
        
        confirmed[des_id] = path
        
        for nid in get_active_nid_list(LSA_TB[des_id].lsa):
            if nid not in confirmed:
                tentative.put((nid, Path(path.cost + 1, path.nxt_id)))
 
    # build forward table based on `confirmed`
    FWD_TB = {}
    # remove entry where host as destination
    del confirmed[host_id]   
    for des_id, path in confirmed.items():
        FWD_TB[addr_tb[des_id]] = addr_tb[path.nxt_id]
    
    display_forward_table()


def display_forward_table():
    """
    Display latest forward table with shortest-path cost.
    Only callable from `build_forward_table()`
    """
    global print_count
    print_count += 1;

    # debug: display LSA_TB
    # print(f'\n> LSA_TB:')
    # for i, ls in enumerate(LSA_TB):
    #     print(f'| {i:2} {ls.seq_no:3} {get_active_nid_list(ls.lsa)}')
    # print()

    PREFIX   = '> ' 
    SEP_LINE = PREFIX + ('-' * 60)
    # table header
    print()
    print(f'{PREFIX}{"":19}LATEST FORWARDING TABLE')
    print(SEP_LINE)
    print(f'{PREFIX}{"":7}Destination{"":7}|{"":8}Next Hop{"":9}|{"":2}Cost')
    print(SEP_LINE)

    # print content
    for des, nxt in FWD_TB.items():
        des_id = nid_tb[des]
        nxt_id = nid_tb[nxt]
        print(f'{PREFIX}'
              f' {des_id:2}  {des.ipv4}:{des.port} |'
              f' {nxt_id:2}  {nxt.ipv4}:{nxt.port} |'
              f' {confirmed[des_id].cost:4}')
    # if empty
    if len(FWD_TB) == 0:
        print(f'{PREFIX}{"":22}- empty table -')
    # timestamp
    print(SEP_LINE)
    print(f'{PREFIX}Table printed at: {datetime.now()}, print count: {print_count}\n')
    _print_lsa_log()


def create_route():
    """
    Run the emulator according to the lab specifications.
    """
    global emu_running, HELLO, LSA_TB
    emu_running = True

    # create a socket and set it as non-blocking
    emu_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    emu_socket.setblocking(False)
    emu_socket.bind(('0.0.0.0', HOST.port))
    
    # init last receive time (ns) for hello message
    init_time_ns = time.time_ns()
    for neib in HELLO.lastrecv_ns:
        HELLO.lastrecv_ns[neib] = init_time_ns

    # clearing LSA_TB for dynamic updates from 'live' nodes
    for nid in range(TOTAL_NODES):
        if nid != host_id:
            LSA_TB[nid] = LinkState(seq_no=-1, lsa=0)

    # working loop
    while emu_running:
        try:
            # receive and dispatch packet
            ip_packet, prev = emu_socket.recvfrom(8192)
            forward_packet(emu_socket, ip_packet, prev)

        except BlockingIOError:
            pass

        send_hello_packet(emu_socket)
        process_local_lsa(emu_socket)
        
        if task_q.qsize() > 0:
            emu_socket.sendto(*task_q.get())

    # graceful termination with notification
    emu_socket.close()
    print(f"The emulator on host '{socket.gethostname()}'"
          f" and port '{args.port}' has been terminated.")


def signal_handler(sig, frame):
    """
    Set the emulator flag to terminate (False) with notification.
    """
    global emu_running
    emu_running = False
    print('\nCtrl + C received. Stopping the emulator...')


def main():
    """
    Perform required setup tasks and run this emulator.
    """
    signal.signal(signal.SIGINT, signal_handler)

    parse_args()
    _show_args()

    read_topology()
    #_display_topo()

    build_forward_table()
    create_route()


if __name__ == '__main__':
    main()
