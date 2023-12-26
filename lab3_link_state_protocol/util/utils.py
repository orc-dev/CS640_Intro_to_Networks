"""
File Name:    sender.py
Author:       Xin Cai
Email:        xcai72@wisc.edu
Date:         Nov.18 2023

Description:  This auxiliary program updates the data files with the hostname 
              of the current CS machine, facilitating testing purposes.

command:      python3 utils.py

Course:       CS 640
Instructor:   Prof. Paul Barford
Assignment:   3. Network Emulator and Reliable Transfer
Due Date:     Dec.11 2023
"""

import socket

HOST_NAME = socket.gethostname()
HOST_IPV4 = socket.gethostbyname(HOST_NAME)

def print_file(file_path):
    print(f"'{file_path}' has been refreshed with current host '{HOST_NAME}':")
    with open(file_path, 'r') as file:
        content = file.read()
        print(content)


def refresh_tracker_file(filename):
    buffer = []

    with open(filename, 'r') as file:
        for line in file:
            parts = line.strip().split(" ")
            parts[2] = HOST_NAME
            buffer.append(parts)

    with open(filename, 'w') as file:
        for record in buffer:
            file.write(' '.join(record) + '\n')


def refresh_topo_file(filename):
    buffer = []
    # read original file, update host name
    with open(filename, 'r') as file:
        for line in file:
            addrs = line.strip().split(" ")
            for i, addr in enumerate(addrs):
                item = addr.strip().split(",")
                item[0] = HOST_IPV4
                addrs[i] = ','.join(item)
            
            buffer.append(addrs)

    # write updated back
    with open(filename, 'w') as file:
        for addrs in buffer:
            file.write(' '.join(addrs) + '\n')


def main():
    # refresh table file with current host name
    file_list = ['data/topo1.txt', 
                 'data/topo2.txt',
                 'data/topo3.txt']
    
    for f in file_list:
        refresh_topo_file(f)
        print_file(f)

    tracker = 'data/tracker.txt'
    refresh_tracker_file(tracker)
    print_file(tracker)
    
    
if __name__ == "__main__":
    main()