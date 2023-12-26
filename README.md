# Lab Projects in CS 640: Intro to Computer Networks
This repo contains two selected projects in CS 640.

#### Lab2: Reliable Transfer
The 'Reliable Transfer' project implements a protocol similar to TCP for reliable data transfer. 
The Requester communicates with Senders by exchanging window size parameters. Senders transmit packets 
in window units, awaiting acknowledgment (ACK) messages, and retransmitting packets in case of timeouts. 
The Requester employs a buffer to store received packets and ensures proper sequencing by leveraging sequence numbers. 
The emulator program emulates routers in the Network Layer, featuring packet queuing and simulated packet drops to mimic 
packet loss events. Various parameters can be configured to simulate diverse network traffic environments.

#### Lab3: Link State Protocol
The 'Link State Protocol' project implements a simplified version of the link-state protocol, 
employing a reliable flooding mechanism to disseminate the latest link state information to all 
routers within a network. Each router dynamically updates its forwarding table to establish the shortest 
path to every reachable host in the network. These updates are designed to be responsive, with each active 
node swiftly adapting to changes resulting from the shutdown or recovery of nodes in the network. The 'trace' 
program is utilized to examine nodes along the shortest path, serving as a testing tool to verify the correctness of the protocol implementation.
