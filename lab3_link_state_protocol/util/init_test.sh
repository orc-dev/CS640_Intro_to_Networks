#!/bin/bash

# File Name:    init_test.sh
# Author:       Xin Cai
# Email:        xcai72@wisc.edu
# Date:         Nov.18 2023
#
# Description:  Create a new instance of test folder and relative subfolders,
#               copy and organize data files and source files to corresponding
#               subfolders.
#
# command:      ./init_test.sh
#
# Course:       CS 640
# Instructor:   Prof. Paul Barford
# Assignment:   3. Network Emulator and Reliable Transfer
# Due Date:     Dec.11 2023

# Remove all files and folders in the 'test' folder
rm -rf ./test/*

# Create 9 subfolders in the 'test' folder
mkdir ./test/{e0,e1,e2,e3,e4,e5,e6,r7,s8,s9,trace}

# Copy 'emulator.py' and topo files to each 'e*' folder
for folder in ./test/e*; do
    cp ./src/emulator.py ./data/topo{1..3}.txt "$folder"
done

# Copy 'trace.py' to 'trace' folder
cp ./src/trace.py ./test/trace/

# Copy 'requester.py'
for folder in ./test/r*; do
    cp ./src/requester.py ./data/tracker.txt "$folder"
done

# Copy 'sender.py'
for folder in ./test/s*; do
    cp ./src/sender.py "$folder"
done

# split and move file chunks to sender's folders
split -n 2 -d ./data/compilers.txt temp
mv temp00 ./test/s9/compilers.txt
mv temp01 ./test/s8/compilers.txt