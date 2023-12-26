import socket

def print_file(file_path):
    with open(file_path, 'r') as file:
        content = file.read()
        print(content)


def refresh_table_file(filename):
    # get host name
    HOST_NAME = socket.gethostname()
    buffer = []

    # read original file, update host name
    with open(filename, 'r') as file:
        for line in file:
            parts = line.strip().split(" ")
            parts[0] = HOST_NAME
            parts[2] = HOST_NAME
            parts[4] = HOST_NAME
            buffer.append(parts)

    # write updated back
    with open(filename, 'w') as file:
        for record in buffer:
            file.write(' '.join(record) + '\n')


def refresh_tracker_file(filename):

    HOST_NAME = socket.gethostname()
    buffer = []

    with open(filename, 'r') as file:
        for line in file:
            parts = line.strip().split(" ")
            parts[2] = HOST_NAME
            buffer.append(parts)

    with open(filename, 'w') as file:
        for record in buffer:
            file.write(' '.join(record) + '\n')

# python3 utils.py
def main():
    # refresh table file with current host name
    path_table = 'data/table.txt'
    path_tracker = 'data/tracker.txt'

    refresh_table_file(path_table)
    print_file(path_table)
    refresh_tracker_file(path_tracker)
    print_file(path_tracker)
    
if __name__ == "__main__":
    main()