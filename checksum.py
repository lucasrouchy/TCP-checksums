from cgi import parse_header
import socket

 
def get_ip_bytes(ip):
    with open(ip) as fi:
        # getting both IPs
        ip = fi.read().split()
        # setting first ip as source and second for destination
        src, dest = ip[0], ip[1]
        # getting the bytes version using socket library.
        src_bytes = socket.inet_aton(src)
        dest_bytes = socket.inet_aton(dest)
    return src_bytes, dest_bytes


def tcp_length(tcp_file):
    # opening file with in rb mode which is for opening files in binary format for reading.
    with open(tcp_file, 'rb') as tf:
        tcp = tf.read()
        tcp_len = len(tcp)
    return tcp_len

def pseudo_header(ip, tcp):
    src, dest = get_ip_bytes(ip)
    tcp_len = tcp_length(tcp)
    # pseudo header is formed ffrom the scr ip address, dest ip address, reserved bits(zeros), protocol, and tcp length
    p_header = src + dest + b'\x00' + b'\x06' + tcp_len.to_bytes(2, 'big')
    return p_header
def get_checksum(tcp):
    with open(tcp, 'rb') as cf:
        tcp = cf.read()
        # checksum is in every TCP header and is a 2 byte value starting at the 16th bit
        checksum = tcp[16:18]
    checksum = int.from_bytes(checksum, 'big')
    return checksum

def zeroed_tcp_checksum(tcp):
    with open(tcp, 'rb') as tf:
        tcp = tf.read()
        # to zero checksum use the tcp packet but just force zero bits for the checksum bits
        zero_checksum_tcp = tcp[:16] + b'\x00\x00' + tcp[18:]
    # if length is odd padd the last octet with zero bit to form 16 bit word
    if len(zero_checksum_tcp) % 2 ==1:
        zero_checksum_tcp += b'\x00'
    return zero_checksum_tcp

def checksum(p_header, zero_chksum_tcp):
    data = p_header + zero_chksum_tcp
    total = 0
    offset = 0
    # loops through each 16 bit word of data
    while offset < len(data):
        word = int.from_bytes(data[offset:offset+2], 'big')
        total += word
        # carry around for ones compliment and forcing python to give us 16 bit integers
        total = (total & 0xffff) + (total >> 16)
        offset += 2
    # returning ones complement of the sum
    return (~total) & 0xffff


for n in list(range(0,10)):
    # creating pseudo header
    p_header = pseudo_header(f'tcp_addrs_{n}.txt', f'tcp_data_{n}.dat')
    # getting zeroed checksum
    zc_tcp = zeroed_tcp_checksum(f'tcp_data_{n}.dat')
    # checksum is formed with the pseudo header and zeroed checksum
    c_sum = checksum(p_header, zc_tcp)
    # getting original checksum to compare to formed checksum
    og_c_sum = get_checksum(f'tcp_data_{n}.dat')

    if c_sum == og_c_sum:
        print('Pass')
    else:
        print('Fail')


