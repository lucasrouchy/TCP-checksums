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

def pseudo_ip(ip, tcp):
    src, dest = get_ip_bytes(ip)
    tcp_len = tcp_length(tcp)
    header = src + dest + b'\x00' + b'\x06' + tcp_len.to_bytes(2, 'big')
    return header
