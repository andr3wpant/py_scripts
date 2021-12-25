import sys
import socket
import time
import struct
import select


echo_request_icmp = 8  # код 8, ожидание эха в icmp
timeout = 2  # таймаут в секундах, после его достижения увеличиваем ttl на 1
max_ttl = 30  # максимальное значение ttl


# подсчёт контрольной суммы, rfc1071
def calc_checksum(header):
    checksum = 0
    overflow = 0
    for i in range(0, len(header), 2):
        word = header[i] + (header[i+1] << 8)
        checksum = checksum + word
        overflow = checksum >> 16
        while overflow > 0:
            checksum = checksum & 0xFFFF
            checksum = checksum + overflow
            overflow = checksum >> 16
    overflow = checksum >> 16
    while overflow > 0:
        checksum = checksum & 0xFFFF
        checksum = checksum + overflow
        overflow = checksum >> 16

    checksum = ~checksum
    checksum = checksum & 0xFFFF

    return checksum


def ping(destination_address, icmp_socket, ttl):

    initial_checksum = 0
    #  bbHHh ~ signed char, signed char, unsingned short, unsigned short, signed short
    #           type,          code,        checksum,       id,             sequence
    # type == 8 (8 бит) 
    # code == 0 (8 бит)
    # checksum - контрольная сумма, сначала инициализируем 0 (16 бит)
    # identifier == 0 (16 бит)
    # sequence number == 0 (16 бит)
    initial_header = struct.pack("bbHHh", echo_request_icmp, 0, initial_checksum,  0, 0)

    calculated_checksum = calc_checksum(initial_header)
    header = struct.pack("bbHHh", echo_request_icmp, 0, calculated_checksum, 0, 0)

    icmp_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

    icmp_socket.sendto(header, (destination_address, 1))
    timeout_first_timestamp = time.time()
    socket_response = select.select([icmp_socket], [], [], timeout)

    if socket_response[0] == []:
        print('ttl: {0}\t resp_time: {1} ms\t***\t(Timeout, ttl+=1)'.
              format(ttl,
                     int((time.time() - timeout_first_timestamp) * 1000)))
        return False

    smth, (got_ip, port) = icmp_socket.recvfrom(128)

    hostname = ""
    try:
        host_info = socket.gethostbyaddr(got_ip)
        if len(host_info) > 0:
            hostname = host_info[0]
    except:
        hostname = 'unknown'

    print(' ttl: {0}\t resp_time:{1} ms\t ip: {2}\t{3}\t{4}'.
          format( ttl, int((time.time() - timeout_first_timestamp) * 1000), got_ip, "hostname (if presents):", hostname))

    if got_ip == destination_address:
        return True

    return False


def main():

    if (len(sys.argv) != 2):

        print("Right usage \n")
        print(" python3 tracert.py hostname")
        sys.exit(" Try again ")
    else:

        destination_host = sys.argv[1]

        destination_address = socket.gethostbyname(destination_host)

        print("tracert to {0} ({1}) with maximum {2} hops".
              format(destination_address, destination_host, max_ttl))

        ttl = 1
        icmp_protocol = socket.getprotobyname("icmp")
        while(ttl < max_ttl):

            
            icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp_protocol)
            if (ping(destination_address, icmp_socket, ttl)):
                icmp_socket.close()
                break
            ttl += 1
            icmp_socket.close()
        sys.exit()


if __name__ == "__main__":
    main()
