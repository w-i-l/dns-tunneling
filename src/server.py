import socket
from datetime import datetime
import random
import os

from dns_errors import DNSTunnelingDetectedError, CLOSE_FLAG, OK_FLAG, RESEND_FLAG
from dns_header import DNSHeader, DNSHeaderFlags
from dns_packet import DNSPacket
from dns_answear import DNSAnswear
from dns_question import DNSQuestion
from dns_enums import *
from utils import verify_dns_server_ip


DNS_SERVER_IP = None
while not verify_dns_server_ip(DNS_SERVER_IP):
    DNS_SERVER_IP = input("Enter the IP address of the DNS server: ")
GOOGLE_DNS_IP = '8.8.8.8'
DNS_PORT = 53

def redirect_to_google(query: bytes) -> tuple[bytes, DNSHeaderResponseCode]:
    '''
    Redirects the query to google and returns the response data and response code
    '''

    google_connection = socket.socket(
        socket.AF_INET, # IPv4 
        socket.SOCK_DGRAM # UDP
    )

    # send the original query to google
    google_connection.sendto(query, (GOOGLE_DNS_IP, DNS_PORT))
    
    google_data, _ = google_connection.recvfrom(1024)
    google_connection.close()

    # get the response code from the google response
    dns_header = DNSHeader(google_data)
    response_code = dns_header.flags.rcode

    return google_data, response_code


def handle_tunneling(filename: str, address: str, connection: socket.socket):
    '''
    Handles the tunneling by sending the file back to the client
    as chunks of maximum 512 bytes encoded in TXT records
    it uses the index of the chunk to send the chunks in order
    and waits for the client to acknowledge the packet
    '''
    try:
        f = open(f'files/{filename}', 'r')
    except FileNotFoundError:
        print(f"File {filename} not found")
        connection.sendto(bytes(CLOSE_FLAG, 'utf-8'), address)
        return
    
    filesize = os.path.getsize(f'files/{filename}')

    # it represnets the index of a chunk
    # it can be at most 255
    index = 0

    def build_packet() -> bytes:
        header = DNSHeader(create_empty=True)
        header.id = random.randint(0, 65535)
        header.flags = DNSHeaderFlags(
            qr=DNSHeaderQR.RESPONSE,
            opcode=DNSHeaderOPCODE.QUERY,
            aa=DNSHeaderAuthoritiveAnswear.NON_AUTHORITIVE,
            tc=DNSHeaderTruncated.NOT_TRUNCATED,
            rd=DNSHeaderRecursionDesired.NO_RECURSION,
            ra=DNSHeaderRecursionAvailable.NO_RECURSION,
            rcode=DNSHeaderResponseCode.NO_ERROR
        )
        header.questions_count = 1
        header.answers_count = 1
        header.authority_count = 0
        header.additional_count = 0

        question = DNSQuestion(create_empty=True)
        question.domain = filename
        question.qtype = DNSQuestionType.TXT
        question.qclass = DNSQuestionClass.IN

        header_bytes = header.as_bytes()
        question_bytes = question.as_bytes()

        return header_bytes + question_bytes

    # loop through the file and send the chunks
    while True:
        packet_data = build_packet()
        packet_length = len(packet_data)

        answear_bytes = b''
        answear_bytes += b'\xc0\x0c'
        answear_bytes += DNSQuestionType.TXT.value.to_bytes(2, 'big')
        answear_bytes += DNSQuestionClass.IN.value.to_bytes(2, 'big')
        answear_bytes += (1200).to_bytes(4, 'big') # TTL

        answear_length = len(answear_bytes) + 2 # 2 bytes for the length of the rdata

        '''
        The DNS payload is limited to 512 bytes so we need to split the file data into chunks
        As the TXT record is split into chunks of 255 bytes we will split the file data into chunks of 255 bytes
        So if the total length of the file data is 512 bytes we will have maximum 2 chunks

        A chunk will have the following format:
        - 1 byte for the length of the chunk
        - n bytes of data

        As the index can be at most 255 we will use 1 byte for the index
        it will be the last byte of the chunk
        '''

        remaining_bytes = filesize - f.tell() # remaining bytes which can be read
        additional_bytes_length = 1 if remaining_bytes <= 255 else 2 # the length bytes for txt data chunks 
        file_data_legth = 512 - (packet_length + answear_length + additional_bytes_length + 1) # index byte

        file_data = f.read(file_data_legth)
        file_data_legth = len(file_data) + 1 # 1 byte for the index
        file_data = file_data.encode('utf-8')

        # if we reached the end of the file
        if not file_data:
            break
        
        # encoding the length of the rdata
        answear_bytes += (file_data_legth + additional_bytes_length).to_bytes(2, 'big')

        # encoding file data
        max_length = min(255, file_data_legth)

        answear_bytes += max_length.to_bytes(1, 'big') # length of the first txt chunk
        answear_bytes += file_data[:max_length]

        # second chunk length
        max_length = max(0, file_data_legth - 255)
        # if there is a second chunk
        if max_length > 0:
            answear_bytes += max_length.to_bytes(1, 'big') # length of the second txt chunk
            file_data = file_data[255:] # remove the first chunk
            answear_bytes += file_data[:max_length]

        answear_bytes += index.to_bytes(1, 'big') # index of the chunk

        # send the packet
        packet = packet_data + answear_bytes
        connection.sendto(packet, address)

        # wait for the client to acknowledge the packet
        # if the client does not acknowledge the packet in 50ms resend it
        connection.settimeout(1) # 1 second
        try:
            curent_date = datetime.strftime(datetime.now(), "%d-%m-%Y %H:%M:%S")
            print(f"[{curent_date}] Waiting for ack")
            while True:
                data, _ = connection.recvfrom(1024)

                curent_date = datetime.strftime(datetime.now(), "%d-%m-%Y %H:%M:%S")
                if data == bytes(OK_FLAG, 'utf-8'):
                    print(f"[{curent_date}] Received ack for {filename}")
                    break
                elif data == bytes(RESEND_FLAG, 'utf-8'):
                    print(f"[{curent_date}] Resending {filename}")
                    connection.sendto(packet, address)

        except socket.timeout:
            print(f"[{curent_date}] Resending {filename} - timeout")
            connection.sendto(packet, address)

        # increment the index
        index += 1
    
    # send the close flag to the client
    close_flag = bytes(CLOSE_FLAG, 'utf-8')
    connection.sendto(close_flag, address)
    try:
        while True:
            data, _ = connection.recvfrom(1024)
            if data == bytes(OK_FLAG, 'utf-8'):
                break
            elif data == bytes(RESEND_FLAG, 'utf-8'):
                connection.sendto(close_flag, address)
    except socket.timeout:
        close_flag = bytes(CLOSE_FLAG, 'utf-8')
        connection.sendto(close_flag, address)

    curent_date = datetime.strftime(datetime.now(), "%d-%m-%Y %H:%M:%S")
    print(f"[{curent_date}] Sent close flag for {filename}")

    # set the connection to blocking for the next request
    connection.setblocking(True)
    f.close()


def main():
    connection = socket.socket(
        socket.AF_INET, # IPv4 
        socket.SOCK_DGRAM # UDP
    )
    
    print(f"Starting DNS server on {DNS_SERVER_IP}:{DNS_PORT}")
    connection.bind((DNS_SERVER_IP, DNS_PORT))

    DNSAnswear.load_zones()

    while True:
        print("--------------------")
        data, address = connection.recvfrom(1024) # buffer size
        
        if len(data) < 12:
            print(f"Received invalid packet from {address}")
            continue

        curent_date = datetime.strftime(datetime.now(), "%d-%m-%Y %H:%M:%S")
        packet = DNSPacket(data)
        print(f"[{curent_date}] Received request for \"{packet.question.domain}\"")
        
        # build the response if possible and not tunneling is detected
        try:
            response_data, response_code = packet.build_response()
        except DNSTunnelingDetectedError as e:
            filename = e.filename
            print(f"[{curent_date}] Tunneling detected with filename \"{filename}\"")
            handle_tunneling(filename, address, connection)
            continue


        curent_date = datetime.strftime(datetime.now(), "%d-%m-%Y %H:%M:%S")

        # redirect to google if the domain is not found
        # and recursion is desired
        if response_code == DNSHeaderResponseCode.NAME_ERROR and packet.header.flags.rd == DNSHeaderRecursionDesired.RECURSION:
            print(f"[{curent_date}] Redirecting to Google")

            response_data, response_code = redirect_to_google(data)
            # send the response back to the client
            connection.sendto(response_data, address)

            print(f"[{curent_date}] Responded from Google with {response_code.name} for \"{packet.question.domain}\"")
            continue

        print(f"[{curent_date}] Responded with {response_code.name} for \"{packet.question.domain}\"")
        connection.sendto(response_data, address)


if __name__ == "__main__":
    main()
