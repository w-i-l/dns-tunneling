from dns_packet import DNSPacket
from dns_header import DNSHeaderFlags, DNSHeader
from dns_enums import *
from dns_question import DNSQuestion
from dns_answear import DNSAnswear
from dns_errors import DNS_TUNNELING_IDENTIFIER, CLOSE_FLAG, OK_FLAG, RESEND_FLAG
from utils import verify_dns_server_ip

import random
import socket

class Client:

    @classmethod
    def _generate_id(cls) -> int:
        id = 0
        for i in range(0, 16):
            id = id << 1
            id = id | random.randint(0, 1)
        return id

    @classmethod
    def build_query_packet(cls, domain: str) -> DNSPacket:
        header_flags = DNSHeaderFlags(
            qr=DNSHeaderQR.QUERY,
            opcode=DNSHeaderOPCODE.QUERY,
            aa=DNSHeaderAuthoritiveAnswear.NON_AUTHORITIVE,
            tc=DNSHeaderTruncated.NOT_TRUNCATED,
            rd=DNSHeaderRecursionDesired.NO_RECURSION,
            ra=DNSHeaderRecursionAvailable.NO_RECURSION,
            rcode=DNSHeaderResponseCode.NO_ERROR
        )

        header = DNSHeader(create_empty=True)
        header.id = Client._generate_id()
        header.flags = header_flags
        header.questions_count = 1
        header.answers_count = 0
        header.authority_count = 0
        header.additional_count = 0

        question = DNSQuestion(create_empty=True)
        question.domain = domain
        question.qtype = DNSQuestionType.TXT
        question.qclass = DNSQuestionClass.IN

        answear = DNSAnswear(question)

        packet = DNSPacket(create_empty=True)
        packet.header = header
        packet.question = question
        packet.answears = answear

        return packet

DNS_SERVER_IP = None
while not verify_dns_server_ip(DNS_SERVER_IP):
    DNS_SERVER_IP = input("Enter the IP address of the DNS server: ")
DNS_PORT = 53

def send():
    packet = Client.build_query_packet(f'test.txt.www.example.com.{DNS_TUNNELING_IDENTIFIER}')
    packet_bytes = packet.encode()

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(packet_bytes, (DNS_SERVER_IP, DNS_PORT))
        
        '''
        Receive the data from the server and write it to a file
        We can only store 255 chunks of data as the index is a byte
        So we will store the data in a list and then write it to a file

        The maximum size of a TXT record can be up to ~480 bytes
        So we can store up to 255 * 480 bytes of data = 122400 bytes = 122.4 KB
        '''
        data_d = [None for _ in range(255)]

        while True:
            data, _ = s.recvfrom(1024)

            # if the data is the close flag then we break
            if data == bytes(CLOSE_FLAG, 'utf-8'):
                s.sendto(bytes(OK_FLAG, 'utf-8'), (DNS_SERVER_IP, DNS_PORT))
                print("Closed connection")
                break
            
            packet = DNSPacket(data, read_answear=True)

            # TXT record data is the data of the answears without the last byte which is the index
            data = packet.answears.data[:-1]
            index = packet.answears.data[-1]
            index = int(index)
            
            data = data.decode('utf-8')
            try:
                data_d[index] = data
            except IndexError: # bigger file than expected
                break

            # fake packet loss
            if random.randint(0, 1) < 0.5:
                # acknowledge the received data
                s.sendto(bytes(RESEND_FLAG, 'utf-8'), (DNS_SERVER_IP, DNS_PORT))
            else:
                # acknowledge the received data
                s.sendto(bytes(OK_FLAG, 'utf-8'), (DNS_SERVER_IP, DNS_PORT))

    # write the data to a file
    print("Writing the data to a file")
    with open('files/received.txt', 'w+') as f:
        for data in data_d:
            if data:
                f.write(data)
    
    print("Data written to files/received.txt")

if __name__ == '__main__':
    send()