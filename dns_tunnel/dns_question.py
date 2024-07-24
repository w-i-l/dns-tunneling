from utils import convert_bytes_to_int
from dns_enums import DNSQuestionType, DNSQuestionClass

class DNSQuestion:
    '''
    A class representing only one DNS question
    '''

    def __init__(self, data: bytes = b'', create_empty: bool = False):
        '''
        The data is the bytes of the question which are offseted by the header bytes (12 bytes)
        '''

        if not create_empty:
            self.data = data
            self.__parse_data()

    def __parse_data(self) -> int:
        '''
        Parses the data and sets the domain, qtype and qclass

        Sets: the index where the question ends
        '''
        
        self.domain, index = self.__read_domain()

        qtype = convert_bytes_to_int(self.data[index:index+2])
        qclass = convert_bytes_to_int(self.data[index+2:index+4])
        self.qtype = DNSQuestionType.init_from(qtype)
        self.qclass = DNSQuestionClass.init_from(qclass)

        self.question_index_end = index + 4

    def __read_domain(self) -> tuple[str, int]:
        '''
        Reads the domain from the data and returns it

        Assuming that the domain is not compressed to points to another part of the packet

        Returns: a tuple of the domain and the index where the domain ends
        '''

        '''
        The domain is a sequence of labels, where each label consists of a length byte followed by that number of bytes
        The domain is terminated by a zero length byte
        https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.2

        Example:
        3www6google3com0 -> www.google.com
        '''
        domain = ''
        index = 0

        while True:
            # read the length of the part
            length = self.data[index]
            if length == 0:
                break

            index += 1
            # read the part and decode it
            domain += self.data[index:index+length].decode('utf-8') + '.'
            index += length
        
        return domain[:-1], index + 1
    
    def as_bytes(self) -> bytes:
        '''
        Convert the DNSQuestion to bytes
        '''
        result_bytes= b''

        # break the domain into parts and encode them
        domain_parts = self.domain.split('.')
        for part in domain_parts:
            # extract the length of the part and encode it
            result_bytes += len(part).to_bytes(1, byteorder='big')
            # encode the part
            result_bytes += part.encode('utf-8')
        # add the terminating zero length byte
        result_bytes += b'\x00'

        result_bytes += self.qtype.value.to_bytes(2, byteorder='big')
        result_bytes += self.qclass.value.to_bytes(2, byteorder='big')

        return result_bytes
    
    def __str__(self) -> str:
        to_return = f"DOMAIN: {self.domain}\n"
        to_return += f"QTYPE: {self.qtype}\n"
        to_return += f"QCLASS: {self.qclass}\n"
        return to_return
    
    def __repr__(self) -> str:
        return self.__str__()
