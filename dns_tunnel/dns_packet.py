from dns_header import DNSHeader
from dns_question import DNSQuestion
from dns_enums import DNSHeaderResponseCode
from dns_answear import DNSAnswear
from dns_errors import DNSTunnelingDetectedError

from typing import Self

class DNSPacket:
    '''
    A class representing a DNS packet split into header, question and answears
    '''

    def __init__(self, data: bytes = b'', create_empty: bool = False, read_answear: bool = False):
        '''
        Only one of the parameters should be True
        - data is the bytes of the packet which are offseted by the header bytes (12 bytes)
        - create_empty is True if the packet should be created empty
        - read_answear is True if the answears should be read from the data
        '''

        if not create_empty:
            self.data = data
            self.header = DNSHeader(data)
            self.question = DNSQuestion(data[12:])

            if read_answear:
                question_index_end = self.question.question_index_end + 12 # 12 bytes for the header
                self.answears = DNSAnswear(answears=data[question_index_end:])
            else:
                self.answears = DNSAnswear(question=self.question)

    def build_response(self) -> tuple[bytes, DNSHeaderResponseCode]:
        '''
        Builds the response bytes for the packet from the current packet

        Returns the response bytes and the response code

        Raises DNSTunnelingDetectedError if the tunneling identifier is detected
        '''

        response_question_bytes = self.question.as_bytes()
        response_answears, answears_count = self.answears.build_response()

        # detected dns tunneling
        if isinstance(response_answears, str):
            raise DNSTunnelingDetectedError(response_answears)

        response_code = DNSHeaderResponseCode.NO_ERROR if isinstance(response_answears, bytes) else response_answears
        authority_bytes = self.answears.get_authority()

        response_header = self.header.build_response_header(
            answers_count=answears_count,
            response_code=response_code,
            authority_count=1 if authority_bytes else 0
        )
        response_header_bytes = response_header.as_bytes()

        response_answears_bytes = response_answears if isinstance(response_answears, bytes) else b''
        authority_bytes = authority_bytes if authority_bytes else b''

        response_bytes = response_header_bytes + response_question_bytes + response_answears_bytes + authority_bytes
        
        return response_bytes, response_code
    
    def encode(self) -> bytes:
        '''
        Encodes the packet to bytes
        '''
    
        question_bytes = self.question.as_bytes()
        header_bytes = self.header.as_bytes()

        return header_bytes + question_bytes
        


    def __str__(self) -> str:
        return f"{self.header}\n{self.question}"
    
    def __repr__(self) -> str:
        return self.__str__()
    
