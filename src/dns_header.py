from dns_enums import *
from utils import convert_bytes_to_int
from typing import Self

class DNSHeaderFlags:
    '''
    Flags of DNS header
    '''

    def __init__(
        self,
        qr: DNSHeaderQR,
        opcode: DNSHeaderOPCODE,
        aa: DNSHeaderAuthoritiveAnswear,
        tc: DNSHeaderTruncated,
        rd: DNSHeaderRecursionDesired,
        ra: DNSHeaderRecursionAvailable,
        rcode: DNSHeaderResponseCode
    ):
        self.qr = qr
        self.opcode = opcode
        self.aa = aa
        self.tc = tc
        self.rd = rd
        self.ra = ra
        self.reserved = DNSHeaderZ.RESERVED
        self.rcode = rcode

    def __str__(self) -> str:
        to_return = f"QR: {self.qr}\n"
        to_return += f"OPCODE: {self.opcode}\n"
        to_return += f"AA: {self.aa}\n"
        to_return += f"TC: {self.tc}\n"
        to_return += f"RD: {self.rd}\n"
        to_return += f"RA: {self.ra}\n"
        to_return += f"Z: {self.reserved}\n"
        to_return += f"RCODE: {self.rcode}\n"
        return to_return
    
    def __repr__(self) -> str:
        return self.__str__()
    
    def build_response_header_flags(
            self,
            response_code: DNSHeaderResponseCode = DNSHeaderResponseCode.NO_ERROR
    ) -> Self:
        '''
        Returns a new DNSHeaderFlags object with the response flags set from the current flags

        QR is set to RESPONSE\n
        OPCODE is set to the current OPCODE\n
        AA is set to AUTHORITIVE\n
        TC is set to NOT_TRUNCATED\n
        RD is set to NO_RECURSION\n
        RA is set to NO_RECURSION\n
        RCODE is set to the response_code parameter\n
        '''
        return DNSHeaderFlags(
            DNSHeaderQR.RESPONSE,
            self.opcode,
            DNSHeaderAuthoritiveAnswear.AUTHORITIVE,
            DNSHeaderTruncated.NOT_TRUNCATED,
            DNSHeaderRecursionDesired.NO_RECURSION,
            DNSHeaderRecursionAvailable.RECURSION,
            response_code
        )
    
    def as_bytes(self) -> bytes:
        '''
        Convert the flags to bytes
        '''

        '''
        format of the flags:
                                        1  1  1  1  1  1
          0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
        '''
        qr = self.qr.value << 7
        opcode = self.opcode.value << 3
        aa = self.aa.value << 2
        tc = self.tc.value << 1
        rd = self.rd.value
        ra = self.ra.value << 7
        reserved = self.reserved.value << 4
        rcode = self.rcode.value

        result = qr + opcode + aa + tc + rd
        result_bytes = result.to_bytes(1, byteorder='big')
        result = ra + reserved + rcode
        result_bytes += result.to_bytes(1, byteorder='big')

        return result_bytes

class DNSHeader:
    '''
    Header of DNS packet
    '''


    def __init__(self, data: bytes = b'', create_empty: bool = False):
        '''
        For initialization from bytes skip the create_empty parameter

        Use the create_empty parameter to create an empty DNSHeader object
        '''
        if not create_empty:
            self.data = data
            self.__parse_data()

    def __parse_data(self):
        '''
        Parse the data from the bytes and convert it to required format, sets the id, flags, questions_count, answers_count, authority_count and additional_count
        '''
        self.id = convert_bytes_to_int(self.data[:2])
        flags_bytes = self.data[2:4]
        self.flags = self.__read_flags(flags_bytes)
        self.questions_count = convert_bytes_to_int(self.data[4:6])
        self.answers_count = convert_bytes_to_int(self.data[6:8])
        self.authority_count = convert_bytes_to_int(self.data[8:10])
        self.additional_count = convert_bytes_to_int(self.data[10:12])

    def __read_flags(self, flags: bytes) -> DNSHeaderFlags:
        '''
        Read the flags from the bytes and convert them to DNSHeaderFlags object
        '''

        '''
        format of the flags:
                                        1  1  1  1  1  1
          0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
        '''
        qr = (flags[0] & 0b10000000) >> 7
        opcode = (flags[0] & 0b01111000) >> 3
        aa = (flags[0] & 0b00000100) >> 2
        tc = (flags[0] & 0b00000010) >> 1
        rd = (flags[0] & 0b00000001)
        ra = (flags[1] & 0b10000000) >> 7
        rcode = (flags[1] & 0b00001111)

        qr = DNSHeaderQR.init_from(qr)
        opcode = DNSHeaderOPCODE.init_from(opcode)
        aa = DNSHeaderAuthoritiveAnswear.init_from(aa)
        tc = DNSHeaderTruncated.init_from(tc)
        rd = DNSHeaderRecursionDesired.init_from(rd)
        ra = DNSHeaderRecursionAvailable.init_from(ra)
        rcode = DNSHeaderResponseCode.init_from(rcode)

        return DNSHeaderFlags(qr, opcode, aa, tc, rd, ra, rcode)

    def build_response_header(
            self,
            answers_count: int = 0,
            response_code: DNSHeaderResponseCode = DNSHeaderResponseCode.NO_ERROR,
            authority_count: int = 1
    ) -> Self:
        '''
        Returns a new DNSHeader object with the response flags set from the current header

        Questions count is set to 1\n
        Answers count is set to the answer_count parameter\n
        Authority count is set to authority_count\n
        Additional count is set to 0\n
        '''
        new_header = DNSHeader(create_empty=True)
        new_header.id = self.id
        new_header.flags = self.flags.build_response_header_flags(response_code)
        new_header.questions_count = 1
        new_header.answers_count = answers_count
        new_header.authority_count = authority_count
        new_header.additional_count = 0
        return new_header
    
    def as_bytes(self) -> bytes:
        '''
        Convert the header to bytes
        '''
        id_bytes = self.id.to_bytes(2, byteorder='big')
        flags_bytes = self.flags.as_bytes()
        questions_count_bytes = self.questions_count.to_bytes(2, byteorder='big')
        answers_count_bytes = self.answers_count.to_bytes(2, byteorder='big')
        authority_count_bytes = self.authority_count.to_bytes(2, byteorder='big')
        additional_count_bytes = self.additional_count.to_bytes(2, byteorder='big')

        return id_bytes +\
                flags_bytes +\
                questions_count_bytes +\
                answers_count_bytes +\
                authority_count_bytes +\
                additional_count_bytes
    
    def __str__(self):
        to_return = f"ID: {self.id}\n"
        to_return += f"FLAGS: {str(self.flags)}\n"
        to_return += f"QUESTIONS COUNT: {self.questions_count}\n"
        to_return += f"ANSWERS COUNT: {self.answers_count}\n"
        to_return += f"AUTHORITY COUNT: {self.authority_count}\n"
        to_return += f"ADDITIONAL COUNT: {self.additional_count}\n"
        return to_return
    
    def __repr__(self):
        return self.__str__()