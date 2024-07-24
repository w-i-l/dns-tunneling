import glob
from dns_question import DNSQuestion
import json
from dns_enums import DNSQuestionType, DNSHeaderResponseCode
from dns_errors import *
from utils import convert_bytes_to_int

class DNSAnswear:
    '''
    A class representing the answears for a DNS question

    It holds the zones files statically
    '''

    # A dictionary with the zones where the key is the zone name
    # and the value is the zone data
    zones = None

    def __init__(self, question: DNSQuestion = None, answears: bytes = b''):
        '''
        Only one of the parameters should be provided
        - question is the DNSQuestion for which the answears should be built
        - answears is the bytes of the answears which are offseted by the header bytes (12 bytes)
        '''

        self.question = question

        if answears:
            '''
            We skip the name - always 2 bytes
            We skip the type - always 2 bytes
            We skip the class - always 2 bytes
            We skip the ttl - always 4 bytes
            We skip the rdlength - always 2 bytes
            And decode the value
            '''
            answears = answears[2 + 2 + 2 + 4 + 2:]
            length = answears[0] # length of the value
            self.data = answears[1:length + 1] # the first chunk of the value

            # if the length of the value is greater than 255 we need to read the second chunk
            if len(answears) > length + 1:
                self.data += answears[length + 2:]
            


    def build_response(self) -> tuple[bytes | DNSHeaderResponseCode | str, int]:
        '''
        Builds the response bytes for the answears

        Returns the response bytes or a DNSHeaderResponseCode if an error occurs or the filename for the tunneling
        '''

        try:
            '''
            Find the zone for the question, if the zone is not found
            raise a DNSNoDomainFoundError, if the server has no zones
            raise a DNSServerError
            '''
            self.zone = self.__find_zone()
            # verify tunneling
            if self.zone.get('filename'):
                return (self.zone['filename'], 1)

            answears = self.__format_anwser()
            answears_count = 1 if self.question.qtype == DNSQuestionType.SOA else len(answears)

        except DNSNoDomainFoundError:
            self.zone = None
            return (DNSHeaderResponseCode.NAME_ERROR, 0)
        
        except DNSServerError:
            self.zone = None
            return (DNSHeaderResponseCode.SERVER_FAILURE, 0)
        
        '''
        Encoding answeares to bytes and returning the result
        if any error occurs return during the process, it means that we can't parse the data
        so we return a DNSHeaderResponseCode.FORMAT_ERROR
        '''
        try:
            result = b''

            if self.question.qtype == DNSQuestionType.SOA:
                result = self.__answear_as_bytes(answears)
            elif isinstance(answears, dict) and answears.get('filename'):
                return (answears['filename'].encode('utf-8'), 1)
            else:
                for answear in answears:
                    result += self.__answear_as_bytes(answear)

        except Exception as e:
            self.zone = None
            return (DNSHeaderResponseCode.FORMAT_ERROR, 0)
        
        return (result, answears_count)
    
    def get_authority(self) -> bytes | None:
        '''
        Builds the authority section of the response

        Returns the authority section as bytes or None if the question is SOA
        '''
        
        try:
            # if the question is SOA we don't need the authority section
            if self.question.qtype == DNSQuestionType.SOA:
                return None

            authority = self.__format_anwser(DNSQuestionType.SOA)
            return self.__answear_as_bytes(authority, DNSQuestionType.SOA)
        except Exception:
            return None

    def __answear_as_bytes(
            self, 
            info: tuple[str, int, str] | dict[str, str],
            qtype: DNSQuestionType = None
    ) -> bytes:
        '''
        Converts the answear to bytes

        The info tuple should have the following format:
        (type, ttl, value)

        If qtype is not provided it will be taken from the question
        '''

        if qtype is None:
            qtype = self.question.qtype

        result_bytes = b''

        info_type = info[0] if qtype != DNSQuestionType.SOA else None
        if info_type and info_type != '@':
            result_bytes = self.__encode_domain(info_type)
        
        '''
        Pointer to the domain name which starts at the beginning of the message, after the header
        https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4
        '''
        result_bytes += b'\xc0\x0c'

        # adding the record type
        result_bytes += qtype.value.to_bytes(2, byteorder='big')

        result_bytes += b'\x00\x01' # IN class type

        ttl = info[1] if qtype != DNSQuestionType.SOA else int(info["ttl"])
        result_bytes += ttl.to_bytes(4, byteorder='big')  # TTL

        value = info[2] if qtype != DNSQuestionType.SOA else None

        '''
        Adding the length of the value and the value itself encoded

        RDLENGTH is the length of the RDATA field in octets
        '''
        if qtype == DNSQuestionType.A:
            # for A record type the length is 4
            result_bytes += b'\x00\x04'

            # convert the IPv4 address to bytes
            parts = value.split('.')
            result_bytes += bytes([int(part) for part in parts])

        elif qtype == DNSQuestionType.CNAME or qtype == DNSQuestionType.NS:
            encoded_value = self.__encode_domain(value)
            length = len(encoded_value)

            # add the length of the encoded value
            result_bytes += length.to_bytes(2, byteorder='big')
            result_bytes += encoded_value

        elif qtype == DNSQuestionType.TXT:

            # dns tunneling - we need to return the tunnel value
            if self.question.domain.endswith(DNS_TUNNELING_IDENTIFIER):
                return b''

            encoded_value = value.encode('utf-8')
            length = len(encoded_value)

            # total length of the value is the length of the value plus the length of the length byte
            result_bytes += (length + 1).to_bytes(2, byteorder='big')
            result_bytes += length.to_bytes(1, byteorder='big')
            result_bytes += encoded_value

        elif qtype == DNSQuestionType.MX:
            preference, exchange = value.split()
            encoded_value = self.__encode_domain(exchange)
            length = len(encoded_value) + 2

            # total length of the value is the length of the value plus the length of the length byte
            result_bytes += length.to_bytes(2, byteorder='big')
            result_bytes += int(preference).to_bytes(2, byteorder='big')
            result_bytes += encoded_value

        elif qtype == DNSQuestionType.SOA:

            # extract the values from the info dictionary
            mname = info["mname"]
            rname = info["rname"]
            serial = info["serial"]
            refresh = info["refresh"]
            retry = info["retry"]
            expire = info["expire"]
            minimum = info["minimum"]

            local_bytes = b''

            local_bytes += self.__encode_domain(mname) # primary name server
            local_bytes += self.__encode_domain(rname) # responsible authority's mailbox
            local_bytes += int(serial).to_bytes(4, byteorder='big') # Serial number
            local_bytes += int(refresh).to_bytes(4, byteorder='big') # Refresh interval
            local_bytes += int(retry).to_bytes(4, byteorder='big') # Retry interval
            local_bytes += int(expire).to_bytes(4, byteorder='big') # Expire interval
            local_bytes += int(minimum).to_bytes(4, byteorder='big') # Minimum TTL

            # add the length of the local bytes to the result bytes
            length = len(local_bytes)
            result_bytes += length.to_bytes(2, byteorder='big')

            result_bytes += local_bytes

        return result_bytes
    
    def __encode_domain(self, domain: str) -> bytes:
        '''
        Encodes the domain name into bytes
        '''
        result_bytes = b''
        domain_parts = domain.split('.')
        for part in domain_parts:
            result_bytes += len(part).to_bytes(1, byteorder='big')
            result_bytes += part.encode('utf-8')
        return result_bytes
    
    def __format_anwser(self, qtype: DNSQuestionType = None) -> list[tuple[str, int, str]] | dict[str, str]:
        '''
        Getting the quried answears from the zone file and formatting them
        as a dictionary of string-string for SOA queries and as a list of tuples with the following format:
        (type, ttl, value) for any other query

        If qtype is not provided it will be taken from the question
        '''
        
        # the zone file is a dictionary with the keys being the qtype as a lower case string
        if qtype is None:
            qtype = self.question.qtype.__str__().lower()
        else:
            qtype = qtype.__str__().lower()
        if qtype not in self.zone:
            raise DNSNoDomainFoundError(self.question.domain)
        
        # retrieve the values for the qtype
        values = self.zone[qtype]
        formatted_values = []

        # if the qtype is SOA return the values as they are
        if qtype == 'soa':
            return values
        
        # format the values
        for ans in values:
            type = ans["name"]
            ttl = ans["ttl"]
            value = ans["value"]
            formatted_values.append((type, ttl, value))

        return formatted_values

    def __find_zone(self) -> dict[str, list[dict[str, str]]]:
        '''
        Find the zone for the question

        Returns the zone data or throws DNSNoDomainFoundError if the zone is not found
        '''

        if DNSAnswear.zones is None:
            raise DNSServerError("No zones found")

        zone_name = self.question.domain

        '''
        If the zone name ends with the DNS_TUNNELING_IDENTIFIER
        we take the txt file name from the domain
        domain name will look something like this: test.txt.www.example.com.tunnel.live
        '''
        if zone_name.endswith(DNS_TUNNELING_IDENTIFIER):
            zone_name = zone_name.split('.')[:2]
            filename = '.'.join(zone_name)
            print(filename)
            return {"filename": filename}

        # if the zone name is not in the zones dictionary
        # with the subdomain of the domain
        # try to find the zone with the domain name
        if zone_name not in DNSAnswear.zones:
            zone_name = '.'.join(zone_name.split('.')[1:])
        
        try:
            return DNSAnswear.zones[zone_name]
        except KeyError:
            raise DNSNoDomainFoundError(zone_name)
    
    @classmethod
    def load_zones(cls):
        '''
        Get the zones files(.zone) from the zone folder
        and load them into the zones dictionary
        '''
        path = "zones/*.zone"
        # get all the zone files from the specified path
        zone_files = glob.glob(path)

        DNSAnswear.zones = {}
        for zone_file in zone_files:
            with open(zone_file) as file:
                data = json.load(file)
                zone_name = data["$origin"]
                DNSAnswear.zones[zone_name] = data

        if len(DNSAnswear.zones) == 0:
            DNSAnswear.zones = None