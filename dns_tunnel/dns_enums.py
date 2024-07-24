from enum import Enum
from typing import Self

class DNSHeaderQR(Enum):
    '''
    DNS Header query type field which tells if the message is a query or a response

    Values:
    - 0 - Query
    - 1 - Response
    '''

    QUERY = 0
    RESPONSE = 1

    @classmethod
    def init_from(cls, value: int) -> Self:
        '''
        Initialize the DNSHeaderQR from a value
        '''

        if value == 0:
            return DNSHeaderQR.QUERY
        elif value == 1:
            return DNSHeaderQR.RESPONSE
        
    def __str__(self):
        return 'QUERY' if self == DNSHeaderQR.QUERY else 'RESPONSE'
    
    def __repr__(self):
        return self.__str__()

class DNSHeaderOPCODE(Enum):
    '''
    DNS Header opcode field which tells the type of the query

    Values:
    - 0 - QUERY
    - 1 - IQUERY
    - 2 - STATUS
    '''

    QUERY = 0
    IQUERY = 1
    STATUS = 2

    @classmethod
    def init_from(cls, value: int) -> Self:
        '''
        Initialize the DNSHeaderOPCODE from a value
        '''

        if value == 0:
            return DNSHeaderOPCODE.QUERY
        elif value == 1:
            return DNSHeaderOPCODE.IQUERY
        elif value == 2:
            return DNSHeaderOPCODE.STATUS
        
    def __str__(self):
        if self == DNSHeaderOPCODE.QUERY:
            return 'QUERY'
        elif self == DNSHeaderOPCODE.IQUERY:
            return 'IQUERY'
        elif self == DNSHeaderOPCODE.STATUS:
            return 'STATUS'
        
    def __repr__(self):
        return self.__str__()

class DNSHeaderAuthoritiveAnswear(Enum):
    '''
    DNS Header authoritive type field which tells if the server is authoritive

    Values:
    - 0 - NON_AUTHORITIVE
    - 1 - AUTHORITIVE
    '''

    NON_AUTHORITIVE = 0
    AUTHORITIVE = 1

    @classmethod
    def init_from(cls, value: int) -> Self:
        '''
        Initialize the DNSHeaderAuthoritiveAnswear from a value
        '''

        if value == 0:
            return DNSHeaderAuthoritiveAnswear.NON_AUTHORITIVE
        elif value == 1:
            return DNSHeaderAuthoritiveAnswear.AUTHORITIVE
        
    def __str__(self):
        return 'NON_AUTHORITIVE' if self == DNSHeaderAuthoritiveAnswear.NON_AUTHORITIVE else 'AUTHORITIVE'
    
    def __repr__(self):
        return self.__str__()

class DNSHeaderTruncated(Enum):
    '''
    DNS Header truncated field which tells if the message was truncated

    Values:
    - 0 - NOT_TRUNCATED
    - 1 - TRUNCATED
    '''

    NOT_TRUNCATED = 0
    TRUNCATED = 1

    @classmethod
    def init_from(cls, value: int) -> Self:
        '''
        Initialize the DNSHeaderTruncated from a value
        '''
        
        if value == 0:
            return DNSHeaderTruncated.NOT_TRUNCATED
        elif value == 1:
            return DNSHeaderTruncated.TRUNCATED
        
    def __str__(self):
        return 'NOT_TRUNCATED' if self == DNSHeaderTruncated.NOT_TRUNCATED else 'TRUNCATED'
    
    def __repr__(self):
        return self.__str__()

class DNSHeaderRecursionDesired(Enum):
    '''
    DNS Header recursion desired field which tells the server if the client wants recursion

    Values:
    - 0 - NO_RECURSION
    - 1 - RECURSION
    '''

    NO_RECURSION = 0
    RECURSION = 1

    @classmethod
    def init_from(cls, value: int) -> Self:
        '''
        Initialize the DNSHeaderRecursionDesired from a value
        '''

        if value == 0:
            return DNSHeaderRecursionDesired.NO_RECURSION
        elif value == 1:
            return DNSHeaderRecursionDesired.RECURSION
        
    def __str__(self):
        return 'NO_RECURSION' if self == DNSHeaderRecursionDesired.NO_RECURSION else 'RECURSION'
    
    def __repr__(self):
        return self.__str__()

class DNSHeaderRecursionAvailable(Enum):
    '''
    DNS Header recursion available field which tells if the server can do recursion

    Values:
    - 0 - NO_RECURSION
    - 1 - RECURSION
    '''

    NO_RECURSION = 0
    RECURSION = 1

    @classmethod
    def init_from(cls, value: int) -> Self:
        '''
        Initialize the DNSHeaderRecursionAvailable from a value
        '''

        if value == 0:
            return DNSHeaderRecursionAvailable.NO_RECURSION
        elif value == 1:
            return DNSHeaderRecursionAvailable.RECURSION
        
    def __str__(self):
        return 'NO_RECURSION' if self == DNSHeaderRecursionAvailable.NO_RECURSION else 'RECURSION'
    
    def __repr__(self):
        return self.__str__()

class DNSHeaderZ(Enum):
    '''
    DNS Header Z field which is reserved for future use

    Values:
    - 0 - RESERVED
    - 1 - FILE_CHUNCK_OFFSET
    '''

    RESERVED = 0

    def __str__(self):
        return 'RESERVED'
    
    def __repr__(self):
        return self.__str__()

class DNSHeaderResponseCode(Enum):
    '''
    DNS Header response code field which tells the status of the response

    Values:
    - 0 - NO_ERROR
    - 1 - FORMAT_ERROR
    - 2 - SERVER_FAILURE
    - 3 - NAME_ERROR
    - 4 - NOT_IMPLEMENTED 
    - 5 - REFUSED
    '''

    NO_ERROR = 0
    FORMAT_ERROR = 1
    SERVER_FAILURE = 2
    NAME_ERROR = 3
    NOT_IMPLEMENTED = 4
    REFUSED = 5

    @classmethod
    def init_from(cls, value: int) -> Self:
        '''
        Initialize the DNSHeaderResponseCode from a value
        '''

        if value == 0:
            return DNSHeaderResponseCode.NO_ERROR
        elif value == 1:
            return DNSHeaderResponseCode.FORMAT_ERROR
        elif value == 2:
            return DNSHeaderResponseCode.SERVER_FAILURE
        elif value == 3:
            return DNSHeaderResponseCode.NAME_ERROR
        elif value == 4:
            return DNSHeaderResponseCode.NOT_IMPLEMENTED
        elif value == 5:
            return DNSHeaderResponseCode.REFUSED
        
    def __str__(self):
        if self == DNSHeaderResponseCode.NO_ERROR:
            return 'NO_ERROR'
        elif self == DNSHeaderResponseCode.FORMAT_ERROR:
            return 'FORMAT_ERROR'
        elif self == DNSHeaderResponseCode.SERVER_FAILURE:
            return 'SERVER_FAILURE'
        elif self == DNSHeaderResponseCode.NAME_ERROR:
            return 'NAME_ERROR'
        elif self == DNSHeaderResponseCode.NOT_IMPLEMENTED:
            return 'NOT_IMPLEMENTED'
        elif self == DNSHeaderResponseCode.REFUSED:
            return 'REFUSED'
        
    def __repr__(self):
        return self.__str__()

class DNSQuestionType(Enum):
    '''
    DNS Question type field which tells the type of the question

    Values:
    - A - 1
    - NS - 2
    - CNAME - 5
    - SOA - 6
    - WKS - 11
    - PTR - 12
    - MX - 15
    - TXT - 16
    '''

    A = 1
    NS = 2
    CNAME = 5
    SOA = 6
    WKS = 11
    PTR = 12
    MX = 15
    TXT = 16
   
    @classmethod
    def init_from(cls, value: int) -> Self:
        '''
        Initialize the DNSQuestionType from a value
        '''

        if value == 1:
            return DNSQuestionType.A
        elif value == 2:
            return DNSQuestionType.NS
        elif value == 5:
            return DNSQuestionType.CNAME
        elif value == 6:
            return DNSQuestionType.SOA
        elif value == 11:
            return DNSQuestionType.WKS
        elif value == 12:
            return DNSQuestionType.PTR
        elif value == 15:
            return DNSQuestionType.MX
        elif value == 16:
            return DNSQuestionType.TXT
        
    def __str__(self):
        if self == DNSQuestionType.A:
            return 'A'
        elif self == DNSQuestionType.NS:
            return 'NS'
        elif self == DNSQuestionType.CNAME:
            return 'CNAME'
        elif self == DNSQuestionType.SOA:
            return 'SOA'
        elif self == DNSQuestionType.WKS:
            return 'WKS'
        elif self == DNSQuestionType.PTR:
            return 'PTR'
        elif self == DNSQuestionType.MX:
            return 'MX'
        elif self == DNSQuestionType.TXT:
            return 'TXT'
        
    def __repr__(self):
        return self.__str__()
    
class DNSQuestionClass(Enum):
    '''
    DNS Question class field which tells the class of the question

    Values:
    - IN - 1
    '''

    IN = 1

    @classmethod
    def init_from(cls, value: int) -> Self:
        '''
        Initialize the DNSQuestionClass from a value
        '''

        if value == 1:
            return DNSQuestionClass.IN
        
    def __str__(self):
        return 'IN'
    
    def __repr__(self):
        return self.__str__()
