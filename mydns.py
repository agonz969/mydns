import struct
import random
import socket
import sys

# py Desktop\mydns.py cs.fiu.edu 198.41.0.4
#-------------------------------------------------------------------------------
#                           Function Definitions
#-------------------------------------------------------------------------------
def pack(value):
    return struct.pack('>H', value)

def unpack(data):
    return struct.unpack('>H', data)[0]

def decode_string(message, offset):
    index = offset
    result = ''
    offset = 0
    while message[index] != 0:
        value = message[index]
        if (value>>6) == 3:
            next = unpack(message[index:index + 2])
            if offset == 0:
                offset = index + 2
            index = next ^ (3<<14)
        else:
            result += message[index + 1:index + 1 + value].decode('utf-8') + '.'
            index += value + 1
    if offset == 0:
        offset = index + 1
    result = result[:-1]
    return (offset, result)

#-------------------------------------------------------------------------------
#                           Global Variables
#-------------------------------------------------------------------------------
usage = '$./mydns [host_name] [root_name]'
serverName = ''
rootName = ''
DNSPort = 53
query_type_names = { 1:'A', 2:'NS'}
opcodes = { 0:'QUERY'}
query_class_names = { 1:'IN' }
message_types = { 0:'QUERY', 1:'RESPONSE' }
separator = '\n-----------------------------------------------------------'

#-------------------------------------------------------------------------------
#                           Message Header
#-------------------------------------------------------------------------------
class MessageHeader:

    def generate_ID(self):
        return random.randint(0, 65535)

    def set_question_header(self):
        self.messageID = self.generate_ID()
        self.qr = 0
        self.opcode = 0
        self.aa = 0
        self.tc = 0
        self.rd = 0
        self.ra = 0
        self.rcode = 0
        self.qd_count = 1
        self.an_count = 0
        self.ns_count = 0
        self.ar_count = 0

    def encode(self):
        result = pack(self.messageID)
        meta = 0
        meta |= self.qr
        meta <<= 1
        meta |= self.opcode
        meta <<= 4
        meta |= self.aa
        meta <<= 1
        meta |= self.tc
        meta <<= 1
        meta |= self.rd
        meta <<= 1
        meta |= self.ra
        meta <<= 7
        meta |= self.rcode
        result += pack(meta)
        result += pack(self.qd_count)
        result += pack(self.an_count)
        result += pack(self.ns_count)
        result += pack(self.ar_count)
        return result

    def decode(self, message):
        self.messageID = unpack(message[0:2])
        meta = unpack(message[2:4])
        self.rcode = (meta & 15)
        meta >>= 7
        self.ra = (meta & 1)
        meta >>= 1
        self.rd = (meta & 1)
        meta >>= 1
        self.tc = (meta & 1)
        meta >>= 1
        self.aa = (meta & 1)
        meta >>= 1
        self.opcode = (meta & 15)
        meta >>= 4
        self.qr = meta
        self.qd_count = unpack(message[4:6])
        self.an_count = unpack(message[6:8])
        self.ns_count = unpack(message[8:10])
        self.ar_count = unpack(message[10:12])
        return 12


#-------------------------------------------------------------------------------
#                           DNS Question
#-------------------------------------------------------------------------------
class DNSQuestion:

    def set_question(self, name):
        self.name = name
        self.type = 1
        self.request_class = 1

    def decode(self, message, offset):
        name = decode_string(message, offset)
        offset = name[0]
        self.name = name[1]
        self.type = unpack(message[offset:offset + 2])
        self.request_class = unpack(message[offset + 2:offset + 4])
        return offset + 4

    def encode(self):
        result = self.encode_name()
        result += pack(self.type)
        result += pack(self.request_class)
        return result

    def encode_name(self):
        name = self.name
        if name.endswith('.'):
            name = name[:-1]
        result = b''
        for domain_name in name.split('.'):
            result += struct.pack('B', len(domain_name))
            result += bytes(domain_name, 'utf-8')
        result += b'\x00'
        return result


#-------------------------------------------------------------------------------
#                           A - ResourceRecord
#-------------------------------------------------------------------------------
class AResourceData:

    def __init__(self, data):
        ip = struct.unpack('BBBB', data)
        self.ip = str(ip[0]) + '.' + str(ip[1]) + \
                '.' + str(ip[2]) + '.' + str(ip[3])

    def print(self):
        print('\tA: {0}'.format(self.ip))


#-------------------------------------------------------------------------------
#                           NS - ResourceRecord
#-------------------------------------------------------------------------------
class NSResourceData:

    def __init__(self, message, offset):
        self.name = decode_string(message, offset)[1]

    def print(self):
        print('\tNS: {0}'.format(self.name))


#-------------------------------------------------------------------------------
#                           Bin - ResourceRecord
#-------------------------------------------------------------------------------
class BinaryResourceData:

    def __init__(self, data):
        self.data = data

    def print(self):
         print('\tData: {0}'.format(self.data))


#-------------------------------------------------------------------------------
#                           ResourceRecord
#-------------------------------------------------------------------------------
class ResourceRecord:

    def set_resource_data(self, message, offset):
        rdata = message[offset: offset + self.rd_length]
        if self.type == 1:
            self.resource_data = AResourceData(rdata)
        elif self.type == 2:
            self.resource_data = NSResourceData(message, offset)
        else:
            self.resource_data = BinaryResourceData(rdata)

    def decode(self, message, offset):
        name = decode_string(message, offset)
        offset = name[0]
        self.name = name[1]
        self.type = unpack(message[offset:offset + 2])
        offset += 2
        self.request_class = unpack(message[offset:offset + 2])
        offset += 2
        self.ttl = struct.unpack('>I', message[offset: offset + 4])[0]
        offset += 4
        self.rd_length = unpack(message[offset:offset + 2])
        offset += 2
        self.set_resource_data(message, offset)
        return offset + self.rd_length


    def print(self):
        if self.type == 1 or self.type == 2:
            print('\tName: {0}'.format(self.name), end =" ")
            self.resource_data.print()
        else:
            pass
            #used to display binary resources fetched
            #print('\tName: {0}'.format(self.name), end ="\n")


#-------------------------------------------------------------------------------
#                           DNS Format
#-------------------------------------------------------------------------------
class DNSMessageFormat:

    def encode(self, host_name):
        message = b''
        self.header = MessageHeader()
        self.header.set_question_header()
        message += self.header.encode()
        self.question = DNSQuestion()
        self.question.set_question(host_name)
        message += self.question.encode()
        return message

    def decode(self, message):
        self.header = MessageHeader()
        offset = self.header.decode(message)
        self.questions = []
        self.answers = []
        self.authority_RRs = []
        self.additional_RRs = []
        for i in range(self.header.qd_count):
            self.questions.append(DNSQuestion())
            offset = self.questions[i].decode(message, offset)
        for i in range(self.header.an_count):
            self.answers.append(ResourceRecord())
            offset = self.answers[i].decode(message, offset)
        for i in range(self.header.ns_count):
            self.authority_RRs.append(ResourceRecord())
            offset = self.authority_RRs[i].decode(message, offset)
        for i in range(self.header.ar_count):
            self.additional_RRs.append(ResourceRecord())
            offset = self.additional_RRs[i].decode(message, offset)

    def getRoot(self):
        return self.additional_RRs[0].resource_data.ip

    def print(self):
        print('Reply received. Content overview:')
        print('\t' + str(self.header.an_count) + ' Answers')
        print('\t' + str(self.header.ns_count) + ' Intermediate Name Servers')
        print('\t' + str(self.header.ar_count) + ' Additional Information Records')


        print('\nAnswer Section:')
        for i in range(self.header.an_count):
            self.answers[i].print()

        print('\nAuthoritative Section:')
        for i in range(self.header.ns_count):
            self.authority_RRs[i].print()

        print('\nAdditional Information Section:')
        for i in range(self.header.ar_count):
            self.additional_RRs[i].print()



#-------------------------------------------------------------------------------
#                           MAIN()
#-------------------------------------------------------------------------------
try:
    serverName = sys.argv[1]
    rootName = sys.argv[2]
except IndexError:
    print(usage)
    sys.exit()

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
except socket.error as err_msg:
    print ('Error code:' + str(err_msg[0]) + ', Error message:' + err_msg[1])
    sys.exit()

s.settimeout(5.0)

while(1):
    print(separator)
    rootAddr = (rootName, DNSPort)
    format = DNSMessageFormat()
    query = format.encode(serverName)
    print('DNS server to query: ' + rootName)

    s.sendto(query, rootAddr)
    try:
        receivedBytes, addr = s.recvfrom(512)
    except socket.timeout:
        print('REQUEST TIMED OUT')
        sys.exit()

    format.decode(receivedBytes)
    format.print()
    if len(format.answers) > 0:
        s.close()
        sys.exit()

    rootName = format.getRoot()
