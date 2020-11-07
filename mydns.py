import struct
import random
import socket
import sys

# py Desktop\mydns.py cs.fiu.edu 198.41.0.4
#-------------------------------------------------------------------------------
#                           Global Variables
#-------------------------------------------------------------------------------
serverName = ''
rootName = ''
DNSPort = 53
usage = 'Invalid Usage: $./mydns [host_name] [root_name]'
separator = '\n-----------------------------------------------------------'

#-------------------------------------------------------------------------------
#                           Function Definitions
#-------------------------------------------------------------------------------
def pack(msg):
    return struct.pack('>H', msg)

def unpack(msg):
    return struct.unpack('>H', msg)[0]

def unpackMsg(msg, bitcount):
    i = bitcount
    bitcount = 0
    string = ''
    while msg[i] != 0:
        val = msg[i]
        if (val>>6) == 3:
            nextval = unpack(msg[i:i+2])
            if bitcount == 0:
                bitcount = i+2
            i = nextval^(3<<14)
        else:
            string += msg[i+1:i+1+val].decode('utf-8')+'.'
            i += val+1
    if bitcount == 0:
        bitcount = i+1
    string = string[:-1]
    return (bitcount, string)


#-------------------------------------------------------------------------------
#                           Message Header
#-------------------------------------------------------------------------------
class Header:

    def randID(header):
        return random.randint(0, 65535)

    def setHeader(header):
        header.messageID = header.randID()
        header.qr = 0
        header.op = 0
        header.aa = 0
        header.tc = 0
        header.rd = 0
        header.ra = 0
        header.rcode = 0
        header.qdCount = 1
        header.anCount = 0
        header.nsCount = 0
        header.arCount = 0

    def encode(header):
        encodedMsg = pack(header.messageID)
        offset = 0
        offset |= header.qr
        offset <<= 1
        offset |= header.op
        offset <<= 4
        offset |= header.aa
        offset <<= 1
        offset |= header.tc
        offset <<= 1
        offset |= header.rd
        offset <<= 1
        offset |= header.ra
        offset <<= 7
        offset |= header.rcode
        encodedMsg += pack(offset)
        encodedMsg += pack(header.qdCount)
        encodedMsg += pack(header.anCount)
        encodedMsg += pack(header.nsCount)
        encodedMsg += pack(header.arCount)
        return encodedMsg

    def decode(header, msg):
        header.messageID = unpack(msg[0:2])
        offset = unpack(msg[2:4])
        header.rcode = (offset & 15)
        offset >>= 7
        header.ra = (offset & 1)
        offset >>= 1
        header.rd = (offset & 1)
        offset >>= 1
        header.tc = (offset & 1)
        offset >>= 1
        header.aa = (offset & 1)
        offset >>= 1
        header.op = (offset & 15)
        offset >>= 4
        header.qr = offset
        header.qdCount = unpack(msg[4:6])
        header.anCount = unpack(msg[6:8])
        header.nsCount = unpack(msg[8:10])
        header.arCount = unpack(msg[10:12])
        return 12


#-------------------------------------------------------------------------------
#                           DNS Question
#-------------------------------------------------------------------------------
class Question:

    def setQuestion(question, name):
        question.name = name
        question.type = 1
        question.rClass = 1

    def decode(question, msg, bitcount):
        name = unpackMsg(msg, bitcount)
        bitcount = name[0]
        question.name = name[1]
        question.type = unpack(msg[bitcount:bitcount + 2])
        question.rClass = unpack(msg[bitcount + 2:bitcount + 4])
        return bitcount + 4

    def encode(question):
        result = question.encodeName()
        result += pack(question.type)
        result += pack(question.rClass)
        return result

    def encodeName(question):
        Qname = question.name
        if Qname.endswith('.'):
            Qname = Qname[:-1]
        encodedName = b''
        for domName in Qname.split('.'):
            encodedName += struct.pack('B', len(domName))
            encodedName += bytes(domName, 'utf-8')
        encodedName += b'\x00'
        return encodedName


#-------------------------------------------------------------------------------
#                           A - ResourceRecord
#-------------------------------------------------------------------------------
class ARR:

    def __init__(ARR, data):
        ip = struct.unpack('BBBB', data)
        ARR.ip = str(ip[0])+'.'+str(ip[1])+'.'+str(ip[2])+'.'+str(ip[3])

    def print(ARR):
        print('\tIP: {0}'.format(ARR.ip))


#-------------------------------------------------------------------------------
#                           NS - ResourceRecord
#-------------------------------------------------------------------------------
class NSRR:

    def __init__(NSRR, msg, offset):
        NSRR.name = unpackMsg(msg, offset)[1]

    def print(NSRR):
        print('\tName Server: {0}'.format(NSRR.name))



#-------------------------------------------------------------------------------
#                           ResourceRecord
#-------------------------------------------------------------------------------
class RR:

    def setRData(RR, msg, bitcount):
        resourceData = msg[bitcount: bitcount + RR.rdLen]
        if RR.type == 1:
            RR.rData = ARR(resourceData)
        elif RR.type == 2:
            RR.rData = NSRR(msg, bitcount)


    def decode(RR, msg, bitcount):
        name = unpackMsg(msg, bitcount)
        bitcount = name[0]
        RR.name = name[1]
        RR.type = unpack(msg[bitcount:bitcount + 2])
        bitcount += 2
        RR.rClass = unpack(msg[bitcount:bitcount + 2])
        bitcount += 2
        RR.ttl = struct.unpack('>I', msg[bitcount: bitcount + 4])[0]
        bitcount += 4
        RR.rdLen = unpack(msg[bitcount:bitcount + 2])
        bitcount += 2
        RR.setRData(msg, bitcount)
        return bitcount + RR.rdLen


    def print(RR):
        if RR.type == 1 or RR.type == 2:
            print('\tName: {0}'.format(RR.name), end =" ")
            RR.rData.print()
        else:
            pass



#-------------------------------------------------------------------------------
#                           DNS Format
#-------------------------------------------------------------------------------
class DnsMsg:

    def encode(DNS, host):
        msg = b''
        DNS.header = Header()
        DNS.header.setHeader()
        msg += DNS.header.encode()
        DNS.question = Question()
        DNS.question.setQuestion(host)
        msg += DNS.question.encode()
        return msg

    def decode(DNS, msg):
        DNS.header = Header()
        offset = DNS.header.decode(msg)
        DNS.questions = []
        DNS.answers = []
        DNS.authRR = []
        DNS.addiRR = []
        for i in range(DNS.header.qdCount):
            DNS.questions.append(Question())
            offset = DNS.questions[i].decode(msg, offset)
        for i in range(DNS.header.anCount):
            DNS.answers.append(RR())
            offset = DNS.answers[i].decode(msg, offset)
        for i in range(DNS.header.nsCount):
            DNS.authRR.append(RR())
            offset = DNS.authRR[i].decode(msg, offset)
        for i in range(DNS.header.arCount):
            DNS.addiRR.append(RR())
            offset = DNS.addiRR[i].decode(msg, offset)

    def getRoot(DNS):
        return DNS.addiRR[0].rData.ip

    def print(DNS):
        print('Reply received. Content overview:')
        print('\t'+str(DNS.header.anCount)+' Answers')
        print('\t'+str(DNS.header.nsCount)+' Intermediate Name Servers')
        print('\t'+str(DNS.header.arCount)+' Additional Information Records')
        print('\nAnswer Section:')
        for i in range(DNS.header.anCount):
            DNS.answers[i].print()
        print('\nAuthoritative Section:')
        for i in range(DNS.header.nsCount):
            DNS.authRR[i].print()
        print('\nAdditional Information Section:')
        for i in range(DNS.header.arCount):
            DNS.addiRR[i].print()



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
    format = DnsMsg()
    query = format.encode(serverName)
    print('DNS server to query: ' + rootName)

    try:
        s.sendto(query, rootAddr)
    except socket.gaierror:
        print("Failed to resolve '%s'" % serverName)
        sys.exit()

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
