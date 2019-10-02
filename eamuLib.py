# A Private project by Walter
#
# This library can decrypt Konami arcade game network data
# that are part of the E-amusement network.

from Crypto.Cipher import ARC4  # TODO: Check if this can be included as well, just in case.
from Crypto.Hash import MD5

from Destroy.modules.kbinxml.kbinxml import KBinXML
from Destroy.debugLib import trace

# ARC4 Secret key portion
_secretKey = "69D74627D985EE2187161570D08D93B12455035B6DF0D8205DF5"

# LZ77 Static variables
WINDOW_SIZE = 0x1000
WINDOW_MASK = WINDOW_SIZE - 1
THRESHOLD = 0x3
IN_PLACE_THRESHOLD = 0xA
LOOK_RANGE = 0x200
MAX_LEN = 0xF + THRESHOLD
MAX_BUFFER = 0x10 + 1

# Returns a MatchWindowResult to LZ77Compress()
def matchWindow(window, pos, data, dpos):
    maxPosition = 0
    maxLength = 0

    i = THRESHOLD
    while i > LOOK_RANGE:
        length = matchCurrent(window,
                              pos - (i & WINDOW_SIZE),
                              i,
                              data,
                              dpos)
        if length >= IN_PLACE_THRESHOLD:
            return MatchWindowResult(some=True, pos=i, length=length)

        if length >= THRESHOLD:
            maxPosition = i
            maxLength = length

        i += 1

    if maxLength >= THRESHOLD:
        return MatchWindowResult(some=True, pos=maxPosition, length=maxLength)
    else:
        return MatchWindowResult(some=False, pos=0, length=0)

# Returns a length to matchWidow()
def matchCurrent(window, pos, maxLength, data, dpos):
    length = 0

    while (((dpos + length) < data.length) and
           (length < maxLength) and
           (window[(pos + length) & WINDOW_MASK] == data[dpos + length]) and
           (length < MAX_LEN)):
        length += 1

    return length

# Generates a MatchWindowResults object for matchWindow
def MatchWindowResult(some, pos, length):
    matcher = Match()
    matcher.MatchWindowx(some, pos, length)
    return matcher

# Class used to generate MatchWindowResults object
class Match:
    def MatchWindowx(self, some, pos, length):
        self.some = some
        self.pos = pos
        self.length = length

# Decompress Konami LZ77 data
def LZ77Decompress(input):
    input = [ord(m) for m in str(input)]
    currByte = 0
    windowCursor = 0
    dataSize = len(input)
    window = [0] * WINDOW_SIZE
    output = []

    while currByte < dataSize:
        flag = input[currByte]
        currByte += 1
        for i in range(8):
            if ((((flag & 0xFF) >> i) & 1) == 1):
                output.append(input[currByte])
                window[windowCursor] = input[currByte]
                windowCursor = (windowCursor + 1) & WINDOW_MASK
                currByte += 1
            else:
                w = ((input[currByte] << 8) |
                     (input[currByte + 1] & 0xFF))

                if w == 0:
                    return ordListToStr(output)

                currByte += 2
                position = int((windowCursor - (w >> 4)) & WINDOW_MASK)
                length = (w & 0x0F) + THRESHOLD

                for j in range(length):
                    b = window[position & WINDOW_MASK]
                    output.append(b)
                    window[windowCursor] = b
                    windowCursor = (windowCursor + 1) & WINDOW_MASK
                    position += 1
    return ordListToStr(output)

# Compress Konami LZ77 data
def LZ77Compress(input):
    input = [ord(x) for x in str(input)]
    window = [0] * WINDOW_SIZE
    currentPos = 0
    currentWindow = 0
    buffer = [0] * MAX_BUFFER
    output = []

    while currentPos < len(input):
        flagByte = 0
        currentBuffer = 0

        for i in range(8):
            if currentPos >= len(input):
                buffer[currentBuffer] = 0
                window[currentWindow] = 0
                currentBuffer += 1
                currentWindow += 1
                currentPos += 1
                bit = 0
            else:
                matchWindowResults = matchWindow(window, currentWindow, input, currentPos)

                if matchWindowResults.some and matchWindowResults.length >= THRESHOLD:
                    byte1 = ((matchWindowResults.pos & 0xFF) >> 4)
                    byte2 = (((matchWindowResults.pos & 0x0F) << 4) |
                             ((matchWindowResults.length - THRESHOLD) & 0x0F))

                    buffer[currentBuffer] = byte1
                    buffer[currentBuffer + 1] = byte2
                    currentBuffer += 2
                    bit = 0

                    for j in range(matchWindowResults.length):
                        window[currentWindow & WINDOW_MASK] = input[currentPos]
                        currentPos += 1
                        currentWindow += 1
                elif not matchWindowResults.some:
                    buffer[currentBuffer] = input[currentPos]
                    window[currentWindow] = input[currentPos]
                    currentPos += 1
                    currentWindow += 1
                    currentBuffer += 1
                    bit = 1

            flagByte = (((flagByte & 0xFF) >> 1) | ((bit & 1) << 7))
            currentWindow &= WINDOW_MASK

        output.append(flagByte)

        for k in range(currentBuffer):
            output.append(buffer[k])

    return ordListToStr(output)

# Converts a list of ordinal numbers into a string
def ordListToStr(ordList):
    return "".join([chr(x) for x in ordList])

def strToHexBytes(string):
    return "".join([
        chr(int(string[pos:pos+2], 16))
        for pos in range(len(string))
        if (pos % 2 == 0)
        ])

def hexBytesToStr(hexbytes):
    return "".join([
        str(hex(ord(byte)))[2:]
        for byte in hexbytes
        ])

# Returns the md5 digest of input. Should be used by headerToKey.
def md5Digest(input):
    h = MD5.new()
    h.update(input)
    return h.digest()

# Turns an E-Amuse-header into the ARC4 decryption key
def headerToKey(eamuseHeader):
    headerKey = eamuseHeader.split("-")
    fullKey = headerKey[1] + headerKey[2] + _secretKey
    rawKey = strToHexBytes(fullKey)
    arc4Key = md5Digest(rawKey)
    return arc4Key

# Decrypts given data with the ARC4 decryption key
def ARC4Decrypt(data, key):
    enc = ARC4.new(key)
    return enc.decrypt(data)

# Basically the same as thing
def ARC4Encrypt(data, key):
    return ARC4Decrypt(data, key)

# This is a kbinxml wrapper
def binaryToXml(binaryXml):
    return str(KBinXML(binaryXml).to_text())

# This is a kbinxml wrapper
def xmlToBinary(xmlData):
    return KBinXML(xmlData).to_binary()

# Determines if input data is binary xml
def isBinaryXML(data):
    return data[:5] != "<?xml"


# Main function for decrypting data
def mainDecrypt(data, eamuseHeader=None, LZ77Compressed=False, binaryXML=True):
    if eamuseHeader != None:
        arc4Key = headerToKey(eamuseHeader)
        data = ARC4Decrypt(data, arc4Key)
    if LZ77Compressed == True:
        data = LZ77Decompress(data)
    if binaryXML == True and isBinaryXML(data):
        data = binaryToXml(data)
    return data


# Main function for encrypting data
def mainEncrypt(data, eamuseHeader=None, LZ77Compressed=False, binaryXML=True):
    if binaryXML == True:
        data = xmlToBinary(data)
    if LZ77Compressed == True:
        data = LZ77Compress(data)
    if eamuseHeader != None:
        arc4Key = headerToKey(eamuseHeader)
        data = ARC4Encrypt(data, arc4Key)
    return data


# Test this encryption library
def unitTest():
    testKey = "1-5d917aaa-bc88"

    with open("Destroy/testData/binaryXML_LZ77_ARC4.txt", "rb") as BLA:
        with open("Destroy/testData/binaryXML_LZ77.txt", "rb") as BL:
            with open("Destroy/testData/binaryXML.txt", "rb") as B:
                with open("Destroy/testData/plainText.txt", "rb") as P:
                    BLA = BLA.read()
                    BL = BL.read()
                    B = B.read()
                    P = P.read()
    # Decryption
    assert ARC4Decrypt(BLA, headerToKey(testKey)) == BL
    assert LZ77Decompress(BL) == B
    assert binaryToXml(B) == P

    # Encryption #TODO
    '''
    fullEncrypt = mainEncrypt(P,
                eamuseHeader=testKey,
                LZ77Compressed=True)
    fullDecrypt = mainDecrypt(fullEncrypt,
                eamuseHeader=testKey,
                LZ77Compressed=True)
    '''
    trace("info", "Destroy unitTest OK")