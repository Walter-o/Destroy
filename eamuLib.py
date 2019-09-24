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
    input = [ord(m) for m in input]
    currByte = 0
    windowCursor = 0
    dataSize = len(input)
    window = [None for m in range(WINDOW_SIZE)]
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
                    return "".join([chr(m) for m in output])

                currByte += 2
                position = int((windowCursor - (w >> 4)) & WINDOW_MASK)
                length = (w & 0x0F) + THRESHOLD

                for j in range(length):
                    b = window[position & WINDOW_MASK]
                    output.append(b)
                    window[windowCursor] = b
                    windowCursor = (windowCursor + 1) & WINDOW_MASK
                    position += 1
    return "".join([chr(m) for m in output])

# Compress Konami LZ77 data
def LZ77Compress(input):
    input = [ord(x) for x in input]
    window = [None for x in range(WINDOW_SIZE)]
    currentPos = 0
    currentWindow = 0
    buffer = [None for x in range(MAX_BUFFER)]
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

    return "".join([chr(m) for m in output])

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
    # trace("debug", "headerToKey received: %s" % eamuseHeader)
    headerKey = eamuseHeader.split("-")
    fullKey = headerKey[1] + headerKey[2] + _secretKey
    rawKey = strToHexBytes(fullKey)
    arc4Key = md5Digest(rawKey)
    # trace("debug", "ARC4 key: %s"%hexBytesToStr(arc4Key))
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
    return KBinXML(binaryXml).to_text()

# This is a kbinxml wrapper
def xmlToBinary(xmlData):
    return KBinXML(xmlData).to_binary()

# Determines if input data is binary xml
def isBinaryXML(data):
    return data[:5] != "<?xml"


# Main function for decrypting data
def mainDecrypt(data, eamuseHeader=None, LZ77Compressed=False, binaryXML=True):
    if LZ77Compressed == True:
        data = LZ77Decompress(data)
    if eamuseHeader != None:
        arc4Key = headerToKey(eamuseHeader)
        data = ARC4Decrypt(data, arc4Key)
    if binaryXML == True and isBinaryXML(data):
        data = binaryToXml(data)
    trace("debug", "data: %s" % data)
    # Converting to string because Mon put effort into getting
    # unicode but it ends up not working with text to binary
    return str(data)


# Main function for encrypting data
def mainEncrypt(data, eamuseHeader=None, LZ77Compressed=False, binaryXML=True):
    if binaryXML == True:
        data = xmlToBinary(data)
    if eamuseHeader != None:
        arc4Key = headerToKey(eamuseHeader)
        data = ARC4Encrypt(data, arc4Key)
    if LZ77Compressed == True:
        data = LZ77Compress(data)
    return data


# Test this encryption library
def unitTest():
    # Set test header and test data
    testHeader = "1-5bfc6ff6-ba2f"
    with open("Destroy/testData/unitTestData.txt","rb") as testData:
        testDataBefore = testData.read()

    # Decrypting and re-encrypting the data, then assert equal to original
    testDataAfter = mainEncrypt( mainDecrypt(testDataBefore, testHeader), testHeader)
    assert testDataBefore == testDataAfter
    trace("info", "ARC4 Decrypt: OK")

    tests = ["small", "medium"]

    # LZ77 Decompression test
    for test in tests:
        with open("Destroy/testData/LZ77_%sData.txt" % test, "rb") as data:
            result = LZ77Decompress(data.read())
        with open("Destroy/testData/LZ77_%sDataAnswer.txt" % test, "rb") as answer:
            answer = answer.read()
        trace("info", "LZ77 Decompress: %s Data " % test + ("OK" if result == answer else "FAIL"))

    # LZ77 Compression test
    for test in tests:
        with open("Destroy/testData/LZ77_%sData.txt" % test, "rb") as data:
            compressedData = data.read()
        with open("Destroy/testData/LZ77_%sDataAnswer.txt" % test, "rb") as answer:
            compressedAnswer = LZ77Compress(answer.read())
        trace("info", "LZ77 Compress: %s Data " % test + ("OK" if compressedData == compressedAnswer else "FAIL"))


