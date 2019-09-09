# A Private project by Walter
#
# This library can decrypt Konami arcade game network data
# that are part of the E-amusement network.

from Crypto.Cipher import ARC4  # TODO: Check if this can be included as well, just in case.
from Crypto.Hash import MD5

from modules.kbinxml.kbinxml import KBinXML
from debugLib import trace

_secretKey = "69D74627D985EE2187161570D08D93B12455035B6DF0D8205DF5"

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
def mainDecrypt(data, eamuseHeader=None, LZ77Compressed=False):
    if LZ77Compressed == True:
        trace("warn", "LZ77 not implemented yet.")
    if eamuseHeader != None:
        arc4Key = headerToKey(eamuseHeader)
        data = ARC4Decrypt(data, arc4Key)
    if isBinaryXML(data):
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
        trace("warn", "LZ77 not implemented yet.")
    return data


# Test this encryption library
def unitTest():
    # Set test header and test data
    testHeader = "1-5bfc6ff6-ba2f"
    with open("testData/unitTestData.txt","rb") as testData:
        testDataBefore = testData.read()

    # Decrypting and re-encrypting the data, then assert equal to original
    testDataAfter = mainEncrypt( mainDecrypt(testDataBefore, testHeader), testHeader)
    assert testDataBefore == testDataAfter
    trace("info", "Unit-test OK")

unitTest()