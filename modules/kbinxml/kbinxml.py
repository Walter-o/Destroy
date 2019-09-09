# python 3 style, ints instead of b''
from builtins import bytes
from struct import calcsize
import string
import sys
import operator
from io import BytesIO

import lxml.etree as etree

from .bytebuffer import ByteBuffer
from .sixbit import pack_sixbit, unpack_sixbit
from .format_ids import xml_formats, xml_types

stdout = getattr(sys.stdout, 'buffer', sys.stdout)

DEBUG_OFFSETS = False
DEBUG = False

SIGNATURE = 0xA0

SIG_COMPRESSED = 0x42
SIG_UNCOMPRESSED = 0x45

XML_ENCODING = 'UTF-8'
BIN_ENCODING = 'cp932' # windows shift-jis variant

# NOTE: all of these are their python codec names
encoding_strings = {
    0x20: 'ASCII',
    0x00: 'ISO-8859-1',
    0x60: 'EUC_JP',
    0x80: 'cp932',
    0xA0: 'UTF-8'
}

encoding_vals = {val : key for key, val in encoding_strings.items()}

def debug_print(string):
    if DEBUG:
        print(string)

class KBinXML():

    def __init__(self, input):
        if isinstance(input, etree._Element):
            self.xml_doc = input
        elif isinstance(input, etree._ElementTree):
            self.xml_doc = input.getroot()
        elif KBinXML.is_binary_xml(input):
            self.from_binary(input)
        else:
            self.from_text(input)

    def to_text(self):
        # we decode again because I want unicode, dammit
        return etree.tostring(self.xml_doc, pretty_print=True,
            encoding=XML_ENCODING, xml_declaration=True).decode(XML_ENCODING)

    def from_text(self, input):
        self.xml_doc = etree.parse(BytesIO(input)).getroot()
        self.encoding = XML_ENCODING
        self.compressed = True
        self.dataSize = None

    @staticmethod
    def is_binary_xml(input):
        nodeBuf = ByteBuffer(input)
        return (nodeBuf.get_u8() == SIGNATURE and
            nodeBuf.get_u8() in (SIG_COMPRESSED, SIG_UNCOMPRESSED))

    @property
    def _data_mem_size(self):
        # This is probably better to be done in the parsing/writeout stage...

        data_len = 0
        for e in self.xml_doc.iter(tag=etree.Element):
            t = e.attrib.get('__type')
            if t is None:
                continue

            count = e.attrib.get('__count', 1)
            size = e.attrib.get('__size', 1)
            x = xml_formats[xml_types[t]]
            if x['count'] > 0:
                m = x['count'] * calcsize(x['type']) * count * size
            elif x['name'] == 'bin':
                m = len(e.text) // 2
            else: # string
                # null terminator space
                m = len(e.text.encode(self.encoding)) + 1

            if m <= 4:
                continue

            if x['name'] == 'bin':
                data_len += (m + 1) & ~1
            else:
                data_len += (m + 3) & ~3
        return data_len

    @property
    def mem_size(self):
        '''used when allocating memory ingame'''

        data_len = self._data_mem_size
        node_count = len(list(self.xml_doc.iter(tag=etree.Element)))

        if self.compressed:
            size = 52 * node_count + data_len + 630
        else:
            tags_len = 0
            for e in self.xml_doc.iter(tag=etree.Element):
                e_len = max(len(e.tag), 8)
                e_len = (e_len + 3) & ~3
                tags_len += e_len

            size = 56 * node_count + data_len + 630 + tags_len

        # debugging
        #print('nodes:{} ({}) data:{} ({})'.format(node_count,hex(node_count), data_len, hex(data_len)))

        return (size + 8) & ~7

    def data_grab_auto(self):
        size = self.dataBuf.get_s32()
        ret = self.dataBuf.get_bytes(size)
        self.dataBuf.realign_reads()
        return ret

    def data_append_auto(self, data):
        self.dataBuf.append_s32(len(data))
        self.dataBuf.append_bytes(data)
        self.dataBuf.realign_writes()

    def data_grab_string(self):
        data = self.data_grab_auto()
        return bytes(data[:-1]).decode(self.encoding)

    def data_append_string(self, string):
        string = bytes(string.encode(self.encoding) + b'\0')
        self.data_append_auto(string)

    # has its own separate state and other assorted garbage
    def data_grab_aligned(self, type, count):
        if self.dataByteBuf.offset % 4 == 0:
            self.dataByteBuf.offset = self.dataBuf.offset
        if self.dataWordBuf.offset % 4 == 0:
            self.dataWordBuf.offset = self.dataBuf.offset
        # multiply by count since 2u2 reads from the 16 bit buffer, for example
        size = calcsize(type) * count
        if size == 1:
            ret = self.dataByteBuf.get(type, count)
        elif size == 2:
            ret = self.dataWordBuf.get(type, count)
        else:
            ret = self.dataBuf.get(type, count)
            self.dataBuf.realign_reads()
        trailing = max(self.dataByteBuf.offset, self.dataWordBuf.offset)
        if self.dataBuf.offset < trailing:
            self.dataBuf.offset = trailing
            self.dataBuf.realign_reads()
        return ret

    def data_append_aligned(self, data, type, count):
        if self.dataByteBuf.offset % 4 == 0:
            self.dataByteBuf.offset = self.dataBuf.offset
        if self.dataWordBuf.offset % 4 == 0:
            self.dataWordBuf.offset = self.dataBuf.offset
        # multiply by count since 2u2 reads from the 16 bit buffer, for example
        size = calcsize(type) * count
        if size == 1:
            # make room for our stuff if fresh dword
            if self.dataByteBuf.offset % 4 == 0:
                self.dataBuf.append_u32(0)
            self.dataByteBuf.set(data, self.dataByteBuf.offset, type, count)
        elif size == 2:
            if self.dataWordBuf.offset % 4 == 0:
                self.dataBuf.append_u32(0)
            self.dataWordBuf.set(data, self.dataWordBuf.offset, type, count)
        else:
            self.dataBuf.append(data, type, count)
            self.dataBuf.realign_writes()

    def append_node_name(self, name):
        if self.compressed:
            pack_sixbit(name, self.nodeBuf)
        else:
            enc = name.encode(self.encoding)
            self.nodeBuf.append_u8((len(enc) - 1) | 64)
            self.nodeBuf.append_bytes(enc)

    def _node_to_binary(self, node):
        nodeType = node.attrib.get('__type')
        if not nodeType:
            # typeless tags with text become string
            if node.text is not None and len(node.text.strip()) > 0:
                nodeType = 'str'
            else:
                nodeType = 'void'
        nodeId = xml_types[nodeType]

        isArray = 0
        count = node.attrib.get('__count')
        if count:
            count = int(count)
            isArray = 64 # bit position for array flag

        self.nodeBuf.append_u8(nodeId | isArray)

        name = node.tag
        self.append_node_name(name)

        if nodeType != 'void':
            fmt = xml_formats[nodeId]

            val = node.text
            if fmt['name'] == 'bin':
                data = bytes(bytearray.fromhex(val))
            elif fmt['name'] == 'str':
                if val is None: # empty string
                    val = ''
                data = bytes(val.encode(self.encoding, 'replace') + b'\0')
            else:
                val = val.split(' ')
                data = list(map(fmt.get('fromStr', int), val))
                if count and len(data) / fmt['count'] != count:
                    raise ValueError('Array length does not match __count attribute')

            if isArray or fmt['count'] == -1:
                self.dataBuf.append_u32(len(data) * calcsize(fmt['type']))
                self.dataBuf.append(data, fmt['type'], len(data))
                self.dataBuf.realign_writes()
            else:
                self.data_append_aligned(data, fmt['type'], fmt['count'])

        # for test consistency and to be more faithful, sort the attrs
        sorted_attrs = sorted(node.attrib.items(), key=operator.itemgetter(0))
        for key, value in sorted_attrs:
            if key not in ['__type', '__size', '__count']:
                self.data_append_string(value)
                self.nodeBuf.append_u8(xml_types['attr'])
                self.append_node_name(key)

        for child in node.iterchildren(tag=etree.Element):
            self._node_to_binary(child)

        # always has the isArray bit set
        self.nodeBuf.append_u8(xml_types['nodeEnd'] | 64)

    def to_binary(self, encoding = BIN_ENCODING, compressed = True):
        self.encoding = encoding
        self.compressed = compressed

        header = ByteBuffer()
        header.append_u8(SIGNATURE)
        if self.compressed:
            header.append_u8(SIG_COMPRESSED)
        else:
            header.append_u8(SIG_UNCOMPRESSED)
        header.append_u8(encoding_vals[self.encoding])
        # Python's ints are big, so can't just bitwise invert
        header.append_u8(0xFF ^ encoding_vals[self.encoding])
        self.nodeBuf = ByteBuffer()
        self.dataBuf = ByteBuffer()
        self.dataByteBuf = ByteBuffer(self.dataBuf.data)
        self.dataWordBuf = ByteBuffer(self.dataBuf.data)

        self._node_to_binary(self.xml_doc)

        # always has the isArray bit set
        self.nodeBuf.append_u8(xml_types['endSection'] | 64)
        self.nodeBuf.realign_writes()
        header.append_u32(len(self.nodeBuf))
        self.dataSize = len(self.dataBuf)
        self.nodeBuf.append_u32(self.dataSize)
        return bytes(header.data + self.nodeBuf.data + self.dataBuf.data)

    def from_binary(self, input):
        self.xml_doc = etree.Element('root')
        node = self.xml_doc

        self.nodeBuf = ByteBuffer(input)
        assert self.nodeBuf.get_u8() == SIGNATURE

        compress = self.nodeBuf.get_u8()
        assert compress in (SIG_COMPRESSED, SIG_UNCOMPRESSED)
        self.compressed = compress == SIG_COMPRESSED

        encoding_key = self.nodeBuf.get_u8()
        assert self.nodeBuf.get_u8() == 0xFF ^ encoding_key
        self.encoding = encoding_strings[encoding_key]

        nodeEnd = self.nodeBuf.get_u32() + 8
        self.nodeBuf.end = nodeEnd

        self.dataBuf = ByteBuffer(input, nodeEnd)
        self.dataSize = self.dataBuf.get_u32()
        # This is all no fun
        self.dataByteBuf = ByteBuffer(input, nodeEnd)
        self.dataWordBuf = ByteBuffer(input, nodeEnd)

        nodesLeft = True
        while nodesLeft and self.nodeBuf.hasData():
            while self.nodeBuf.peek_u8() == 0:
                debug_print("Skipping 0 node ID")
                self.nodeBuf.get_u8()

            nodeType = self.nodeBuf.get_u8()
            isArray = nodeType & 64
            nodeType &= ~64

            nodeFormat = xml_formats.get(nodeType, {'name':'Unknown'})
            debug_print('Node type is {} ({})'.format(nodeFormat['name'], nodeType))

            # node or attribute name
            name = ''
            if nodeType != xml_types['nodeEnd'] and nodeType != xml_types['endSection']:
                if self.compressed:
                    name = unpack_sixbit(self.nodeBuf)
                else:
                    length = (self.nodeBuf.get_u8() & ~64) + 1
                    name = self.nodeBuf.get_bytes(length)
                    name = bytes(name).decode(self.encoding)
                debug_print(name)

            skip = True

            if nodeType == xml_types['attr']:
                value = self.data_grab_string()
                node.attrib[name] = value
            elif nodeType == xml_types['nodeEnd']:
                if node.getparent() is not None:
                    node = node.getparent()
            elif nodeType == xml_types['endSection']:
                nodesLeft = False
            elif nodeType not in xml_formats:
                raise NotImplementedError('Implement node {}'.format(nodeType))
            else: # inner value to process
                skip = False

            if skip:
                continue

            child = etree.SubElement(node, name)
            node = child

            if nodeType == xml_types['nodeStart']:
                continue

            node.attrib['__type'] = nodeFormat['name']

            varCount = nodeFormat['count']
            arrayCount = 1
            if varCount == -1: # the 2 cannot be combined
                varCount = self.dataBuf.get_u32()
                isArray = True
            elif isArray:
                arrayCount = self.dataBuf.get_u32() // (calcsize(nodeFormat['type'] * varCount))
                node.attrib['__count'] = str(arrayCount)
            totalCount = arrayCount * varCount

            if isArray:
                data = self.dataBuf.get(nodeFormat['type'], totalCount)
                self.dataBuf.realign_reads()
            else:
                data = self.data_grab_aligned(nodeFormat['type'], totalCount)

            if nodeType == xml_types['binary']:
                node.attrib['__size'] = str(totalCount)
                string = ''.join(('{0:02x}'.format(x) for x in data))
            elif nodeType == xml_types['string']:
                string = bytes(data[:-1]).decode(self.encoding)
            else:
                string = ' '.join(map(nodeFormat.get('toStr', str), data))

            node.text = string

        # because we need the 'real' root
        self.xml_doc = self.xml_doc[0]

def main():
    if len(sys.argv) != 2:
        print('bin_xml.py file.[xml/bin]')
        exit()

    with open(sys.argv[1], 'rb') as f:
        input = f.read()

    xml = KBinXML(input)
    if KBinXML.is_binary_xml(input):
        stdout.write(xml.to_text().encode('utf-8'))
    else:
        stdout.write(xml.to_binary())

if __name__ == '__main__':
    main()
