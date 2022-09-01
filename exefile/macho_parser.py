"""

Code based on https://github.com/penvirus/macho_parser

Adopted by Elias Bachaalany <elias.bachaalany@gmail.com>

- 01/17/2019 - make it work on Windows
             - added test dump function
             - make it work in Python 3.x

"""

from collections import namedtuple
from struct import Struct

try:
    # Python 2
    xrange
except NameError:
    # Python 3, xrange is now named range
    xrange = range

"""
struct mach_header {
        uint32_t        magic;
        cpu_type_t      cputype;
        cpu_subtype_t   cpusubtype;
        uint32_t        filetype;
        uint32_t        ncmds;
        uint32_t        sizeofcmds;
        uint32_t        flags;
};

#define MH_MAGIC        0xfeedface
#define MH_CIGAM        0xcefaedfe
"""
mach_header = namedtuple('mach_header', 'magic cputype cpusubtype filetype ncmds sizeofcmds flags')
mach_header_struct = Struct('IiiIIII')
mh_magic = 0xfeedface
mh_cigam = 0xcefaedfe

"""
struct mach_header_64 {
        uint32_t        magic;
        cpu_type_t      cputype;
        cpu_subtype_t   cpusubtype;
        uint32_t        filetype;
        uint32_t        ncmds;
        uint32_t        sizeofcmds;
        uint32_t        flags;
        uint32_t        reserved;
};

#define MH_MAGIC_64 0xfeedfacf
#define MH_CIGAM_64 0xcffaedfe
"""
mach_header_64 = namedtuple('mach_header_64', 'magic cputype cpusubtype filetype ncmds sizeofcmds flags reserved')
mach_header_64_struct = Struct('IiiIIIII')
mh_magic_64 = 0xfeedfacf
mh_cigam_64 = 0xcffaedfe

"""
struct load_command {
        uint32_t cmd;
        uint32_t cmdsize;
};

#define LC_SEGMENT      0x1
#define LC_SEGMENT_64   0x19
"""
load_command = namedtuple('load_command', 'cmd cmdsize')
load_command_struct = Struct('II')
LC_SEGMENT = 0x1
LC_SEGMENT_64 = 0x19

"""
struct segment_command {
        uint32_t        cmd;
        uint32_t        cmdsize;
        char            segname[16];
        uint32_t        vmaddr;
        uint32_t        vmsize;
        uint32_t        fileoff;
        uint32_t        filesize;
        vm_prot_t       maxprot;
        vm_prot_t       initprot;
        uint32_t        nsects;
        uint32_t        flags;
};
"""
segment_command = namedtuple('segment_command', 'cmd cmdsize segname vmaddr vmsize fileoff filesize maxprot initprot nsects flags')
segment_command_struct = Struct('II16sIIIIiiII')

"""
struct segment_command_64 {
        uint32_t        cmd;
        uint32_t        cmdsize;
        char            segname[16];
        uint64_t        vmaddr;
        uint64_t        vmsize;
        uint64_t        fileoff;
        uint64_t        filesize;
        vm_prot_t       maxprot;
        vm_prot_t       initprot;
        uint32_t        nsects;
        uint32_t        flags;
};
"""
segment_command_64 = namedtuple('segment_command_64', 'cmd cmdsize segname vmaddr vmsize fileoff filesize maxprot initprot nsects flags')
segment_command_64_struct = Struct('II16sQQQQiiII')

"""
struct section {
        char            sectname[16];
        char            segname[16];
        uint32_t        addr;
        uint32_t        size;
        uint32_t        offset;
        uint32_t        align;
        uint32_t        reloff;
        uint32_t        nreloc;
        uint32_t        flags;
        uint32_t        reserved1;
        uint32_t        reserved2;
};
"""
section = namedtuple('section', 'sectname segname addr size offset align reloff nreloc flags reserved1 reserved2')
section_struct = Struct('16s16sIIIIIIIII')

"""
struct section_64 {
        char            sectname[16];
        char            segname[16];
        uint64_t        addr;
        uint64_t        size;
        uint32_t        offset;
        uint32_t        align;
        uint32_t        reloff;
        uint32_t        nreloc;
        uint32_t        flags;
        uint32_t        reserved1;
        uint32_t        reserved2;
        uint32_t        reserved3;
};
"""
section_64 = namedtuple('section_64', 'sectname segname addr size offset align reloff nreloc flags reserved1 reserved2 reserved3')
section_64_struct = Struct('16s16sQQIIIIIIII')


class MachO(object):
    def __init__(self, filename):
        self._filename = filename
        self._rf = None
        self._mem = None

    def __enter__(self):
        self._rf = open(self._filename, 'rb')
        self._mem = self._rf.read()
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        if exc_type is not None:
            pass
        self._mem = None
        self._rf.close()

    def _get_header(self):
        """return a 3-tuple (begin_pos, end_pos, header)."""
        header = mach_header._make(mach_header_struct.unpack(self._mem[:mach_header_struct.size]))
        if header.magic == mh_magic_64 or header.magic == mh_cigam_64:
            return (0, mach_header_64_struct.size, mach_header_64._make(mach_header_64_struct.unpack(self._mem[:mach_header_64_struct.size])))
        else:
            return (0, mach_header_struct.size, header)

    def get_header(self):
        return self._get_header()[2]

    def _get_load_commands(self):
        """return a 3-tuple (begin_pos, end_pos, load_command)."""
        _, cur_pos, header = self._get_header()
        for i in xrange(header.ncmds):
            lc = load_command._make(load_command_struct.unpack(self._mem[cur_pos : cur_pos + load_command_struct.size]))
            yield (cur_pos, cur_pos + load_command_struct.size, lc)
            cur_pos += lc.cmdsize

    def get_load_commands(self):
        for _, _, lc in self._get_load_commands():
            yield lc

    def _get_segments(self):
        """return a 3-tuple (begin_pos, end_pos, segment)."""
        for pos, _, lc in self._get_load_commands():
            if lc.cmd == LC_SEGMENT_64:
                seg = segment_command_64._make(segment_command_64_struct.unpack(self._mem[pos : pos + segment_command_64_struct.size]))
                yield (pos, pos + segment_command_64_struct.size, seg)
            elif lc.cmd == LC_SEGMENT:
                seg = segment_command._make(segment_command_struct.unpack(self._mem[pos : pos + segment_command_struct.size]))
                yield (pos, pos + segment_command_struct.size, seg)

    def get_segments(self):
        for _, _, seg in self._get_segments():
            yield seg

    def _get_sections(self):
        """return a 3-tuple (begin_pos, end_pos, section)."""
        for pos, sect_pos, seg in self._get_segments():
            for i in xrange(seg.nsects):
                """NOTE: move the branch to outter loop will be better for performance consideration, but it will duplicate some code."""
                """NOTE: in the case, I don't care about the performance."""
                if seg.cmd == LC_SEGMENT_64:
                    sect = section_64._make(section_64_struct.unpack(self._mem[sect_pos : sect_pos + section_64_struct.size]))
                    yield (sect_pos, sect_pos + section_64_struct.size, sect)
                    sect_pos += section_64_struct.size
                else:
                    sect = section._make(section_struct.unpack(self._mem[sect_pos : sect_pos + section_struct.size]))
                    yield (sect_pos, sect_pos + section_struct.size, sect)
                    sect_pos += section_struct.size

    def get_sections(self):
        for _, _, sect in self._get_sections():
            yield sect

    def _get_data(self, offset, length):
        return self._mem[offset : offset + length]

    @staticmethod
    def as_string(byte_str):
        if len(byte_str) == 0:
            return ''
        try:
            cvt = chr(byte_str[0])
            cvt = chr
        except:
            cvt = lambda x: x

        s = ''
        for x in byte_str:
            x = cvt(x)
            if x == '\x00':
                break
            s += x

        return s

    def get_section_data(self, segname, sectname):
        """Return the binary data for the given segment/section"""
        for sect in self.get_sections():
            sgname = self.as_string(sect.segname)
            stname = self.as_string(sect.sectname)
            if sgname == segname and stname == sectname:
                return self._get_data(sect.offset, sect.size)

        return None


def test_dump_info(fn, segs = True, secs = True):
    with MachO(fn) as m:
        if segs:
            print()
            print("Dumping segments:")
            print("-----------------")
            for x in m.get_segments():
                print(m.as_string(x.segname))

        if secs:
            print()
            print("Dumping sections:")
            print("-----------------")
            for x in m.get_sections():
                print("Segment: %30s Section: %30s" % (
                    m.as_string(x.segname), m.as_string(x.sectname)))

