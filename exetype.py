#---------------------------------------------------------------------
#
# Executable identification
#
EXETYPE_NONE        = 0x0000
EXETYPE_LINUX       = 0x0001
EXETYPE_WINDOWS     = 0x0002
EXETYPE_MACOS       = 0x0004
EXETYPE_MACOS_FAT   = 0x0008
EXETYPE_32BITS      = 0x0010
EXETYPE_64BITS      = 0x0020

# Keep signatures sorted by size
_EXE_SIGNATURES = (
    ("\x4D\x5A", EXETYPE_WINDOWS),
    ("\xCE\xFA\xED\xFE", EXETYPE_MACOS | EXETYPE_32BITS),
    ("\xCF\xFA\xED\xFE", EXETYPE_MACOS | EXETYPE_64BITS),
    ("\xBE\xBA\xFE\xCA", EXETYPE_MACOS | EXETYPE_32BITS | EXETYPE_MACOS_FAT),
    ("\xBF\xBA\xFE\xCA", EXETYPE_MACOS | EXETYPE_64BITS | EXETYPE_MACOS_FAT),
    ("\x7F\x45\x4C\x46\x01", EXETYPE_LINUX | EXETYPE_32BITS),
    ("\x7F\x45\x4C\x46\x02", EXETYPE_LINUX | EXETYPE_64BITS)
)

def get_exetype(filepath):
    try:
        with open(filepath, "rb") as f:
            buf = ""
            buf_len = 0
            for sig, exe_type in _EXE_SIGNATURES:
                sig_len = len(sig)
                if buf_len < sig_len:
                    buf += f.read(sig_len - buf_len)
                    buf_len = sig_len

                if buf == sig:
                    return exe_type
    except:
        pass

    return EXETYPE_NONE
