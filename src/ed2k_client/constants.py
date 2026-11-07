"""Protocol constants of eD2k and Kad 2, taken from the aMule headers.

The opcode values come from ``src/include/protocol`` and ``src/include/tags`` of aMule at commit
6a1105634d81242a581a0f36a7e00379b12a83f3, and each group links to its header. Every value here is fixed by the
protocol. The values this client chose, its timeouts and safety limits, live in :mod:`ed2k_client.settings`.
"""

from enum import IntEnum, IntFlag


# https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/include/protocol/Protocols.h#L34
class Protocol(IntEnum):
    """First byte of every packet, which selects the opcode namespace."""

    EDONKEY = 0xE3
    EMULE = 0xC5
    PACKED = 0xD4
    KAD = 0xE4
    KAD_PACKED = 0xE5


# https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/include/protocol/ed2k/Client2Server/TCP.h#L30
class ServerOp(IntEnum):
    """Opcodes of the client to server TCP session."""

    LOGINREQUEST = 0x01
    REJECT = 0x05
    GETSERVERLIST = 0x14
    OFFERFILES = 0x15
    SEARCHREQUEST = 0x16
    DISCONNECT = 0x18
    GETSOURCES = 0x19
    CALLBACKREQUEST = 0x1C
    QUERY_MORE_RESULT = 0x21
    GETSOURCES_OBFU = 0x23
    SERVERLIST = 0x32
    SEARCHRESULT = 0x33
    SERVERSTATUS = 0x34
    CALLBACKREQUESTED = 0x35
    CALLBACK_FAIL = 0x36
    SERVERMESSAGE = 0x38
    IDCHANGE = 0x40
    SERVERIDENT = 0x41
    FOUNDSOURCES = 0x42
    USERS_LIST = 0x43
    FOUNDSOURCES_OBFU = 0x44


# https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/include/protocol/ed2k/Client2Client/TCP.h#L31
class PeerOp(IntEnum):
    """Opcodes of the client to client TCP session in the original eDonkey namespace."""

    HELLO = 0x01
    SENDINGPART = 0x46
    REQUESTPARTS = 0x47
    FILEREQANSNOFIL = 0x48
    END_OF_DOWNLOAD = 0x49
    ASKSHAREDFILES = 0x4A
    HELLOANSWER = 0x4C
    MESSAGE = 0x4E
    SETREQFILEID = 0x4F
    FILESTATUS = 0x50
    HASHSETREQUEST = 0x51
    HASHSETANSWER = 0x52
    STARTUPLOADREQ = 0x54
    ACCEPTUPLOADREQ = 0x55
    CANCELTRANSFER = 0x56
    OUTOFPARTREQS = 0x57
    REQUESTFILENAME = 0x58
    REQFILENAMEANSWER = 0x59
    QUEUERANK = 0x5C
    ASKSHAREDDENIEDANS = 0x61


# https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/include/protocol/ed2k/Client2Client/TCP.h#L62
class EmuleOp(IntEnum):
    """Opcodes of the client to client TCP session in the eMule extension namespace."""

    EMULEINFO = 0x01
    EMULEINFOANSWER = 0x02
    COMPRESSEDPART = 0x40
    QUEUERANKING = 0x60
    AICHREQUEST = 0x9B
    AICHANSWER = 0x9C
    REQUESTSOURCES2 = 0x83
    ANSWERSOURCES2 = 0x84
    MULTIPACKET = 0x92
    MULTIPACKETANSWER = 0x93
    COMPRESSEDPART_I64 = 0xA1
    SENDINGPART_I64 = 0xA2
    REQUESTPARTS_I64 = 0xA3


# https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/include/protocol/kad2/Client2Client/UDP.h#L34
class KadOp(IntEnum):
    """Opcodes of Kad 2 over UDP."""

    BOOTSTRAP_REQ = 0x01
    BOOTSTRAP_RES = 0x09
    HELLO_REQ = 0x11
    HELLO_RES = 0x19
    REQ = 0x21
    HELLO_RES_ACK = 0x22
    RES = 0x29
    SEARCH_KEY_REQ = 0x33
    SEARCH_SOURCE_REQ = 0x34
    SEARCH_NOTES_REQ = 0x35
    SEARCH_RES = 0x3B
    PUBLISH_KEY_REQ = 0x43
    PUBLISH_SOURCE_REQ = 0x44
    PUBLISH_RES = 0x4B
    PING = 0x60
    PONG = 0x61


# https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/include/tags/TagTypes.h#L30
class TagType(IntEnum):
    """Value types of a tag; the short string types STR1 to STR16 follow ``STR1`` consecutively."""

    HASH16 = 0x01
    STRING = 0x02
    UINT32 = 0x03
    FLOAT32 = 0x04
    BOOL = 0x05
    BOOLARRAY = 0x06
    BLOB = 0x07
    UINT16 = 0x08
    UINT8 = 0x09
    BSOB = 0x0A
    UINT64 = 0x0B
    STR1 = 0x11
    STR16 = 0x20


# https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/include/tags/FileTags.h#L30
class FileTag(IntEnum):
    """Numeric tag names that describe a file."""

    NAME = 0x01
    SIZE = 0x02
    TYPE = 0x03
    FORMAT = 0x04
    SOURCES = 0x15
    COMPLETE_SOURCES = 0x30
    SIZE_HI = 0x3A
    MEDIA_LENGTH = 0xD3
    ENCRYPTION = 0xF3
    SOURCE_UDP_PORT = 0xFC
    SOURCE_PORT = 0xFD
    SOURCE_IP = 0xFE
    SOURCE_TYPE = 0xFF


# https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/include/tags/ClientTags.h#L30
class ClientTag(IntEnum):
    """Numeric tag names of the login and hello packets."""

    NAME = 0x01
    PORT = 0x0F
    VERSION = 0x11
    SERVER_FLAGS = 0x20
    EMULECOMPAT_OPTIONS = 0xEF
    EMULE_UDPPORTS = 0xF9
    EMULE_MISCOPTIONS1 = 0xFA
    EMULE_VERSION = 0xFB
    EMULE_MISCOPTIONS2 = 0xFE


# https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/include/tags/ClientTags.h#L71
class LoginFlag(IntFlag):
    """Capabilities a client announces to a server in the login tag ``SERVER_FLAGS``."""

    ZLIB = 0x0001
    IP_IN_LOGIN = 0x0002
    AUXPORT = 0x0004
    NEWTAGS = 0x0008
    UNICODE = 0x0010
    LARGEFILES = 0x0100
    SUPPORTCRYPT = 0x0200
    REQUESTCRYPT = 0x0400
    REQUIRECRYPT = 0x0800


# https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/include/protocol/ed2k/Client2Server/TCP.h#L65
class ServerTcpFlag(IntFlag):
    """Capabilities a server reports to a client after the assigned ID in ``IDCHANGE``."""

    COMPRESSION = 0x0001
    NEWTAGS = 0x0008
    UNICODE = 0x0010
    RELATEDSEARCH = 0x0040
    TYPETAGINTEGER = 0x0080
    LARGEFILES = 0x0100
    TCPOBFUSCATION = 0x0400


class CryptOption(IntFlag):
    """Obfuscation settings of a source as a server or Kad reports them."""

    SUPPORTED = 0x01
    REQUESTED = 0x02
    REQUIRED = 0x04
    HAS_USER_HASH = 0x80


class SearchOperator(IntEnum):
    """Comparison operators of a numeric search term."""

    EQUAL = 0
    GREATER = 1
    LESS = 2
    GREATER_EQUAL = 3
    LESS_EQUAL = 4
    NOT_EQUAL = 5


# File geometry. A file is hashed in parts and transferred in blocks that never cross a part boundary.
# https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/include/protocol/ed2k/Constants.h#L77
PART_SIZE: int = 9_728_000
BLOCK_SIZE: int = 184_320
MAX_FILE_SIZE: int = 0x40_0000_0000

# Above 4 GiB the 32-bit offsets of the original packets overflow, and the _I64 opcodes and SIZE_HI tag take over
LARGE_FILE_THRESHOLD: int = 0xFFFF_FFFF

# The MD4 of no bytes, appended to the part hashes when a file is an exact multiple of PART_SIZE
EMPTY_MD4: bytes = bytes.fromhex('31D6CFE0D16AE931B73C59D7E0C089C0')
HASH_LENGTH: int = 16
# AICH hashes are SHA-1 digests
AICH_HASH_LENGTH: int = 20

# Identity and versions announced to the network
# https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/include/common/ClientVersion.h#L42
EDONKEY_VERSION: int = 0x3C
# https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/include/protocol/kad2/Constants.h#L29
KADEMLIA_VERSION: int = 0x08
# SO_COMPAT_UNK, an eMule-compatible client without an assigned id:
# https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/include/protocol/ed2k/ClientSoftware.h#L47
SOFTWARE_ID: int = 0xFF
SOFTWARE_VERSION: tuple[int, int, int] = (0, 1, 0)

# Byte 5 = 14 and byte 14 = 111 mark the user hash of an eMule-family client, and aMule tells clients apart by them:
# https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/BaseClient.cpp#L1743
USER_HASH_MARKERS: dict[int, int] = {5: 14, 14: 111}

# An ID below 2^24 is a Low ID, a server-assigned number of a client that cannot accept connections:
# https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/NetworkFunctions.h#L123
LOW_ID_LIMIT: int = 0x0100_0000

# Default ports
DEFAULT_TCP_PORT: int = 4662
DEFAULT_UDP_PORT: int = 4672

# OP_REQUESTPARTS carries exactly three start and three end offsets:
# https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/include/protocol/ed2k/Client2Client/TCP.h#L33
MAX_REQUEST_RANGES: int = 3

# Limits the protocol itself sets: one block plus its header, and the parts of the largest file plus one spare
MAX_DATA_PACKET: int = BLOCK_SIZE + 1024
MAX_HASHSET_PARTS: int = MAX_FILE_SIZE // PART_SIZE + 2
