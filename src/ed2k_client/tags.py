"""Tags: the typed name and value pairs that carry metadata in eD2k and Kad packets.

Reading accepts both name forms (a one-byte id after a type with the high bit set, or a length-prefixed name) and
every value type aMule accepts. Writing always uses the old form with a length-prefixed name, which aMule's
``WriteTagToFile`` uses for login and hello packets and which every server and client reads.
"""

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ed2k_client.constants import HASH_LENGTH, MAX_TAGS, TagType
from ed2k_client.errors import ProtocolError
from ed2k_client.wire import U8, U32, Reader, Writer, decode_text

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Mapping

type TagName = int | str
type TagValue = int | str | bytes | float

NEW_FORM_BIT: int = 0x80
UINT32_MAX: int = 0xFFFF_FFFF


@dataclass(frozen=True, slots=True)
class Tag:
    """One tag.

    :ivar name: a numeric id or a string name.
    :ivar value: an integer, a text, raw bytes (hash or blob) or a float.
    """

    name: TagName
    value: TagValue


VALUE_READERS: dict[int, Callable[[Reader], TagValue]] = {
    TagType.STRING: Reader.string,
    TagType.UINT8: Reader.u8,
    TagType.BOOL: Reader.u8,
    TagType.UINT16: Reader.u16,
    TagType.UINT32: Reader.u32,
    TagType.UINT64: Reader.u64,
    TagType.FLOAT32: Reader.f32,
    TagType.HASH16: Reader.hash16,
    TagType.BOOLARRAY: lambda reader: reader.take(reader.u16() // 8 + 1),
    TagType.BLOB: lambda reader: reader.take(reader.u32()),
    TagType.BSOB: lambda reader: reader.take(reader.u8()),
}


def _read_value(reader: Reader, tag_type: int) -> TagValue:
    """Read a tag value of the given type.

    :param reader: the reader.
    :type reader: Reader
    :param tag_type: the value type without the name-form bit.
    :type tag_type: int
    :returns: the value.
    :rtype: TagValue
    :raises ProtocolError: on an unknown type.
    """
    if (read := VALUE_READERS.get(tag_type)) is not None:
        return read(reader)
    if TagType.STR1 <= tag_type <= TagType.STR16:
        return decode_text(reader.take(tag_type - TagType.STR1 + 1))
    err_msg = f'unknown tag type 0x{tag_type:02X}'
    raise ProtocolError(err_msg)


def read_tag(reader: Reader) -> Tag:
    """Read one tag.

    :param reader: the packet reader.
    :type reader: Reader
    :returns: the tag.
    :rtype: Tag
    :raises ProtocolError: on an unknown type, whose length cannot be known, so the whole packet is lost.
    """
    tag_type = reader.u8()
    name: TagName
    if tag_type & NEW_FORM_BIT:
        tag_type &= ~NEW_FORM_BIT
        name = reader.u8()
    else:
        raw_name = reader.take(reader.u16())
        name = raw_name[0] if len(raw_name) == 1 else decode_text(raw_name)
    return Tag(name=name, value=_read_value(reader, tag_type))


def read_tags(reader: Reader, *, count_size: int = 4) -> list[Tag]:
    """Read a counted tag list.

    :param reader: the packet reader.
    :type reader: Reader
    :param count_size: width of the count, 4 bytes in eD2k and 1 byte in Kad.
    :type count_size: int
    :returns: the tags in order.
    :rtype: list[Tag]
    :raises ProtocolError: when the count exceeds :data:`MAX_TAGS`.
    """
    count = reader.u8() if count_size == 1 else reader.u32()
    if count > MAX_TAGS:
        err_msg = f'{count} tags exceed the limit of {MAX_TAGS}'
        raise ProtocolError(err_msg)
    return [read_tag(reader) for _ in range(count)]


def write_tag(writer: Writer, tag: Tag) -> None:
    """Append one tag in the old form with a length-prefixed name.

    Integers take UINT32 when they fit and UINT64 otherwise, because some servers reject the 8- and 16-bit types in
    login packets.

    :param writer: the payload writer.
    :type writer: Writer
    :param tag: the tag.
    :type tag: Tag
    """
    body = Writer()
    match tag.value:
        case int() as number if number <= UINT32_MAX:
            tag_type = TagType.UINT32
            body.u32(number)
        case int() as number:
            tag_type = TagType.UINT64
            body.u64(number)
        case str() as text:
            tag_type = TagType.STRING
            body.string(text)
        case float() as real:
            tag_type = TagType.FLOAT32
            body.f32(real)
        case bytes() as blob if len(blob) == HASH_LENGTH:
            tag_type = TagType.HASH16
            body.raw(blob)
        case bytes() as blob:
            tag_type = TagType.BLOB
            body.u32(len(blob)).raw(blob)
    name = bytes([tag.name]) if isinstance(tag.name, int) else tag.name.encode()
    writer.u8(tag_type).u16(len(name)).raw(name).raw(body.getvalue())


def write_tags(writer: Writer, tags: Iterable[Tag], *, count_size: int = 4) -> None:
    """Append a counted tag list.

    :param writer: the payload writer.
    :type writer: Writer
    :param tags: the tags.
    :type tags: Iterable[Tag]
    :param count_size: width of the count, 4 bytes in eD2k and 1 byte in Kad.
    :type count_size: int
    """
    materialised = list(tags)
    writer.raw((U8 if count_size == 1 else U32).pack(len(materialised)))
    for tag in materialised:
        write_tag(writer, tag)


def tag_map(tags: Iterable[Tag]) -> Mapping[TagName, TagValue]:
    """Index tags by name, keeping the first occurrence as aMule does.

    :param tags: the tags.
    :type tags: Iterable[Tag]
    :returns: the values by name.
    :rtype: Mapping[TagName, TagValue]
    """
    result: dict[TagName, TagValue] = {}
    for tag in tags:
        result.setdefault(tag.name, tag.value)
    return result


def int_value(tags: Mapping[TagName, TagValue], name: TagName, *, default: int = 0) -> int:
    """Read an integer tag, accepting it only when it really is an integer.

    :param tags: the indexed tags.
    :type tags: Mapping[TagName, TagValue]
    :param name: the tag name.
    :type name: TagName
    :param default: the value when the tag is absent or of another type.
    :type default: int
    :returns: the integer.
    :rtype: int
    """
    value = tags.get(name)
    return value if isinstance(value, int) else default


def str_value(tags: Mapping[TagName, TagValue], name: TagName, *, default: str = '') -> str:
    """Read a text tag, accepting it only when it really is a text.

    :param tags: the indexed tags.
    :type tags: Mapping[TagName, TagValue]
    :param name: the tag name.
    :type name: TagName
    :param default: the value when the tag is absent or of another type.
    :type default: str
    :returns: the text.
    :rtype: str
    """
    value = tags.get(name)
    return value if isinstance(value, str) else default
