from io import BytesIO
from typing import BinaryIO

from wiithon.structs.DOLHeader import DOLHeader

TEXT_SECTIONS = 7
DATA_SECTIONS = 11
HEADER_SIZE = 0x100


class DOL:
    def __init__(self):
        self.header: DOLHeader = DOLHeader()
        self.text_sections: list[bytes] = [b''] * TEXT_SECTIONS
        self.data_sections: list[bytes] = [b''] * DATA_SECTIONS

    @classmethod
    def read(cls, stream: BinaryIO) -> "DOL":
        obj = cls()
        start = stream.tell()

        obj.header = DOLHeader.read(stream)

        for i in range(TEXT_SECTIONS):
            if obj.header.text_length[i] == 0:
                obj.text_sections[i] = b''
            else:
                stream.seek(start + obj.header.text_offset[i])
                obj.text_sections[i] = stream.read(obj.header.text_length[i])

        for i in range(DATA_SECTIONS):
            if obj.header.data_length[i] == 0:
                obj.data_sections[i] = b''
            else:
                stream.seek(start + obj.header.data_offset[i])
                obj.data_sections[i] = stream.read(obj.header.data_length[i])

        return obj

    def _virtual_to_section(self, virtual_addr: int) -> tuple[str, int, int]:
        for i in range(TEXT_SECTIONS):
            length = self.header.text_length[i]
            if length == 0:
                continue
            start = self.header.text_starts[i]
            if start <= virtual_addr < start + length:
                return ('text', i, virtual_addr - start)

        for i in range(DATA_SECTIONS):
            length = self.header.data_length[i]
            if length == 0:
                continue
            start = self.header.data_starts[i]
            if start <= virtual_addr < start + length:
                return ('data', i, virtual_addr - start)

        raise ValueError(f"Virtual address {virtual_addr:#010x} not found in any DOL section")

    def read_at(self, virtual_addr: int, size: int) -> bytes:
        stype, i, offset = self._virtual_to_section(virtual_addr)
        section = self.text_sections[i] if stype == 'text' else self.data_sections[i]

        if offset + size > len(section):
            raise ValueError(
                f"Read of {size} bytes at {virtual_addr:#010x} overflows section "
                f"(section size={len(section):#x}, offset={offset:#x})"
            )

        return section[offset:offset + size]

    def write_at(self, virtual_addr: int, data: bytes) -> None:
        stype, i, offset = self._virtual_to_section(virtual_addr)
        section = self.text_sections[i] if stype == 'text' else self.data_sections[i]

        if offset + len(data) > len(section):
            raise ValueError(
                f"Write of {len(data)} bytes at {virtual_addr:#010x} overflows section "
                f"(section size={len(section):#x}, offset={offset:#x})"
            )

        buf = bytearray(section)
        buf[offset:offset + len(data)] = data

        if stype == 'text':
            self.text_sections[i] = bytes(buf)
        else:
            self.data_sections[i] = bytes(buf)

    def to_bytes(self) -> bytes:
        current_offset = HEADER_SIZE

        for i in range(TEXT_SECTIONS):
            section = self.text_sections[i]
            if len(section) == 0:
                self.header.text_offset[i] = 0
                self.header.text_length[i] = 0
            else:
                self.header.text_offset[i] = current_offset
                self.header.text_length[i] = len(section)
                current_offset += _align4(len(section))

        for i in range(DATA_SECTIONS):
            section = self.data_sections[i]
            if len(section) == 0:
                self.header.data_offset[i] = 0
                self.header.data_length[i] = 0
            else:
                self.header.data_offset[i] = current_offset
                self.header.data_length[i] = len(section)
                current_offset += _align4(len(section))

        out = BytesIO()
        self.header.write(out)

        for section in self.text_sections:
            if len(section) > 0:
                out.write(section)
                padding = _align4(len(section)) - len(section)
                out.write(b'\x00' * padding)

        for section in self.data_sections:
            if len(section) > 0:
                out.write(section)
                padding = _align4(len(section)) - len(section)
                out.write(b'\x00' * padding)

        return out.getvalue()


def _align4(size: int) -> int:
    return (size + 3) & ~3
