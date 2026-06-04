import unittest
from io import BytesIO

from wiithon.file_helper.dol import DOL, HEADER_SIZE, DATA_SECTIONS, TEXT_SECTIONS
from wiithon.structs.DOLHeader import DOLHeader


def build_mock_dol(text_data: bytes = b'\x60\x00\x00\x00' * 4,
                   text_start: int = 0x80003100) -> bytes:
    out = BytesIO()

    header = DOLHeader()
    header.text_offset = [HEADER_SIZE] + [0] * 6
    header.text_starts = [text_start] + [0] * 6
    header.text_length = [len(text_data)] + [0] * 6
    header.data_offset = [0] * 11
    header.data_starts = [0] * 11
    header.data_length = [0] * 11
    header.bss_start   = 0
    header.bss_size    = 0
    header.entry_point = text_start

    header.write(out)
    out.write(text_data)

    return out.getvalue()


class TestDOLRead(unittest.TestCase):

    def test_read_sections(self):
        text_data = b'\xAB\xCD\xEF\x00' * 4
        raw = build_mock_dol(text_data)
        dol = DOL.read(BytesIO(raw))

        self.assertEqual(dol.text_sections[0], text_data)
        for i in range(1, 7):
            self.assertEqual(dol.text_sections[i], b'')
        for i in range(11):
            self.assertEqual(dol.data_sections[i], b'')

    def test_entry_point(self):
        raw = build_mock_dol(text_start=0x80003100)
        dol = DOL.read(BytesIO(raw))
        self.assertEqual(dol.header.entry_point, 0x80003100)


class TestDOLReadAt(unittest.TestCase):

    def setUp(self):
        self.text_data = b'\x38\x60\x00\x01' * 4
        self.text_start = 0x80003100
        raw = build_mock_dol(self.text_data, self.text_start)
        self.dol = DOL.read(BytesIO(raw))

    def test_read_first_instruction(self):
        result = self.dol.read_at(self.text_start, 4)
        self.assertEqual(result, b'\x38\x60\x00\x01')

    def test_read_middle(self):
        result = self.dol.read_at(self.text_start + 8, 4)
        self.assertEqual(result, b'\x38\x60\x00\x01')

    def test_read_multiple_instructions(self):
        result = self.dol.read_at(self.text_start, 8)
        self.assertEqual(result, b'\x38\x60\x00\x01' * 2)

    def test_read_invalid_address(self):
        with self.assertRaises(ValueError):
            self.dol.read_at(0x80000000, 4)

    def test_read_overflow(self):
        with self.assertRaises(ValueError):
            self.dol.read_at(self.text_start, len(self.text_data) + 4)


class TestDOLWriteAt(unittest.TestCase):

    def setUp(self):
        self.text_data = b'\x60\x00\x00\x00' * 4
        self.text_start = 0x80003100
        raw = build_mock_dol(self.text_data, self.text_start)
        self.dol = DOL.read(BytesIO(raw))

    def test_write_single_instruction(self):
        new_instr = b'\x38\x60\x00\x01'
        self.dol.write_at(self.text_start, new_instr)
        self.assertEqual(self.dol.read_at(self.text_start, 4), new_instr)

    def test_write_does_not_affect_neighbours(self):
        self.dol.write_at(self.text_start + 4, b'\x38\x60\x00\x02')
        self.assertEqual(self.dol.read_at(self.text_start, 4), b'\x60\x00\x00\x00')

    def test_write_invalid_address(self):
        with self.assertRaises(ValueError):
            self.dol.write_at(0x90000000, b'\x60\x00\x00\x00')

    def test_write_overflow(self):
        with self.assertRaises(ValueError):
            self.dol.write_at(self.text_start, b'\x00' * (len(self.text_data) + 4))


class TestDOLToBytes(unittest.TestCase):

    def test_roundtrip(self):
        text_data = b'\x38\x60\x00\x01' * 4
        raw = build_mock_dol(text_data, 0x80003100)
        dol = DOL.read(BytesIO(raw))

        rebuilt = dol.to_bytes()
        dol2 = DOL.read(BytesIO(rebuilt))

        self.assertEqual(dol2.text_sections[0], text_data)
        self.assertEqual(dol2.header.entry_point, 0x80003100)
        self.assertEqual(dol2.header.text_starts[0], 0x80003100)

    def test_roundtrip_after_patch(self):
        text_data = b'\x60\x00\x00\x00' * 4
        raw = build_mock_dol(text_data, 0x80003100)
        dol = DOL.read(BytesIO(raw))

        dol.write_at(0x80003100, b'\x38\x60\x00\x01')  # patch nop -> li r3, 1

        rebuilt = dol.to_bytes()
        dol2 = DOL.read(BytesIO(rebuilt))

        self.assertEqual(dol2.read_at(0x80003100, 4), b'\x38\x60\x00\x01')
        self.assertEqual(dol2.read_at(0x80003104, 4), b'\x60\x00\x00\x00')

    def test_header_size_is_0x100(self):
        raw = build_mock_dol()
        dol = DOL.read(BytesIO(raw))
        rebuilt = dol.to_bytes()
        dol2 = DOL.read(BytesIO(rebuilt))
        self.assertEqual(dol2.header.text_offset[0], HEADER_SIZE)

class TestAddTextSection(unittest.TestCase):

    def setUp(self):
        raw = build_mock_dol(b'\x60\x00\x00\x00' * 4, text_start=0x80004000)
        self.dol = DOL.read(BytesIO(raw))
        self.inject_addr = 0x806AE000
        self.inject_data = b'\x38\x60\x00\x2A' * 4  # li r3, 42 x4

    def test_uses_first_free_slot(self):
        self.dol.add_text_section(self.inject_addr, self.inject_data)
        self.assertEqual(self.dol.text_sections[1], self.inject_data)

    def test_sets_virtual_address(self):
        self.dol.add_text_section(self.inject_addr, self.inject_data)
        self.assertEqual(self.dol.header.text_starts[1], self.inject_addr)

    def test_sets_length(self):
        self.dol.add_text_section(self.inject_addr, self.inject_data)
        self.assertEqual(self.dol.header.text_length[1], len(self.inject_data))

    def test_readable_via_read_at(self):
        self.dol.add_text_section(self.inject_addr, self.inject_data)
        result = self.dol.read_at(self.inject_addr, 4)
        self.assertEqual(result, b'\x38\x60\x00\x2A')

    def test_roundtrip_after_add(self):
        self.dol.add_text_section(self.inject_addr, self.inject_data)
        rebuilt = DOL.read(BytesIO(self.dol.to_bytes()))
        self.assertEqual(rebuilt.read_at(self.inject_addr, len(self.inject_data)), self.inject_data)

    def test_does_not_affect_existing_section(self):
        self.dol.add_text_section(self.inject_addr, self.inject_data)
        self.assertEqual(self.dol.read_at(0x80004000, 4), b'\x60\x00\x00\x00')

    def test_raises_when_all_slots_used(self):
        for i in range(TEXT_SECTIONS - 1):
            self.dol.add_text_section(0x80700000 + i * 0x1000, b'\x60\x00\x00\x00' * 4)
        with self.assertRaises(RuntimeError):
            self.dol.add_text_section(0x80800000, b'\x60\x00\x00\x00' * 4)


class TestAddDataSection(unittest.TestCase):

    def setUp(self):
        raw = build_mock_dol(b'\x60\x00\x00\x00' * 4, text_start=0x80004000)
        self.dol = DOL.read(BytesIO(raw))
        self.inject_addr = 0x806AE000
        self.inject_data = b'\xDE\xAD\xBE\xEF' * 4

    def test_uses_first_free_slot(self):
        self.dol.add_data_section(self.inject_addr, self.inject_data)
        self.assertEqual(self.dol.data_sections[0], self.inject_data)

    def test_sets_virtual_address(self):
        self.dol.add_data_section(self.inject_addr, self.inject_data)
        self.assertEqual(self.dol.header.data_starts[0], self.inject_addr)

    def test_sets_length(self):
        self.dol.add_data_section(self.inject_addr, self.inject_data)
        self.assertEqual(self.dol.header.data_length[0], len(self.inject_data))

    def test_readable_via_read_at(self):
        self.dol.add_data_section(self.inject_addr, self.inject_data)
        result = self.dol.read_at(self.inject_addr, 4)
        self.assertEqual(result, b'\xDE\xAD\xBE\xEF')

    def test_roundtrip_after_add(self):
        self.dol.add_data_section(self.inject_addr, self.inject_data)
        rebuilt = DOL.read(BytesIO(self.dol.to_bytes()))
        self.assertEqual(rebuilt.read_at(self.inject_addr, len(self.inject_data)), self.inject_data)
        self.assertEqual(self.dol.header.data_length[0], 4 * 0x4)

    def test_raises_when_all_slots_used(self):
        for i in range(DATA_SECTIONS):
            self.dol.add_data_section(0x80700000 + i * 0x1000, b'\x00' * 4)
        with self.assertRaises(RuntimeError):
            self.dol.add_data_section(0x80800000, b'\x00' * 4)


if __name__ == '__main__':
    unittest.main()
