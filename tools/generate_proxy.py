import argparse
import ctypes
from pathlib import Path
import struct
import sys


DLL_NAMES = ("winhttp", "d3d9", "d3d10", "d3d11", "xinput1_3", "winmm", "version")


def system_directory(function_name, optional=False):
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    function = getattr(kernel32, function_name)
    function.argtypes = (ctypes.POINTER(ctypes.c_wchar), ctypes.c_uint)
    function.restype = ctypes.c_uint
    buffer = ctypes.create_unicode_buffer(32768)
    length = function(buffer, len(buffer))
    if not length:
        if optional:
            return None
        raise ctypes.WinError(ctypes.get_last_error())
    if length >= len(buffer):
        raise ValueError("System directory path is too long")
    return Path(buffer.value)


def dll_paths(name, arch):
    directory = system_directory("GetSystemDirectoryW")
    wow64 = system_directory("GetSystemWow64DirectoryW", optional=True)
    if arch == "x86" and wow64:
        directory = wow64
    forward_path = directory / (name + ".dll")
    if arch == "x64" and wow64 and ctypes.sizeof(ctypes.c_void_p) == 4:
        read_path = directory.parent / "Sysnative" / (name + ".dll")
    else:
        read_path = forward_path
    return read_path, forward_path


class PEExports:
    def __init__(self, data, arch):
        self.data = data
        if data[:2] != b"MZ":
            raise ValueError("Missing DOS header")
        pe = self.unpack("<I", 0x3C)[0]
        if data[pe:pe + 4] != b"PE\0\0":
            raise ValueError("Missing PE header")
        machine, section_count, _, _, _, optional_size, _ = self.unpack("<HHIIIHH", pe + 4)
        if machine != {"x86": 0x14C, "x64": 0x8664}[arch]:
            raise ValueError("System DLL architecture does not match " + arch)
        optional = pe + 24
        magic = self.unpack("<H", optional)[0]
        expected_magic, directory_offset = {"x86": (0x10B, 96), "x64": (0x20B, 112)}[arch]
        if magic != expected_magic or optional_size < directory_offset + 8:
            raise ValueError("Invalid optional header")
        if self.unpack("<I", optional + directory_offset - 4)[0] == 0:
            raise ValueError("Missing data directories")
        self.header_size = self.unpack("<I", optional + 60)[0]
        self.sections = []
        for index in range(section_count):
            section = optional + optional_size + index * 40
            virtual_size, rva, raw_size, raw_offset = self.unpack("<IIII", section + 8)
            self.sections.append((rva, max(virtual_size, raw_size), raw_size, raw_offset))
        export_rva, export_size = self.unpack("<II", optional + directory_offset)
        if not export_rva or export_size < 40:
            raise ValueError("DLL has no export directory")
        fields = self.unpack("<IIHHIIIIIII", self.offset(export_rva, 40))
        _, _, _, _, _, self.base, count, name_count, functions_rva, names_rva, ordinals_rva = fields
        functions = self.offset(functions_rva, count * 4)
        names = self.offset(names_rva, name_count * 4) if name_count else 0
        ordinals = self.offset(ordinals_rva, name_count * 2) if name_count else 0
        self.entries = {}
        for index in range(count):
            if self.unpack("<I", functions + index * 4)[0]:
                ordinal = self.base + index
                if not 1 <= ordinal <= 65535:
                    raise ValueError("Export ordinal is outside the linker-supported range")
                self.entries[ordinal] = []
        seen_names = set()
        for index in range(name_count):
            ordinal = self.base + self.unpack("<H", ordinals + index * 2)[0]
            if ordinal not in self.entries:
                raise ValueError("Export name refers to a missing function")
            name_rva = self.unpack("<I", names + index * 4)[0]
            start = self.offset(name_rva, 1)
            end = data.find(b"\0", start)
            if end < 0:
                raise ValueError("Unterminated export name")
            self.offset(name_rva, end - start + 1)
            name = data[start:end].decode("ascii")
            if not name or any(ord(char) < 32 or char in '\"\r\n' for char in name):
                raise ValueError("Invalid export name")
            if name in seen_names:
                raise ValueError("Duplicate export name")
            seen_names.add(name)
            self.entries[ordinal].append(name)

    def unpack(self, format_string, offset):
        size = struct.calcsize(format_string)
        if offset < 0 or offset + size > len(self.data):
            raise ValueError("Truncated PE data")
        return struct.unpack_from(format_string, self.data, offset)

    def offset(self, rva, size):
        if rva < self.header_size and rva + size <= min(self.header_size, len(self.data)):
            return rva
        for begin, virtual_size, raw_size, raw_offset in self.sections:
            if begin <= rva < begin + virtual_size:
                delta = rva - begin
                if delta + size <= raw_size and raw_offset + delta + size <= len(self.data):
                    return raw_offset + delta
                break
        raise ValueError("Export RVA is outside file-backed PE data")

    def definition(self, name, forward_path):
        module_path = str(forward_path.with_suffix(""))
        if any(char in module_path for char in '\"\r\n'):
            raise ValueError("Invalid forwarding path")
        lines = ['LIBRARY "' + name + '"', "EXPORTS"]
        exported_names = {name for names in self.entries.values() for name in names}
        for ordinal, names in sorted(self.entries.items()):
            forwarder = '"' + module_path + ".#" + str(ordinal) + '"'
            if names:
                for export_name in names:
                    lines.append('    "' + export_name + '"=' + forwarder + " @" + str(ordinal))
            else:
                alias = "hooklib_ordinal_" + str(ordinal)
                while alias in exported_names:
                    alias += "_"
                lines.append('    "' + alias + '"=' + forwarder + " @" + str(ordinal) + " NONAME")
        return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description="Generate a proxy DLL definition from local system exports")
    parser.add_argument("--dll", choices=DLL_NAMES, required=True)
    parser.add_argument("--arch", choices=("x86", "x64"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    if sys.platform != "win32":
        parser.error("Proxy export generation requires a Windows build host")
    read_path, forward_path = dll_paths(arguments.dll, arguments.arch)
    definition = PEExports(read_path.read_bytes(), arguments.arch).definition(arguments.dll, forward_path)
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    if arguments.output.exists() and arguments.output.read_text(encoding="utf-8") == definition:
        return
    temporary = arguments.output.with_suffix(".def.tmp")
    temporary.write_text(definition, encoding="utf-8")
    temporary.replace(arguments.output)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, struct.error) as error:
        print("hooklib proxy generation failed: " + str(error), file=sys.stderr)
        sys.exit(1)
