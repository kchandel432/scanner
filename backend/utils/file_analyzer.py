"""
File analysis utilities
"""
import os
import hashlib
import magic
import math
from typing import Dict, Any, Optional, List
import pefile
import lief

class FileAnalyzer:
    """Advanced file analysis utility"""

    def analyze_file(self, file_path: str, content: Optional[bytes] = None) -> Dict[str, Any]:
        """Comprehensive file analysis"""
        if content:
            file_size = len(content)
            file_content = content
        else:
            file_size = os.path.getsize(file_path)
            with open(file_path, 'rb') as f:
                file_content = f.read()

        # Basic file info
        file_info = {
            "size": file_size,
            "md5": hashlib.md5(file_content).hexdigest(),
            "sha1": hashlib.sha1(file_content).hexdigest(),
            "sha256": hashlib.sha256(file_content).hexdigest(),
            "entropy": self._calculate_entropy(file_content),
            "magic": magic.from_buffer(file_content[:2048]) if file_content else "Unknown",
            "is_executable": self._is_executable(file_content),
            "has_network_calls": self._has_network_calls(file_content),
            "suspicious_sections": False,
            "string_count": 0,
            "suspicious_strings": []
        }

        # Extract strings
        strings = self._extract_strings(file_content)
        file_info["string_count"] = len(strings)
        file_info["suspicious_strings"] = self._find_suspicious_strings(strings)

        # PE file analysis
        if file_info["magic"].startswith("PE"):
            pe_info = self._analyze_pe_file(file_content)
            file_info.update(pe_info)

        return file_info

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0

        entropy = 0.0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log2(p_x)

        return entropy

    def _is_executable(self, data: bytes) -> bool:
        """Check if file is executable"""
        magic_str = magic.from_buffer(data[:1024]) if data else ""
        return any(x in magic_str.lower() for x in ['executable', 'elf', 'mach-o', 'pe32', 'pe64'])

    def _has_network_calls(self, data: bytes) -> bool:
        """Check for network-related strings"""
        network_keywords = [
            b'http://', b'https://', b'connect', b'socket',
            b'winsock', b'wininet', b'urlmon', b'ws2_32'
        ]

        for keyword in network_keywords:
            if keyword in data[:8192]:  # Check first 8KB
                return True
        return False

    def _extract_strings(self, data: bytes, min_length: int = 4) -> List[str]:
        """Extract printable strings from binary data"""
        strings = []
        current_string = []

        for byte in data:
            if 32 <= byte <= 126:  # Printable ASCII
                current_string.append(chr(byte))
            else:
                if len(current_string) >= min_length:
                    strings.append(''.join(current_string))
                current_string = []

        if len(current_string) >= min_length:
            strings.append(''.join(current_string))

        return strings

    def _find_suspicious_strings(self, strings: List[str]) -> List[str]:
        """Find suspicious strings in file"""
        suspicious_patterns = [
            'CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory',
            'LoadLibrary', 'GetProcAddress', 'WinExec', 'ShellExecute',
            'regsvr32', 'rundll32', 'powershell', 'cmd.exe', 'wscript',
            'cscript', 'schtasks', 'taskkill', 'net user', 'net localgroup',
            'encrypt', 'decrypt', 'ransom', 'bitcoin', 'wallet', 'keylogger',
            'backdoor', 'trojan', 'virus', 'malware'
        ]

        found = []
        for string in strings:
            lower_string = string.lower()
            for pattern in suspicious_patterns:
                if pattern in lower_string and string not in found:
                    found.append(string)

        return found

    def _analyze_pe_file(self, data: bytes) -> Dict[str, Any]:
        """Analyze PE (Portable Executable) files"""
        pe_info = {
            "is_pe": True,
            "suspicious_sections": False,
            "sections": [],
            "imports": [],
            "exports": []
        }

        try:
            # Using pefile library
            pe = pefile.PE(data=data)

            # Analyze sections
            suspicious_sections = []
            for section in pe.sections:
                section_info = {
                    "name": section.Name.decode('utf-8', errors='ignore').strip('\x00'),
                    "virtual_size": section.Misc_VirtualSize,
                    "raw_size": section.SizeOfRawData,
                    "characteristics": section.Characteristics
                }

                # Check for suspicious section characteristics
                if section.Characteristics & 0x20000000:  # EXECUTE
                    if section.Characteristics & 0x80000000:  # WRITE
                        suspicious_sections.append(section_info["name"])

                pe_info["sections"].append(section_info)

            if suspicious_sections:
                pe_info["suspicious_sections"] = True

            # Extract imports
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name:
                            pe_info["imports"].append(imp.name.decode('utf-8', errors='ignore'))

            # Extract exports
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        pe_info["exports"].append(exp.name.decode('utf-8', errors='ignore'))

        except Exception as e:
            pe_info["error"] = str(e)

        return pe_info
