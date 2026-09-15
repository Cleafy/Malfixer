#!/usr/bin/env python3
"""
ZIP/APK Malformation Detection and Recovery Tool

This module provides comprehensive analysis and recovery capabilities for
malformed ZIP and APK files, detecting various anti-analysis techniques
commonly used to evade security scanners.

Author: Cleafy Labs
Version: 1.0.0
License: MIT
"""

import sys
import struct
import traceback
import logging
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass
from enum import Enum


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class CompressionMethod(Enum):
    """Supported ZIP compression methods."""
    STORED = 0x00
    DEFLATE = 0x08


class ZipSignature(Enum):
    """ZIP file format signatures."""
    LOCAL_FILE_HEADER = b'\x50\x4b\x03\x04'
    CENTRAL_DIRECTORY_HEADER = b'\x50\x4b\x01\x02'
    DATA_DESCRIPTOR_HEADER = b'\x50\x4b\x07\x08'


@dataclass
class FileHeader:
    """Represents a ZIP file header with relevant metadata."""
    position: int
    bit_flag: int
    compression_method: int
    crc: int
    compressed_size: int 
    uncompressed_size: int 
    filename: str = ""


@dataclass
class MalformationResult:
    """Contains the results of malformation analysis."""
    unsupported_compression: Dict[str, FileHeader]
    malformed_directories: List[str]
    password_malformation_type1: Dict[str, FileHeader]
    password_malformation_type2: Dict[str, FileHeader]
    is_multipart: bool
    has_obfuscated_filenames: bool
    has_data_descriptor: bool
    
    @property
    def is_malformed(self) -> bool:
        """Check if any malformation was detected."""
        return bool(
            self.unsupported_compression or
            self.malformed_directories or
            self.password_malformation_type1 or
            self.password_malformation_type2 or
            self.is_multipart or
            self.has_obfuscated_filenames
        )


class ZipFixer:
    """
    Comprehensive ZIP/APK file analyzer for detecting and fixing malformations.
    
    This class provides methods to detect various anti-analysis techniques
    used in malformed ZIP files and offers recovery capabilities.
    """

    MALFORMED_DIRECTORY_PATTERNS = [
        b"AndroidManifest.xml/",
        b"classes.dex/",
        b"resources.arsc/"
    ]
    
    def __init__(self, file_path: str, main_logger: Optional[logging.Logger] = None):
        """
        Initialize the analyzer with a file path.
        
        Args:
            file_path: Path to the ZIP/APK file to analyze
            main_logger: Logger
            
        Raises:
            FileNotFoundError: If the specified file doesn't exist
            PermissionError: If the file cannot be read
        """
        self.file_path = Path(file_path)
        if not self.file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        self._file_content: Optional[bytes] = None
        self._local_headers: Optional[Dict[str, FileHeader]] = None
        self._central_directory_headers: Optional[Dict[str, FileHeader]] = None


        if main_logger:
            self.logger = main_logger
        else:
            self.logger = logger


    @property
    def file_content(self) -> bytes:
        """Lazy-load and cache file content."""
        if self._file_content is None:
            try:
                with open(self.file_path, 'rb') as file:
                    self._file_content = file.read()
            except IOError as e:
                self.logger.error(f"Failed to read file {self.file_path}: {e}")
                raise
        return self._file_content
    
    def analyze(self) -> MalformationResult:
        """
        Perform comprehensive malformation analysis.
        
        Returns:
            MalformationResult containing all detected malformations
        """
        self.logger.info("Starting ZIP analysis")
        
        try:
            local_headers = self._parse_local_file_headers()
            central_headers = self._parse_central_directory_headers()
            
            result = MalformationResult(
                unsupported_compression=self._check_unsupported_compression(local_headers),
                malformed_directories=self._check_malformed_directories(),
                password_malformation_type1=self._check_password_malformation_type1(
                    local_headers, central_headers
                ),
                password_malformation_type2=self._check_password_malformation_type2(
                    local_headers, central_headers
                ),
                is_multipart=self._check_multipart_zip(),
                has_obfuscated_filenames=self._check_obfuscated_filenames(),
                has_data_descriptor=self._check_data_desc_malformation(local_headers)
            )
            
            self._log_analysis_results(result)
            return result
            
        except Exception as e:
            self.logger.error(f"Analysis failed: {e}")
            raise
    
    def recover(self, output_path: Optional[str] = None) -> str:
        """
        Recover the malformed ZIP file by fixing detected issues.
        
        Args:
            output_path: Optional custom output path. If None, appends '-fixed' to original filename
            
        Returns:
            Path to the recovered file, None if recovery is not needed
            
        Raises:
            ValueError: If no malformations were detected
        """
        result = self.analyze()
        
        if not result.is_malformed:
            self.logger.info("No malformations detected - recovery not needed")
            return "None"
        
        if output_path is None:
            output_path = str(self.file_path.with_suffix('')) + '-fixed' + self.file_path.suffix
        
        self.logger.debug(f"Starting ZIP recovery process, output: {output_path}")
        
        try:
            recovered_content = self._perform_recovery(result)
            
            with open(output_path, 'wb') as output_file:
                output_file.write(recovered_content)
            
            self.logger.info(f"Recovery completed successfully: {output_path}")
            return output_path
            
        except Exception as e:
            self.logger.error(f"Recovery failed: {e}")
            traceback.print_exc()  # Print the full stack trace
            raise
    
    
    def _check_password_malformation_type1(
        self, 
        local_headers: Dict[str, FileHeader], 
        central_headers: Dict[str, FileHeader]
    ) -> Dict[str, FileHeader]:
        """
        Checks if the headers have different values for the General Purpose Bit Flag.

        :param local_headers: Dictionary containing the Local File Header for each file.
        :param central_headers: Dictionary containing the Central Directory Header for each file.
        :return: A dictionary indicating the presence of malformed password-protected files
        """

        malformed = {}
        for filename, central_header in central_headers.items():
            if filename in local_headers:
                # Verify if the file results password protected (General Purpose Bit Flag is odd)
                if central_header.bit_flag % 2 != 0:
                    # File seems password-protected: verify if the General Purpose Bit Flag in the Local File Header corresponds
                    local_header = local_headers[filename]
                    if local_header.bit_flag != central_header.bit_flag:
                        # Malformed
                        malformed[filename] = central_header

        return malformed


    def _check_password_malformation_type2(
        self, 
        local_headers: Dict[str, FileHeader], 
        central_headers: Dict[str, FileHeader]
    ) -> Dict[str, FileHeader]:
        """
        Checks if both the headers have the General Purpose Bit Flag with LSB equal to 0.

        :param local_headers: Dictionary containing the Local File Header for each file.
        :param central_dir_headers: Dictionary containing the Central Directory Header for each file.
        :return: A dictionary indicating the presence of malformed password-protected files
        """

        malformed = {}
        for filename, central_header in central_headers.items():
            if filename in local_headers:
                local_header = local_headers[filename]
                # Verify if the file results password protected (General Purpose Bit Flag is odd)
                if central_header.bit_flag % 2 != 0 and local_header.bit_flag % 2 != 0:
                    # File seems password-protected
                    malformed[filename] = central_header

        return malformed

    def _check_malformed_directories(self) -> List[str]:
        """
        Checks if the file content contains specific strings associated with directory names.

        :return: A list indicating the presence of each string.
        """

        malformed = []
        for pattern in self.MALFORMED_DIRECTORY_PATTERNS:
            if pattern in self.file_content:
                malformed.append(pattern.decode('ascii'))

        return malformed


    def _check_unsupported_compression(self, headers: Dict[str, FileHeader]) -> Dict[str, FileHeader]:
        """
        Checks if the Unsupported Compression Anti-Analysis method has been used.

        :param headers: The local file headers of the files present in the APK/ZIP file.
        :return: A dictionary indicating the presence of each header with usupported compression methods.
        """

        unsupported = {}
        supported_methods = {CompressionMethod.STORED.value, CompressionMethod.DEFLATE.value}
        
        for filename, header in headers.items():
            # Compression Method is not STORE (0x0) or DEFLATE (0x8)
            if header.compression_method not in supported_methods:
                unsupported[filename] = header
        return unsupported


    def _check_multipart_zip(self) -> bool:
        """
        Checks if the APK file claims to be the last disk of a multi-part ZIP archive

        :return: Boolean value indicating whether the ZIP is malformed.
        """

        # Seek to the end of central directory record 
        eocd = self.file_content[-22:] 

        disk_number = int.from_bytes(eocd[4:6], 'little')
        total_disks = int.from_bytes(eocd[6:8], 'little')

        if disk_number != 0 or total_disks != 0:
            return True
        else:
            return False


    def _check_obfuscated_filenames(self) -> bool:
        """
        Checks if the APK contains obfuscetd filenames (e.g. with extended Unicode characteres) 

        :return: Boolean value indicating whether the ZIP is malformed.
        """
        try:
            check = False

            # Check if all characters in filenames are in the ASCII range 
            for filename in self._extract_filenames_from_local_headers():
                if any(ord(char) > 127 for char in filename):
                    check = True

            for filename in self._extract_filenames_from_central_headers():
                if any(ord(char) > 127 for char in filename):
                    check = True

            return check

        except Exception as e:
            self.logger.warning(f"Error checking obfuscated filenames: {e}")
            traceback.print_exc()  # Print the full stack trace

            return False


    def _check_data_desc_malformation(self, headers: Dict[str, FileHeader]) -> bool:
        """
        Checks if the APK/ZIP contains zoroed value in the CRC, Compressed and Uncompressd size fields

        :return: Boolean value indicating whether the ZIP is malformed.
        """
        zeroed = False 
        for filename, header in headers.items():
            if (header.bit_flag & (1 << 3)): #header.crc == 0 or header.compressed_size == 0 or header.uncompressed_size == 0:
                zeroed = True
                break

        return zeroed


    def _extract_filenames_from_local_headers(self) -> List[str]:
        """
        Retrieves the filenames in the ZIP file from the Local File Headers 

        :return: List of filenames
        """

        filenames = []
        offset = 0
        data = self.file_content
        while offset < len(data):
            header = data[offset:offset+4]
            if header == b'PK\x03\x04':  # Local file header signature
                offset += 26  # Skip rest of local file header
                filename_length, extra_length = struct.unpack('<HH', data[offset:offset+4])
                offset += 4
                filename = data[offset:offset+filename_length].decode('utf-8', errors='ignore')
                filenames.append(filename)
                offset += filename_length + extra_length  # Move to next entry
            else:
                offset += 1  # Move forward if no header found
        return filenames

    def _extract_filenames_from_central_headers(self) -> List[str]:
        """
        Retrieves the filenames in the ZIP file from the Central Directory Headers 

        :return: List of filenames
        """

        filenames = []
        offset = 0
        data = self.file_content
        while offset < len(data):
            offset = data.find(b'PK\x01\x02', offset)
            if offset == -1:
                break
            
            filename_length, extra_length, comment_length = struct.unpack('<HHH', data[offset + 28:offset + 34])
            filename_start = offset + 46
            filename = data[filename_start:filename_start + filename_length].decode('utf-8', errors='ignore')
            filenames.append(filename)
            offset += 46 + filename_length + extra_length + comment_length
        return filenames


    def _parse_local_file_headers(self) -> Dict[str, FileHeader]:
        """
        Finds the local file headers in a APK/ZIP file and extracts the corresponding compression methods.

        :return: A dictionary of tuples containing the position, General Purpose Bit Flag, Compression Method CRC, 
        compressed size, uncompressed size and filename.
        """

        local_file_header_pos = 0
        headers_info = {}

        file_content = self.file_content

        # Use Central Directory Header for possible data recovery
        cdh = self._parse_central_directory_headers()

        while local_file_header_pos != -1:
            # Find the next local file header
            local_file_header_pos = file_content.find(ZipSignature.LOCAL_FILE_HEADER.value, local_file_header_pos)


            if local_file_header_pos != -1:

                # Extract the General Purpose Bit Flag (2 bytes starting at offset 6 from the start of the header)
                bit_flag_offset = local_file_header_pos + 6
                bit_flag = struct.unpack('<H', file_content[bit_flag_offset:bit_flag_offset + 2])[0]

                # Read the compression method (2 bytes starting at offset 8 from the start of the header)
                compression_method_offset = local_file_header_pos + 8
                compression_method = struct.unpack('<H', file_content[compression_method_offset:compression_method_offset + 2])[0]

                # Read the CRC (4 bytes starting at offset 14 from the start of the header)
                crc_offset = local_file_header_pos + 14
                crc = struct.unpack('<I', file_content[crc_offset:crc_offset + 4])[0]
                
                # Read the Compressed Size (4 bytes starting at offset 18 from the start of the header)
                compressed_size__offset = local_file_header_pos + 18
                compressed_size = struct.unpack('<I', file_content[compressed_size__offset:compressed_size__offset + 4])[0]

                # Read the Uncompressed Size (4 bytes starting at offset 22 from the start of the header)
                uncompressed_size__offset = local_file_header_pos + 22
                uncompressed_size = struct.unpack('<I', file_content[uncompressed_size__offset:uncompressed_size__offset + 4])[0]

                # Read the filename length (2 bytes starting at offset 26 from the start of the header)
                filename_length_offset = local_file_header_pos + 26
                filename_length = struct.unpack('<H', file_content[filename_length_offset:filename_length_offset + 2])[0]

                # Read the extra field length (2 bytes starting at offset 28 from the start of the header)
                extra_field_length_offset = local_file_header_pos + 28
                extra_field_length = struct.unpack('<H', file_content[extra_field_length_offset:extra_field_length_offset + 2])[0]

                # Calculate the positions where the filename starts and ends
                filename_start = local_file_header_pos + 30
                filename_end = filename_start + filename_length

                # Extract the filename
                filename = file_content[filename_start:filename_end].decode('utf-8', errors='replace')

                headers_info[filename] = FileHeader(
                    position=local_file_header_pos,
                    bit_flag=bit_flag,
                    compression_method=compression_method,
                    crc=crc,
                    compressed_size=compressed_size,
                    uncompressed_size=uncompressed_size,
                    filename=filename
                )

                if (bit_flag & (1 << 3)) : #crc == 0 and compressed_size == 0 and uncompressed_size == 0:
                    # ZIP uses Data Descriptors

                    # Read correct compressed size value from CDH
                    real_compressed_size = compressed_size  # fallback to LFH value
                    if filename in cdh:
                        real_compressed_size = cdh[filename].compressed_size

                    # Locate the Data Descriptor after file data
                    data_desc_pos = file_content.find(ZipSignature.DATA_DESCRIPTOR_HEADER.value, filename_end + extra_field_length + real_compressed_size)

                    if data_desc_pos != -1:
                        # skip 16 bytes
                        local_file_header_pos = data_desc_pos + 16
                    else:
                        # No data descriptor found; skip past this entry using compressed size
                        local_file_header_pos = filename_end + extra_field_length + real_compressed_size

                else:
                    # Move to the next header (header size + filename size + extra field size + compressed size)
                    local_file_header_pos = filename_end + extra_field_length + compressed_size

        return headers_info


    def _parse_central_directory_headers(self) -> Dict[str, FileHeader]:
        """
        Finds all central directory headers in the ZIP file and extract relevant information.

        :return: A dictionary of tuples containing the position, General Purpose Bit Flag, compression method, and filename.
        """

        central_directory_headers = {}
        central_directory_pos = 0

        file_content = self.file_content

        while central_directory_pos != -1:
            # Find the next central directory header
            central_directory_pos = file_content.find(ZipSignature.CENTRAL_DIRECTORY_HEADER.value, central_directory_pos)

            if central_directory_pos != -1:
                # Extract the General Purpose Bit Flag (2 bytes starting at offset 8 from the start of the header)
                bit_flag_offset = central_directory_pos + 8
                bit_flag = struct.unpack('<H', file_content[bit_flag_offset:bit_flag_offset + 2])[0]

                # Extract the compression method (2 bytes starting at offset 10 from the start of the header)
                compression_method_offset = central_directory_pos + 10
                compression_method = struct.unpack('<H', file_content[compression_method_offset:compression_method_offset + 2])[0]

                # Read the CRC (4 bytes starting at offset 16 from the start of the header)
                crc_offset = central_directory_pos + 16
                crc = struct.unpack('<I', file_content[crc_offset:crc_offset + 4])[0]
                
                # Read the Compressed Size (4 bytes starting at offset 20 from the start of the header)
                compressed_size__offset = central_directory_pos + 20
                compressed_size = struct.unpack('<I', file_content[compressed_size__offset:compressed_size__offset + 4])[0]

                # Read the Uncompressed Size (4 bytes starting at offset 24 from the start of the header)
                uncompressed_size__offset = central_directory_pos + 24
                uncompressed_size = struct.unpack('<I', file_content[uncompressed_size__offset:uncompressed_size__offset + 4])[0]

                # Extract the filename length (2 bytes starting at offset 28 from the start of the header)
                filename_length_offset = central_directory_pos + 28
                filename_length = struct.unpack('<H', file_content[filename_length_offset:filename_length_offset + 2])[0]

                # Extract the extra field length (2 bytes starting at offset 30 from the start of the header)
                extra_field_length_offset = central_directory_pos + 30
                extra_field_length = struct.unpack('<H', file_content[extra_field_length_offset:extra_field_length_offset + 2])[0]

                # Calculate the position where the filename starts
                filename_start = central_directory_pos + 46  # 46 bytes offset from the start of the central directory header
                filename_end = filename_start + filename_length

                # Extract the filename
                raw_filename_bytes = file_content[filename_start:filename_end]
                try:
                    filename = raw_filename_bytes.decode('utf-8')
                except UnicodeDecodeError:
                    filename = raw_filename_bytes.decode('cp437', errors='replace')

                central_directory_headers[filename] = FileHeader(
                    position=central_directory_pos,
                    bit_flag=bit_flag,
                    compression_method=compression_method,
                    crc=crc,
                    compressed_size=compressed_size,
                    uncompressed_size=uncompressed_size,
                    filename=filename
                )

                # Move to the next header (header size + filename size + extra field size)
                central_directory_pos = filename_end + extra_field_length

        return central_directory_headers


    def _log_analysis_results(self, result: MalformationResult):
        """Log the results of the analysis."""
        if result.unsupported_compression:
            self.logger.warning(f"Found {len(result.unsupported_compression)} files with unsupported compression")
            for filename, header in result.unsupported_compression.items():
                self.logger.warning(f"  - {filename}: compression method {hex(header.compression_method)}")

        if result.malformed_directories:
            self.logger.warning(f"Found {len(result.malformed_directories)} malformed directories")
            for directory in result.malformed_directories:
                self.logger.warning(f"  - {directory}")

        if result.password_malformation_type1:
            self.logger.warning(f"Found {len(result.password_malformation_type1)} files with password malformation type 1")

        if result.password_malformation_type2:
            self.logger.warning(f"Found {len(result.password_malformation_type2)} files with password malformation type 2")

        if result.is_multipart:
            self.logger.warning("File claims to be part of a multi-part archive")

        if result.has_obfuscated_filenames:
            self.logger.warning("File contains obfuscated filenames")

        if result.has_data_descriptor:
            self.logger.warning("File contains zeroed header fields with data descriptor malformation")

        if not result.is_malformed:
            self.logger.info("No malformations detected")


    def _perform_recovery(self, result: MalformationResult) -> bytes:
        """Perform the actual recovery operations."""
        content = bytearray(self.file_content)

        if result.has_data_descriptor:
            content = self._fix_data_desc_malformation(content)
            self.logger.info("Fixed data descriptor malformation")

        if result.unsupported_compression:
            content = self._fix_unsupported_compression(content, result.unsupported_compression)
            self.logger.info("Fixed unsupported compression methods")

        if result.malformed_directories:
            content = self._fix_malformed_directories(content, result.malformed_directories)
            self.logger.info("Fixed malformed directories")

        if result.password_malformation_type1:
            content = self._fix_password_malformation(content, result.password_malformation_type1)
            self.logger.info("Fixed password malformation type 1")

        if result.password_malformation_type2:
            content = self._fix_password_malformation(content, result.password_malformation_type2)
            self.logger.info("Fixed password malformation type 2")

        if result.is_multipart:
            content = self._fix_multipart_malformation(content)
            self.logger.info("Fixed multipart malformation")
        
        return bytes(content)


    def _fix_unsupported_compression(
        self, 
        file_content: bytearray, 
        unsupported_headers: Dict[str, FileHeader]
    ) -> bytearray:
        """
        Fixes the Malformed ZIP by setting the correct compression method values

        :param file_content: The content of the file as bytes.
        :param unsupported_headers: dictionary of files with unsupported comprssion methods.
        :return: The fixed ZIP data.
        """   

        local_headers = self._parse_local_file_headers()
        central_headers = self._parse_central_directory_headers()

        new_content =file_content
        for filename, values in unsupported_headers.items():

            local_header = local_headers[filename]
            central_header = central_headers[filename]

            # Get the Local File Header
            local_file_header_pos = local_header.position

            # The Compression Method field is 8 bytes after the start of the Local File Header
            compression_method_pos = local_file_header_pos + 8

            compression_method_value_local = new_content[compression_method_pos:compression_method_pos+2]
            
            # Get the Central Directory File Header
            central_dir_header_pos = central_header.position

            # The Compression Method field is 10 bytes after the start of the Central Directory File Header
            compression_method_pos_dir = central_dir_header_pos + 10

            compression_method_value_dir = new_content[compression_method_pos_dir:compression_method_pos_dir+2]
            
            # if the Compression Method in Central Directory File Header is not DEFLATE, set all values to STORED 
            # otherwise set just the Compression Method in the Local File Header to DEFLATE
            if compression_method_value_dir != b'\x08\x00':

                # Change the Compression Method to STORED (0x00 0x00)
                new_content = (new_content[:compression_method_pos] + b'\x00\x00' + 
                           new_content[compression_method_pos + 2:])

                # Set the uncompressed size field equal to the compressed size field in the Local File Header
                # Uncompressed size in Local File Header is at offset 22 from the Local File Header start
                local_uncompressed_size_pos = local_file_header_pos + 22
                uncompressed_size = new_content[local_uncompressed_size_pos:local_uncompressed_size_pos + 4]

                # Compressed size in Local File Header is at offset 18 from the start of the Local File Header
                compressed_size_pos = local_file_header_pos + 18
                new_content = (new_content[:compressed_size_pos] + uncompressed_size +
                           new_content[compressed_size_pos + 4:])

                # Get the Central Directory File Header
                central_dir_header_pos = central_header.position

                # The Compression Method field is 10 bytes after the start of the Central Directory File Header
                compression_method_pos = central_dir_header_pos + 10
                # Modify the Compression Method to STORED (0x00 0x00)
                new_content = (new_content[:compression_method_pos] + b'\x00\x00' + 
                           new_content[compression_method_pos + 2:])

                # Set the uncompressed size field equal to the compressed size field in the Central Directory Header
                # Uncompressed size in Central Directory Header is at offset 24 from the Local File Header start
                central_directory_size_pos = central_dir_header_pos + 24
                uncompressed_size = new_content[central_directory_size_pos:central_directory_size_pos + 4]

                # Compressed size in Central Directory Header is at offset 20 from the start of the Central Directory Header
                compressed_size_pos = central_dir_header_pos + 20
                new_content = (new_content[:compressed_size_pos] + uncompressed_size +
                           new_content[compressed_size_pos + 4:])
            
            else:

                # Change the Compression Method in the Local File Header to DEFLATE (0x08 0x00)
                new_content = (new_content[:compression_method_pos] + b'\x08\x00' + 
                           new_content[compression_method_pos + 2:])


        return new_content


    def _fix_malformed_directories(self, file_content: bytearray, mal_dirs: List[str]) -> bytearray:
        """
        Fixes the Malformed ZIP by renaming malicious directory entry names.

        Only modifies filename fields inside LFH and CD headers — does NOT do a
        global byte replacement, which would corrupt binary file data that happens
        to contain the same byte sequence.

        :param file_content: The content of the file as bytes.
        :param mal_dirs: list of malicious directory prefixes present in the ZIP.
        :return: The fixed ZIP data.
        """

        new_content = file_content

        for maldir in mal_dirs:
            newdir = maldir.replace(".", "_")
            maldir_b = maldir.encode('ascii')
            newdir_b = newdir.encode('ascii')
            assert len(maldir_b) == len(newdir_b), "replacement must be same length"

            # Patch LFH filename fields
            pos = 0
            while True:
                pos = new_content.find(b'PK\x03\x04', pos)
                if pos == -1:
                    break
                fname_len = struct.unpack_from('<H', new_content, pos + 26)[0]
                fname_start = pos + 30
                fname_end = fname_start + fname_len
                fname = bytes(new_content[fname_start:fname_end])
                patched = fname.replace(maldir_b, newdir_b)
                if patched != fname:
                    new_content[fname_start:fname_end] = patched
                pos += 4

            # Patch CD filename fields
            pos = 0
            while True:
                pos = new_content.find(b'PK\x01\x02', pos)
                if pos == -1:
                    break
                fname_len = struct.unpack_from('<H', new_content, pos + 28)[0]
                fname_start = pos + 46
                fname_end = fname_start + fname_len
                fname = bytes(new_content[fname_start:fname_end])
                patched = fname.replace(maldir_b, newdir_b)
                if patched != fname:
                    new_content[fname_start:fname_end] = patched
                pos += 4

        return new_content


    def _fix_password_malformation(
        self, 
        content: bytearray, 
        pass_malformed: Dict[str, FileHeader]
    ) -> bytearray:
        """
        Fixes the Malformed ZIP by changing wrong General Purpose Bit Flag values in Central Directory headers

        :param content: The content of the file as bytes.
        :param pass_malformed: password malformed headers
        :return: The fixed ZIP data.
        """    

        local_file_headers = self._parse_local_file_headers()
        central_dir_headers = self._parse_central_directory_headers()

        new_content = content
        for filename, mal_header in pass_malformed.items():
            # General Purpose Bit Flags are at offset 8 from the start of the Central Directory File Header
            central_dir_header_pos = central_dir_headers[filename].position
            general_purpose_bit_flags_pos = central_dir_header_pos + 8

            # Get the General Purpose Bit Flags in the Local File Headers
            new_flags_bytes = local_file_headers[filename].bit_flag.to_bytes(2, byteorder='little')

            #Force least significant bit (LSB) to 0 (not password protected)
            flags_int = int.from_bytes(new_flags_bytes)
            flags_int = flags_int & (~1)
            new_flags_bytes = flags_int.to_bytes(2, byteorder='little')
             
            # Set the new value from the corresponding value in the Local File Headers
            new_content = (new_content[:general_purpose_bit_flags_pos] + new_flags_bytes +
                       new_content[general_purpose_bit_flags_pos + 2:])

        return new_content


    def _fix_multipart_malformation(self, content: bytearray) -> bytearray:
        """
        Fixes multi-part zip malformation

        :param content: The content of the file as bytes.
        :return: The fixed ZIP data.
        """   

        # Modify the last 22 bytes (End of Central Directory record)
        eocd = bytearray(content[-22:])  

        eocd[4:6] = (0).to_bytes(2, 'little')  # Set disk number to 0
        eocd[6:8] = (0).to_bytes(2, 'little')  # Set total number of disks to 0

        return content[:-22] + eocd  

    def _fix_data_desc_malformation(        
        self, 
        content: bytearray, 
    ) -> bytearray:
        """
        Fixes the Malformed ZIP by copying correct input values in the LFH from the CDH

        :param content: The content of the file as bytes.
        :return: The fixed ZIP data.
        """    
        central_dir_headers = self._parse_central_directory_headers()

        local_file_header_pos = 0

        file_content = content

        while local_file_header_pos != -1:
            # Find the next local file header
            local_file_header_pos = file_content.find(ZipSignature.LOCAL_FILE_HEADER.value, local_file_header_pos)

            if local_file_header_pos != -1:

                # Find the filename to use it as a key in the CDH

                # Read the filename length (2 bytes starting at offset 26 from the start of the header)
                filename_length_offset = local_file_header_pos + 26
                filename_length = struct.unpack('<H', file_content[filename_length_offset:filename_length_offset + 2])[0]

                # Calculate the position where the filename starts
                filename_start = local_file_header_pos + 30
                filename_end = filename_start + filename_length

                # Extract the filename
                filename = file_content[filename_start:filename_end].decode('utf-8', errors='replace')

                # Extract the General Purpose Bit Flag (2 bytes starting at offset 6 from the start of the header)
                bit_flag_offset = local_file_header_pos + 6
                bit_flag = struct.unpack('<H', file_content[bit_flag_offset:bit_flag_offset + 2])[0]

                # Read the extra field length (2 bytes starting at offset 28 from the start of the header)
                extra_field_length_offset = local_file_header_pos + 28
                extra_field_length = struct.unpack('<H', file_content[extra_field_length_offset:extra_field_length_offset + 2])[0]

                if (bit_flag & (1 << 3)): 

                    # Data Descriptor used
                    # Fix with correct values

                    # Write the CRC
                    crc_offset = local_file_header_pos + 14
                    file_content[crc_offset:crc_offset + 4] = struct.pack('<I', central_dir_headers[filename].crc)

                    # Write the Compressed Size
                    compressed_size_offset = local_file_header_pos + 18
                    file_content[compressed_size_offset:compressed_size_offset + 4] = struct.pack('<I', central_dir_headers[filename].compressed_size)

                    # Write the Uncompressed Size
                    uncompressed_size_offset = local_file_header_pos + 22
                    file_content[uncompressed_size_offset:uncompressed_size_offset + 4] = struct.pack('<I', central_dir_headers[filename].uncompressed_size)

                    # Move to the next header (header size + filename size + extra field size)
                    #Find Data Descriptor field and skip it (16 bytes)
                    data_desc_pos = file_content.find(ZipSignature.DATA_DESCRIPTOR_HEADER.value, filename_end + extra_field_length + central_dir_headers[filename].compressed_size)

                    if data_desc_pos != -1:
                        local_file_header_pos = data_desc_pos + 16
                    else:
                        local_file_header_pos = filename_end + extra_field_length + central_dir_headers[filename].compressed_size
                
                else:
                    # No data descriptor used
                    local_file_header_pos = filename_end + extra_field_length + central_dir_headers[filename].compressed_size
        
        return file_content


class ZipFixerCLI:
    """Command-line interface for the ZIP analyzer."""
    
    def __init__(self):
        self.analyzer: Optional[ZipFixer] = None
    
    def run(self, args: List[str]) -> int:
        """
        Run the CLI application.
        
        Args:
            args: Command line arguments
            
        Returns:
            Exit code (0 for success, 1 for error)
        """
        if len(args) < 2:
            self._print_usage(args[0] if args else "zipfixer.py")
            return 1
        
        file_path = args[1]
        
        try:
            self.analyzer = ZipFixer(file_path)
            result = self.analyzer.analyze()

            if result.is_malformed:
                print("\n" + "="*50)
                print("MALFORMED ZIP/APK DETECTED")
                print("="*50)
                
                try:
                    recovered_file = self.analyzer.recover()
                    print(f"\nRecovery completed successfully!")
                    print(f"Recovered file: {recovered_file}")
                except Exception as e:
                    logger.error(f"Recovery failed: {e}")
                    return 1
            else:
                print("\n" + "="*50)
                print("NO MALFORMATIONS DETECTED")
                print("="*50)
                print("The ZIP/APK file appears to be valid.")
            
            return 0
            
        except FileNotFoundError:
            logger.error(f"File not found: {file_path}")
            return 1
        except PermissionError:
            logger.error(f"Permission denied accessing file: {file_path}")
            return 1
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug(traceback.format_exc())
            traceback.print_exc()  # Print the full stack trace
            return 1
    
    def _print_usage(self, program_name: str):
        """Print usage information."""
        print(f"Usage: python {program_name} <zip_or_apk_file>")
        print("\nDescription:")
        print("  Analyze ZIP/APK files for malformations and recover them if possible.")
        print("\nExample:")
        print(f"  python {program_name} malformed_app.apk")


def main():
    """Main entry point for the application."""
    cli = ZipFixerCLI()
    exit_code = cli.run(sys.argv)
    sys.exit(exit_code)

if __name__ == "__main__":
    main()