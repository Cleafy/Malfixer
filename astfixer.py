#!/usr/bin/env python3
"""
APK Asset Extraction and Decompression Tool

This module provides functionality to extract and decompress assets from APK files,
with particular focus on detecting and handling obfuscated filenames and various
compression methods used in ZIP-based archives.

Author: Cleafy Spa
Version: 1.0.0
License: MIT
"""

import struct
import argparse
import zlib
import os
import logging
from pathlib import Path
from typing import Dict, Tuple, Optional, List, Union
from dataclasses import dataclass
from enum import Enum

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class CompressionMethod(Enum):
    """ZIP compression methods."""
    STORED = 0
    DEFLATE = 8

class ZipSignature(Enum):
    """ZIP file format signatures."""
    LOCAL_FILE_HEADER = b'PK\x03\x04'

class APKAssetExtractor:
    """
    APK obfuscated asset extraction and decompression tool.
    
    This class provides comprehensive functionality for extracting obfuscated assets from APK files,
    with support for various compression methods and detection of obfuscated filenames.
    """
    
    # Minimum size for a valid local file header
    MIN_HEADER_SIZE = 30
    
    def __init__(self, apk_path: Union[str, Path], main_logger: Optional[logging.Logger] = None):
        """
        Initialize the extractor with an APK file path.
        
        Args:
            apk_path: Path to the APK file to process
            main_logger: Logger
            
        Raises:
            FileNotFoundError: If the APK file doesn't exist
            PermissionError: If the file cannot be read
        """
        self.apk_path = Path(apk_path)
        if not self.apk_path.exists():
            raise FileNotFoundError(f"APK file not found: {apk_path}")
        
        if not self.apk_path.is_file():
            raise ValueError(f"Path is not a file: {apk_path}")
        
        self._file_content: Optional[bytes] = None

        if main_logger:
            self.logger = main_logger
        else:
            self.logger = logger

        self.logger.info(f"Initialized assets extractor: {self.apk_path}")


    def _contains_non_ascii(self, s: str) -> bool:
        """
        Check if a string contains non-ASCII characters.
            
        Args:
            s: String to check
                
        Returns:
            True if non-ASCII characters are present
        """
        try:
            s.encode('ascii')
            return False
        except UnicodeEncodeError:
            return True

    def find_malformed_assets(
        self, 
        directory: Optional[str] = "assets/"
        ) -> Dict[str, tuple]:
        """
        Checks if the APK file contains obfuscated filenames in the specified directory.

        Args:
            directory: Directory to search within the APK (default: assets/)
            
        Returns:
            Dictionary mapping generated filenames to AssetFile objects 
        """

        with open(self.apk_path, "rb") as f:
            data = f.read()

        files = {}
        pos = 0

        while pos < len(data):
            # Ensure there is enough space for a valid header
            if len(data) - pos < self.MIN_HEADER_SIZE:
                break

            # Look for the local file header signature (0x04034b50)
            if data[pos:pos+4] == ZipSignature.LOCAL_FILE_HEADER.value:
                # Extract local file header (only if enough bytes remain)
                header = struct.unpack("<IHHHHHIIIHH", data[pos:pos+self.MIN_HEADER_SIZE])
                compression_method = header[3]  # Compression method
                compressed_size = header[7]  # Compressed size
                uncompressed_size = header[8]  # Uncompressed size
                file_name_length = header[9]
                extra_field_length = header[10]

                # Ensure there is enough data for the file name and extra field
                file_name_start = pos + self.MIN_HEADER_SIZE
                file_name_end = file_name_start + file_name_length

                if file_name_end > len(data):
                    break  # Prevent reading beyond file size

                file_name = data[file_name_start:file_name_end].decode()
                
                # Check for the presence of obfuscated filenames 
                if self._contains_non_ascii(file_name):
                    self.logger.warning(f"Non-ASCII characters detected in filename: {file_name}")
                
                    # Skip the file if it not under the specified directory
                    if not file_name.startswith(directory):
                        # Move to the next file entry
                        pos = file_name_end + extra_field_length + compressed_size
                        continue

                    # Extract compressed data start position
                    compressed_data_start = file_name_end + extra_field_length
                    compressed_data_end = compressed_data_start + compressed_size

                    if compressed_data_end > len(data):
                        break  # Prevent reading beyond file size

                    compressed_content = data[compressed_data_start:compressed_data_end]

                    files["asset_"+str(pos)] = (compressed_content, compression_method, uncompressed_size)

                # Move to the next file entry
                pos = file_name_end + extra_field_length + compressed_size
            else:
                pos += 1  # Move forward if not a file header

        return files

    def decompress_and_save_files(
        self, 
        compressed_files: Dict[str, tuple], 
        output_dir="assets"):
        """
        Extract and decompress the found asset files.
        
        Args:
            compressed_files: Dictionary of asset files to process
            output_dir: Directory to save extracted files
            
        """

        os.makedirs(output_dir, exist_ok=True)

        for filename, (compressed_data, compression_method, _) in compressed_files.items():
            output_path = os.path.join(output_dir, os.path.basename(filename))

            if compression_method == CompressionMethod.STORED.value:
                # no compression
                decompressed_data = compressed_data
            elif compression_method == CompressionMethod.DEFLATE.value:
                try:
                    decompressed_data = zlib.decompress(compressed_data, -15)  # Use raw Deflate mode
                except zlib.error as e:
                    self.logger.error(f"Error decompressing {filename}: {e}")
                    continue
            else:
                self.logger.warning(f"Skipping {filename}: Unsupported compression method {compression_method}")
                continue

            with open(output_path, "wb") as f:
                f.write(decompressed_data)
            self.logger.info(f"File successfully extracted: {output_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract and decompress obfuscated files under 'assets/' from a APK file.")
    parser.add_argument("zipfile", help="Path to the APK file")
    parser.add_argument("-o", "--output", default="assets", help="Output directory for extracted files")
    args = parser.parse_args()

    astfixer = APKAssetExtractor(args.zipfile)
    malformed_assets = astfixer.find_malformed_assets()

    if malformed_assets:
        astfixer.decompress_and_save_files(malformed_assets, args.output)
    else:
        print("No files found under 'assets/' or invalid APK file.")
