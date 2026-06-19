#!/usr/bin/env python3
"""
Android Manifest XML Parser and Recovery Tool

This module provides functionality to parse and recover corrupted Android Manifest XML files.
It handles binary XML format used by Android APK files and can fix various corruption issues
including duplicate string offsets, incorrect string counts, and malformed attribute sizes.

Author: Cleafy Spa
Version: 1.0.0
License: MIT
"""

import sys
import struct
import logging
from typing import Dict, List, Tuple, BinaryIO, Any, Optional
from dataclasses import dataclass
from enum import IntEnum

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ResourceType(IntEnum):
    """Android resource type constants."""
    RES_XML_TYPE = 3
    RES_STRING_POOL_TYPE = 1
    RES_XML_RESOURCE_MAP_TYPE = 384
    RES_XML_FIRST_CHUNK_TYPE = 256
    RES_XML_START_ELEMENT_TYPE = 258
    RES_XML_END_ELEMENT_TYPE = 259
    RES_XML_END_NAMESPACE_TYPE = 257

class ResourceHeader(IntEnum):
    """Android resource type constants."""
    RES_XML_TYPE = 0x00080003
    RES_STRING_POOL_TYPE = 0x001C0001
    RES_XML_RESOURCE_MAP_TYPE = 0x00080180
    RES_XML_FIRST_CHUNK_TYPE = 0x00100100
    RES_XML_START_ELEMENT_TYPE = 0x00100102
    RES_XML_END_ELEMENT_TYPE = 0x00100103
    RES_XML_END_NAMESPACE_TYPE = 0x00100101

STRLEN_THRESHOLD = 6000


class AndroidManifestParser:
    """
    Parser for Android Manifest XML files in binary format.
    
    This class can parse corrupted manifest files and attempt to recover them
    by fixing common corruption patterns.
    """

    def __init__(self, output_dir: str = "temp_apk_content", main_logger: Optional[logging] = None):
        """
        Initialize the parser.
        
        Args:
            output_dir: Directory where recovered files will be saved
            main_logger: Logger
        """
        self.output_dir = output_dir

        self.strPool_broken_flag = 0
        self.wrong_stringCount = 0
        self.duplicate_offsets = []

        if main_logger:
            self.logger = main_logger
        else:
            self.logger = logger

        self.corruption_flag = False


    @staticmethod
    def read_uint32(f: BinaryIO) -> int:
        """Read 4 bytes and return it as an unsigned 32-bit integer."""
        return struct.unpack('<I', f.read(4))[0]

    @staticmethod
    def read_uint16(f: BinaryIO) -> int:
        """Read 2 bytes and return it as an unsigned 16-bit integer."""
        return struct.unpack('<H', f.read(2))[0]

    @staticmethod
    def write_uint32(f: BinaryIO, value: int) -> None:
        """Write an unsigned 32-bit integer (4 bytes) to the file."""
        f.write(struct.pack('<I', value))

    @staticmethod
    def write_uint16(f: BinaryIO, value: int) -> None:
        """Write an unsigned 16-bit integer (2 bytes) to the file."""
        f.write(struct.pack('<H', value))


    def _parse_xml_document(self, f: BinaryIO) -> Dict[str, Any]:
        """Parse the complete XML document structure."""

        xmlDict = {} 

        # Parse the header section
        xmlDict["header"] = self._parse_main_header(f)

        # Parse the strPool section
        xmlDict["strPool"] = self._parse_string_pool(f)

        # Parse the resMap section
        xmlDict["resMap"] = self._parse_resource_map(f)

        # Parse the start Ns section
        xmlDict["startNs"] = self._parse_start_namespace(f)

        # Parse the Elements
        element_list, endNs = self._parse_elements(f, xmlDict)

        xmlDict["elements"] = element_list
        xmlDict["endNs"] = endNs

        return xmlDict


    def _parse_main_header(self, f: BinaryIO) -> Dict[str, Any]:
        """Parse the main XML document header."""
                    
        type = self.read_uint16(f)
        headerSize = self.read_uint16(f)
        size = self.read_uint32(f)

        header = {}

        header["type"] = type
        header["headerSize"] = headerSize
        header["size"] = size

        if type != 3:
            self.logger.warning("First byte of the file is not 0x03 (RES_XML_TYPE)")
            self.corruption_flag = True
            header["type"] = 3

        return header


    def _parse_chunk_header(self, f: BinaryIO, header_info: ResourceHeader) -> Dict[str, Any]:
        """Parse a generic chunk header, seeking to the expected type if necessary."""

        res = self.read_uint32(f)

        while res != header_info:
            f.seek(-4, 1)
            f.read(1) # Skip one byte
            res = self.read_uint32(f)

        self.logger.debug(f"Parsed RES {hex(res)} at offset {f.tell() - 4}")

        headerSize = (res >> 16) & 0xFFFF
        type = res & 0xFFFF
        size = self.read_uint32(f)

        header = {}

        header["type"] = type
        header["headerSize"] = headerSize
        header["size"] = size

        return header


    def _parse_element_header(self, f: BinaryIO) -> Dict[str, Any]:
        """Parse element header, seeking to valid element types."""
            
        res = self.read_uint32(f)

        while (
            res != ResourceHeader.RES_XML_START_ELEMENT_TYPE.value and 
            res != ResourceHeader.RES_XML_END_ELEMENT_TYPE.value and 
            res != ResourceHeader.RES_XML_END_NAMESPACE_TYPE.value
            ):
            f.seek(-3, 1) # step back and skip one byte
            res = self.read_uint32(f)

        headerSize = (res >> 16) & 0xFFFF
        type = res & 0xFFFF
        size = self.read_uint32(f)

        header = {}

        header["type"] = type
        header["headerSize"] = headerSize
        header["size"] = size

        return header


    def _parse_string_pool(self, f: BinaryIO) -> Dict[str, Any]:
        """Parse the string pool section with error detection and correction."""

        strPool = {}

        header = self._parse_chunk_header(f, ResourceHeader.RES_STRING_POOL_TYPE.value)
        stringCount = self.read_uint32(f)
        styleCount = self.read_uint32(f)
        flags = self.read_uint32(f)
        stringsStart = self.read_uint32(f)
        stylesStart = self.read_uint32(f)

        strPool["header"] = header
        strPool["stringCount"] = stringCount
        strPool["styleCount"] = styleCount
        strPool["flags"] = flags
        strPool["stringsStart"] = stringsStart
        strPool["stylesStart"] = stylesStart


        current_position = f.tell()  # Save the current position
        f.seek(0, 2)  # Move to the end of the file
        file_size = f.tell()  # Get the position at the end (file size in bytes)
        f.seek(current_position) # Restore the original position

        strPool["stringoffsets"] = []
        
        for i in range(stringCount):
            stringoffset = self.read_uint32(f)
            if stringoffset >= file_size or (i!=0 and stringoffset <= 0):
                self.logger.warning(f"The file contains a wrong value for the stringCount header field: {str(stringCount)} instead of {str(i)}")
                self.corruption_flag = True
                f.seek(-4, 1) 
                self.strPool_broken_flag = 1
                break
            elif stringoffset in strPool["stringoffsets"]:
                self.logger.warning(f"The file contains duplicate values for the string offset: {str(stringoffset)}")
                self.corruption_flag = True
                self.strPool_broken_flag = 2
                self.duplicate_offsets.append(i)
            else:
                strPool["stringoffsets"].append(stringoffset)

        if self.strPool_broken_flag == 1:
            # Correct stringCount, stringStart and header size values 
            self.wrong_stringCount = stringCount
            stringCount = len(strPool["stringoffsets"])
            strPool["stringCount"] = stringCount

        elif self.strPool_broken_flag == 2:
            # Correct stringCount, stringStart and header size values 
            self.wrong_stringCount = stringCount
            stringCount = len(strPool["stringoffsets"])
            strPool["stringCount"] = stringCount

            strPool["stringsStart"] -= (self.wrong_stringCount - stringCount) * 4 
            strPool["header"]["size"] -= (self.wrong_stringCount - stringCount) * 4 

        strdata = []
        length = 0
        for i in range(stringCount):
            
            
            # Move file cursor to string offset (Header Size + Strings Start + String Offset)
            f.seek(8 + stringsStart + strPool["stringoffsets"][i])
            
            if flags == 0:
                length = self.read_uint16(f)
                strdata_el = f.read(2*(length+1))  
            elif flags == 1:
                raise ValueError("Error: the Manifest contains string data in UTF-8 encoding. Not yet implemented.")
            elif flags == 256:
                length = f.read(1) # Length UTF-16
                length = int.from_bytes(length, byteorder="big")
                if length & 0x80:
                    # MSB is 1
                    length_2 = f.read(1) 
                    length_2 = int.from_bytes(length_2, byteorder="big")
                    length = length & 0x7F
                    length = (length << 8) | length_2
                    length = f.read(1) # Length UTF-8
                    length = int.from_bytes(length, byteorder="big")
                    if length & 0x80:
                        # MSB is 1
                        length_2 = f.read(1) 
                        length_2 = int.from_bytes(length_2, byteorder="big")
                        length = length & 0x7F
                        length = (length << 8) | length_2
                else:
                    length = f.read(1) # Length UTF-8
                    length = int.from_bytes(length, byteorder="big")
                strdata_el = f.read(length+1)

            strdata.append(strdata_el)
        strPool["strdata"] = strdata

        return strPool


    def _parse_resource_map(self, f: BinaryIO) -> Dict[str, Any]:
        """Parse the resource map section."""

        resMap = {}
        header = self._parse_chunk_header(f, ResourceHeader.RES_XML_RESOURCE_MAP_TYPE.value)
        resMap["header"] = header

        size = header["size"]
        headerSize = header["headerSize"]
        len = int((size - headerSize) / 4)


        resids_list = []
        for i in range(len):
            resids = self.read_uint32(f)
            resids_list.append(resids)
            
        resMap["resids"] = resids_list

        # Update section size 
        #TODO

        return resMap


    def _parse_start_namespace(self, f: BinaryIO) -> Dict[str, Any]:
        """Parse the start namespace section."""

        startNs = {}

        header = self._parse_chunk_header(f, ResourceHeader.RES_XML_FIRST_CHUNK_TYPE.value)
        lineNumber = self.read_uint32(f)
        comment = self.read_uint32(f)

        startNs["header"] = header
        startNs["lineNumber"] = lineNumber
        startNs["comment"] = comment

        ext_prefix_index = self.read_uint32(f)
        ext_uri_index = self.read_uint32(f)

        startNs["ext_prefix_index"] = ext_prefix_index
        startNs["ext_uri_index"] = ext_uri_index

        if self.strPool_broken_flag == 2:

            if len(self.duplicate_offsets) > 0:
                if startNs["ext_prefix_index"] > self.duplicate_offsets[0] and startNs["ext_prefix_index"] != 4294967295:
                    startNs["ext_prefix_index"] -= len(self.duplicate_offsets)
                if startNs["ext_uri_index"] > self.duplicate_offsets[0] and startNs["ext_uri_index"] != 4294967295:
                    startNs["ext_uri_index"] -= len(self.duplicate_offsets)        


        return startNs


    def _parse_elements(self, f: BinaryIO, xmlDict: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Parse all XML elements until end namespace is reached."""

        element_list = []
        endNs = None

        i = 0
        while True:

            element = {}
            element["header"] = self._parse_element_header(f)
            element["lineNumber"] = self.read_uint32(f)
            element["comment"] = self.read_uint32(f)

            res = (element["header"]["headerSize"] << 16) | element["header"]["type"] 

            if res == ResourceHeader.RES_XML_START_ELEMENT_TYPE.value:   

                self.logger.debug(f"Parsed RES {hex(res)} at offset {f.tell()-16}")

                element["attrExt_ns_index"] = self.read_uint32(f)
                element["attrExt_name_index"] = self.read_uint32(f)

                if self.strPool_broken_flag == 2:

                    if len(self.duplicate_offsets) > 0:
                        if element["attrExt_ns_index"] > self.duplicate_offsets[0] and element["attrExt_ns_index"] != 4294967295:
                            element["attrExt_ns_index"] -= len(self.duplicate_offsets)
                        if element["attrExt_name_index"] > self.duplicate_offsets[0] and element["attrExt_name_index"] != 4294967295:
                            element["attrExt_name_index"] -= len(self.duplicate_offsets)

                element["attributeStart"] = self.read_uint16(f)
                wrong_start = 0
                if(element["attributeStart"] != 0x14):
                    self.logger.warning(f"The file contains wrong values for the attributeStart fields: {str(hex(element['attributeStart']))} instead of 0x14")
                    self.corruption_flag = True
                    wrong_start = element["attributeStart"]
                    element["attributeStart"] = 0x14

                    # Correct total section size
                    element["header"]["size"] -= (wrong_start-20) 

                element["attributeSize"] = self.read_uint16(f)
                element["attributeCount"] = self.read_uint16(f)

                wrong_size = 0
                if(element["attributeSize"] != 0x14):
                    self.logger.warning(f"The file contains wrong values for the attributeSize fields: {str(hex(element['attributeSize']))} instead of 0x14")
                    self.corruption_flag = True
                    wrong_size = element["attributeSize"]
                    element["attributeSize"] = 0x14

                    # Correct total section size
                    element["header"]["size"] -= (wrong_size-20) * element["attributeCount"] 

                
                element["idIndex"]  = self.read_uint16(f)
                element["classIndex"] = self.read_uint16(f)
                element["styleIndex"] = self.read_uint16(f)

                attrib_list = []
                if wrong_start:
                    f.read(wrong_start-20) # skip garbage bytes due to wrong start value
                for i in range(element["attributeCount"]):
                    attrib = {}    
                    attrib["attrib_ns_index"] = self.read_uint32(f)
                    attrib["attrib_name_index"] = self.read_uint32(f)
                    attrib["attrib_rawValue"] = self.read_uint32(f)

                    if self.strPool_broken_flag == 2:

                        if len(self.duplicate_offsets) > 0:
                            if attrib["attrib_ns_index"] > self.duplicate_offsets[0] and attrib["attrib_ns_index"] != 4294967295:
                                attrib["attrib_ns_index"] -= len(self.duplicate_offsets)
                            if attrib["attrib_name_index"] > self.duplicate_offsets[0] and attrib["attrib_name_index"] != 4294967295:
                                attrib["attrib_name_index"] -= len(self.duplicate_offsets)
                            if attrib["attrib_rawValue"] > self.duplicate_offsets[0] and attrib["attrib_rawValue"] != 4294967295:
                                attrib["attrib_rawValue"] -= len(self.duplicate_offsets)
                    
                    if (attrib["attrib_rawValue"] < 0 or attrib["attrib_rawValue"] >= xmlDict["strPool"]["stringCount"]) and attrib["attrib_rawValue"] != 4294967295:
                        self.logger.warning(f"The file contains a wrong value for the attribute raw value index: {str(attrib['attrib_rawValue'])}")
                        self.corruption_flag = True
                        attrib["attrib_rawValue"] = 0


                    attrib["attrib_typedValue_size"] = self.read_uint16(f)
                    attrib["attrib_typedValue_res0"] = f.read(1)
                    attrib["attrib_typedValue_dataType"] = f.read(1)
                    attrib["attrib_typedValue_data"]  = self.read_uint32(f)

                    if self.strPool_broken_flag == 2:
                        if len(self.duplicate_offsets) > 0:
                            if attrib["attrib_typedValue_dataType"] == b'\x03' and attrib["attrib_typedValue_data"] > self.duplicate_offsets[0]:
                                attrib["attrib_typedValue_data"] -= len(self.duplicate_offsets)
                    
                    if attrib["attrib_typedValue_dataType"] == b'\x03' and (attrib["attrib_typedValue_data"] < 0 or (attrib["attrib_typedValue_data"] >= xmlDict["strPool"]["stringCount"] and attrib["attrib_typedValue_data"] != 4294967295)):
                        self.logger.warning(f"The file contains a wrong value for the attribute typed value data: {str(attrib['attrib_typedValue_data'])}")
                        self.corruption_flag = True
                        attrib["attrib_typedValue_data"] = 0

                    attrib_list.append(attrib)

                    if wrong_size > 0:
                        difference = wrong_size-element["attributeSize"]
                        f.read(difference)
                    
                element["attrib"] = attrib_list

                # Update section size
                element["header"]["size"] = 36 + 20*element["attributeCount"]

                element_list.append(element)

            elif res == ResourceHeader.RES_XML_END_ELEMENT_TYPE.value: 

                self.logger.debug(f"Parsed RES {hex(res)} at offset {f.tell()}")

                element["endEleExt_ns_index"] = self.read_uint32(f)
                element["endEleExt_name_index"] = self.read_uint32(f)

                if self.strPool_broken_flag == 2:

                    if len(self.duplicate_offsets) > 0:
                        if element["endEleExt_ns_index"] > self.duplicate_offsets[0] and element["endEleExt_ns_index"] != 4294967295:
                            element["endEleExt_ns_index"] -= len(self.duplicate_offsets)
                        if element["endEleExt_name_index"] > self.duplicate_offsets[0] and element["endEleExt_name_index"] != 4294967295:
                            element["endEleExt_name_index"] -= len(self.duplicate_offsets)

                # Update section size
                element["header"]["size"] = 24

                element_list.append(element)

            elif res == ResourceHeader.RES_XML_END_NAMESPACE_TYPE.value: 

                self.logger.debug(f"Parsed RES {hex(res)} at offset {f.tell()}")

                element["ext_prefix_index"] = self.read_uint32(f)
                element["ext_uri_index"] = self.read_uint32(f)

                if self.strPool_broken_flag == 2:

                    if len(self.duplicate_offsets) > 0:
                        if element["ext_prefix_index"] > self.duplicate_offsets[0] and element["ext_prefix_index"] != 4294967295:
                            element["ext_prefix_index"] -= len(self.duplicate_offsets)
                        if element["ext_uri_index"] > self.duplicate_offsets[0] and element["ext_uri_index"] != 4294967295:
                            element["ext_uri_index"] -= len(self.duplicate_offsets)

                endNs = element
                break
            else:
                self.logger.debug(f"Parsed unknown RES {hex(res)} at offset {f.tell()}")

        return element_list, endNs


    def _align_data(self, f):
        while f.tell() % 4 != 0:
            f.write(b'\x00')

    def recover_manifest(self, xmlDict: Dict[str, Any]) -> None:
        """
        Recover and write the corrected manifest to a file.
        
        Args:
            xmlDict: Parsed XML data dictionary
        """

        with open(self.output_dir+"/fixed.xml", 'wb') as output_stream:
            for element in xmlDict:
                if element == "header":
                    self.write_uint16(output_stream, xmlDict[element]["type"])
                    self.write_uint16(output_stream, xmlDict[element]["headerSize"])
                    self.write_uint32(output_stream, xmlDict[element]["size"])
                
                elif element == "strPool":
                    self._align_data(output_stream)
                    self.write_uint16(output_stream, xmlDict[element]["header"]["type"])
                    self.write_uint16(output_stream, xmlDict[element]["header"]["headerSize"])
                    self.write_uint32(output_stream, xmlDict[element]["header"]["size"])
                    self.write_uint32(output_stream, xmlDict[element]["stringCount"])
                    self.write_uint32(output_stream, xmlDict[element]["styleCount"])
                    self.write_uint32(output_stream, xmlDict[element]["flags"])
                    self.write_uint32(output_stream, xmlDict[element]["stringsStart"])
                    self.write_uint32(output_stream, xmlDict[element]["stylesStart"])

                    for stringoffset in xmlDict[element]["stringoffsets"]:
                        self.write_uint32(output_stream, stringoffset)

                    for strdata in xmlDict[element]["strdata"]:

                        if xmlDict[element]["flags"] == 0:
                            strdata2 = strdata.decode("UTF-16")

                            strlen = len(strdata2)-1 
                            if strlen > STRLEN_THRESHOLD:
                                self.logger.warning(f"StrPool contains strings that exceed max length: {str(strlen)}")
                                self.corruption_flag = True
                                self.write_uint16(output_stream, 0)
                                strdata = b'\x00\x00' + strdata[2:]

                            else:
                                self.write_uint16(output_stream, len(strdata2) -1 )
                                
                            output_stream.write(strdata)

                        if xmlDict[element]["flags"] == 1:
                            pass #TODO
                        if xmlDict[element]["flags"] == 256:
                            
                            strdata_utf8 = strdata.decode("UTF-8")
                            strdata_utf16 = strdata_utf8.encode("UTF-16")
                            length_utf16 = ((len(strdata_utf16)- 2) // 2) -1
                             
                            if length_utf16 > 127:
                                # First byte: MSB set to 1, followed by the upper 7 bits of the length
                                first_byte = 0x80 | (length_utf16 >> 8)
                                # Second byte: Lower 8 bits of the length
                                second_byte = length_utf16 & 0xFF
                                output_stream.write(first_byte.to_bytes(1, byteorder='big', signed=False))
                                output_stream.write(second_byte.to_bytes(1, byteorder='big', signed=False))
                            else:
                                output_stream.write(length_utf16.to_bytes(1, byteorder='big', signed=False))

                            length_utf8 = len(strdata)-1
                            if length_utf8 > 127:
                                # First byte: MSB set to 1, followed by the upper 7 bits of the length
                                first_byte = 0x80 | (length_utf8 >> 8)
                                # Second byte: Lower 8 bits of the length
                                second_byte = length_utf8 & 0xFF
                                output_stream.write(first_byte.to_bytes(1, byteorder='big', signed=False))
                                output_stream.write(second_byte.to_bytes(1, byteorder='big', signed=False))
                            else:
                                output_stream.write(length_utf8.to_bytes(1, byteorder='big', signed=False))

                            output_stream.write(strdata)
                            
                elif element == "resMap":
                    self._align_data(output_stream)
                    self.write_uint16(output_stream, xmlDict[element]["header"]["type"])
                    self.write_uint16(output_stream, xmlDict[element]["header"]["headerSize"])
                    self.write_uint32(output_stream, xmlDict[element]["header"]["size"])
                    
                    for resid in xmlDict[element]["resids"]:
                        self.write_uint32(output_stream, resid)
                
                elif element == "startNs":
                    self._align_data(output_stream)
                    self.write_uint16(output_stream, xmlDict[element]["header"]["type"])
                    self.write_uint16(output_stream, xmlDict[element]["header"]["headerSize"])
                    self.write_uint32(output_stream, xmlDict[element]["header"]["size"])
                    self.write_uint32(output_stream, xmlDict[element]["lineNumber"])
                    self.write_uint32(output_stream, xmlDict[element]["comment"])
                    self.write_uint32(output_stream, xmlDict[element]["ext_prefix_index"])
                    self.write_uint32(output_stream, xmlDict[element]["ext_uri_index"])
                    
                elif element == "elements":
                    self._align_data(output_stream)
                    for el in xmlDict[element]:
                        self.write_uint16(output_stream, el["header"]["type"])
                        self.write_uint16(output_stream, el["header"]["headerSize"])
                        self.write_uint32(output_stream, el["header"]["size"])
                        self.write_uint32(output_stream, el["lineNumber"])
                        self.write_uint32(output_stream, el["comment"])

                        if el["header"]["type"] == ResourceType.RES_XML_START_ELEMENT_TYPE.value:
                            self.write_uint32(output_stream, el["attrExt_ns_index"])
                            self.write_uint32(output_stream, el["attrExt_name_index"])
                            self.write_uint16(output_stream, el["attributeStart"])
                            self.write_uint16(output_stream, el["attributeSize"])
                            self.write_uint16(output_stream, el["attributeCount"])
                            self.write_uint16(output_stream, el["idIndex"])
                            self.write_uint16(output_stream, el["classIndex"])
                            self.write_uint16(output_stream, el["styleIndex"])

                            for attrib in el["attrib"]:
                                self.write_uint32(output_stream, attrib["attrib_ns_index"])
                                self.write_uint32(output_stream, attrib["attrib_name_index"])
                                self.write_uint32(output_stream, attrib["attrib_rawValue"])
                                self.write_uint16(output_stream, attrib["attrib_typedValue_size"])
                                output_stream.write(attrib["attrib_typedValue_res0"])
                                output_stream.write(attrib["attrib_typedValue_dataType"])
                                self.write_uint32(output_stream, attrib["attrib_typedValue_data"])        

                        elif el["header"]["type"] == ResourceType.RES_XML_END_ELEMENT_TYPE.value: 
                            self.write_uint32(output_stream, el["endEleExt_ns_index"])
                            self.write_uint32(output_stream, el["endEleExt_name_index"])

                elif element == "endNs":
                    self._align_data(output_stream)
                    self.write_uint16(output_stream, xmlDict[element]["header"]["type"])
                    self.write_uint16(output_stream, xmlDict[element]["header"]["headerSize"])
                    self.write_uint32(output_stream, xmlDict[element]["header"]["size"])
                    self.write_uint32(output_stream, xmlDict[element]["lineNumber"])
                    self.write_uint32(output_stream, xmlDict[element]["comment"])
                    self.write_uint32(output_stream, xmlDict[element]["ext_prefix_index"])
                    self.write_uint32(output_stream, xmlDict[element]["ext_uri_index"])        

            # Update file size
            total_size = output_stream.tell()
            output_stream.seek(4)
            self.write_uint32(output_stream, total_size)


    def parse_manifest(self, manifest_file_path: str):
        """
        Parse Android Manifest XML file.
        
        Args:
            manifest_file_path: Path to the manifest file            
        """

        self.logger.info("Starting Android Manifest analysis")

        with open(manifest_file_path, 'rb') as input_stream:
            xmlDict = self._parse_xml_document(input_stream)
            
            if self.corruption_flag:
                self.recover_manifest(xmlDict)
            return self.corruption_flag
            

def main():
    if len(sys.argv) < 2:
        print("Usage: python " + sys.argv[0] + " <path_to_AndroidManifest.xml>")
        return

    manifest_file_path = sys.argv[1]

    parser = AndroidManifestParser()
    parser.parse_manifest(manifest_file_path)
    

if __name__ == "__main__":
    main()
