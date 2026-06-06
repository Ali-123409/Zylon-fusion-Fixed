#!/usr/bin/env python3
"""
ZYLON FUSION v5.0.0 - Metadata + OPSEC Engine
===============================================
Fused from: metadata-extractor (https://github.com/drewnoakes/metadata-extractor)
           + MAT2 (https://0xacab.org/jvoisin/mat2)
           + ExRecon (https://github.com/0x9alice/exrecon)
           + Custom Zylon Techniques
Capabilities:
  - Image EXIF data extraction (GPS, camera, dates)
  - Document metadata extraction (PDF, DOCX, XLSX, PPTX)
  - Metadata stripping/anonymization
  - OPSEC check for scanning operations
  - Geographic location extraction from EXIF
  - Author/creator information extraction
  - Software version detection from metadata
  - Social media metadata analysis
  - Steganography detection hints
  - Privacy risk assessment from metadata
Termux Compatible | No Root Required | Python 3.13+
"""

import os
import sys
import re
import json
import time
import struct
import threading
import hashlib
import random
import zipfile
from datetime import datetime
from xml.etree import ElementTree as ET

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from core.var import (
    USER_AGENTS, DEFAULT_TIMEOUT, MAX_THREADS
)

from core.shared_infra import shared_session

# ============================================================================
# ANSI COLOR CODES (Termux-compatible)
# ============================================================================

RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
MAGENTA = '\033[95m'
BOLD = '\033[1m'
DIM = '\033[2m'
RESET = '\033[0m'

# ============================================================================
# EXIF TAG DEFINITIONS
# ============================================================================

EXIF_TAGS = {
    0x010F: "Make",
    0x0110: "Model",
    0x0112: "Orientation",
    0x011A: "XResolution",
    0x011B: "YResolution",
    0x0131: "Software",
    0x0132: "DateTime",
    0x013B: "Artist",
    0x8298: "Copyright",
    0x8769: "ExifIFDPointer",
    0x8825: "GPSInfoIFDPointer",
    0x9000: "ExifVersion",
    0x9003: "DateTimeOriginal",
    0x9004: "DateTimeDigitized",
    0x9201: "ShutterSpeedValue",
    0x9202: "ApertureValue",
    0x9204: "ExposureBiasValue",
    0x9205: "MaxApertureValue",
    0x9207: "MeteringMode",
    0x9209: "Flash",
    0x920A: "FocalLength",
    0xA001: "ColorSpace",
    0xA002: "PixelXDimension",
    0xA003: "PixelYDimension",
    0xA405: "FocalLengthIn35mmFilm",
    0xA431: "BodySerialNumber",
    0xA432: "LensSpecification",
    0xA433: "LensMake",
    0xA434: "LensModel",
}

GPS_TAGS = {
    0x0001: "GPSLatitudeRef",
    0x0002: "GPSLatitude",
    0x0003: "GPSLongitudeRef",
    0x0004: "GPSLongitude",
    0x0005: "GPSAltitudeRef",
    0x0006: "GPSAltitude",
    0x0007: "GPSTimeStamp",
    0x001D: "GPSDateStamp",
}

# ============================================================================
# PRIVACY RISK LEVELS
# ============================================================================

PRIVACY_RISK_FIELDS = {
    "critical": [
        "GPSLatitude", "GPSLongitude", "GPSAltitude",
        "GPSLatitudeRef", "GPSLongitudeRef",
        "gps_coordinates", "location",
    ],
    "high": [
        "Artist", "Author", "Creator", "LastModifiedBy",
        "BodySerialNumber", "LensSerialNumber",
        "owner", "user", "username",
    ],
    "medium": [
        "Make", "Model", "Software", "DateTime",
        "DateTimeOriginal", "DateTimeDigitized",
        "LensModel", "LensMake", "LensSpecification",
        "camera_model", "device_info",
    ],
    "low": [
        "Orientation", "XResolution", "YResolution",
        "ColorSpace", "PixelXDimension", "PixelYDimension",
        "ExifVersion", "Flash", "FocalLength",
        "image_size", "dpi",
    ],
}

# ============================================================================
# OPSEC CHECK ITEMS
# ============================================================================

OPSEC_CHECKS = [
    {
        "id": "dns_leak",
        "name": "DNS Leak Check",
        "description": "Verify DNS queries are not leaking",
        "check": "Verify DNS resolution does not reveal scanning source",
        "severity": "High",
    },
    {
        "id": "ip_exposure",
        "name": "IP Address Exposure",
        "description": "Check if real IP is exposed during scanning",
        "check": "Verify proxy/VPN is active before scanning",
        "severity": "Critical",
    },
    {
        "id": "user_agent",
        "name": "User-Agent Fingerprint",
        "description": "Check for identifying User-Agent strings",
        "check": "Verify User-Agent is not default tool UA string",
        "severity": "Medium",
    },
    {
        "id": "timing_pattern",
        "name": "Timing Pattern Analysis",
        "description": "Check for automated scanning patterns",
        "check": "Add random delays between requests",
        "severity": "Medium",
    },
    {
        "id": "cookie_tracking",
        "name": "Cookie/Session Tracking",
        "description": "Check for tracking cookies from scans",
        "check": "Clear cookies between different target scans",
        "severity": "Medium",
    },
    {
        "id": "metadata_leak",
        "name": "File Metadata Leak",
        "description": "Check uploaded files for metadata",
        "check": "Strip metadata from all uploaded files",
        "severity": "High",
    },
    {
        "id": "rate_limiting",
        "name": "Rate Limiting Detection",
        "description": "Check if scan rate triggers detection",
        "check": "Use throttled scanning for sensitive targets",
        "severity": "Medium",
    },
    {
        "id": "tls_fingerprint",
        "name": "TLS Fingerprint",
        "description": "Check for distinctive TLS fingerprint",
        "check": "Use JA3-randomizing tools for HTTPS scans",
        "severity": "Low",
    },
    {
        "id": "log_artifacts",
        "name": "Log Artifacts",
        "description": "Check for artifacts left in target logs",
        "check": "Minimize log entries (avoid error-producing payloads)",
        "severity": "Medium",
    },
    {
        "id": "payload_signature",
        "name": "Payload Signature",
        "description": "Check if payloads have identifying signatures",
        "check": "Use custom/modified payloads without tool markers",
        "severity": "High",
    },
]

# ============================================================================
# STEGANOGRAPHY DETECTION PATTERNS
# ============================================================================

STEG_INDICATORS = {
    "lsb_hints": [
        "Unusual LSB patterns in image data",
        "File size larger than expected for image dimensions",
        "Compressed data patterns in raw pixel values",
    ],
    "format_anomalies": [
        "Extra data after image end marker (EOF)",
        "Unexpected chunks in PNG (e.g., tEXt with large data)",
        "Multiple EOF markers in JPEG",
        "APP markers with unusual data lengths",
    ],
    "statistical": [
        "Chi-squared analysis suggests non-random LSB distribution",
        "Palette-based images with unusual color frequencies",
        "Histogram analysis shows unusual patterns",
    ],
}


class MetadataEngine:
    """Metadata + OPSEC Engine - Fused from metadata-extractor + MAT2 + ExRecon + Custom"""

    def __init__(self, timeout=DEFAULT_TIMEOUT, threads=MAX_THREADS, proxy=None):
        self.timeout = timeout
        self.threads = threads
        self.proxy = proxy
        self.session = shared_session
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': USER_AGENTS[0] if USER_AGENTS else 'Mozilla/5.0'
        })
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}
        self.lock = threading.Lock()

    def _print(self, msg, color=CYAN):
        """Thread-safe colored print"""
        with self.lock:
            print(f"{color}{msg}{RESET}")

    # ========================================================================
    # IMAGE EXIF EXTRACTION
    # ========================================================================

    def extract_image_metadata(self, file_path):
        """Extract EXIF data from image files

        Supports JPEG, TIFF, PNG, and other EXIF-compatible formats.

        Args:
            file_path: Path to image file or URL

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  Image EXIF Extraction{RESET}", CYAN)
        self._print(f"  [*] File: {file_path}", CYAN)

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "file_path": file_path,
                "file_type": "",
                "exif_data": {},
                "gps_data": {},
                "has_gps": False,
                "has_exif": False,
                "privacy_risks": [],
            },
            "scan_type": "image_exif_extract",
        }

        # Handle URL input
        if file_path.startswith('http'):
            try:
                resp = self.session.get(file_path, timeout=self.timeout, verify=False)
                if resp.status_code != 200:
                    result["findings"].append({
                        "type": "error",
                        "description": f"Failed to download: HTTP {resp.status_code}",
                    })
                    return result
                # Save to temp
                import tempfile
                ext = os.path.splitext(file_path.split('?')[0])[1] or '.jpg'
                tmp = tempfile.NamedTemporaryFile(suffix=ext, delete=False)
                tmp.write(resp.content)
                tmp.close()
                actual_path = tmp.name
            except Exception as e:
                result["findings"].append({
                    "type": "error",
                    "description": f"Failed to download file: {str(e)[:100]}",
                })
                return result
        else:
            actual_path = file_path

        if not os.path.isfile(actual_path):
            result["findings"].append({
                "type": "error",
                "description": f"File not found: {actual_path}",
            })
            return result

        # Get file info
        file_size = os.path.getsize(actual_path)
        _, ext = os.path.splitext(actual_path)
        result["details"]["file_type"] = ext.lower()

        # Read binary data
        try:
            with open(actual_path, 'rb') as f:
                data = f.read()
        except Exception as e:
            result["findings"].append({
                "type": "error",
                "description": f"Cannot read file: {str(e)[:100]}",
            })
            return result

        # JPEG EXIF extraction
        if data[:2] == b'\xff\xd8':
            result["details"]["file_type"] = "JPEG"
            exif_data = self._parse_jpeg_exif(data)
            if exif_data:
                result["details"]["exif_data"] = exif_data
                result["details"]["has_exif"] = True
                result["findings"].append({
                    "type": "exif_found",
                    "description": f"Found {len(exif_data)} EXIF fields in JPEG image",
                    "count": len(exif_data),
                })

                # Extract GPS data
                gps_data = self._extract_gps_from_exif(exif_data)
                if gps_data:
                    result["details"]["gps_data"] = gps_data
                    result["details"]["has_gps"] = True
                    result["vulnerable"] = True
                    result["findings"].append({
                        "type": "gps_data_found",
                        "severity": "Critical",
                        "description": f"GPS coordinates found in EXIF data: {gps_data.get('latitude', 'N/A')}, {gps_data.get('longitude', 'N/A')}",
                        "gps": gps_data,
                    })
                    self._print(f"  [!!!] GPS DATA FOUND: {gps_data.get('latitude', 'N/A')}, {gps_data.get('longitude', 'N/A')}", RED)

        # PNG metadata extraction
        elif data[:8] == b'\x89PNG\r\n\x1a\n':
            result["details"]["file_type"] = "PNG"
            png_data = self._parse_png_metadata(data)
            if png_data:
                result["details"]["exif_data"] = png_data
                result["details"]["has_exif"] = True
                result["findings"].append({
                    "type": "png_metadata_found",
                    "description": f"Found {len(png_data)} metadata fields in PNG image",
                    "count": len(png_data),
                })

        # GIF metadata extraction
        elif data[:6] in (b'GIF87a', b'GIF89a'):
            result["details"]["file_type"] = "GIF"
            gif_data = self._parse_gif_metadata(data)
            if gif_data:
                result["details"]["exif_data"] = gif_data
                result["details"]["has_exif"] = True

        # Assess privacy risks
        privacy_risks = self.assess_privacy_risk(result["details"]["exif_data"])
        result["details"]["privacy_risks"] = privacy_risks.get("details", {}).get("risks", [])

        if privacy_risks.get("vulnerable"):
            result["vulnerable"] = True

        if not result["details"]["has_exif"]:
            result["findings"].append({
                "type": "no_exif",
                "description": "No EXIF data found in image (may have been stripped)",
            })
            self._print(f"  [-] No EXIF data found", GREEN)

        # Steganography detection hints
        steg_hints = self._check_steg_hints(data, ext.lower())
        if steg_hints:
            result["findings"].append({
                "type": "steg_hints",
                "description": f"Potential steganography indicators: {steg_hints}",
                "hints": steg_hints,
            })

        self._print(f"  [+] EXIF fields: {len(result['details']['exif_data'])}", GREEN)
        return result

    def _parse_jpeg_exif(self, data):
        """Parse EXIF data from JPEG binary data"""
        exif_data = {}
        try:
            # Find APP1 marker (0xFFE1)
            offset = 2  # Skip SOI marker
            while offset < len(data) - 4:
                if data[offset] == 0xFF:
                    marker = (data[offset] << 8) | data[offset + 1]
                    if marker == 0xFFE1:  # APP1 (EXIF)
                        length = (data[offset + 2] << 8) | data[offset + 3]
                        exif_start = offset + 4
                        exif_chunk = data[exif_start:exif_start + length - 2]

                        # Check for "Exif\0\0" header
                        if exif_chunk[:6] == b'Exif\x00\x00':
                            tiff_data = exif_chunk[6:]
                            parsed = self._parse_tiff_exif(tiff_data)
                            exif_data.update(parsed)
                        break
                    elif marker == 0xFFDA:  # SOS - start of scan
                        break
                    else:
                        length = (data[offset + 2] << 8) | data[offset + 3]
                        offset += 2 + length
                else:
                    offset += 1
        except Exception:
            pass
        return exif_data

    def _parse_tiff_exif(self, tiff_data):
        """Parse TIFF-format EXIF data"""
        exif_data = {}
        try:
            # Determine byte order
            if tiff_data[:2] == b'II':
                endian = '<'
            elif tiff_data[:2] == b'MM':
                endian = '>'
            else:
                return exif_data

            # TIFF magic number
            magic = struct.unpack(endian + 'H', tiff_data[2:4])[0]
            if magic != 42:
                return exif_data

            # Offset to first IFD
            ifd_offset = struct.unpack(endian + 'I', tiff_data[4:8])[0]

            # Parse IFD0
            ifd_entries = self._parse_ifd(tiff_data, ifd_offset, endian)
            for tag_id, value in ifd_entries.items():
                tag_name = EXIF_TAGS.get(tag_id, f"Tag_0x{tag_id:04X}")
                exif_data[tag_name] = value

            # Parse ExifIFD if present
            if 0x8769 in ifd_entries:
                # The value is the offset to the ExifIFD
                # Need raw offset value
                raw_exif_ifd = self._get_ifd_offset(tiff_data, ifd_offset, endian, 0x8769)
                if raw_exif_ifd is not None:
                    exif_ifd_entries = self._parse_ifd(tiff_data, raw_exif_ifd, endian)
                    for tag_id, value in exif_ifd_entries.items():
                        tag_name = EXIF_TAGS.get(tag_id, f"Tag_0x{tag_id:04X}")
                        exif_data[tag_name] = value

            # Parse GPS IFD if present
            if 0x8825 in ifd_entries:
                raw_gps_ifd = self._get_ifd_offset(tiff_data, ifd_offset, endian, 0x8825)
                if raw_gps_ifd is not None:
                    gps_ifd_entries = self._parse_ifd(tiff_data, raw_gps_ifd, endian)
                    for tag_id, value in gps_ifd_entries.items():
                        tag_name = GPS_TAGS.get(tag_id, f"GPS_Tag_0x{tag_id:04X}")
                        exif_data[tag_name] = value

        except Exception:
            pass
        return exif_data

    def _parse_ifd(self, tiff_data, offset, endian):
        """Parse an IFD (Image File Directory)"""
        entries = {}
        try:
            if offset + 2 > len(tiff_data):
                return entries
            num_entries = struct.unpack(endian + 'H', tiff_data[offset:offset + 2])[0]

            for i in range(num_entries):
                entry_offset = offset + 2 + (i * 12)
                if entry_offset + 12 > len(tiff_data):
                    break

                tag_id = struct.unpack(endian + 'H', tiff_data[entry_offset:entry_offset + 2])[0]
                data_type = struct.unpack(endian + 'H', tiff_data[entry_offset + 2:entry_offset + 4])[0]
                count = struct.unpack(endian + 'I', tiff_data[entry_offset + 4:entry_offset + 8])[0]

                value_offset = entry_offset + 8
                value_data = tiff_data[value_offset:value_offset + 4]

                # Parse value based on type
                try:
                    if data_type == 2:  # ASCII
                        if count <= 4:
                            value = value_data[:count].decode('ascii', errors='replace').rstrip('\x00')
                        else:
                            actual_offset = struct.unpack(endian + 'I', value_data)[0]
                            value = tiff_data[actual_offset:actual_offset + count].decode('ascii', errors='replace').rstrip('\x00')
                    elif data_type == 3:  # SHORT
                        value = struct.unpack(endian + 'H', value_data[:2])[0]
                    elif data_type == 4:  # LONG
                        value = struct.unpack(endian + 'I', value_data)[0]
                    elif data_type == 5:  # RATIONAL
                        actual_offset = struct.unpack(endian + 'I', value_data)[0]
                        if actual_offset + 8 <= len(tiff_data):
                            num = struct.unpack(endian + 'I', tiff_data[actual_offset:actual_offset + 4])[0]
                            den = struct.unpack(endian + 'I', tiff_data[actual_offset + 4:actual_offset + 8])[0]
                            value = f"{num}/{den}" if den != 0 else f"{num}/0"
                        else:
                            value = "N/A"
                    elif data_type == 7:  # UNDEFINED
                        value = value_data[:min(count, 4)].hex()
                    elif data_type == 9:  # SLONG
                        value = struct.unpack(endian + 'i', value_data)[0]
                    elif data_type == 10:  # SRATIONAL
                        actual_offset = struct.unpack(endian + 'I', value_data)[0]
                        if actual_offset + 8 <= len(tiff_data):
                            num = struct.unpack(endian + 'i', tiff_data[actual_offset:actual_offset + 4])[0]
                            den = struct.unpack(endian + 'i', tiff_data[actual_offset + 4:actual_offset + 8])[0]
                            value = f"{num}/{den}" if den != 0 else f"{num}/0"
                        else:
                            value = "N/A"
                    else:
                        value = value_data.hex()
                except Exception:
                    value = f"<raw:{value_data.hex()}>"

                entries[tag_id] = value

        except Exception:
            pass
        return entries

    def _get_ifd_offset(self, tiff_data, ifd_offset, endian, target_tag):
        """Get the offset value for a specific IFD tag (used for sub-IFDs)"""
        try:
            num_entries = struct.unpack(endian + 'H', tiff_data[ifd_offset:ifd_offset + 2])[0]
            for i in range(num_entries):
                entry_offset = ifd_offset + 2 + (i * 12)
                if entry_offset + 12 > len(tiff_data):
                    break
                tag_id = struct.unpack(endian + 'H', tiff_data[entry_offset:entry_offset + 2])[0]
                if tag_id == target_tag:
                    data_type = struct.unpack(endian + 'H', tiff_data[entry_offset + 2:entry_offset + 4])[0]
                    count = struct.unpack(endian + 'I', tiff_data[entry_offset + 4:entry_offset + 8])[0]
                    value_data = tiff_data[entry_offset + 8:entry_offset + 12]
                    if data_type == 4:  # LONG
                        return struct.unpack(endian + 'I', value_data)[0]
        except Exception:
            pass
        return None

    def _extract_gps_from_exif(self, exif_data):
        """Extract and convert GPS coordinates from EXIF data"""
        gps = {}
        try:
            if 'GPSLatitude' in exif_data and 'GPSLongitude' in exif_data:
                lat_str = exif_data['GPSLatitude']
                lon_str = exif_data['GPSLongitude']

                # Parse rational format "d/m, d/m, d/m"
                def _safe_rational(val_str):
                    """Safely parse rational number like '37/1' or '0.123' without eval()"""
                    val_str = val_str.strip()
                    try:
                        if '/' in val_str:
                            num, den = val_str.split('/', 1)
                            return float(num.strip()) / float(den.strip())
                        return float(val_str)
                    except (ValueError, ZeroDivisionError):
                        return 0.0

                def parse_rational_coords(coord_str):
                    parts = coord_str.split(',')
                    if len(parts) == 3:
                        degrees = _safe_rational(parts[0])
                        minutes = _safe_rational(parts[1])
                        seconds = _safe_rational(parts[2])
                        return degrees + minutes / 60.0 + seconds / 3600.0
                    return None

                lat = parse_rational_coords(lat_str)
                lon = parse_rational_coords(lon_str)

                if lat is not None and lon is not None:
                    lat_ref = exif_data.get('GPSLatitudeRef', 'N')
                    lon_ref = exif_data.get('GPSLongitudeRef', 'E')
                    if lat_ref == 'S':
                        lat = -lat
                    if lon_ref == 'W':
                        lon = -lon

                    gps['latitude'] = round(lat, 6)
                    gps['longitude'] = round(lon, 6)
                    gps['latitude_str'] = f"{abs(lat):.6f}° {lat_ref}"
                    gps['longitude_str'] = f"{abs(lon):.6f}° {lon_ref}"
                    gps['google_maps_url'] = f"https://maps.google.com/?q={lat},{lon}"
                    gps['osm_url'] = f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=15/{lat}/{lon}"

            if 'GPSAltitude' in exif_data:
                alt_str = str(exif_data['GPSAltitude'])
                try:
                    if '/' in alt_str:
                        num, den = alt_str.split('/')
                        gps['altitude'] = round(float(num) / float(den), 2)
                    else:
                        gps['altitude'] = float(alt_str)
                    gps['altitude_unit'] = 'meters above sea level'
                except Exception:
                    pass

        except Exception:
            pass
        return gps

    def _parse_png_metadata(self, data):
        """Parse metadata from PNG files"""
        metadata = {}
        try:
            offset = 8  # Skip PNG signature
            while offset < len(data) - 8:
                chunk_length = struct.unpack('>I', data[offset:offset + 4])[0]
                chunk_type = data[offset + 4:offset + 8].decode('ascii', errors='replace')
                chunk_data = data[offset + 8:offset + 8 + chunk_length]

                if chunk_type == 'tEXt':
                    # Text chunk
                    null_idx = chunk_data.find(b'\x00')
                    if null_idx > 0:
                        key = chunk_data[:null_idx].decode('ascii', errors='replace')
                        value = chunk_data[null_idx + 1:].decode('ascii', errors='replace')
                        metadata[key] = value

                elif chunk_type == 'iTXt':
                    # International text chunk
                    try:
                        null_idx = chunk_data.find(b'\x00')
                        key = chunk_data[:null_idx].decode('utf-8', errors='replace')
                        # Skip compression flag, method, language, translated keyword
                        remaining = chunk_data[null_idx + 1:]
                        null_idx2 = remaining.find(b'\x00')
                        null_idx3 = remaining.find(b'\x00', null_idx2 + 1)
                        value = remaining[null_idx3 + 1:].decode('utf-8', errors='replace')
                        metadata[key] = value
                    except Exception:
                        pass

                elif chunk_type == 'zTXt':
                    metadata['zTXt_chunk'] = f"<compressed text, length={chunk_length}>"

                offset += 12 + chunk_length  # 4(len) + 4(type) + data + 4(crc)

        except Exception:
            pass
        return metadata

    def _parse_gif_metadata(self, data):
        """Parse metadata from GIF files"""
        metadata = {}
        try:
            offset = 6  # Skip header
            # Skip logical screen descriptor
            offset += 7
            # Check for global color table
            if data[4] & 0x80:
                gct_size = 3 * (2 << (data[4] & 0x07))
                offset += gct_size

            # Parse blocks
            while offset < len(data):
                block = data[offset]
                if block == 0x21:  # Extension
                    offset += 1
                    label = data[offset]
                    if label == 0xFE:  # Comment extension
                        offset += 1
                        comment_parts = []
                        while offset < len(data):
                            block_size = data[offset]
                            offset += 1
                            if block_size == 0:
                                break
                            comment_parts.append(data[offset:offset + block_size].decode('ascii', errors='replace'))
                            offset += block_size
                        metadata['Comment'] = ''.join(comment_parts)
                    elif label == 0xFF:  # Application extension
                        offset += 1
                        block_size = data[offset]
                        offset += 1
                        app_id = data[offset:offset + 8].decode('ascii', errors='replace')
                        offset += block_size
                        # Skip sub-blocks
                        while offset < len(data):
                            sub_size = data[offset]
                            offset += 1
                            if sub_size == 0:
                                break
                            offset += sub_size
                        metadata['Application'] = app_id
                    else:
                        # Skip unknown extension
                        offset += 1
                        while offset < len(data):
                            sub_size = data[offset]
                            offset += 1
                            if sub_size == 0:
                                break
                            offset += sub_size
                elif block == 0x2C:  # Image descriptor
                    break
                elif block == 0x3B:  # Trailer
                    break
                else:
                    offset += 1
        except Exception:
            pass
        return metadata

    def _check_steg_hints(self, data, ext):
        """Check for steganography indicators"""
        hints = []
        try:
            # Check for data after EOF markers
            if data[:2] == b'\xff\xd8':  # JPEG
                eof_marker = data.rfind(b'\xff\xd9')
                if eof_marker > 0 and eof_marker + 2 < len(data):
                    trailing = len(data) - eof_marker - 2
                    if trailing > 100:
                        hints.append(f"JPEG: {trailing} bytes of data after EOF marker")

            elif data[:8] == b'\x89PNG\r\n\x1a\n':  # PNG
                iend_pos = data.find(b'IEND')
                if iend_pos > 0 and iend_pos + 8 < len(data):
                    trailing = len(data) - iend_pos - 8
                    if trailing > 100:
                        hints.append(f"PNG: {trailing} bytes of data after IEND chunk")

            # Check file size vs expected size
            # This is a rough heuristic
            file_size = len(data)
            if ext in ('.jpg', '.jpeg', '.png') and file_size > 10 * 1024 * 1024:
                hints.append(f"File size ({file_size} bytes) is unusually large for a {ext} image")

        except Exception:
            pass
        return hints

    # ========================================================================
    # DOCUMENT METADATA EXTRACTION
    # ========================================================================

    def extract_doc_metadata(self, file_path):
        """Extract metadata from document files

        Supports PDF, DOCX, XLSX, PPTX (Office Open XML formats)

        Args:
            file_path: Path to document file or URL

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  Document Metadata Extraction{RESET}", CYAN)
        self._print(f"  [*] File: {file_path}", CYAN)

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "file_path": file_path,
                "file_type": "",
                "metadata": {},
                "authors": [],
                "software": [],
                "privacy_risks": [],
            },
            "scan_type": "doc_metadata_extract",
        }

        # Handle URL input
        if file_path.startswith('http'):
            try:
                resp = self.session.get(file_path, timeout=self.timeout, verify=False)
                if resp.status_code != 200:
                    result["findings"].append({
                        "type": "error",
                        "description": f"Failed to download: HTTP {resp.status_code}",
                    })
                    return result
                import tempfile
                ext = os.path.splitext(file_path.split('?')[0])[1] or '.pdf'
                tmp = tempfile.NamedTemporaryFile(suffix=ext, delete=False)
                tmp.write(resp.content)
                tmp.close()
                actual_path = tmp.name
            except Exception as e:
                result["findings"].append({
                    "type": "error",
                    "description": f"Failed to download file: {str(e)[:100]}",
                })
                return result
        else:
            actual_path = file_path

        if not os.path.isfile(actual_path):
            result["findings"].append({
                "type": "error",
                "description": f"File not found: {actual_path}",
            })
            return result

        _, ext = os.path.splitext(actual_path)
        ext = ext.lower()

        if ext == '.pdf':
            result["details"]["file_type"] = "PDF"
            metadata = self._parse_pdf_metadata(actual_path)
        elif ext in ('.docx', '.xlsx', '.pptx'):
            doc_types = {'.docx': 'Word', '.xlsx': 'Excel', '.pptx': 'PowerPoint'}
            result["details"]["file_type"] = f"Office {doc_types[ext]}"
            metadata = self._parse_ooxml_metadata(actual_path)
        elif ext == '.odt':
            result["details"]["file_type"] = "OpenDocument Text"
            metadata = self._parse_ooxml_metadata(actual_path)
        else:
            # Try as Office Open XML
            try:
                metadata = self._parse_ooxml_metadata(actual_path)
                result["details"]["file_type"] = "Office Document"
            except Exception:
                metadata = {}
                result["findings"].append({
                    "type": "error",
                    "description": f"Unsupported file type: {ext}",
                })

        if metadata:
            result["details"]["metadata"] = metadata

            # Extract authors
            author_fields = ['Author', 'creator', 'LastModifiedBy', 'dc:creator', 'meta:initial-author']
            for field in author_fields:
                if field in metadata and metadata[field]:
                    result["details"]["authors"].append(str(metadata[field]))

            # Extract software
            software_fields = ['Software', 'Application', 'Producer', 'Creator', 'meta:generator']
            for field in software_fields:
                if field in metadata and metadata[field]:
                    result["details"]["software"].append(str(metadata[field]))

            result["findings"].append({
                "type": "metadata_found",
                "description": f"Found {len(metadata)} metadata fields in {result['details']['file_type']} document",
                "count": len(metadata),
            })

            # Check for privacy risks
            privacy_risks = self.assess_privacy_risk(metadata)
            result["details"]["privacy_risks"] = privacy_risks.get("details", {}).get("risks", [])
            if privacy_risks.get("vulnerable"):
                result["vulnerable"] = True

            if result["details"]["authors"]:
                result["vulnerable"] = True
                result["findings"].append({
                    "type": "author_found",
                    "severity": "High",
                    "description": f"Author information found: {result['details']['authors']}",
                    "authors": result["details"]["authors"],
                })
                self._print(f"  [!] Authors found: {result['details']['authors']}", YELLOW)

            if result["details"]["software"]:
                result["findings"].append({
                    "type": "software_found",
                    "severity": "Medium",
                    "description": f"Software detected: {result['details']['software']}",
                    "software": result["details"]["software"],
                })
        else:
            result["findings"].append({
                "type": "no_metadata",
                "description": "No metadata found in document",
            })

        self._print(f"  [+] Metadata fields: {len(metadata)}", GREEN)
        return result

    def _parse_pdf_metadata(self, file_path):
        """Parse PDF metadata"""
        metadata = {}
        try:
            with open(file_path, 'rb') as f:
                data = f.read()

            # Find document info dictionary
            # Look for /Title, /Author, /Subject, etc.
            info_pattern = re.compile(rb'/(\w+)\s*\(([^)]*)\)')
            for match in info_pattern.finditer(data):
                key = match.group(1).decode('ascii', errors='replace')
                value = match.group(2).decode('latin-1', errors='replace')
                if key in ('Title', 'Author', 'Subject', 'Keywords', 'Creator',
                           'Producer', 'CreationDate', 'ModDate'):
                    metadata[key] = value

            # Also check for hex-encoded strings
            hex_pattern = re.compile(rb'/(\w+)\s*<([0-9A-Fa-f]+)>')
            for match in hex_pattern.finditer(data):
                key = match.group(1).decode('ascii', errors='replace')
                hex_val = match.group(2).decode('ascii')
                try:
                    value = bytes.fromhex(hex_val).decode('utf-8', errors='replace')
                    if key in ('Title', 'Author', 'Subject', 'Keywords', 'Creator',
                               'Producer', 'CreationDate', 'ModDate'):
                        metadata[key] = value
                except Exception:
                    pass

            # File size
            metadata['FileSize'] = os.path.getsize(file_path)

            # PDF version
            if data[:5] == b'%PDF-':
                pdf_version = data[5:8].decode('ascii', errors='replace').strip()
                metadata['PDFVersion'] = pdf_version

        except Exception:
            pass
        return metadata

    def _parse_ooxml_metadata(self, file_path):
        """Parse Office Open XML metadata (DOCX, XLSX, PPTX)"""
        metadata = {}
        try:
            with zipfile.ZipFile(file_path, 'r') as z:
                # Read core properties
                if 'docProps/core.xml' in z.namelist():
                    core_xml = z.read('docProps/core.xml').decode('utf-8', errors='replace')
                    root = ET.fromstring(core_xml)
                    ns = {
                        'dc': 'http://purl.org/dc/elements/1.1/',
                        'cp': 'http://schemas.openxmlformats.org/package/2006/metadata/core-properties',
                        'dcterms': 'http://purl.org/dc/terms/',
                        'meta': 'http://schemas.openxmlformats.org/officedocument/2006/meta',
                    }
                    # Try without namespace
                    for elem in root:
                        tag = elem.tag
                        # Remove namespace
                        if '}' in tag:
                            tag = tag.split('}', 1)[1]
                        if elem.text:
                            metadata[tag] = elem.text

                # Read app properties
                if 'docProps/app.xml' in z.namelist():
                    app_xml = z.read('docProps/app.xml').decode('utf-8', errors='replace')
                    root = ET.fromstring(app_xml)
                    for elem in root:
                        tag = elem.tag
                        if '}' in tag:
                            tag = tag.split('}', 1)[1]
                        if elem.text:
                            metadata[tag] = elem.text

                # List all files in archive
                metadata['ArchiveFiles'] = str(z.namelist()[:30])

        except Exception as e:
            metadata['parse_error'] = str(e)[:200]
        return metadata

    # ========================================================================
    # METADATA STRIPPING / ANONYMIZATION
    # ========================================================================

    def strip_metadata(self, file_path, output_path=None):
        """Strip metadata from file (anonymize)

        Args:
            file_path: Path to input file
            output_path: Path for anonymized output (default: <filename>_clean.<ext>)

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  Metadata Stripping / Anonymization{RESET}", CYAN)
        self._print(f"  [*] Input: {file_path}", CYAN)

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "input_file": file_path,
                "output_file": "",
                "original_size": 0,
                "output_size": 0,
                "fields_removed": [],
                "stripped": False,
            },
            "scan_type": "metadata_strip",
        }

        if not os.path.isfile(file_path):
            result["findings"].append({
                "type": "error",
                "description": f"File not found: {file_path}",
            })
            return result

        if not output_path:
            base, ext = os.path.splitext(file_path)
            output_path = f"{base}_clean{ext}"

        result["details"]["output_file"] = output_path
        result["details"]["original_size"] = os.path.getsize(file_path)

        _, ext = os.path.splitext(file_path)
        ext = ext.lower()

        try:
            if ext in ('.docx', '.xlsx', '.pptx'):
                # Strip OOXML metadata
                with zipfile.ZipFile(file_path, 'r') as zin:
                    with zipfile.ZipFile(output_path, 'w') as zout:
                        for item in zin.namelist():
                            data = zin.read(item)
                            if item == 'docProps/core.xml':
                                # Create minimal core.xml
                                data = (
                                    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                                    '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties">'
                                    '</cp:coreProperties>'
                                ).encode()
                                result["details"]["fields_removed"].append("core.xml (all core properties)")
                            elif item == 'docProps/app.xml':
                                data = (
                                    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                                    '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">'
                                    '</Properties>'
                                ).encode()
                                result["details"]["fields_removed"].append("app.xml (all app properties)")
                            zout.writestr(item, data)

                result["details"]["stripped"] = True

            elif ext == '.pdf':
                # Basic PDF metadata stripping
                with open(file_path, 'rb') as f:
                    data = f.read()

                # Remove info dictionary reference
                stripped = data
                removed_fields = []
                for field in ('/Title', '/Author', '/Subject', '/Keywords',
                              '/Creator', '/Producer', '/CreationDate', '/ModDate'):
                    pattern = re.compile(field.encode() + rb'\s*\([^)]*\)')
                    matches = pattern.findall(stripped)
                    if matches:
                        removed_fields.append(field)
                        stripped = pattern.sub(field.encode() + b' ()', stripped)

                    # Also handle hex strings
                    hex_pattern = re.compile(field.encode() + rb'\s*<[0-9A-Fa-f]+>')
                    matches = hex_pattern.findall(stripped)
                    if matches:
                        removed_fields.append(f"{field} (hex)")
                        stripped = hex_pattern.sub(field.encode() + b' ()', stripped)

                result["details"]["fields_removed"] = removed_fields

                with open(output_path, 'wb') as f:
                    f.write(stripped)

                result["details"]["stripped"] = True

            elif ext in ('.jpg', '.jpeg'):
                # JPEG EXIF stripping - copy image data without EXIF
                with open(file_path, 'rb') as f:
                    data = f.read()

                # Find image data start (after all markers)
                output = b'\xff\xd8'  # SOI
                offset = 2
                while offset < len(data) - 1:
                    if data[offset] == 0xFF:
                        marker = data[offset + 1]
                        if marker == 0xD8:  # SOI
                            offset += 2
                            continue
                        elif marker == 0xD9:  # EOI
                            break
                        elif marker in (0x00, 0x01, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7):
                            offset += 2
                            continue
                        else:
                            length = (data[offset + 2] << 8) | data[offset + 3]
                            if marker == 0xE1:  # APP1 (EXIF) - skip
                                result["details"]["fields_removed"].append("APP1 (EXIF data)")
                                offset += 2 + length
                            elif marker == 0xE0:  # APP0 (JFIF) - keep but skip EXIF parts
                                output += data[offset:offset + 2 + length]
                                offset += 2 + length
                            elif marker == 0xDA:  # SOS - copy rest
                                output += data[offset:]
                                break
                            else:
                                output += data[offset:offset + 2 + length]
                                offset += 2 + length
                    else:
                        offset += 1

                with open(output_path, 'wb') as f:
                    f.write(output)

                result["details"]["stripped"] = True

            else:
                result["findings"].append({
                    "type": "unsupported",
                    "description": f"Metadata stripping not implemented for {ext} files. "
                                  f"Supported: JPEG, PDF, DOCX, XLSX, PPTX",
                })
                return result

            if result["details"]["stripped"]:
                result["details"]["output_size"] = os.path.getsize(output_path)
                result["findings"].append({
                    "type": "strip_success",
                    "description": f"Metadata stripped successfully. Removed {len(result['details']['fields_removed'])} field group(s). "
                                  f"Original: {result['details']['original_size']}B -> Clean: {result['details']['output_size']}B",
                    "fields_removed": result["details"]["fields_removed"],
                })
                self._print(f"  [+] Stripped {len(result['details']['fields_removed'])} field group(s)", GREEN)

        except Exception as e:
            result["findings"].append({
                "type": "error",
                "description": f"Metadata stripping failed: {str(e)[:200]}",
            })

        return result

    # ========================================================================
    # OPSEC CHECK
    # ========================================================================

    def opsec_check(self):
        """Perform OPSEC status check for scanning operations

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  OPSEC Status Check{RESET}", CYAN)

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "checks_performed": 0,
                "checks_passed": 0,
                "checks_failed": 0,
                "check_results": [],
                "recommendations": [],
                "overall_status": "UNKNOWN",
            },
            "scan_type": "opsec_check",
        }

        passed = 0
        failed = 0

        for check in OPSEC_CHECKS:
            check_result = {
                "id": check["id"],
                "name": check["name"],
                "description": check["description"],
                "severity": check["severity"],
                "status": "WARNING",
                "notes": "",
            }

            # Perform actual checks where possible
            if check["id"] == "ip_exposure":
                # Check if common proxy headers are set
                check_result["status"] = "WARNING"
                check_result["notes"] = "Could not verify VPN/proxy status. Ensure VPN is active before scanning."
                failed += 1

            elif check["id"] == "user_agent":
                ua = self.session.headers.get('User-Agent', '')
                if 'python' in ua.lower() or 'requests' in ua.lower():
                    check_result["status"] = "FAIL"
                    check_result["notes"] = f"Default User-Agent detected: {ua[:50]}"
                    failed += 1
                else:
                    check_result["status"] = "PASS"
                    check_result["notes"] = "Custom User-Agent in use"
                    passed += 1

            elif check["id"] == "cookie_tracking":
                cookies = len(self.session.cookies)
                if cookies > 5:
                    check_result["status"] = "FAIL"
                    check_result["notes"] = f"{cookies} cookies accumulated in session"
                    failed += 1
                else:
                    check_result["status"] = "PASS"
                    check_result["notes"] = f"Only {cookies} cookies in session"
                    passed += 1

            elif check["id"] == "metadata_leak":
                check_result["status"] = "WARNING"
                check_result["notes"] = "Always strip metadata from files before uploading to targets"
                failed += 1

            elif check["id"] == "timing_pattern":
                check_result["status"] = "WARNING"
                check_result["notes"] = "Use random delays between requests (0.5-3s recommended)"
                failed += 1

            elif check["id"] == "payload_signature":
                check_result["status"] = "WARNING"
                check_result["notes"] = "Avoid default tool payloads that can be fingerprinted"
                failed += 1

            elif check["id"] == "dns_leak":
                check_result["status"] = "WARNING"
                check_result["notes"] = "DNS queries may leak scanning source. Use DNS-over-HTTPS if possible."
                failed += 1

            else:
                check_result["status"] = "INFO"
                check_result["notes"] = check["check"]
                passed += 1

            result["details"]["check_results"].append(check_result)
            result["details"]["checks_performed"] += 1

            if check_result["status"] == "FAIL" or check_result["status"] == "WARNING":
                result["details"]["recommendations"].append({
                    "check": check["name"],
                    "recommendation": check["check"],
                    "severity": check["severity"],
                })

        result["details"]["checks_passed"] = passed
        result["details"]["checks_failed"] = failed

        # Overall status
        if failed == 0:
            result["details"]["overall_status"] = "GOOD"
        elif failed <= 3:
            result["details"]["overall_status"] = "MODERATE_RISK"
            result["vulnerable"] = True
        else:
            result["details"]["overall_status"] = "HIGH_RISK"
            result["vulnerable"] = True

        result["findings"].append({
            "type": "opsec_summary",
            "description": f"OPSEC Check: {passed} passed, {failed} need attention. Overall: {result['details']['overall_status']}",
            "passed": passed,
            "failed": failed,
            "overall_status": result["details"]["overall_status"],
        })

        self._print(f"  [*] OPSEC Status: {result['details']['overall_status']}", 
                    GREEN if failed == 0 else (YELLOW if failed <= 3 else RED))
        return result

    # ========================================================================
    # PRIVACY RISK ASSESSMENT
    # ========================================================================

    def assess_privacy_risk(self, metadata):
        """Assess privacy risk from metadata

        Args:
            metadata: Dict of metadata key-value pairs

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  Privacy Risk Assessment{RESET}", CYAN)

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "total_fields": len(metadata) if isinstance(metadata, dict) else 0,
                "risks": [],
                "risk_score": 0,
                "risk_level": "LOW",
                "critical_fields": [],
                "high_risk_fields": [],
                "medium_risk_fields": [],
                "recommendations": [],
            },
            "scan_type": "privacy_risk_assessment",
        }

        if not isinstance(metadata, dict) or not metadata:
            result["findings"].append({
                "type": "no_metadata",
                "description": "No metadata to assess",
            })
            return result

        risk_score = 0

        for field_name, field_value in metadata.items():
            field_lower = field_name.lower()
            risk = None

            # Check critical fields
            for critical_field in PRIVACY_RISK_FIELDS["critical"]:
                if critical_field.lower() in field_lower:
                    risk = {"field": field_name, "value": str(field_value)[:100], "level": "CRITICAL", "score": 50}
                    result["details"]["critical_fields"].append(risk)
                    risk_score += 50
                    break

            if not risk:
                # Check high risk fields
                for high_field in PRIVACY_RISK_FIELDS["high"]:
                    if high_field.lower() in field_lower:
                        risk = {"field": field_name, "value": str(field_value)[:100], "level": "HIGH", "score": 30}
                        result["details"]["high_risk_fields"].append(risk)
                        risk_score += 30
                        break

            if not risk:
                # Check medium risk fields
                for med_field in PRIVACY_RISK_FIELDS["medium"]:
                    if med_field.lower() in field_lower:
                        risk = {"field": field_name, "value": str(field_value)[:100], "level": "MEDIUM", "score": 15}
                        result["details"]["medium_risk_fields"].append(risk)
                        risk_score += 15
                        break

            if risk:
                result["details"]["risks"].append(risk)

        # Calculate risk level
        if risk_score >= 100:
            result["details"]["risk_level"] = "CRITICAL"
            result["vulnerable"] = True
        elif risk_score >= 50:
            result["details"]["risk_level"] = "HIGH"
            result["vulnerable"] = True
        elif risk_score >= 20:
            result["details"]["risk_level"] = "MEDIUM"
        else:
            result["details"]["risk_level"] = "LOW"

        result["details"]["risk_score"] = risk_score

        # Generate recommendations
        if result["details"]["critical_fields"]:
            result["details"]["recommendations"].append(
                "CRITICAL: GPS/location data found - strip immediately before sharing"
            )
        if result["details"]["high_risk_fields"]:
            result["details"]["recommendations"].append(
                "HIGH: Author/creator info found - remove before publishing"
            )
        if result["details"]["medium_risk_fields"]:
            result["details"]["recommendations"].append(
                "MEDIUM: Device/software info found - consider stripping for anonymity"
            )

        result["findings"].append({
            "type": "risk_assessment",
            "description": f"Privacy risk score: {risk_score} ({result['details']['risk_level']}). "
                          f"Critical: {len(result['details']['critical_fields'])}, "
                          f"High: {len(result['details']['high_risk_fields'])}, "
                          f"Medium: {len(result['details']['medium_risk_fields'])}",
            "risk_score": risk_score,
            "risk_level": result["details"]["risk_level"],
        })

        self._print(f"  [*] Risk Score: {risk_score} ({result['details']['risk_level']})",
                    RED if risk_score >= 50 else (YELLOW if risk_score >= 20 else GREEN))
        return result

    # ========================================================================
    # GEO LOCATION EXTRACTION
    # ========================================================================

    def extract_geo_location(self, exif_data):
        """Extract geographic location from EXIF data

        Args:
            exif_data: Dict of EXIF data

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  Geographic Location Extraction{RESET}", CYAN)

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "gps_coordinates": {},
                "google_maps_url": "",
                "osm_url": "",
                "has_location": False,
            },
            "scan_type": "geo_location_extract",
        }

        gps = self._extract_gps_from_exif(exif_data)

        if gps:
            result["details"]["gps_coordinates"] = gps
            result["details"]["google_maps_url"] = gps.get('google_maps_url', '')
            result["details"]["osm_url"] = gps.get('osm_url', '')
            result["details"]["has_location"] = True
            result["vulnerable"] = True
            result["findings"].append({
                "type": "location_found",
                "severity": "Critical",
                "description": f"GPS location extracted: Lat={gps.get('latitude', 'N/A')}, "
                              f"Lon={gps.get('longitude', 'N/A')}",
                "coordinates": gps,
                "google_maps": gps.get('google_maps_url', ''),
            })
            self._print(f"  [!!!] Location: {gps.get('latitude_str', 'N/A')}, {gps.get('longitude_str', 'N/A')}", RED)
            self._print(f"  [*] Google Maps: {gps.get('google_maps_url', 'N/A')}", CYAN)
        else:
            result["findings"].append({
                "type": "no_location",
                "description": "No GPS location data found in EXIF",
            })
            self._print(f"  [-] No GPS data found", GREEN)

        return result

    # ========================================================================
    # MAIN ENTRY POINT
    # ========================================================================

    def run(self, target=None, scan_type='extract', **kwargs):
        """Main entry point for Metadata + OPSEC Engine

        Args:
            target: File path or URL
            scan_type: Scan type ('extract', 'image_exif', 'doc_metadata',
                       'strip', 'opsec', 'privacy_risk', 'geo_location', 'full_scan')
            **kwargs: Additional arguments

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        if scan_type == 'extract' or scan_type == 'image_exif':
            return self.extract_image_metadata(target or '')
        elif scan_type == 'doc_metadata':
            return self.extract_doc_metadata(target or '')
        elif scan_type == 'strip':
            output = kwargs.get('output_path', None)
            return self.strip_metadata(target or '', output)
        elif scan_type == 'opsec':
            return self.opsec_check()
        elif scan_type == 'privacy_risk':
            metadata = kwargs.get('metadata', {})
            if target and isinstance(target, dict):
                metadata = target
            return self.assess_privacy_risk(metadata)
        elif scan_type == 'geo_location':
            exif_data = kwargs.get('exif_data', {})
            if target and isinstance(target, dict):
                exif_data = target
            return self.extract_geo_location(exif_data)
        elif scan_type == 'full_scan':
            return self._full_scan(target or '')
        else:
            return self.extract_image_metadata(target or '')

    def _full_scan(self, file_path):
        """Full metadata scan: Image + Document + Privacy + OPSEC

        Args:
            file_path: Path to file

        Returns:
            dict with combined results
        """
        self._print(f"\n{BOLD}{CYAN}  Metadata Full Scan{RESET}", CYAN)
        self._print(f"  [*] Target: {file_path}", CYAN)

        all_results = {}

        # Phase 1: Image EXIF extraction
        self._print(f"\n  {CYAN}=== Phase 1: Image EXIF Extraction ==={RESET}", CYAN)
        image_result = self.extract_image_metadata(file_path)
        all_results['image_exif'] = image_result

        # Phase 2: Document metadata (if applicable)
        self._print(f"\n  {CYAN}=== Phase 2: Document Metadata ==={RESET}", CYAN)
        doc_result = self.extract_doc_metadata(file_path)
        all_results['doc_metadata'] = doc_result

        # Phase 3: Privacy risk assessment
        self._print(f"\n  {CYAN}=== Phase 3: Privacy Risk Assessment ==={RESET}", CYAN)
        combined_metadata = {}
        combined_metadata.update(image_result.get('details', {}).get('exif_data', {}))
        combined_metadata.update(doc_result.get('details', {}).get('metadata', {}))
        privacy_result = self.assess_privacy_risk(combined_metadata)
        all_results['privacy_risk'] = privacy_result

        # Phase 4: OPSEC check
        self._print(f"\n  {CYAN}=== Phase 4: OPSEC Check ==={RESET}", CYAN)
        opsec_result = self.opsec_check()
        all_results['opsec_check'] = opsec_result

        total_findings = sum(
            len(r.get('findings', [])) for r in all_results.values()
        )

        return {
            "vulnerable": any(r.get('vulnerable', False) for r in all_results.values()),
            "findings": [{"type": "full_scan", "description": f"Full metadata scan: {total_findings} total findings across 4 phases"}],
            "details": all_results,
            "scan_type": "metadata_full_scan",
        }


# ============================================================================
# MODULE-LEVEL RUN FUNCTION
# ============================================================================

def run(target=None, scan_type='extract', **kwargs):
    """Module-level run function for ZYLON integration"""
    engine = MetadataEngine()
    return engine.run(target=target, scan_type=scan_type, **kwargs)
