#!/usr/bin/env python3
"""
forensic_init - Automatic Forensic File Analyzer for CTF Challenges
Version: 1.0.0
"""

import argparse
import hashlib
import math
import os
import re
import subprocess
import sys
import shutil
import tarfile
import zipfile
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from pathlib import Path

try:
    import magic
    HAS_MAGIC = True
except ImportError:
    HAS_MAGIC = False

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init()
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False


# Constants
TOOL_TIMEOUT = 60
MAX_NESTED_DEPTH = 5
MIN_STRING_LENGTH = 4

# Flag patterns
STANDARD_FLAG_PATTERNS = [
    r'FLAG\{[^\}]+\}',
    r'flag\{[^\}]+\}',
    r'CTF\{[^\}]+\}',
    r'ctf\{[^\}]+\}',
    r'picoCTF\{[^\}]+\}',
    r'hackthebox\{[^\}]+\}',
    r'HTB\{[^\}]+\}',
    r'flag\[[^\]]+\]',
]

# File type mappings
IMAGE_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.bmp', '.gif', '.tiff', '.tif', '.webp'}
ARCHIVE_EXTENSIONS = {'.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.tgz'}
PCAP_EXTENSIONS = {'.pcap', '.pcapng', '.cap', '.dump'}
DISK_EXTENSIONS = {'.raw', '.img', '.iso', '.e01', '.aff', '.vmdk', '.vhd', '.vhdx'}
DOCUMENT_EXTENSIONS = {'.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.odt', '.ods', '.odp'}
MEMORY_EXTENSIONS = {'.raw', '.mem', '.dmp', '.vmem'}


@dataclass
class AnalysisResult:
    """Stores analysis results"""
    success: bool = True
    output: str = ""
    error: str = ""
    data: Dict = field(default_factory=dict)
    flags_found: List[str] = field(default_factory=list)
    artifacts: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class TimelineEvent:
    """Represents a single event in the analysis timeline"""
    timestamp: str
    duration: float
    action: str
    status: str = "success"


class ForensicAnalyzer:
    """Base analyzer class with common functionality"""
    
    def __init__(self, filepath: str, extract_dir: str, custom_patterns: Optional[List[str]] = None):
        self.filepath = Path(filepath).resolve()
        self.extract_dir = Path(extract_dir).resolve()
        self.custom_patterns = custom_patterns or []
        self.results: Dict[str, AnalysisResult] = {}
        self.timeline: List[TimelineEvent] = []
        self.start_time = datetime.now()
        self.tools_used: List[str] = []
        self.all_flags: List[str] = []
        self.all_artifacts: List[str] = []
        
        # Create extraction directory
        self.extract_dir.mkdir(parents=True, exist_ok=True)
        
    def check_tool(self, tool_name: str) -> bool:
        """Check if a tool is available"""
        return shutil.which(tool_name) is not None
    
    def run_command(self, cmd: List[str], timeout: int = TOOL_TIMEOUT, 
                    capture_output: bool = True) -> Tuple[bool, str, str]:
        """Run a command with timeout"""
        try:
            result = subprocess.run(
                cmd,
                capture_output=capture_output,
                text=True,
                timeout=timeout
            )
            return (result.returncode == 0, result.stdout, result.stderr)
        except subprocess.TimeoutExpired:
            return (False, "", f"Timeout after {timeout} seconds")
        except Exception as e:
            return (False, "", str(e))
    
    def add_timeline_event(self, action: str, duration: float, status: str = "success"):
        """Add event to timeline"""
        self.timeline.append(TimelineEvent(
            timestamp=datetime.now().isoformat(),
            duration=duration,
            action=action,
            status=status
        ))
    
    def calculate_hashes(self) -> AnalysisResult:
        """Calculate MD5, SHA1, SHA256 hashes"""
        start = datetime.now()
        result = AnalysisResult()
        
        try:
            with open(self.filepath, 'rb') as f:
                data = f.read()
                result.data['md5'] = hashlib.md5(data).hexdigest()
                result.data['sha1'] = hashlib.sha1(data).hexdigest()
                result.data['sha256'] = hashlib.sha256(data).hexdigest()
                result.data['size'] = len(data)
            result.success = True
            result.output = "Hashes calculated successfully"
        except Exception as e:
            result.success = False
            result.error = str(e)
        
        duration = (datetime.now() - start).total_seconds()
        self.add_timeline_event("Hash calculation", duration, "success" if result.success else "failed")
        return result
    
    def extract_strings(self, min_length: int = MIN_STRING_LENGTH) -> AnalysisResult:
        """Extract printable strings from file"""
        start = datetime.now()
        result = AnalysisResult()
        
        if self.check_tool('strings'):
            success, stdout, stderr = self.run_command(['strings', '-n', str(min_length), str(self.filepath)])
            if success:
                result.output = stdout
                result.data['strings'] = stdout.split('\n')
                result.success = True
                self.tools_used.append('strings')
                # Check for flags
                flags = self.detect_flags(stdout)
                if flags:
                    result.flags_found = flags
                    self.all_flags.extend(flags)
            else:
                result.success = False
                result.error = stderr
        else:
            result.success = False
            result.error = "strings tool not found"
        
        duration = (datetime.now() - start).total_seconds()
        self.add_timeline_event("Strings extraction", duration, "success" if result.success else "failed")
        return result
    
    def calculate_entropy(self) -> AnalysisResult:
        """Calculate file entropy"""
        start = datetime.now()
        result = AnalysisResult()
        
        try:
            with open(self.filepath, 'rb') as f:
                data = f.read()
            
            if len(data) == 0:
                result.data['entropy'] = 0.0
            else:
                byte_counts = [0] * 256
                for byte in data:
                    byte_counts[byte] += 1
                
                entropy = 0.0
                for count in byte_counts:
                    if count > 0:
                        p = count / len(data)
                        entropy -= p * math.log2(p)
                
                result.data['entropy'] = round(entropy, 2)
                result.success = True
                result.output = f"Entropy: {result.data['entropy']}"
        except Exception as e:
            result.success = False
            result.error = str(e)
        
        duration = (datetime.now() - start).total_seconds()
        self.add_timeline_event("Entropy calculation", duration, "success" if result.success else "failed")
        return result
    
    def get_file_metadata(self) -> AnalysisResult:
        """Get file metadata using file command"""
        start = datetime.now()
        result = AnalysisResult()
        
        if self.check_tool('file'):
            success, stdout, stderr = self.run_command(['file', str(self.filepath)])
            if success:
                result.output = stdout
                result.data['file_type'] = stdout.strip()
                result.success = True
                self.tools_used.append('file')
            else:
                result.success = False
                result.error = stderr
        else:
            result.success = False
            result.error = "file tool not found"
        
        duration = (datetime.now() - start).total_seconds()
        self.add_timeline_event("Metadata extraction", duration, "success" if result.success else "failed")
        return result
    
    def detect_flags(self, text: str) -> List[str]:
        """Detect flags in text"""
        flags = []
        all_patterns = STANDARD_FLAG_PATTERNS + self.custom_patterns
        
        for pattern in all_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            flags.extend(matches)
        
        # Try to detect base64-encoded flags
        b64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        b64_matches = re.findall(b64_pattern, text)
        for match in b64_matches:
            try:
                import base64
                decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                for pattern in all_patterns:
                    decoded_matches = re.findall(pattern, decoded, re.IGNORECASE)
                    flags.extend([f"{m} (base64 encoded)" for m in decoded_matches])
            except:
                pass
        
        # Try hex-encoded flags
        hex_pattern = r'\b[0-9a-fA-F]{20,}\b'
        hex_matches = re.findall(hex_pattern, text)
        for match in hex_matches:
            try:
                decoded = bytes.fromhex(match).decode('utf-8', errors='ignore')
                for pattern in all_patterns:
                    decoded_matches = re.findall(pattern, decoded, re.IGNORECASE)
                    flags.extend([f"{m} (hex encoded)" for m in decoded_matches])
            except:
                pass
        
        # Try reversed flags
        reversed_text = text[::-1]
        for pattern in all_patterns:
            matches = re.findall(pattern, reversed_text, re.IGNORECASE)
            flags.extend([f"{m[::-1]} (reversed)" for m in matches])
        
        return list(set(flags))  # Remove duplicates
    
    def detect_file_type(self) -> str:
        """Detect file type using magic bytes and extension"""
        ext = self.filepath.suffix.lower()
        
        # Try magic first
        if HAS_MAGIC:
            try:
                mime = magic.Magic(mime=True)
                mime_type = mime.from_file(str(self.filepath))
                
                if 'image' in mime_type:
                    return 'image'
                elif 'pcap' in mime_type or 'cap' in mime_type:
                    return 'pcap'
                elif 'pdf' in mime_type:
                    return 'document'
                elif 'zip' in mime_type or 'rar' in mime_type or '7z' in mime_type:
                    return 'archive'
                elif 'tar' in mime_type:
                    return 'archive'
            except:
                pass
        
        # Fallback to extension
        if ext in IMAGE_EXTENSIONS:
            return 'image'
        elif ext in ARCHIVE_EXTENSIONS:
            return 'archive'
        elif ext in PCAP_EXTENSIONS:
            return 'pcap'
        elif ext in DISK_EXTENSIONS:
            return 'disk'
        elif ext in DOCUMENT_EXTENSIONS:
            return 'document'
        elif ext in MEMORY_EXTENSIONS:
            return 'memory'
        
        return 'unknown'
    
    def analyze(self) -> Dict[str, AnalysisResult]:
        """Run all basic analyses (base class implementation)"""
        return self.run_all_basic()
    
    def run_all_basic(self) -> Dict[str, AnalysisResult]:
        """Run all basic analyses"""
        self.results['hashes'] = self.calculate_hashes()
        self.results['strings'] = self.extract_strings()
        self.results['entropy'] = self.calculate_entropy()
        self.results['metadata'] = self.get_file_metadata()
        return self.results


class ImageAnalyzer(ForensicAnalyzer):
    """Analyzer for image files"""
    
    def run_zsteg(self) -> AnalysisResult:
        """Run zsteg for PNG steganography"""
        start = datetime.now()
        result = AnalysisResult()
        
        if self.check_tool('zsteg'):
            success, stdout, stderr = self.run_command(['zsteg', '-a', str(self.filepath)])
            if success or stdout:
                result.output = stdout
                result.success = True
                self.tools_used.append('zsteg')
                flags = self.detect_flags(stdout)
                if flags:
                    result.flags_found = flags
                    self.all_flags.extend(flags)
            else:
                result.success = False
                result.error = stderr
        else:
            result.success = False
            result.error = "zsteg tool not found"
        
        duration = (datetime.now() - start).total_seconds()
        self.add_timeline_event("Zsteg analysis", duration, "success" if result.success else "failed")
        return result
    
    def run_steghide(self, password: str = "") -> AnalysisResult:
        """Run steghide extraction"""
        start = datetime.now()
        result = AnalysisResult()
        
        if self.check_tool('steghide'):
            output_file = self.extract_dir / f"{self.filepath.stem}_steghide.txt"
            cmd = ['steghide', 'extract', '-sf', str(self.filepath), '-xf', str(output_file)]
            if password:
                cmd.extend(['-p', password])
            else:
                cmd.append('-p')  # Empty password
                cmd.append('')
            
            success, stdout, stderr = self.run_command(cmd)
            if success:
                result.output = f"Extracted to {output_file}"
                result.success = True
                result.artifacts.append(str(output_file))
                self.all_artifacts.append(str(output_file))
                self.tools_used.append('steghide')
                
                if output_file.exists():
                    with open(output_file, 'r', errors='ignore') as f:
                        content = f.read()
                        flags = self.detect_flags(content)
                        if flags:
                            result.flags_found = flags
                            self.all_flags.extend(flags)
            else:
                result.success = False
                result.error = stderr if stderr else "No data extracted"
        else:
            result.success = False
            result.error = "steghide tool not found"
        
        duration = (datetime.now() - start).total_seconds()
        self.add_timeline_event("Steghide extraction", duration, "success" if result.success else "failed")
        return result
    
    def run_pngcheck(self) -> AnalysisResult:
        """Run pngcheck for PNG analysis"""
        start = datetime.now()
        result = AnalysisResult()
        
        if self.check_tool('pngcheck'):
            success, stdout, stderr = self.run_command(['pngcheck', '-v', str(self.filepath)])
            result.output = stdout + stderr
            result.success = True
            self.tools_used.append('pngcheck')
        else:
            result.success = False
            result.error = "pngcheck tool not found"
        
        duration = (datetime.now() - start).total_seconds()
        self.add_timeline_event("PNGCheck analysis", duration, "success" if result.success else "failed")
        return result
    
    def run_exiftool(self) -> AnalysisResult:
        """Run exiftool for metadata"""
        start = datetime.now()
        result = AnalysisResult()
        
        if self.check_tool('exiftool'):
            success, stdout, stderr = self.run_command(['exiftool', str(self.filepath)])
            if success:
                result.output = stdout
                result.success = True
                self.tools_used.append('exiftool')
                flags = self.detect_flags(stdout)
                if flags:
                    result.flags_found = flags
                    self.all_flags.extend(flags)
            else:
                result.success = False
                result.error = stderr
        else:
            result.success = False
            result.error = "exiftool tool not found"
        
        duration = (datetime.now() - start).total_seconds()
        self.add_timeline_event("ExifTool analysis", duration, "success" if result.success else "failed")
        return result
    
    def analyze(self) -> Dict[str, AnalysisResult]:
        """Run all image analyses"""
        self.run_all_basic()
        self.results['zsteg'] = self.run_zsteg()
        self.results['steghide'] = self.run_steghide()
        self.results['exiftool'] = self.run_exiftool()
        
        if self.filepath.suffix.lower() == '.png':
            self.results['pngcheck'] = self.run_pngcheck()
        
        return self.results


class PCAPAnalyzer(ForensicAnalyzer):
    """Analyzer for PCAP files"""
    
    def get_conversations(self) -> AnalysisResult:
        """Get network conversations"""
        start = datetime.now()
        result = AnalysisResult()
        
        if self.check_tool('tshark'):
            success, stdout, stderr = self.run_command([
                'tshark', '-r', str(self.filepath), '-q', '-z', 'conv,tcp'
            ])
            if success:
                result.output = stdout
                result.success = True
                self.tools_used.append('tshark')
            else:
                result.success = False
                result.error = stderr
        else:
            result.success = False
            result.error = "tshark tool not found"
        
        duration = (datetime.now() - start).total_seconds()
        self.add_timeline_event("Conversation extraction", duration, "success" if result.success else "failed")
        return result
    
    def get_http_objects(self) -> AnalysisResult:
        """Extract HTTP objects"""
        start = datetime.now()
        result = AnalysisResult()
        
        if self.check_tool('tshark'):
            http_dir = self.extract_dir / "http_objects"
            http_dir.mkdir(parents=True, exist_ok=True)
            
            success, stdout, stderr = self.run_command([
                'tshark', '-r', str(self.filepath), 
                '--export-objects', f'http,{str(http_dir)}'
            ])
            
            # Check if any files were extracted
            if http_dir.exists():
                extracted_files = list(http_dir.iterdir())
                if extracted_files:
                    result.output = f"Extracted {len(extracted_files)} HTTP objects"
                    result.success = True
                    result.artifacts = [str(f) for f in extracted_files]
                    self.all_artifacts.extend(result.artifacts)
                    self.tools_used.append('tshark')
                    
                    # Check extracted files for flags
                    for f in extracted_files:
                        try:
                            with open(f, 'r', errors='ignore') as file:
                                content = file.read()
                                flags = self.detect_flags(content)
                                if flags:
                                    result.flags_found = flags
                                    self.all_flags.extend(flags)
                        except:
                            pass
                else:
                    result.success = True
                    result.output = "No HTTP objects found"
            else:
                result.success = False
                result.error = stderr
        else:
            result.success = False
            result.error = "tshark tool not found"
        
        duration = (datetime.now() - start).total_seconds()
        self.add_timeline_event("HTTP object extraction", duration, "success" if result.success else "failed")
        return result
    
    def extract_credentials(self) -> AnalysisResult:
        """Extract credentials from PCAP"""
        start = datetime.now()
        result = AnalysisResult()
        
        if self.check_tool('tshark'):
            # FTP credentials
            success, stdout, stderr = self.run_command([
                'tshark', '-r', str(self.filepath), '-Y', 'ftp', '-T', 'fields',
                '-e', 'ip.src', '-e', 'ip.dst', '-e', 'ftp.user', '-e', 'ftp.pass'
            ])
            
            credentials = []
            if stdout:
                credentials.append(("FTP", stdout))
            
            # HTTP Basic Auth
            success, stdout, stderr = self.run_command([
                'tshark', '-r', str(self.filepath), '-Y', 'http.authorization',
                '-T', 'fields', '-e', 'ip.src', '-e', 'ip.dst', '-e', 'http.authorization'
            ])
            
            if stdout:
                credentials.append(("HTTP Auth", stdout))
            
            result.output = "\n".join([f"{proto}:\n{data}" for proto, data in credentials])
            result.success = True
            self.tools_used.append('tshark')
            flags = self.detect_flags(result.output)
            if flags:
                result.flags_found = flags
                self.all_flags.extend(flags)
        else:
            result.success = False
            result.error = "tshark tool not found"
        
        duration = (datetime.now() - start).total_seconds()
        self.add_timeline_event("Credential extraction", duration, "success" if result.success else "failed")
        return result
    
    def get_dns_queries(self) -> AnalysisResult:
        """Get DNS queries"""
        start = datetime.now()
        result = AnalysisResult()
        
        if self.check_tool('tshark'):
            success, stdout, stderr = self.run_command([
                'tshark', '-r', str(self.filepath), '-Y', 'dns.qry.name',
                '-T', 'fields', '-e', 'dns.qry.name'
            ])
            
            if success:
                result.output = stdout
                result.success = True
                self.tools_used.append('tshark')
                flags = self.detect_flags(stdout)
                if flags:
                    result.flags_found = flags
                    self.all_flags.extend(flags)
            else:
                result.success = False
                result.error = stderr
        else:
            result.success = False
            result.error = "tshark tool not found"
        
        duration = (datetime.now() - start).total_seconds()
        self.add_timeline_event("DNS query extraction", duration, "success" if result.success else "failed")
        return result
    
    def analyze(self) -> Dict[str, AnalysisResult]:
        """Run all PCAP analyses"""
        self.run_all_basic()
        self.results['conversations'] = self.get_conversations()
        self.results['http_objects'] = self.get_http_objects()
        self.results['credentials'] = self.extract_credentials()
        self.results['dns'] = self.get_dns_queries()
        return self.results


class DiskAnalyzer(ForensicAnalyzer):
    """Analyzer for disk images"""
    
    def run_binwalk_scan(self) -> AnalysisResult:
        """Run binwalk signature scan"""
        start = datetime.now()
        result = AnalysisResult()
        
        if self.check_tool('binwalk'):
            success, stdout, stderr = self.run_command(['binwalk', str(self.filepath)])
            if success:
                result.output = stdout
                result.success = True
                self.tools_used.append('binwalk')
            else:
                result.success = False
                result.error = stderr
        else:
            result.success = False
            result.error = "binwalk tool not found"
        
        duration = (datetime.now() - start).total_seconds()
        self.add_timeline_event("Binwalk scan", duration, "success" if result.success else "failed")
        return result
    
    def run_binwalk_extract(self) -> AnalysisResult:
        """Run binwalk extraction"""
        start = datetime.now()
        result = AnalysisResult()
        
        if self.check_tool('binwalk'):
            binwalk_dir = self.extract_dir / "binwalk_extracted"
            
            success, stdout, stderr = self.run_command([
                'binwalk', '-e', '-C', str(binwalk_dir), str(self.filepath)
            ])
            
            if success:
                result.output = f"Extracted to {binwalk_dir}"
                result.success = True
                self.tools_used.append('binwalk')
                
                # List extracted files
                if binwalk_dir.exists():
                    extracted_files = []
                    for root, dirs, files in os.walk(binwalk_dir):
                        for f in files:
                            extracted_files.append(os.path.join(root, f))
                    
                    if extracted_files:
                        result.artifacts = extracted_files
                        self.all_artifacts.extend(extracted_files)
                        
                        for f in extracted_files:
                            try:
                                with open(f, 'r', errors='ignore') as file:
                                    content = file.read()
                                    flags = self.detect_flags(content)
                                    if flags:
                                        result.flags_found = flags
                                        self.all_flags.extend(flags)
                            except:
                                pass
            else:
                result.success = False
                result.error = stderr
        else:
            result.success = False
            result.error = "binwalk tool not found"
        
        duration = (datetime.now() - start).total_seconds()
        self.add_timeline_event("Binwalk extraction", duration, "success" if result.success else "failed")
        return result
    
    def analyze(self) -> Dict[str, AnalysisResult]:
        """Run all disk analyses"""
        self.run_all_basic()
        self.results['binwalk_scan'] = self.run_binwalk_scan()
        self.results['binwalk_extract'] = self.run_binwalk_extract()
        return self.results


class ArchiveAnalyzer(ForensicAnalyzer):
    """Analyzer for archive files"""
    
    def extract_archive(self, archive_path: Path, dest_dir: Path, depth: int = 0) -> List[str]:
        """Recursively extract archives"""
        extracted_files = []
        
        if depth > MAX_NESTED_DEPTH:
            return extracted_files
        
        ext = archive_path.suffix.lower()
        
        try:
            if ext in {'.zip', '.jar', '.war'}:
                with zipfile.ZipFile(archive_path, 'r') as zf:
                    zf.extractall(dest_dir)
                    extracted_files = [str(dest_dir / f) for f in zf.namelist()]
            
            elif ext in {'.tar', '.tgz'} or '.tar' in archive_path.name.lower():
                with tarfile.open(archive_path, 'r:*') as tf:
                    tf.extractall(dest_dir)
                    extracted_files = [str(dest_dir / m.name) for m in tf.getmembers() if m.isfile()]
            
            elif ext in {'.gz', '.bz2', '.xz'}:
                # Single file compression
                import gzip, bz2, lzma
                if ext == '.gz':
                    opener = gzip.open
                elif ext == '.bz2':
                    opener = bz2.open
                else:
                    opener = lzma.open
                
                output_name = archive_path.stem
                if output_name == archive_path.name:
                    output_name += '.extracted'
                
                output_path = dest_dir / output_name
                with opener(archive_path, 'rb') as f_in:
                    with open(output_path, 'wb') as f_out:
                        shutil.copyfileobj(f_in, f_out)
                extracted_files.append(str(output_path))
            
            # Check for nested archives
            for extracted_file in extracted_files:
                file_path = Path(extracted_file)
                if file_path.exists() and file_path.suffix.lower() in ARCHIVE_EXTENSIONS:
                    nested_dir = file_path.parent / f"{file_path.stem}_nested"
                    nested_dir.mkdir(parents=True, exist_ok=True)
                    nested_files = self.extract_archive(file_path, nested_dir, depth + 1)
                    extracted_files.extend(nested_files)
        
        except Exception as e:
            pass
        
        return extracted_files
    
    def analyze(self) -> Dict[str, AnalysisResult]:
        """Run all archive analyses"""
        self.run_all_basic()
        
        result = AnalysisResult()
        start = datetime.now()
        
        extracted = self.extract_archive(self.filepath, self.extract_dir)
        
        if extracted:
            result.success = True
            result.output = f"Extracted {len(extracted)} files"
            result.artifacts = extracted
            self.all_artifacts.extend(extracted)
            
            for f in extracted:
                try:
                    with open(f, 'r', errors='ignore') as file:
                        content = file.read()
                        flags = self.detect_flags(content)
                        if flags:
                            result.flags_found = flags
                            self.all_flags.extend(flags)
                except:
                    pass
        else:
            result.success = False
            result.error = "No files extracted"
        
        duration = (datetime.now() - start).total_seconds()
        self.add_timeline_event("Archive extraction", duration, "success" if result.success else "failed")
        self.results['extraction'] = result
        
        return self.results


class DocumentAnalyzer(ForensicAnalyzer):
    """Analyzer for document files"""
    
    def analyze_pdf(self) -> AnalysisResult:
        """Analyze PDF file"""
        start = datetime.now()
        result = AnalysisResult()
        
        # Use binwalk for embedded content
        if self.check_tool('binwalk'):
            success, stdout, stderr = self.run_command(['binwalk', str(self.filepath)])
            if success:
                result.output = stdout
                result.success = True
                self.tools_used.append('binwalk')
                flags = self.detect_flags(stdout)
                if flags:
                    result.flags_found = flags
                    self.all_flags.extend(flags)
        
        # Try pdftotext
        if self.check_tool('pdftotext'):
            text_file = self.extract_dir / f"{self.filepath.stem}.txt"
            success, stdout, stderr = self.run_command([
                'pdftotext', str(self.filepath), str(text_file)
            ])
            
            if success and text_file.exists():
                with open(text_file, 'r', errors='ignore') as f:
                    content = f.read()
                    flags = self.detect_flags(content)
                    if flags:
                        result.flags_found.extend(flags)
                        self.all_flags.extend(flags)
                result.artifacts.append(str(text_file))
                self.all_artifacts.append(str(text_file))
                self.tools_used.append('pdftotext')
        
        if not result.success:
            result.success = True
            result.output = "PDF analysis completed"
        
        duration = (datetime.now() - start).total_seconds()
        self.add_timeline_event("PDF analysis", duration, "success" if result.success else "failed")
        return result
    
    def analyze_office(self) -> AnalysisResult:
        """Analyze Office document"""
        start = datetime.now()
        result = AnalysisResult()
        
        # Use binwalk for embedded content
        if self.check_tool('binwalk'):
            success, stdout, stderr = self.run_command(['binwalk', str(self.filepath)])
            if success:
                result.output = stdout
                result.success = True
                self.tools_used.append('binwalk')
                flags = self.detect_flags(stdout)
                if flags:
                    result.flags_found = flags
                    self.all_flags.extend(flags)
        
        # Try oletools if available
        if self.check_tool('olevba'):
            success, stdout, stderr = self.run_command(['olevba', str(self.filepath)])
            if success:
                result.output += "\n\nOleTools Output:\n" + stdout
                self.tools_used.append('oletools')
                flags = self.detect_flags(stdout)
                if flags:
                    result.flags_found.extend(flags)
                    self.all_flags.extend(flags)
        
        if not result.success:
            result.success = True
            result.output = "Office document analysis completed"
        
        duration = (datetime.now() - start).total_seconds()
        self.add_timeline_event("Office document analysis", duration, "success" if result.success else "failed")
        return result
    
    def analyze(self) -> Dict[str, AnalysisResult]:
        """Run document analysis"""
        self.run_all_basic()
        
        ext = self.filepath.suffix.lower()
        if ext == '.pdf':
            self.results['document'] = self.analyze_pdf()
        elif ext in {'.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'}:
            self.results['document'] = self.analyze_office()
        
        return self.results


class ReportGenerator:
    """Generates markdown report"""
    
    def __init__(self, analyzer: ForensicAnalyzer, output_file: str):
        self.analyzer = analyzer
        self.output_file = Path(output_file)
    
    def generate(self) -> str:
        """Generate complete markdown report"""
        sections = [
            self._header_section(),
            self._overview_section(),
            self._findings_summary(),
            self._detailed_results(),
            self._flags_section(),
            self._artifacts_section(),
            self._timeline_section(),
            self._tools_section()
        ]
        return '\n'.join(sections)
    
    def _header_section(self) -> str:
        """Generate report header"""
        return f"""# Forensic Analysis Report

**File**: `{self.analyzer.filepath.name}`
**Path**: `{self.analyzer.filepath}`
**Analyzed**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Tool**: forensic_init v1.0.0

---"""
    
    def _overview_section(self) -> str:
        """Generate file overview"""
        hash_result = self.analyzer.results.get('hashes', AnalysisResult())
        entropy_result = self.analyzer.results.get('entropy', AnalysisResult())
        metadata_result = self.analyzer.results.get('metadata', AnalysisResult())
        
        size_bytes = hash_result.data.get('size', 0)
        size_readable = self._format_size(size_bytes)
        
        entropy = entropy_result.data.get('entropy', 0)
        entropy_note = ""
        if entropy > 7.5:
            entropy_note = " (very high - likely encrypted/compressed)"
        elif entropy > 6.5:
            entropy_note = " (high - possibly compressed)"
        elif entropy < 4.0:
            entropy_note = " (low - likely text or simple data)"
        
        return f"""
## 📊 File Overview

| Property | Value |
|----------|-------|
| **Size** | {size_readable} |
| **Type** | {metadata_result.data.get('file_type', 'Unknown')} |
| **MD5** | `{hash_result.data.get('md5', 'N/A')}` |
| **SHA1** | `{hash_result.data.get('sha1', 'N/A')}` |
| **SHA256** | `{hash_result.data.get('sha256', 'N/A')}` |
| **Entropy** | {entropy}{entropy_note} |

"""
    
    def _findings_summary(self) -> str:
        """Generate findings summary"""
        findings = []
        
        # Check for flags
        if self.analyzer.all_flags:
            findings.append(f"- 🚩 **Flags detected**: {len(self.analyzer.all_flags)} potential flags found")
        
        # Check for artifacts
        if self.analyzer.all_artifacts:
            findings.append(f"- 📁 **Artifacts extracted**: {len(self.analyzer.all_artifacts)} files extracted")
        
        # Check for high entropy
        entropy = self.analyzer.results.get('entropy', AnalysisResult())
        if entropy.data.get('entropy', 0) > 7.5:
            findings.append("- 🔐 **High entropy**: File may be encrypted or compressed")
        
        # Check for interesting strings
        strings_result = self.analyzer.results.get('strings', AnalysisResult())
        if strings_result.success and strings_result.output:
            interesting_strings = []
            for pattern in ['password', 'secret', 'flag', 'key', 'admin', 'root', 'user']:
                if pattern in strings_result.output.lower():
                    interesting_strings.append(pattern)
            if interesting_strings:
                findings.append(f"- 💬 **Interesting strings**: Found mentions of {', '.join(interesting_strings)}")
        
        if not findings:
            findings.append("- ℹ️ No significant findings detected")
        
        return f"""## 🔍 Analysis Summary

{chr(10).join(findings)}

"""
    
    def _detailed_results(self) -> str:
        """Generate detailed results section"""
        sections = ["## 📋 Detailed Results\n"]
        
        # Strings
        strings_result = self.analyzer.results.get('strings', AnalysisResult())
        if strings_result.success and strings_result.output:
            sections.append(f"""### 1. Strings Analysis
<details>
<summary>Click to view strings (truncated)</summary>

```
{self._truncate_output(strings_result.output, 500)}
```

</details>

""")
        
        # Add analyzer-specific results
        for key, result in self.analyzer.results.items():
            if key in ['hashes', 'entropy', 'metadata', 'strings']:
                continue
            
            if result.success and result.output:
                sections.append(f"""### {key.replace('_', ' ').title()}

<details>
<summary>Click to view output</summary>

```
{self._truncate_output(result.output, 1000)}
```

</details>

""")
        
        return '\n'.join(sections)
    
    def _flags_section(self) -> str:
        """Generate flags section"""
        if not self.analyzer.all_flags:
            return "\n## 🚩 Potential Flags\n\nNo flags detected.\n"
        
        unique_flags = list(set(self.analyzer.all_flags))
        flags_list = '\n'.join([f"- `{flag}`" for flag in unique_flags])
        
        return f"""
## 🚩 Potential Flags Detected

{flags_list}

"""
    
    def _artifacts_section(self) -> str:
        """Generate artifacts section"""
        if not self.analyzer.all_artifacts:
            return "\n## 📁 Extracted Artifacts\n\nNo artifacts extracted.\n"
        
        artifacts_list = '\n'.join([
            f"- `{Path(a).relative_to(self.analyzer.extract_dir)}`" 
            for a in self.analyzer.all_artifacts[:20]  # Limit to 20
        ])
        
        if len(self.analyzer.all_artifacts) > 20:
            artifacts_list += f"\n- ... and {len(self.analyzer.all_artifacts) - 20} more files"
        
        return f"""
## 📁 Extracted Artifacts

{artifacts_list}

"""
    
    def _timeline_section(self) -> str:
        """Generate timeline section"""
        if not self.analyzer.timeline:
            return "\n## ⏱️ Analysis Timeline\n\nNo timeline data available.\n"
        
        timeline_list = []
        for i, event in enumerate(self.analyzer.timeline, 1):
            status_icon = "✅" if event.status == "success" else "❌"
            timeline_list.append(
                f"{i}. {status_icon} {event.action} ({event.duration:.2f}s)"
            )
        
        return f"""## ⏱️ Analysis Timeline

{chr(10).join(timeline_list)}

"""
    
    def _tools_section(self) -> str:
        """Generate tools used section"""
        if not self.analyzer.tools_used:
            return "\n## 🛠️ Tools Used\n\nNo external tools used.\n"
        
        tools_list = ', '.join(set(self.analyzer.tools_used))
        return f"""
## 🛠️ Tools Used

{tools_list}

---"""
    
    def _truncate_output(self, text: str, max_lines: int) -> str:
        """Truncate output to max_lines"""
        lines = text.split('\n')
        if len(lines) <= max_lines:
            return text
        return '\n'.join(lines[:max_lines]) + f"\n\n... ({len(lines) - max_lines} more lines)"
    
    def _format_size(self, size_bytes: int) -> str:
        """Format size in human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} PB"
    
    def save(self) -> str:
        """Generate and save report"""
        report = self.generate()
        self.output_file.write_text(report)
        return str(self.output_file)


def get_analyzer(filepath: str, extract_dir: str, custom_patterns: List[str] = None) -> ForensicAnalyzer:
    """Get appropriate analyzer based on file type"""
    
    # Create temp instance to detect type
    temp_analyzer = ForensicAnalyzer(filepath, extract_dir, custom_patterns)
    file_type = temp_analyzer.detect_file_type()
    
    analyzers = {
        'image': ImageAnalyzer,
        'pcap': PCAPAnalyzer,
        'disk': DiskAnalyzer,
        'archive': ArchiveAnalyzer,
        'document': DocumentAnalyzer,
    }
    
    analyzer_class = analyzers.get(file_type, ForensicAnalyzer)
    return analyzer_class(filepath, extract_dir, custom_patterns)


def print_banner():
    """Print tool banner"""
    banner = """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   ███████╗██████╗  ██████╗ ██╗██████╗ ███████╗███████╗██╗    ║
║   ██╔════╝██╔══██╗██╔════╝ ██║██╔══██╗██╔════╝██╔════╝██║    ║
║   ███████╗██████╔╝██║  ███╗██║██████╔╝█████╗  █████╗  ██║    ║
║   ╚════██║██╔══██╗██║   ██║██║██╔══██╗██╔══╝  ██╔══╝  ╚═╝    ║
║   ███████║██║  ██║╚██████╔╝██║██████╔╝███████╗███████╗██╗    ║
║   ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝╚═════╝ ╚══════╝╚══════╝╚═╝    ║
║                                                               ║
║              Automatic Forensic File Analyzer                 ║
║                      v1.0.0 - CTF Edition                     ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
"""
    if HAS_COLORAMA:
        print(Fore.CYAN + banner + Style.RESET_ALL)
    else:
        print(banner)


def print_status(message: str, status: str = "info"):
    """Print colored status message"""
    if HAS_COLORAMA:
        colors = {
            'info': Fore.BLUE,
            'success': Fore.GREEN,
            'warning': Fore.YELLOW,
            'error': Fore.RED,
        }
        color = colors.get(status, Fore.WHITE)
        print(f"{color}[*]{Style.RESET_ALL} {message}")
    else:
        print(f"[*] {message}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Automatic forensic file analyzer for CTF challenges',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s challenge.png
  %(prog)s capture.pcap -o analysis.md
  %(prog)s disk.img --no-extract
  %(prog)s secret.zip --custom-flags "myctf\\{[^}]+\\}"
        """
    )
    
    parser.add_argument('file', help='File to analyze')
    parser.add_argument('-o', '--output', help='Output report file (default: <filename>_report.md)')
    parser.add_argument('-e', '--extract-dir', help='Extraction directory (default: extracted_<filename>/)')
    parser.add_argument('--no-extract', action='store_true', help='Disable auto-extraction')
    parser.add_argument('--timeout', type=int, default=TOOL_TIMEOUT, help='Tool timeout in seconds')
    parser.add_argument('--custom-flags', help='Custom flag regex patterns (comma-separated)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Validate file
    if not os.path.exists(args.file):
        print_status(f"File not found: {args.file}", "error")
        sys.exit(1)
    
    # Print banner
    print_banner()
    
    # Setup paths
    filepath = Path(args.file).resolve()
    filename = filepath.stem
    
    if args.output:
        output_file = Path(args.output)
    else:
        output_file = Path(f"{filename}_report.md")
    
    if args.extract_dir:
        extract_dir = Path(args.extract_dir)
    else:
        extract_dir = Path(f"extracted_{filename}")
    
    # Parse custom flags
    custom_patterns = []
    if args.custom_flags:
        custom_patterns = [p.strip() for p in args.custom_flags.split(',')]
    
    # Status messages
    print_status(f"Analyzing: {filepath.name}", "info")
    print_status(f"Output: {output_file}", "info")
    print_status(f"Extract dir: {extract_dir}", "info")
    print()
    
    # Get appropriate analyzer
    analyzer = get_analyzer(str(filepath), str(extract_dir), custom_patterns)
    
    # Run analysis
    print_status("Running analysis...", "info")
    
    if HAS_TQDM and args.verbose:
        with tqdm(total=5, desc="Analysis Progress") as pbar:
            pbar.set_description("Basic analysis")
            analyzer.run_all_basic()
            pbar.update(1)
            
            pbar.set_description("File-specific analysis")
            analyzer.analyze()
            pbar.update(1)
            
            pbar.set_description("Generating report")
            report_file = ReportGenerator(analyzer, str(output_file)).save()
            pbar.update(1)
    else:
        analyzer.analyze()
        report_file = ReportGenerator(analyzer, str(output_file)).save()
    
    # Print summary
    print()
    print_status("Analysis complete!", "success")
    print_status(f"Report saved to: {report_file}", "success")
    
    if analyzer.all_flags:
        print_status(f"🚩 Potential flags found: {len(analyzer.all_flags)}", "warning")
    
    if analyzer.all_artifacts:
        print_status(f"📁 Artifacts extracted: {len(analyzer.all_artifacts)} files", "info")
    
    print()
    print_status("Happy CTF hunting! 🎯", "success")


if __name__ == '__main__':
    main()
