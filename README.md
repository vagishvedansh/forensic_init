# 🔍 forensic_init

**Automatic forensic file analyzer for CTF challenges**

A powerful, single-file Python tool that automates forensic analysis for CTF competitions. It detects file types, runs appropriate analysis tools, extracts hidden artifacts, and generates comprehensive markdown reports.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🗂️ **File Type Detection** | Automatically identifies images, pcap files, disk images, archives, documents, and memory dumps |
| 🔧 **Tool Integration** | Seamlessly integrates with popular forensic tools |
| 📦 **Auto-Extraction** | Extracts embedded artifacts and hidden data |
| 🔐 **Hash Calculation** | Computes MD5, SHA1, and SHA256 hashes |
| 🚩 **Flag Detection** | Finds flags in various formats (FLAG{}, CTF{}, picoCTF{}, etc.) including encoded variants |
| 📊 **Timeline View** | Presents analysis results in chronological order |
| 📝 **Markdown Reports** | Generates clean, readable markdown reports |

---

## 📦 Installation

### System Requirements

- **Python**: 3.7 or higher
- **OS**: Linux (recommended), macOS

### System Tools

Install the required forensic tools:

```bash
# Debian/Ubuntu
sudo apt install file binwalk foremost exiftool

# Optional but recommended
sudo apt install steghide pngcheck tshark

# Arch Linux
sudo pacman -S file binwalk foremost perl-image-exiftool steghide pngcheck wireshark-cli

# Additional: Install zsteg (Ruby gem)
gem install zsteg
```

| Tool | Required | Purpose |
|------|----------|---------|
| `file` | ✅ Yes | File type identification |
| `strings` | ✅ Yes | Extract printable strings |
| `binwalk` | ✅ Yes | Firmware/embedded file extraction |
| `foremost` | ✅ Yes | File carving and recovery |
| `exiftool` | ✅ Yes | Metadata extraction |
| `zsteg` | ⭕ Optional | PNG steganography detection |
| `steghide` | ⭕ Optional | Steganography extraction (JPEG, BMP, WAV, AU) |
| `pngcheck` | ⭕ Optional | PNG validation and chunk analysis |
| `tshark` | ⭕ Optional | Network packet analysis (Wireshark CLI) |

### Python Dependencies

```bash
pip install python-magic tqdm colorama
```

Or using requirements.txt:

```bash
pip install -r requirements.txt
```

---

## 🚀 Usage

### Basic Usage

```bash
python forensic_init.py <file_path>
```

### CLI Options

```
usage: forensic_init.py [-h] [-o OUTPUT] [-v] [-q] [--no-extract] file

Automatic forensic file analyzer for CTF challenges

positional arguments:
  file                  Path to the file to analyze

options:
  -h, --help            Show help message and exit
  -o, --output OUTPUT   Output directory for report and extracted files (default: ./forensic_report)
  -v, --verbose         Enable verbose output
  -q, --quiet           Suppress console output (only generate report)
  --no-extract          Disable automatic file extraction
```

### Examples

```bash
# Analyze a single file
python forensic_init.py suspicious.png

# Specify custom output directory
python forensic_init.py challenge.pcap -o ./analysis_results

# Quiet mode (only generate report)
python forensic_init.py memory.raw -q

# Disable auto-extraction
python forensic_init.py disk.img --no-extract
```

---

## 📁 Supported File Types

| Category | Extensions | Tools Used |
|----------|------------|------------|
| **Images** | `.png`, `.jpg`, `.jpeg`, `.gif`, `.bmp` | `exiftool`, `zsteg`, `steghide`, `pngcheck`, `strings` |
| **Network Captures** | `.pcap`, `.pcapng`, `.cap` | `tshark`, `strings` |
| **Disk Images** | `.img`, `.raw`, `.dd`, `.e01` | `binwalk`, `foremost`, `strings` |
| **Archives** | `.zip`, `.rar`, `.7z`, `.tar`, `.gz` | `binwalk`, `foremost` |
| **Documents** | `.pdf`, `.doc`, `.docx`, `.xls`, `.xlsx` | `exiftool`, `strings` |
| **Memory Dumps** | `.raw`, `.mem`, `.dmp` | `volatility`, `strings` |
| **Executable** | `.exe`, `.elf`, `.bin` | `strings`, `binwalk` |
| **Audio/Video** | `.wav`, `.mp3`, `.mp4`, `.avi` | `steghide`, `exiftool` |

---

## 📋 Output Format

The tool generates a single markdown report containing:

### Report Structure

```markdown
# Forensic Analysis Report

## 📊 File Information
- Filename, size, type
- Hash values (MD5, SHA1, SHA256)

## 🔍 Analysis Results
### Timeline
[Chronological list of findings]

### Extracted Artifacts
[List of extracted files and their locations]

## 🚩 Detected Flags
[Found flags with context]

## 📝 Detailed Findings
[Tool-specific analysis results]
```

### Sample Output

```
🔍 Analyzing: challenge.png
├── Detecting file type... PNG image
├── Calculating hashes... ✓
├── Running exiftool... ✓
├── Running zsteg... ✓
│   └── Found hidden data in LSB
├── Running strings... ✓
│   └── Detected potential flag: FLAG{h1dd3n_1n_pl41n_s1ght}
└── Generating report... ✓

Report saved to: ./forensic_report/report.md
```

---

## 📚 Examples

> 🚧 **Placeholder** - Real-world examples coming soon!

### Example 1: PNG Steganography

```bash
python forensic_init.py stego.png
```

Expected output when hidden data is found in LSB.

### Example 2: PCAP Analysis

```bash
python forensic_init.py capture.pcap
```

Network traffic analysis with tshark integration.

### Example 3: Memory Dump Analysis

```bash
python forensic_init.py memory.raw
```

Volatility integration for memory forensics.

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

### Ways to Contribute

- 🐛 **Bug Reports**: Open an issue with details and reproduction steps
- 💡 **Feature Requests**: Suggest new analysis tools or file type support
- 🔧 **Pull Requests**: Submit improvements or fixes
- 📖 **Documentation**: Help improve examples and guides

### Development Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/forensic_init.git
cd forensic_init

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run tests
python -m pytest tests/
```

### Code Style

- Follow PEP 8 guidelines
- Use meaningful variable names
- Add docstrings for functions
- Keep the single-file structure

### Submitting Changes

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License.

```
MIT License

Copyright (c) 2024 forensic_init

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 🙏 Acknowledgments

- All the amazing forensic tool developers
- CTF community for inspiration
- Contributors and testers

---

<p align="center">
  Made with ❤️ for CTF enthusiasts
</p>
