# ForEmHash - Forensic eMule Hash Calculator

[![Python](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20|%20macOS%20|%20Linux-lightgrey.svg)](https://github.com/yourusername/foremhash)

ForEmHash is a forensic tool designed to calculate eMule/ED2K hashes for digital evidence analysis. It computes ED2K, ICH (Intelligent Corruption Handling), and AICH (Advanced Intelligent Corruption Handling) hashes used by the eMule P2P network, making it invaluable for forensic investigations involving file sharing activities.

## 🎯 Features

- **Complete eMule Hash Support**
  - ED2K hash calculation (primary eMule file identifier)
  - AICH root hash (corruption recovery system)
  - Individual chunk hashes (9.28MB segments)
  
- **Dual Interface**
  - GUI mode with PyQt5 for ease of use
  - CLI mode for automation and batch processing
  
- **Forensic-Ready**
  - Custom exhibit naming for case management
  - CSV export with timestamp
  - Chain of custody documentation
  - Batch processing capabilities
  
- **Cross-Platform**
  - Windows 10/11
  - macOS 10.14+
  - Linux (Ubuntu, Debian, Fedora, etc.)

## 📋 Requirements

- Python 3.6 or higher
- PyQt5 (for GUI mode)
- pycryptodome (for MD4 hash support)

## 🚀 Installation

### Quick Install

```bash
# Clone the repository
git clone https://github.com/yourusername/foremhash.git
cd foremhash

# Install dependencies
pip install -r requirements.txt
```

### Manual Installation

```bash
# Install required packages
pip install PyQt5 pycryptodome

# Download the script
wget https://raw.githubusercontent.com/yourusername/foremhash/main/foremhash.py
```

### Windows Users

```batch
# Install Python from python.org (check "Add to PATH")
# Open Command Prompt as Administrator

pip install PyQt5 pycryptodome
```

## 💻 Usage

### GUI Mode

Launch the graphical interface:

```bash
python foremhash.py --gui
```

The GUI provides:
- File/directory selection dialogs
- Real-time processing progress
- Results preview table
- Automatic CSV export

### CLI Mode

#### Single File Analysis

```bash
python foremhash.py -e CASE001_HD1 -i /path/to/file.dat -o /output/directory
```

#### Directory Analysis (Recursive)

```bash
python foremhash.py -e CASE001_HD1 -i /evidence/downloads -o /reports
```

#### Command Line Options

```
Required Arguments:
  -e, --exhibit    Exhibit name/identifier (e.g., CASE001_HD1)
  -i, --input      Input file or directory path
  -o, --output     Output directory for CSV results

Optional Arguments:
  --gui            Launch GUI interface
  --test-md4       Test MD4 implementation
  -h, --help       Show help message
```

## 📊 Output Format

ForEmHash generates CSV files with the following structure:

| Column | Description |
|--------|-------------|
| exhibit | User-defined exhibit identifier |
| filename | Name of the processed file |
| filepath | Full path to the file |
| size_bytes | File size in bytes |
| size_mb | File size in megabytes |
| ed2k_hash | ED2K hash (main eMule identifier) |
| aich_hash | AICH root hash |
| num_chunks | Number of 9.28MB chunks |
| chunk_X_hash | Individual chunk hashes (if applicable) |
| status | Processing status (Success/Error) |

### Example Output

```csv
exhibit,filename,filepath,size_bytes,size_mb,ed2k_hash,aich_hash,num_chunks,status
CASE001_HD1,document.pdf,/evidence/document.pdf,5242880,5.0,A1B2C3D4...,E5F6G7H8...,1,Success
```

## 🔬 Technical Details

### ED2K Hash Algorithm

- **Files ≤ 9.28MB**: MD4 hash of entire file content
- **Files > 9.28MB**: MD4 hash of concatenated chunk MD4 hashes
- **Chunk size**: 9,728,000 bytes (9.28 MB)

### AICH Hash Algorithm

- Binary hash tree using SHA-1
- Block size: 180 KB (184,320 bytes)
- Used for advanced corruption recovery in eMule

## 🛠️ Verification

Test the MD4 implementation:

```bash
python foremhash.py --test-md4
```

Expected output:
```
Testing MD4 implementation...
MD4 hash of test string: 1BEE69A46BA811185C194762ABAEAE90
Expected: 1BEE69A46BA811185C194762ABAEAE90
✓ MD4 implementation working correctly!
```

## 🐛 Troubleshooting

### MD4 Hash Not Available

```bash
# Install pycryptodome
pip install pycryptodome --upgrade
```

### PyQt5 Import Error

```bash
# For Ubuntu/Debian
sudo apt-get install python3-pyqt5

# For others
pip install PyQt5
```

### Permission Denied

- Windows: Run as Administrator
- Linux/Mac: Check file permissions with `ls -la`

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes:

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📜 License

This project is licensed under the GNU License - see the [LICENSE](LICENSE) file for details.

## ⚖️ Legal Notice

ForEmHash is designed for legitimate forensic analysis and law enforcement purposes. Users are responsible for compliance with applicable laws and regulations regarding digital evidence handling in their jurisdiction.

## 📊 Performance

| File Size | Processing Time* | Memory Usage |
|-----------|-----------------|--------------|
| 100 MB | ~2 seconds | ~150 MB |
| 1 GB | ~20 seconds | ~200 MB |
| 10 GB | ~3 minutes | ~250 MB |

*Performance varies based on hardware and storage type
