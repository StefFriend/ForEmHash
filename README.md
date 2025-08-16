# ForEmHash - Forensic eMule Hash Calculator

[![Python](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)
![License](https://img.shields.io/badge/License-GNU%20GPLv3-green)
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

## 🔄 CSV Merger Tool (foremhash_merger.py)

### Overview

When processing multiple exhibits, you'll generate multiple CSV files with varying column counts (due to different file sizes and chunk counts). The **foremhash_merger.py** tool merges these CSVs and identifies unique files across all exhibits.

### Key Features

- **Handles Variable Columns**: Automatically manages CSV files with different numbers of columns
- **Deduplication**: Identifies unique files based on ED2K hash
- **Statistics Generation**: Provides comprehensive analysis of file distribution
- **Cross-Exhibit Analysis**: Finds files that appear across multiple exhibits

### Usage

```bash
# Merge all CSV files in current directory
python foremhash_merger.py *.csv

# Merge specific files
python foremhash_merger.py exhibit1.csv exhibit2.csv exhibit3.csv

# Specify output directory
python foremhash_merger.py *.csv -o ./analysis_results
```

### Output Files

The merger generates three files with automatic timestamps:

1. **all_files_[timestamp].csv**
   - Complete merged data including all duplicates
   - All columns from all CSV files preserved
   - Empty cells for missing chunk columns

2. **unique_files_[timestamp].csv**
   - Deduplicated file list (one entry per unique ED2K hash)
   - If a file appears 10 times across exhibits, it's listed once
   - Essential for identifying unique evidence

3. **statistics_[timestamp].txt**
   - Comprehensive statistics report including:
     - Total files vs unique files
     - Duplication percentages
     - Size analysis (MB/GB)
     - Files per exhibit breakdown
     - Top 10 most duplicated files
     - Potential storage savings

### Example Statistics Report

```
========================================================================
FOREMHASH CSV MERGE STATISTICS REPORT
========================================================================
Generated: 2024-12-19 15:30:45

FILE COUNTS
----------------------------------------
Total files processed:     5,234
Unique files (deduplicated): 2,156
Duplicate instances:       3,078

PERCENTAGES
----------------------------------------
Unique files:    41.23%
Duplicate files: 58.77%

SIZE ANALYSIS
----------------------------------------
Total size (all files):      125,432.50 MB (122.49 GB)
Unique files size:           45,678.25 MB (44.61 GB)
Duplicate data size:         79,754.25 MB (77.88 GB)
Potential storage savings:   63.58% if deduplicated
```

### Complete Workflow Example

```bash
# Step 1: Process each exhibit separately
python foremhash.py -e EXHIBIT_001 -i /evidence/device1 -o ./reports
python foremhash.py -e EXHIBIT_002 -i /evidence/device2 -o ./reports
python foremhash.py -e EXHIBIT_003 -i /evidence/device3 -o ./reports

# Step 2: Merge all results and find unique files
python foremhash_merger.py ./reports/*.csv -o ./final_analysis

# Step 3: Review outputs
# - Check unique_files_*.csv for files that exist nowhere else
# - Review statistics_*.txt for overall analysis
# - Use all_files_*.csv for complete documentation
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

### Deduplication Logic

Files are considered identical if they share the same ED2K hash, regardless of:
- File name
- File path
- Exhibit location
- Number of occurrences

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

### CSV Merger Memory Issues

For very large datasets (thousands of files):
- Process CSV files in smaller batches
- Increase Python memory allocation
- Use a system with more RAM

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes:

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📜 License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## ⚖️ Legal Notice

ForEmHash is designed for legitimate forensic analysis and law enforcement purposes. Users are responsible for compliance with applicable laws and regulations regarding digital evidence handling in their jurisdiction.

## 📊 Performance

| File Size | Processing Time* | Memory Usage |
|-----------|-----------------|--------------|
| 100 MB | ~2 seconds | ~150 MB |
| 1 GB | ~20 seconds | ~200 MB |
| 10 GB | ~3 minutes | ~250 MB |

*Performance varies based on hardware and storage type

### CSV Merger Performance

| Number of CSV Files | Total Records | Processing Time* | Memory Usage |
|-------------------|---------------|-----------------|--------------|
| 10 | ~5,000 | ~1 second | ~100 MB |
| 50 | ~25,000 | ~5 seconds | ~300 MB |
| 100 | ~50,000 | ~12 seconds | ~500 MB |

*Performance varies based on file sizes and system specifications
