#!/usr/bin/env python3
"""
eMule Forensics Hash Calculator
Calculates eMule hashes (ED2K/ICH/AICH) for forensic analysis
Supports both CLI and GUI (PyQt5) interfaces
Includes pure Python MD4 implementation for compatibility
"""

import os
import sys
import csv
import argparse
import hashlib
import struct
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional, Tuple
import math

# Try to import PyQt5 for GUI support
try:
    from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                                 QHBoxLayout, QPushButton, QLabel, QLineEdit, 
                                 QTextEdit, QFileDialog, QProgressBar, QTableWidget,
                                 QTableWidgetItem, QHeaderView, QMessageBox)
    from PyQt5.QtCore import Qt, QThread, pyqtSignal
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False

# eMule chunk size constant
EMULE_CHUNK_SIZE = 9728000  # 9500 KB in bytes
AICH_BLOCK_SIZE = 184320    # 180 KB for AICH tree

class MD4:
    """Fallback MD4 - this is a placeholder that will suggest installing pycryptodome"""
    def __init__(self):
        raise ImportError(
            "MD4 is not available. Please install pycryptodome:\n"
            "pip install pycryptodome\n"
            "This will provide reliable MD4 support for eMule hash calculation."
        )

def get_md4():
    """Get MD4 hash object, trying multiple methods"""
    
    # Method 1: Try pycryptodome (most reliable)
    try:
        from Crypto.Hash import MD4 as PyCryptoMD4
        def create_md4_pycrypto():
            return PyCryptoMD4.new()
        # Test if it works
        test = create_md4_pycrypto()
        test.update(b'test')
        test.hexdigest()
        return create_md4_pycrypto
    except ImportError:
        pass
    
    # Method 2: Try standard hashlib (may not work on modern systems)
    try:
        md4 = hashlib.new('md4')
        md4.update(b'test')
        md4.hexdigest()
        return lambda: hashlib.new('md4')
    except:
        pass
    
    # Method 3: If all else fails, provide clear instructions
    def md4_not_available():
        raise ImportError(
            "\n" + "="*60 + "\n"
            "MD4 hash algorithm is not available!\n\n"
            "This is required for eMule hash calculation.\n"
            "Please install pycryptodome to fix this:\n\n"
            "  pip install pycryptodome\n\n"
            "After installation, run this script again.\n"
            + "="*60
        )
    
    return md4_not_available


class MD4Pure:
    """Simplified pure Python MD4 implementation"""
    
    def __init__(self):
        self.data = b''
    
    def update(self, data):
        """Accumulate data"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        self.data += data
    
    def _f(self, x, y, z):
        return (x & y) | (~x & z)
    
    def _g(self, x, y, z):
        return (x & y) | (x & z) | (y & z)
    
    def _h(self, x, y, z):
        return x ^ y ^ z
    
    def _rotleft(self, n, b):
        return ((n << b) | (n >> (32 - b))) & 0xffffffff
    
    def hexdigest(self):
        """Calculate MD4 hash"""
        # Initialize hash values
        h0 = 0x67452301
        h1 = 0xEFCDAB89
        h2 = 0x98BADCFE
        h3 = 0x10325476
        
        # Pre-processing
        msg = self.data
        msg_len = len(msg)
        msg += b'\x80'
        msg += b'\x00' * ((55 - msg_len) % 64)
        msg += struct.pack('<Q', msg_len * 8)
        
        # Process message in 512-bit chunks
        for offset in range(0, len(msg), 64):
            chunk = msg[offset:offset + 64]
            X = list(struct.unpack('<16I', chunk))
            
            # Initialize working variables
            A, B, C, D = h0, h1, h2, h3
            
            # Round 1
            for i in range(16):
                k = i
                if i % 4 == 0:
                    A = (A + self._f(B, C, D) + X[k]) & 0xffffffff
                    A = self._rotleft(A, 3)
                elif i % 4 == 1:
                    D = (D + self._f(A, B, C) + X[k]) & 0xffffffff
                    D = self._rotleft(D, 7)
                elif i % 4 == 2:
                    C = (C + self._f(D, A, B) + X[k]) & 0xffffffff
                    C = self._rotleft(C, 11)
                else:
                    B = (B + self._f(C, D, A) + X[k]) & 0xffffffff
                    B = self._rotleft(B, 19)
            
            # Round 2
            for i in range(16):
                k = (i % 4) * 4 + i // 4
                if i % 4 == 0:
                    A = (A + self._g(B, C, D) + X[k] + 0x5A827999) & 0xffffffff
                    A = self._rotleft(A, 3)
                elif i % 4 == 1:
                    D = (D + self._g(A, B, C) + X[k] + 0x5A827999) & 0xffffffff
                    D = self._rotleft(D, 5)
                elif i % 4 == 2:
                    C = (C + self._g(D, A, B) + X[k] + 0x5A827999) & 0xffffffff
                    C = self._rotleft(C, 9)
                else:
                    B = (B + self._g(C, D, A) + X[k] + 0x5A827999) & 0xffffffff
                    B = self._rotleft(B, 13)
            
            # Round 3
            indices = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
            for i in range(16):
                k = indices[i]
                if i % 4 == 0:
                    A = (A + self._h(B, C, D) + X[k] + 0x6ED9EBA1) & 0xffffffff
                    A = self._rotleft(A, 3)
                elif i % 4 == 1:
                    D = (D + self._h(A, B, C) + X[k] + 0x6ED9EBA1) & 0xffffffff
                    D = self._rotleft(D, 9)
                elif i % 4 == 2:
                    C = (C + self._h(D, A, B) + X[k] + 0x6ED9EBA1) & 0xffffffff
                    C = self._rotleft(C, 11)
                else:
                    B = (B + self._h(C, D, A) + X[k] + 0x6ED9EBA1) & 0xffffffff
                    B = self._rotleft(B, 15)
            
            # Update hash values
            h0 = (h0 + A) & 0xffffffff
            h1 = (h1 + B) & 0xffffffff
            h2 = (h2 + C) & 0xffffffff
            h3 = (h3 + D) & 0xffffffff
        
        # Produce final hash value
        return struct.pack('<4I', h0, h1, h2, h3).hex().upper()
    
    def digest(self):
        """Return binary digest"""
        return bytes.fromhex(self.hexdigest())

# Global MD4 factory
create_md4 = get_md4()

# Alternative: Install pycryptodome for reliable MD4 support
try:
    from Crypto.Hash import MD4 as PyCryptoMD4
    def create_md4_pycrypto():
        return PyCryptoMD4.new()
    # Test if it works
    test = create_md4_pycrypto()
    test.update(b'test')
    test.hexdigest()
    create_md4 = create_md4_pycrypto
    print("Using PyCryptodome MD4 implementation")
except ImportError:
    pass

class eMuleHashCalculator:
    """Core class for calculating eMule hashes"""
    
    def __init__(self):
        self.chunk_size = EMULE_CHUNK_SIZE
        self.aich_block_size = AICH_BLOCK_SIZE
    
    def calculate_ed2k_hash(self, filepath: str) -> Dict:
        """
        Calculate ED2K hash according to eMule specification
        For files <= 9.28MB: MD4 of file content
        For files > 9.28MB: MD4 of concatenated chunk MD4 hashes
        """
        file_size = os.path.getsize(filepath)
        chunk_hashes = []
        
        with open(filepath, 'rb') as f:
            # Calculate MD4 hash for each chunk
            while True:
                chunk = f.read(self.chunk_size)
                if not chunk:
                    break
                
                md4 = create_md4()
                md4.update(chunk)
                chunk_hash = md4.hexdigest().upper()
                chunk_hashes.append(chunk_hash)
        
        # Calculate final ED2K hash
        if len(chunk_hashes) == 1:
            # Single chunk file: ED2K hash is the chunk hash itself
            ed2k_hash = chunk_hashes[0]
        else:
            # Multiple chunks: ED2K hash is MD4 of concatenated chunk hashes
            combined = b''
            for chunk_hash in chunk_hashes:
                combined += bytes.fromhex(chunk_hash)
            
            md4 = create_md4()
            md4.update(combined)
            ed2k_hash = md4.hexdigest().upper()
        
        return {
            'ed2k_hash': ed2k_hash,
            'file_size': file_size,
            'num_chunks': len(chunk_hashes),
            'chunk_hashes': chunk_hashes
        }
    
    def calculate_aich_hash(self, filepath: str) -> str:
        """
        Calculate AICH (Advanced Intelligent Corruption Handling) root hash
        Uses SHA1 in a binary hash tree structure
        """
        file_size = os.path.getsize(filepath)
        
        # Calculate number of blocks and tree levels
        num_blocks = math.ceil(file_size / self.aich_block_size)
        
        # Read file and calculate SHA1 for each 180KB block (leaf level)
        leaf_hashes = []
        with open(filepath, 'rb') as f:
            while True:
                block = f.read(self.aich_block_size)
                if not block:
                    break
                
                sha1 = hashlib.sha1()
                sha1.update(block)
                leaf_hashes.append(sha1.digest())
        
        # Build hash tree from bottom up
        if len(leaf_hashes) == 1:
            # Single block file
            return leaf_hashes[0].hex().upper()
        
        # Build tree levels
        current_level = leaf_hashes
        while len(current_level) > 1:
            next_level = []
            
            # Process pairs of hashes
            for i in range(0, len(current_level), 2):
                sha1 = hashlib.sha1()
                
                if i + 1 < len(current_level):
                    # Hash pair of nodes
                    sha1.update(current_level[i])
                    sha1.update(current_level[i + 1])
                else:
                    # Odd number - last hash stands alone
                    sha1.update(current_level[i])
                
                next_level.append(sha1.digest())
            
            current_level = next_level
        
        # Root hash is the final remaining hash
        return current_level[0].hex().upper()
    
    def process_file(self, filepath: str, exhibit_name: str) -> Dict:
        """Process a single file and return all hash information"""
        try:
            filename = os.path.basename(filepath)
            
            # Calculate ED2K and chunk hashes
            ed2k_result = self.calculate_ed2k_hash(filepath)
            
            # Calculate AICH hash
            aich_hash = self.calculate_aich_hash(filepath)
            
            # Prepare result dictionary
            result = {
                'exhibit': exhibit_name,
                'filename': filename,
                'filepath': filepath,
                'size_bytes': ed2k_result['file_size'],
                'size_mb': round(ed2k_result['file_size'] / (1024 * 1024), 2),
                'ed2k_hash': ed2k_result['ed2k_hash'],
                'aich_hash': aich_hash,
                'num_chunks': ed2k_result['num_chunks'],
                'status': 'Success'
            }
            
            # Add individual chunk hashes
            for i, chunk_hash in enumerate(ed2k_result['chunk_hashes']):
                result[f'chunk_{i}_hash'] = chunk_hash
            
            return result
            
        except Exception as e:
            return {
                'exhibit': exhibit_name,
                'filename': os.path.basename(filepath),
                'filepath': filepath,
                'status': f'Error: {str(e)}'
            }
    
    def process_directory(self, directory: str, exhibit_name: str, 
                         progress_callback=None) -> List[Dict]:
        """Process all files in a directory"""
        results = []
        files = []
        
        # Collect all files
        for root, _, filenames in os.walk(directory):
            for filename in filenames:
                files.append(os.path.join(root, filename))
        
        total_files = len(files)
        
        # Process each file
        for idx, filepath in enumerate(files):
            if progress_callback:
                progress_callback(idx + 1, total_files, os.path.basename(filepath))
            
            result = self.process_file(filepath, exhibit_name)
            results.append(result)
        
        return results
    
    def export_to_csv(self, results: List[Dict], output_path: str):
        """Export results to CSV file"""
        if not results:
            return
        
        # Determine all unique keys
        all_keys = set()
        for result in results:
            all_keys.update(result.keys())
        
        # Define column order
        primary_cols = ['exhibit', 'filename', 'filepath', 'size_bytes', 'size_mb', 
                       'ed2k_hash', 'aich_hash', 'num_chunks', 'status']
        
        # Get chunk columns in order
        chunk_cols = sorted([k for k in all_keys if k.startswith('chunk_')])
        
        # Combine columns
        fieldnames = [col for col in primary_cols if col in all_keys]
        fieldnames.extend(chunk_cols)
        
        # Write CSV
        with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(results)

# GUI Components
if GUI_AVAILABLE:
    class HashWorkerThread(QThread):
        """Worker thread for hash calculations"""
        progress = pyqtSignal(int, int, str)
        finished = pyqtSignal(list)
        
        def __init__(self, path, exhibit_name):
            super().__init__()
            self.path = path
            self.exhibit_name = exhibit_name
            self.calculator = eMuleHashCalculator()
        
        def run(self):
            """Run hash calculations in background thread"""
            if os.path.isfile(self.path):
                self.progress.emit(1, 1, os.path.basename(self.path))
                result = self.calculator.process_file(self.path, self.exhibit_name)
                results = [result]
            else:
                results = self.calculator.process_directory(
                    self.path, 
                    self.exhibit_name,
                    lambda curr, total, name: self.progress.emit(curr, total, name)
                )
            
            self.finished.emit(results)
    
    class eMuleForensicsGUI(QMainWindow):
        """Main GUI window for eMule Forensics Tool"""
        
        def __init__(self):
            super().__init__()
            self.calculator = eMuleHashCalculator()
            self.results = []
            self.init_ui()
        
        def init_ui(self):
            """Initialize the user interface"""
            self.setWindowTitle('ForEmHash v. 0.1')
            self.setGeometry(100, 100, 900, 600)
            
            # Central widget and main layout
            central_widget = QWidget()
            self.setCentralWidget(central_widget)
            layout = QVBoxLayout(central_widget)
            
            # Input section
            input_group = QWidget()
            input_layout = QVBoxLayout(input_group)
            
            # Exhibit name
            exhibit_layout = QHBoxLayout()
            exhibit_layout.addWidget(QLabel('Exhibit Name:'))
            self.exhibit_input = QLineEdit()
            self.exhibit_input.setPlaceholderText('e.g., CASE001_HD1')
            exhibit_layout.addWidget(self.exhibit_input)
            input_layout.addLayout(exhibit_layout)
            
            # File/Directory selection
            path_layout = QHBoxLayout()
            path_layout.addWidget(QLabel('Input Path:'))
            self.path_input = QLineEdit()
            self.path_input.setReadOnly(True)
            path_layout.addWidget(self.path_input)
            
            self.select_file_btn = QPushButton('Select File')
            self.select_file_btn.clicked.connect(self.select_file)
            path_layout.addWidget(self.select_file_btn)
            
            self.select_dir_btn = QPushButton('Select Directory')
            self.select_dir_btn.clicked.connect(self.select_directory)
            path_layout.addWidget(self.select_dir_btn)
            
            input_layout.addLayout(path_layout)
            
            # Output directory selection
            output_layout = QHBoxLayout()
            output_layout.addWidget(QLabel('Output Directory:'))
            self.output_input = QLineEdit()
            self.output_input.setReadOnly(True)
            output_layout.addWidget(self.output_input)
            
            self.select_output_btn = QPushButton('Select Output')
            self.select_output_btn.clicked.connect(self.select_output)
            output_layout.addWidget(self.select_output_btn)
            
            input_layout.addLayout(output_layout)
            
            layout.addWidget(input_group)
            
            # Process button
            self.process_btn = QPushButton('Calculate Hashes')
            self.process_btn.clicked.connect(self.process_files)
            self.process_btn.setStyleSheet('QPushButton { font-weight: bold; padding: 10px; }')
            layout.addWidget(self.process_btn)
            
            # Progress bar
            self.progress_bar = QProgressBar()
            self.progress_bar.setVisible(False)
            layout.addWidget(self.progress_bar)
            
            self.status_label = QLabel('')
            layout.addWidget(self.status_label)
            
            # Results table
            self.results_table = QTableWidget()
            self.results_table.setAlternatingRowColors(True)
            layout.addWidget(self.results_table)
            
            # Export button
            self.export_btn = QPushButton('Export to CSV')
            self.export_btn.clicked.connect(self.export_results)
            self.export_btn.setEnabled(False)
            layout.addWidget(self.export_btn)
        
        def select_file(self):
            """Select a single file for processing"""
            filepath, _ = QFileDialog.getOpenFileName(self, 'Select File')
            if filepath:
                self.path_input.setText(filepath)
        
        def select_directory(self):
            """Select a directory for processing"""
            directory = QFileDialog.getExistingDirectory(self, 'Select Directory')
            if directory:
                self.path_input.setText(directory)
        
        def select_output(self):
            """Select output directory for CSV"""
            directory = QFileDialog.getExistingDirectory(self, 'Select Output Directory')
            if directory:
                self.output_input.setText(directory)
        
        def process_files(self):
            """Start processing files"""
            # Validate inputs
            if not self.exhibit_input.text():
                QMessageBox.warning(self, 'Warning', 'Please enter an exhibit name')
                return
            
            if not self.path_input.text():
                QMessageBox.warning(self, 'Warning', 'Please select a file or directory')
                return
            
            if not self.output_input.text():
                QMessageBox.warning(self, 'Warning', 'Please select an output directory')
                return
            
            # Disable controls during processing
            self.process_btn.setEnabled(False)
            self.export_btn.setEnabled(False)
            self.progress_bar.setVisible(True)
            
            # Start worker thread
            self.worker = HashWorkerThread(
                self.path_input.text(),
                self.exhibit_input.text()
            )
            self.worker.progress.connect(self.update_progress)
            self.worker.finished.connect(self.processing_finished)
            self.worker.start()
        
        def update_progress(self, current, total, filename):
            """Update progress bar and status"""
            self.progress_bar.setMaximum(total)
            self.progress_bar.setValue(current)
            self.status_label.setText(f'Processing: {filename} ({current}/{total})')
        
        def processing_finished(self, results):
            """Handle completion of processing"""
            self.results = results
            self.display_results()
            
            # Re-enable controls
            self.process_btn.setEnabled(True)
            self.export_btn.setEnabled(True)
            self.progress_bar.setVisible(False)
            self.status_label.setText(f'Completed: {len(results)} files processed')
            
            # Auto-export if output directory is set
            if self.output_input.text():
                self.export_results()
        
        def display_results(self):
            """Display results in the table"""
            if not self.results:
                return
            
            # Setup table
            display_cols = ['exhibit', 'filename', 'size_mb', 'ed2k_hash', 'aich_hash', 'status']
            self.results_table.setColumnCount(len(display_cols))
            self.results_table.setHorizontalHeaderLabels(display_cols)
            self.results_table.setRowCount(len(self.results))
            
            # Populate table
            for row, result in enumerate(self.results):
                for col, key in enumerate(display_cols):
                    value = str(result.get(key, ''))
                    item = QTableWidgetItem(value)
                    item.setFlags(item.flags() & ~Qt.ItemIsEditable)
                    self.results_table.setItem(row, col, item)
            
            # Adjust column widths
            self.results_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        
        def export_results(self):
            """Export results to CSV"""
            if not self.results:
                QMessageBox.warning(self, 'Warning', 'No results to export')
                return
            
            # Generate filename with timestamp
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            exhibit = self.exhibit_input.text().replace(' ', '_')
            filename = f'{exhibit}_emule_hashes_{timestamp}.csv'
            
            output_path = os.path.join(self.output_input.text(), filename)
            
            try:
                self.calculator.export_to_csv(self.results, output_path)
                QMessageBox.information(self, 'Success', f'Results exported to:\n{output_path}')
            except Exception as e:
                QMessageBox.critical(self, 'Error', f'Failed to export: {str(e)}')

def cli_main():
    """Command-line interface main function"""
    parser = argparse.ArgumentParser(
        description='eMule Forensics Hash Calculator - Calculate ED2K/AICH hashes for forensic analysis',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s -e CASE001_HD1 -i /path/to/files -o /output/dir
  %(prog)s -e EXHIBIT_A -i /path/to/file.dat -o /output/dir
  %(prog)s --gui  # Launch GUI interface (requires PyQt5)
        '''
    )
    
    parser.add_argument('--gui', action='store_true',
                       help='Launch GUI interface (requires PyQt5)')
    parser.add_argument('-e', '--exhibit', type=str,
                       help='Exhibit name/identifier')
    parser.add_argument('-i', '--input', type=str,
                       help='Input file or directory path')
    parser.add_argument('-o', '--output', type=str,
                       help='Output directory for CSV file')
    parser.add_argument('--test-md4', action='store_true',
                       help='Test MD4 implementation')
    
    args = parser.parse_args()
    
    # Test MD4 if requested
    if args.test_md4:
        print("Testing MD4 implementation...")
        try:
            test_data = b'The quick brown fox jumps over the lazy dog'
            md4 = create_md4()
            md4.update(test_data)
            result = md4.hexdigest().upper()
            print(f"MD4 hash of test string: {result}")
            print(f"Expected: 1BEE69A46BA811185C194762ABAEAE90")
            if result == "1BEE69A46BA811185C194762ABAEAE90":
                print("✓ MD4 implementation working correctly!")
            else:
                print("✗ MD4 implementation error!")
                print("\nPlease install pycryptodome for reliable MD4 support:")
                print("  pip install pycryptodome")
        except ImportError as e:
            print(str(e))
        sys.exit(0)
    
    # Launch GUI if requested
    if args.gui:
        if not GUI_AVAILABLE:
            print("Error: PyQt5 is not installed. Install with: pip install PyQt5")
            sys.exit(1)
        
        app = QApplication(sys.argv)
        window = eMuleForensicsGUI()
        window.show()
        sys.exit(app.exec_())
    
    # CLI mode - validate arguments
    if not all([args.exhibit, args.input, args.output]):
        parser.print_help()
        print("\nError: In CLI mode, --exhibit, --input, and --output are required")
        sys.exit(1)
    
    # Validate paths
    if not os.path.exists(args.input):
        print(f"Error: Input path does not exist: {args.input}")
        sys.exit(1)
    
    if not os.path.exists(args.output):
        print(f"Error: Output directory does not exist: {args.output}")
        sys.exit(1)
    
    # Process files
    print(f"eMule Forensics Hash Calculator")
    print(f"{'=' * 50}")
    print(f"Exhibit: {args.exhibit}")
    print(f"Input: {args.input}")
    print(f"Output: {args.output}")
    
    # Check MD4 implementation
    try:
        test_md4 = create_md4()
        test_md4.update(b'test')
        test_md4.hexdigest()
        print(f"MD4 Implementation: Ready")
    except ImportError:
        print(f"MD4 Implementation: NOT AVAILABLE")
        print("\nERROR: MD4 is required for eMule hash calculation!")
        print("Please install pycryptodome:")
        print("  pip install pycryptodome")
        sys.exit(1)
    
    print(f"{'=' * 50}\n")
    
    calculator = eMuleHashCalculator()
    
    if os.path.isfile(args.input):
        print(f"Processing single file: {os.path.basename(args.input)}")
        results = [calculator.process_file(args.input, args.exhibit)]
    else:
        print(f"Processing directory...")
        results = calculator.process_directory(
            args.input, 
            args.exhibit,
            lambda curr, total, name: print(f"  [{curr}/{total}] {name}")
        )
    
    # Generate output filename
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    exhibit_clean = args.exhibit.replace(' ', '_')
    output_file = os.path.join(args.output, f'{exhibit_clean}_emule_hashes_{timestamp}.csv')
    
    # Export results
    calculator.export_to_csv(results, output_file)
    
    # Print summary
    print(f"\n{'=' * 50}")
    print(f"Processing complete!")
    print(f"Files processed: {len(results)}")
    errors = sum(1 for r in results if 'Error' in r.get('status', ''))
    if errors:
        print(f"Errors: {errors}")
    print(f"Output saved to: {output_file}")

if __name__ == '__main__':
    cli_main()
