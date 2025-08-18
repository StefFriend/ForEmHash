#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Known.met / Known2.met Analyzer for ForEmHash (AICH-fixed version)
Gestisce correttamente i diversi formati AICH nei file known.met
"""

import os
import sys
import csv
import struct
import argparse
import base64
from datetime import datetime
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Set, Optional

# ----------------------------------------------------------------------------------------------------------------------
# Parser known.met con gestione AICH migliorata
# ----------------------------------------------------------------------------------------------------------------------

class KnownMetParser:
    """
    Parser robusto per eMule known.met / known2.met con gestione corretta AICH
    """

    # Header attesi
    MET_HEADER          = 0x0E
    MET_HEADER_I64TAGS  = 0x0F

    # Tipi di tag
    TAGTYPE_INVALID   = 0x00
    TAGTYPE_HASH16    = 0x01
    TAGTYPE_STRING    = 0x02
    TAGTYPE_UINT32    = 0x03
    TAGTYPE_FLOAT32   = 0x04
    TAGTYPE_BOOL      = 0x05
    TAGTYPE_BOOLARRAY = 0x06
    TAGTYPE_BLOB      = 0x07
    TAGTYPE_UINT16    = 0x08
    TAGTYPE_UINT8     = 0x09
    TAGTYPE_BSOB      = 0x0A
    TAGTYPE_UINT64    = 0x0B
    TAGTYPE_STR1      = 0x11
    TAGTYPE_STR2      = 0x12
    TAGTYPE_STR3      = 0x13
    TAGTYPE_STR16     = 0x12  # alias

    # ID noti
    FT_FILENAME = 'ID_01'
    FT_FILESIZE = 'ID_02'
    FT_FILETYPE = 'ID_03'
    FT_LASTSEEN = 'ID_05'
    FT_TRANSFER = 'ID_08'
    FT_SOURCES  = 'ID_15'
    FT_AICH     = 'ID_27'  # AICH hash
    FT_CPLSRC   = 'ID_30'

    def __init__(self, filepath: str, verbose: bool = False, max_tags_limit: int = 10000):
        self.filepath = filepath
        self.verbose = verbose
        self.max_tags_limit = max_tags_limit
        self.exhibit_name = self._extract_exhibit_name(filepath)
        self.files: List[Dict] = []

    def _extract_exhibit_name(self, filepath: str) -> str:
        filename = os.path.basename(filepath)
        low = filename.lower()
        if '_known.met' in low:
            return low.replace('_known.met', '').upper()
        elif 'known2.met' in low or 'known.met' in low:
            dir_name = os.path.basename(os.path.dirname(filepath))
            return dir_name.upper() if dir_name else 'UNKNOWN'
        return 'UNKNOWN'

    def _tell(self, f): return f.tell()

    def _remaining(self, f):
        cur = f.tell()
        f.seek(0, os.SEEK_END)
        end = f.tell()
        f.seek(cur, os.SEEK_SET)
        return end - cur

    def _read_exact(self, f, n: int, what: str = "data") -> bytes:
        data = f.read(n)
        if len(data) != n:
            raise EOFError(f"Unexpected EOF at offset {self._tell(f)}")
        return data

    def read_uint8(self, f):  return struct.unpack('<B', self._read_exact(f, 1, "uint8"))[0]
    def read_uint16(self, f): return struct.unpack('<H', self._read_exact(f, 2, "uint16"))[0]
    def read_uint32(self, f): return struct.unpack('<I', self._read_exact(f, 4, "uint32"))[0]
    def read_uint64(self, f): return struct.unpack('<Q', self._read_exact(f, 8, "uint64"))[0]
    def read_hash16(self, f): return self._read_exact(f, 16, "HASH16")
    def read_hash128_hex(self, f): return self._read_exact(f, 16, "MD4").hex().upper()

    def read_string(self, f, length=None, kind="STRING"):
        if length is None:
            length = self.read_uint16(f)
        if length == 0:
            return ""
        if self._remaining(f) < length:
            raise EOFError(f"Unexpected EOF while reading {kind}")
        return self._read_exact(f, length, kind).decode('utf-8', errors='ignore')

    def read_bsob(self, f):
        blen = self.read_uint16(f)
        if blen == 0:
            return b""
        if self._remaining(f) < blen:
            raise EOFError(f"Unexpected EOF while reading BSOB")
        return self._read_exact(f, blen, "BSOB")

    def read_blob(self, f):
        blen = self.read_uint32(f)
        if blen == 0:
            return b""
        if self._remaining(f) < blen:
            raise EOFError(f"Unexpected EOF while reading BLOB")
        return self._read_exact(f, blen, "BLOB")

    def _bytes_to_base32(self, data: bytes) -> str:
        """Converte bytes in Base32 senza padding (formato eMule)"""
        return base64.b32encode(data).decode('ascii').rstrip('=')

    def _normalize_aich(self, tag_value, tag_type: int) -> str:
        """
        Normalizza l'AICH in Base32 indipendentemente dal formato di storage
        
        eMule può salvare AICH come:
        - STRING (Base32)
        - HASH16 (20 bytes SHA1 binario) 
        - BLOB (20 bytes SHA1 binario)
        """
        if tag_type == self.TAGTYPE_STRING:
            # Già in Base32
            if isinstance(tag_value, str):
                # Rimuovi eventuali padding e normalizza
                return tag_value.upper().rstrip('=')
            else:
                return str(tag_value).upper().rstrip('=')
                
        elif tag_type == self.TAGTYPE_HASH16:
            # 16 bytes binari (ma AICH è SHA1 quindi 20 bytes - possibile troncamento)
            if isinstance(tag_value, str):
                # È già hex, convertiamo in bytes poi Base32
                try:
                    data = bytes.fromhex(tag_value)
                    return self._bytes_to_base32(data)
                except:
                    return tag_value
            elif isinstance(tag_value, bytes):
                return self._bytes_to_base32(tag_value)
                
        elif tag_type == self.TAGTYPE_BLOB or tag_type == self.TAGTYPE_BSOB:
            # SHA1 binario (20 bytes)
            if isinstance(tag_value, bytes) and len(tag_value) == 20:
                return self._bytes_to_base32(tag_value)
            elif isinstance(tag_value, bytes):
                # Potrebbe essere già Base32 encoded come bytes
                try:
                    decoded_str = tag_value.decode('ascii')
                    # Verifica se sembra Base32
                    if all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=' for c in decoded_str.upper()):
                        return decoded_str.upper().rstrip('=')
                    else:
                        # Non è Base32, assumiamo sia binario
                        return self._bytes_to_base32(tag_value)
                except:
                    return self._bytes_to_base32(tag_value)
        
        # Fallback: prova a convertire comunque
        if isinstance(tag_value, bytes):
            if len(tag_value) == 20:  # SHA1 binary
                return self._bytes_to_base32(tag_value)
            else:
                try:
                    # Potrebbe essere Base32 come bytes
                    return tag_value.decode('ascii').upper().rstrip('=')
                except:
                    return tag_value.hex().upper()
        else:
            return str(tag_value).upper().rstrip('=')

    def read_tag(self, f):
        start_off = self._tell(f)
        tag_type = self.read_uint8(f)
        original_tag_type = tag_type  # Salviamo il tipo originale

        # Nome / ID
        if tag_type & 0x80:
            tag_type &= 0x7F
            tag_name = f"ID_{self.read_uint8(f):02X}"
        else:
            name_len = self.read_uint16(f)
            if name_len == 1:
                tag_name = f"ID_{self.read_uint8(f):02X}"
            else:
                tag_name = self.read_string(f, name_len, kind="TAGNAME")

        # Valore
        tag_value = None
        if tag_type == self.TAGTYPE_INVALID:
            return tag_name, None, tag_type
        elif tag_type == self.TAGTYPE_HASH16:
            tag_value = self.read_hash16(f)
        elif tag_type == self.TAGTYPE_STRING:
            tag_value = self.read_string(f, None, kind="STRING")
        elif tag_type == self.TAGTYPE_UINT32:
            tag_value = self.read_uint32(f)
        elif tag_type == self.TAGTYPE_FLOAT32:
            tag_value = struct.unpack('<f', self._read_exact(f, 4, "FLOAT32"))[0]
        elif tag_type == self.TAGTYPE_BOOL:
            tag_value = self.read_uint8(f) != 0
        elif tag_type == self.TAGTYPE_UINT16:
            tag_value = self.read_uint16(f)
        elif tag_type == self.TAGTYPE_UINT8:
            tag_value = self.read_uint8(f)
        elif tag_type == self.TAGTYPE_UINT64:
            tag_value = self.read_uint64(f)
        elif tag_type == self.TAGTYPE_STR1:
            slen = self.read_uint8(f)
            tag_value = self.read_string(f, slen, kind="STR1")
        elif tag_type == self.TAGTYPE_STR2:
            slen = self.read_uint16(f)
            tag_value = self.read_string(f, slen, kind="STR2")
        elif tag_type == self.TAGTYPE_STR3:
            slen = self.read_uint32(f)
            tag_value = self.read_string(f, slen, kind="STR3")
        elif tag_type == self.TAGTYPE_BOOLARRAY:
            tag_value = self.read_blob(f)
        elif tag_type == self.TAGTYPE_BLOB:
            tag_value = self.read_blob(f)
        elif tag_type == self.TAGTYPE_BSOB:
            tag_value = self.read_bsob(f)
        else:
            # Tipo sconosciuto
            try:
                _ = self.read_bsob(f)
            except:
                try:
                    _ = self.read_blob(f)
                except:
                    raise ValueError(f"Unsupported tag type 0x{tag_type:X}")
            return tag_name, None, tag_type

        return tag_name, tag_value, tag_type

    def _peek_tag_count_plausible(self, f) -> Optional[int]:
        pos = self._tell(f)
        if self._remaining(f) < 4:
            return None
        raw = self._read_exact(f, 4, "peek_tag_count")
        tag_count = struct.unpack('<I', raw)[0]
        if 0 <= tag_count <= self.max_tags_limit and self._remaining(f) >= tag_count * 4:
            f.seek(pos, os.SEEK_SET)
            return tag_count
        f.seek(pos, os.SEEK_SET)
        return None

    def _try_hashset_schema(self, f, schema: int):
        start = self._tell(f)
        if schema == 1:
            filehash = self.read_hash16(f).hex().upper()
            part_cnt = self.read_uint16(f)
            if part_cnt * 16 > self._remaining(f):
                raise ValueError("schema1: part_cnt too large")
            if part_cnt:
                f.seek(part_cnt * 16, os.SEEK_CUR)
            if self._peek_tag_count_plausible(f) is None:
                raise ValueError("schema1: implausible tag_count")
            return filehash
        elif schema == 2:
            part_cnt = self.read_uint16(f)
            if part_cnt * 16 > self._remaining(f):
                raise ValueError("schema2: part_cnt too large")
            if part_cnt:
                f.seek(part_cnt * 16, os.SEEK_CUR)
            filehash = self.read_hash16(f).hex().upper()
            if self._peek_tag_count_plausible(f) is None:
                raise ValueError("schema2: implausible tag_count")
            return filehash
        elif schema == 3:
            filehash = self.read_hash16(f).hex().upper()
            if self._peek_tag_count_plausible(f) is None:
                raise ValueError("schema3: implausible tag_count")
            return filehash
        elif schema == 4:
            zero = self.read_uint16(f)
            if zero != 0:
                raise ValueError("schema4: expected 0 WORD")
            filehash = self.read_hash16(f).hex().upper()
            if self._peek_tag_count_plausible(f) is None:
                raise ValueError("schema4: implausible tag_count")
            return filehash
        else:
            raise ValueError("unknown schema")

    def _parse_hashset_flexible(self, f) -> str:
        entry_pos = self._tell(f)
        last_err = None
        for schema in (1, 2, 3, 4):
            try:
                f.seek(entry_pos, os.SEEK_SET)
                return self._try_hashset_schema(f, schema)
            except Exception as e:
                last_err = e
        raise ValueError(f"Failed to parse MD4 hashset at {entry_pos}: {last_err}")

    def parse(self) -> bool:
        any_ok = False
        try:
            with open(self.filepath, 'rb') as f:
                header = self.read_uint8(f)
                if header not in (self.MET_HEADER, self.MET_HEADER_I64TAGS):
                    if self.verbose:
                        print(f"[warn] Unexpected header 0x{header:02X} in {self.filepath}")
                num_files = self.read_uint32(f)

                if self.verbose:
                    print(f"[known] header=0x{header:02X}, entries={num_files}")

                for idx in range(num_files):
                    entry_start = self._tell(f)
                    file_entry = {
                        'exhibit': self.exhibit_name,
                        'source_file': os.path.basename(self.filepath)
                    }
                    try:
                        # 1) data (DWORD)
                        file_entry['entry_date_raw'] = self.read_uint32(f)

                        # 2) MD4 hashset
                        file_entry['ed2k_hash'] = self._parse_hashset_flexible(f)

                        # 3) numero tag
                        num_tags = self.read_uint32(f)
                        if num_tags > self.max_tags_limit:
                            raise ValueError(f"num_tags implausible: {num_tags}")

                        # 4) tag
                        for _ in range(num_tags):
                            tag_name, tag_value, tag_type = self.read_tag(f)
                            if not tag_name:
                                continue
                            
                            if tag_name == self.FT_FILENAME and isinstance(tag_value, str):
                                file_entry['filename'] = tag_value
                            elif tag_name == self.FT_FILESIZE:
                                file_entry['filesize'] = tag_value
                            elif tag_name == self.FT_AICH:
                                # Normalizza AICH in Base32
                                file_entry['aich_hash'] = self._normalize_aich(tag_value, tag_type)
                                if self.verbose:
                                    print(f"  AICH found (type={tag_type}): {file_entry['aich_hash'][:16]}...")
                            elif tag_name == self.FT_LASTSEEN:
                                file_entry['last_seen'] = tag_value
                            elif tag_name == self.FT_TRANSFER:
                                file_entry['transferred'] = tag_value
                            elif tag_name == self.FT_SOURCES:
                                file_entry['sources'] = tag_value
                            elif tag_name == self.FT_CPLSRC:
                                file_entry['complete_sources'] = tag_value

                        self.files.append(file_entry)
                        any_ok = True

                    except Exception as e:
                        if self.verbose:
                            print(f"[warn] Failed entry #{idx} at {entry_start}: {e}")
                        break

            return any_ok
        except Exception as e:
            print(f"Error parsing {self.filepath}: {e}")
            return False

    def get_hashes(self) -> Set[str]:
        return {f['ed2k_hash'] for f in self.files if 'ed2k_hash' in f}


# ----------------------------------------------------------------------------------------------------------------------
# Analyzer con comparazione AICH migliorata
# ----------------------------------------------------------------------------------------------------------------------

class KnownMetAnalyzer:
    """Match tra CSV (ForEmHash) e known.met/known2.met con gestione AICH corretta"""

    def __init__(self):
        self.csv_data: List[Dict] = []
        self.known_met_data: List[Dict] = []
        self.matches: List[Dict] = []
        self.statistics: Dict = {}

    def load_csv_files(self, csv_dir: str) -> int:
        csv_files = list(Path(csv_dir).glob('*.csv'))
        for csv_file in csv_files:
            print(f"Loading CSV: {csv_file.name}")
            try:
                with open(csv_file, 'r', encoding='utf-8') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        row['source_csv'] = csv_file.name
                        # Normalizza AICH dal CSV se presente
                        if 'aich_hash' in row and row['aich_hash']:
                            # Rimuovi padding e converti in maiuscolo
                            row['aich_hash'] = row['aich_hash'].upper().rstrip('=')
                        self.csv_data.append(row)
            except Exception as e:
                print(f"Error reading {csv_file}: {e}")
        return len(self.csv_data)

    def load_known_met_files(self, known_dir: str, verbose: bool = False) -> int:
        patterns = ['*known.met', '*known2.met']
        known_files = []
        for p in patterns:
            known_files.extend(Path(known_dir).glob(p))

        for known_file in known_files:
            print(f"Parsing known: {known_file.name}")
            parser = KnownMetParser(str(known_file), verbose=verbose)
            if parser.parse():
                self.known_met_data.extend(parser.files)
                print(f"  Found {len(parser.files)} entries in {known_file.name}")
            else:
                print(f"  Failed to parse {known_file.name}")
        return len(self.known_met_data)

    def analyze_matches(self):
        # Indicizza per ED2K
        known_hashes = defaultdict(list)
        for known_file in self.known_met_data:
            if 'ed2k_hash' in known_file:
                known_hashes[known_file['ed2k_hash']].append(known_file)

        matched_csv_files = []
        unmatched_csv_files = []
        aich_matches = 0
        aich_mismatches = 0

        for csv_row in self.csv_data:
            ed2k = csv_row.get('ed2k_hash') or csv_row.get('ed2k') or ''
            if ed2k and ed2k in known_hashes:
                for known_entry in known_hashes[ed2k]:
                    # Verifica match AICH
                    aich_csv = csv_row.get('aich_hash', '').upper().rstrip('=')
                    aich_known = known_entry.get('aich_hash', '').upper().rstrip('=')
                    
                    aich_match_status = 'N/A'
                    if aich_csv and aich_known:
                        if aich_csv == aich_known:
                            aich_match_status = 'MATCH'
                            aich_matches += 1
                        else:
                            aich_match_status = 'MISMATCH'
                            aich_mismatches += 1
                    
                    match = {
                        'ed2k_hash': ed2k,
                        'filename_csv': csv_row.get('filename', ''),
                        'filename_known': known_entry.get('filename', ''),
                        'filesize': csv_row.get('size_bytes', csv_row.get('filesize', '')),
                        'exhibit_csv': csv_row.get('exhibit', ''),
                        'exhibit_known': known_entry.get('exhibit', ''),
                        'source_csv': csv_row.get('source_csv', ''),
                        'source_known': known_entry.get('source_file', ''),
                        'sha1_hash': csv_row.get('sha1_hash', ''),
                        'aich_hash_csv': aich_csv,
                        'aich_hash_known': aich_known,
                        'aich_match': aich_match_status,
                        'last_seen': known_entry.get('last_seen', ''),
                        'sources': known_entry.get('sources', ''),
                        'complete_sources': known_entry.get('complete_sources', '')
                    }
                    self.matches.append(match)
                matched_csv_files.append(csv_row)
            else:
                unmatched_csv_files.append(csv_row)

        self.statistics = {
            'total_csv_files': len(self.csv_data),
            'total_known_files': len(self.known_met_data),
            'matched_files': len(matched_csv_files),
            'unmatched_files': len(unmatched_csv_files),
            'unique_matched_hashes': len(set(m['ed2k_hash'] for m in self.matches)),
            'match_percentage': (len(matched_csv_files) / len(self.csv_data) * 100) if self.csv_data else 0,
            'aich_matches': aich_matches,
            'aich_mismatches': aich_mismatches
        }

        # Cross-exhibit
        hash_exhibits = defaultdict(set)
        for match in self.matches:
            if match['exhibit_csv']:
                hash_exhibits[match['ed2k_hash']].add(match['exhibit_csv'])
            if match['exhibit_known']:
                hash_exhibits[match['ed2k_hash']].add(match['exhibit_known'])
        self.statistics['cross_exhibit_matches'] = sum(1 for ex in hash_exhibits.values() if len(ex) > 2)

        # Top 10
        hash_counts = defaultdict(int)
        for match in self.matches:
            hash_counts[match['ed2k_hash']] += 1
        if hash_counts:
            most_common = sorted(hash_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            self.statistics['most_common_files'] = [
                {
                    'hash': h,
                    'count': c,
                    'filename': next((m['filename_csv'] for m in self.matches if m['ed2k_hash'] == h), 'Unknown')
                }
                for h, c in most_common
            ]

    def export_results(self, output_dir: str):
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        os.makedirs(output_dir, exist_ok=True)

        # CSV dei match (con colonna aich_match)
        matched_csv = os.path.join(output_dir, f'known_met_matches_{timestamp}.csv')
        fieldnames = ['ed2k_hash', 'sha1_hash', 'filename_csv', 'filename_known',
                      'filesize', 'exhibit_csv', 'exhibit_known', 'source_csv',
                      'source_known', 'aich_hash_csv', 'aich_hash_known', 'aich_match',
                      'last_seen', 'sources', 'complete_sources']
        if self.matches:
            with open(matched_csv, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(self.matches)
            print(f"Exported matches: {matched_csv}")

        # CSV deduplicato
        unique_matches = {}
        for m in self.matches:
            unique_matches.setdefault(m['ed2k_hash'], m)
        dedup_csv = os.path.join(output_dir, f'known_met_unique_{timestamp}.csv')
        if unique_matches:
            with open(dedup_csv, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(unique_matches.values())
            print(f"Exported unique files: {dedup_csv}")

        # Statistiche TXT
        stats_file = os.path.join(output_dir, f'known_met_statistics_{timestamp}.txt')
        with open(stats_file, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("KNOWN.MET ANALYSIS REPORT\n")
            f.write("=" * 80 + "\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            f.write("OVERVIEW\n")
            f.write("-" * 40 + "\n")
            f.write(f"Total files in CSV inputs:     {self.statistics.get('total_csv_files', 0):,}\n")
            f.write(f"Total files in known.met:      {self.statistics.get('total_known_files', 0):,}\n")
            f.write(f"Matched files:                 {self.statistics.get('matched_files', 0):,}\n")
            f.write(f"Unmatched files:               {self.statistics.get('unmatched_files', 0):,}\n")
            f.write(f"Match percentage:              {self.statistics.get('match_percentage', 0):.2f}%\n")
            f.write(f"Unique matched hashes:         {self.statistics.get('unique_matched_hashes', 0):,}\n")
            f.write(f"AICH matches:                  {self.statistics.get('aich_matches', 0):,}\n")
            f.write(f"AICH mismatches:               {self.statistics.get('aich_mismatches', 0):,}\n")
            f.write(f"Cross-exhibit matches:         {self.statistics.get('cross_exhibit_matches', 0):,}\n\n")

            # Se ci sono AICH mismatch, avvisa
            if self.statistics.get('aich_mismatches', 0) > 0:
                f.write("WARNING: AICH MISMATCHES DETECTED\n")
                f.write("-" * 40 + "\n")
                f.write("Some files have matching ED2K but different AICH hashes.\n")
                f.write("This could indicate:\n")
                f.write("  - File corruption\n")
                f.write("  - Different file versions\n")
                f.write("  - AICH calculation differences\n\n")

            exhibit_matches = defaultdict(int)
            for match in self.matches:
                exhibit_matches[match.get('exhibit_csv', '')] += 1
            if exhibit_matches:
                f.write("MATCHES BY EXHIBIT\n")
                f.write("-" * 40 + "\n")
                for exhibit, count in sorted(exhibit_matches.items()):
                    if exhibit:
                        f.write(f"{exhibit}: {count:,} matches\n")
                f.write("\n")

            known_sources = defaultdict(int)
            for match in self.matches:
                known_sources[match.get('source_known', '')] += 1
            if known_sources:
                f.write("MATCHES BY KNOWN.MET SOURCE\n")
                f.write("-" * 40 + "\n")
                for source, count in sorted(known_sources.items()):
                    if source:
                        f.write(f"{source}: {count:,} matches\n")
                f.write("\n")

            if 'most_common_files' in self.statistics:
                f.write("TOP 10 MOST COMMON MATCHED FILES\n")
                f.write("-" * 40 + "\n")
                for i, info in enumerate(self.statistics['most_common_files'], 1):
                    f.write(f"{i}. {info['filename']}\n")
                    f.write(f"   Hash: {info['hash'][:16]}...\n")
                    f.write(f"   Occurrences: {info['count']}\n")
                f.write("\n")

            f.write("SUMMARY\n")
            f.write("-" * 40 + "\n")
            f.write(f"Analysis complete. {self.statistics.get('matched_files', 0)} files from forensic ")
            f.write(f"analysis were found in eMule known.met files.\n")
            mp = self.statistics.get('match_percentage', 0)
            if mp > 50:
                f.write("HIGH MATCH RATE: Significant overlap with eMule known files.\n")
            elif mp > 20:
                f.write("MODERATE MATCH RATE: Some files present in eMule known files.\n")
            else:
                f.write("LOW MATCH RATE: Few files found in eMule known files.\n")
            f.write("\n" + "=" * 80 + "\n")
            f.write("END OF REPORT\n")
            f.write("=" * 80 + "\n")
        print(f"Exported statistics: {stats_file}")


# ----------------------------------------------------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description='Known.met Analyzer (AICH-fixed) - Match ForEmHash outputs with eMule known.met/known2.met files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s -c ./csv_outputs -k ./known_dir -o ./analysis
  %(prog)s --csv-dir ./forensics/csv --known-dir ./evidence/emule -o ./results --verbose
        '''
    )
    parser.add_argument('-c', '--csv-dir', required=True, help='Directory contenente i CSV di ForEmHash')
    parser.add_argument('-k', '--known-dir', required=True, help='Directory con known.met / known2.met')
    parser.add_argument('-o', '--output', required=True, help='Directory di output')
    parser.add_argument('--verbose', action='store_true', help='Output verboso')

    args = parser.parse_args()

    if not os.path.isdir(args.csv_dir):
        print(f"Error: CSV directory not found: {args.csv_dir}")
        sys.exit(1)
    if not os.path.isdir(args.known_dir):
        print(f"Error: Known.met directory not found: {args.known_dir}")
        sys.exit(1)
    os.makedirs(args.output, exist_ok=True)

    print("=" * 80)
    print("KNOWN.MET ANALYZER FOR FOREMHASH (AICH-FIXED)")
    print("=" * 80)
    print(f"CSV Directory:    {args.csv_dir}")
    print(f"Known Directory:  {args.known_dir}")
    print(f"Output Directory: {args.output}")
    print("=" * 80 + "\n")

    analyzer = KnownMetAnalyzer()

    print("Step 1: Loading ForEmHash CSV files...")
    csv_count = analyzer.load_csv_files(args.csv_dir)
    print(f"  Loaded {csv_count} file records from CSV files\n")
    if csv_count == 0:
        print("Error: No CSV data loaded")
        sys.exit(1)

    print("Step 2: Loading known.met files...")
    known_count = analyzer.load_known_met_files(args.known_dir, verbose=args.verbose)
    print(f"  Loaded {known_count} file records from known.met files\n")
    if known_count == 0:
        print("Warning: No known.met data loaded")

    print("Step 3: Analyzing matches...")
    analyzer.analyze_matches()
    print(f"  Found {analyzer.statistics.get('matched_files', 0)} matches")
    print(f"  AICH matches: {analyzer.statistics.get('aich_matches', 0)}")
    print(f"  AICH mismatches: {analyzer.statistics.get('aich_mismatches', 0)}\n")

    print("Step 4: Exporting results...")
    analyzer.export_results(args.output)

    print("\n" + "=" * 80)
    print("ANALYSIS COMPLETE")
    print("=" * 80)
    print(f"Total CSV files:        {analyzer.statistics.get('total_csv_files', 0):,}")
    print(f"Total known.met files:  {analyzer.statistics.get('total_known_files', 0):,}")
    print(f"Matched files:          {analyzer.statistics.get('matched_files', 0):,}")
    print(f"Match percentage:       {analyzer.statistics.get('match_percentage', 0):.2f}%")
    print(f"Unique matches:         {analyzer.statistics.get('unique_matched_hashes', 0):,}")
    print(f"AICH status:            {analyzer.statistics.get('aich_matches', 0)} matches, "
          f"{analyzer.statistics.get('aich_mismatches', 0)} mismatches")
    print("\nResults saved to: " + args.output)
    print("=" * 80)

if __name__ == '__main__':
    main()