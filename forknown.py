"""
Known.met / Known2.met Analyzer for ForEmHash
"""

import os
import sys
import csv
import struct
import argparse
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Set, Optional, Any, DefaultDict

# ------------------------------- Utilities -------------------------------

def ts_to_iso(ts: Optional[int]) -> str:
    """Convert unix epoch seconds to ISO8601 Z. Returns '' for 0/None."""
    try:
        if not ts:
            return ""
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    except Exception:
        return ""

def fmt_bytes(n: int) -> str:
    """Human-readable bytes (B, KB, MB, GB, TB, PB)."""
    try:
        n = int(n)
    except Exception:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    i = 0
    v = float(n)
    while v >= 1024 and i < len(units) - 1:
        v /= 1024.0
        i += 1
    if i == 0:
        return f"{int(v)} {units[i]}"
    return f"{v:.2f} {units[i]}"

def bytes_to_mb_gb(n: int) -> str:
    """Return string 'XX.XX MB (YY.YY GB)' with dot thousands and comma decimals."""
    try:
        n = int(n)
    except Exception:
        n = 0
    mb = n / (1024.0 ** 2)
    gb = n / (1024.0 ** 3)
    return f"{mb:,.2f} MB ({gb:,.2f} GB)".replace(",", "X").replace(".", ",").replace("X", ".")

def to_int(x: Any) -> int:
    try:
        return int(x)
    except Exception:
        return 0

# ------------------------ known.met parser (extra fields) ------------------------

class KnownMetParser:
    """
    Robust parser for eMule known.met / known2.met.
    Extracts last_written (entry date), last_posted (max of Kad publish times), last_shared and bytes_uploaded.
    """

    MET_HEADER          = 0x0E
    MET_HEADER_I64TAGS  = 0x0F

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

    # Known tag IDs
    FT_FILENAME = 'ID_01'
    FT_FILESIZE = 'ID_02'
    FT_LASTSHARED = 'ID_34'              # uint32
    FT_KADLASTPUBLISHSRC   = 'ID_21'     # uint32
    FT_KADLASTPUBLISHNOTES = 'ID_26'     # uint32
    FT_ATTRANSFERRED_LO    = 'ID_50'     # uint32
    FT_ATTRANSFERRED_HI    = 'ID_54'     # uint32

    def __init__(self, filepath: str, verbose: bool = False, max_tags_limit: int = 10000):
        self.filepath = filepath
        self.verbose = verbose
        self.max_tags_limit = max_tags_limit
        self.exhibit_name = self._extract_exhibit_name(filepath)
        self.files: List[Dict[str, Any]] = []

    def _extract_exhibit_name(self, filepath: str) -> str:
        """Infer exhibit name from filename or parent directory."""
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
            raise EOFError(f"Unexpected EOF at offset {self._tell(f)} while reading {what}")
        return data

    def read_uint8(self, f):  return struct.unpack('<B', self._read_exact(f, 1, "uint8"))[0]
    def read_uint16(self, f): return struct.unpack('<H', self._read_exact(f, 2, "uint16"))[0]
    def read_uint32(self, f): return struct.unpack('<I', self._read_exact(f, 4, "uint32"))[0]
    def read_uint64(self, f): return struct.unpack('<Q', self._read_exact(f, 8, "uint64"))[0]
    def read_hash16(self, f): return self._read_exact(f, 16, "HASH16")

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

    def read_tag(self, f):
        """Read a tag with flexible name encoding and multiple value types."""
        start_off = self._tell(f)
        tag_type = self.read_uint8(f)

        # Name/ID
        if tag_type & 0x80:
            tag_type &= 0x7F
            tag_name = f"ID_{self.read_uint8(f):02X}"
        else:
            name_len = self.read_uint16(f)
            if name_len == 1:
                tag_name = f"ID_{self.read_uint8(f):02X}"
            else:
                tag_name = self.read_string(f, name_len, kind="TAGNAME")

        # Value
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
            # Skip unknown tag types by trying BSOB/BLOB heuristics
            try:
                _ = self.read_bsob(f)
            except:
                try:
                    _ = self.read_blob(f)
                except:
                    raise ValueError(f"Unsupported tag type 0x{tag_type:X} at {start_off}")
            return tag_name, None, tag_type

        return tag_name, tag_value, tag_type

    def _peek_tag_count_plausible(self, f) -> Optional[int]:
        """Heuristic to check if next 4 bytes plausibly represent a tag count."""
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

    def _try_hashset_schema(self, f, schema: int) -> str:
        """Try multiple known MD4-hashset layouts and return ED2K (hex)."""
        entry_pos = self._tell(f)
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
        """Attempt all MD4-hashset schemas until one fits; return ED2K (hex)."""
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
        """Parse known.met/known2.met file and populate self.files entries."""
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
                    file_entry: Dict[str, Any] = {
                        'exhibit': self.exhibit_name,
                        'source_file': os.path.basename(self.filepath)
                    }
                    try:
                        # 1) last_written (DWORD UTC)
                        entry_date_raw = self.read_uint32(f)
                        file_entry['last_written'] = ts_to_iso(entry_date_raw)
                        file_entry['entry_date_raw'] = entry_date_raw

                        # 2) Flexible MD4 hashset -> ED2K hex
                        file_entry['ed2k_hash'] = self._parse_hashset_flexible(f)

                        # 3) number of tags
                        num_tags = self.read_uint32(f)
                        if num_tags > self.max_tags_limit:
                            raise ValueError(f"num_tags implausible: {num_tags}")

                        # Temporary holders for bytes_uploaded and last_posted
                        bytes_lo, bytes_hi = None, None
                        kad_src, kad_notes = None, None

                        # 4) tags
                        for _ in range(num_tags):
                            tag_name, tag_value, tag_type = self.read_tag(f)
                            if not tag_name:
                                continue

                            if tag_name == self.FT_FILENAME and isinstance(tag_value, str):
                                file_entry['filename'] = tag_value
                            elif tag_name == self.FT_FILESIZE:
                                file_entry['filesize'] = tag_value
                            elif tag_name == self.FT_LASTSHARED:
                                file_entry['last_shared'] = ts_to_iso(tag_value)
                            elif tag_name == self.FT_KADLASTPUBLISHSRC:
                                kad_src = int(tag_value)
                            elif tag_name == self.FT_KADLASTPUBLISHNOTES:
                                kad_notes = int(tag_value)
                            elif tag_name == self.FT_ATTRANSFERRED_LO:
                                bytes_lo = int(tag_value)
                            elif tag_name == self.FT_ATTRANSFERRED_HI:
                                bytes_hi = int(tag_value)

                        # last_posted = max(kad_src, kad_notes)
                        if kad_src or kad_notes:
                            last_post = max(kad_src or 0, kad_notes or 0)
                            file_entry['last_posted'] = ts_to_iso(last_post)

                        # bytes_uploaded 64-bit
                        if bytes_lo is not None or bytes_hi is not None:
                            lo = bytes_lo or 0
                            hi = bytes_hi or 0
                            file_entry['bytes_uploaded'] = (hi << 32) | lo

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

# -------------------- Analyzer with intra/inter CSV dedup & stats --------------------

class KnownMetAnalyzer:
    """Match CSV (ForEmHash) with known.met, compute dedup stats, and export summary."""

    def __init__(self):
        self.csv_data: List[Dict[str, Any]] = []
        self.known_met_data: List[Dict[str, Any]] = []
        self.matches: List[Dict[str, Any]] = []
        self.statistics: Dict[str, Any] = {}
        self.csv_exhibits_by_ed2k: DefaultDict[str, Set[str]] = defaultdict(set)
        self.csv_unique_by_file: DefaultDict[str, Set[str]] = defaultdict(set)
        self.ed2k_to_csvfiles: DefaultDict[str, Set[str]] = defaultdict(set)

    def load_csv_files(self, csv_dir: str) -> int:
        """Load all CSVs, normalize ED2K, and collect per-file unique sets."""
        csv_files = list(Path(csv_dir).glob('*.csv'))
        for csv_file in csv_files:
            print(f"Loading CSV: {csv_file.name}")
            try:
                with open(csv_file, 'r', encoding='utf-8') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        row = dict(row)
                        row['source_csv'] = csv_file.name

                        # Normalize ED2K
                        if 'ed2k_hash' not in row and 'ed2k' in row:
                            row['ed2k_hash'] = (row.get('ed2k') or '').upper()
                        if 'ed2k_hash' in row and row['ed2k_hash']:
                            row['ed2k_hash'] = row['ed2k_hash'].upper()

                        ed2k = row.get('ed2k_hash', '').strip()
                        exhibit = (row.get('exhibit') or row.get('Exhibit') or '').strip()

                        if ed2k:
                            self.csv_unique_by_file[csv_file.name].add(ed2k)
                            self.ed2k_to_csvfiles[ed2k].add(csv_file.name)
                        if ed2k and exhibit:
                            self.csv_exhibits_by_ed2k[ed2k].add(exhibit)

                        self.csv_data.append(row)
            except Exception as e:
                print(f"Error reading {csv_file}: {e}")
        return len(self.csv_data)

    def load_known_met_files(self, known_dir: str, verbose: bool = False) -> int:
        """Parse all *known.met / *known2.met files in the directory."""
        patterns = ['*known.met', '*known2.met']
        known_files: List[Path] = []
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
        """Build matches by ED2K and compute all aggregate statistics."""
        # Index known entries by ED2K
        known_by_ed2k: DefaultDict[str, List[Dict[str, Any]]] = defaultdict(list)
        for known_entry in self.known_met_data:
            ed2k = known_entry.get('ed2k_hash')
            if ed2k:
                known_by_ed2k[ed2k].append(known_entry)

        matched_csv_files: List[Dict[str, Any]] = []
        unmatched_csv_files: List[Dict[str, Any]] = []

        # Create match rows (rep aggregates are joined with "-")
        for csv_row in self.csv_data:
            ed2k = (csv_row.get('ed2k_hash') or '').strip()
            if ed2k and ed2k in known_by_ed2k:
                exhibits_for_hash = sorted(self.csv_exhibits_by_ed2k.get(ed2k, set()))
                exhibit_agg = "-".join(exhibits_for_hash) if exhibits_for_hash else (csv_row.get('exhibit') or csv_row.get('Exhibit') or "")

                for known_entry in known_by_ed2k[ed2k]:
                    match = {
                        'ed2k_hash': ed2k,
                        'filename_csv': csv_row.get('filename', ''),
                        'filename_known': known_entry.get('filename', ''),
                        'filesize': csv_row.get('size_bytes', csv_row.get('filesize', '')),
                        'exhibit_csv': exhibit_agg,               # rep1-rep2-...
                        'exhibit_known': known_entry.get('exhibit', ''),
                        'source_csv': csv_row.get('source_csv', ''),
                        'source_known': known_entry.get('source_file', ''),
                        'last_written': known_entry.get('last_written', ''),
                        'last_posted': known_entry.get('last_posted', ''),
                        'last_shared': known_entry.get('last_shared', ''),
                        'bytes_uploaded': known_entry.get('bytes_uploaded', ''),
                    }
                    self.matches.append(match)
                matched_csv_files.append(csv_row)
            else:
                unmatched_csv_files.append(csv_row)

        # ---- Core counts ----
        total_csv_rows = len(self.csv_data)
        total_known_rows = len(self.known_met_data)
        matched_rows = len(matched_csv_files)
        unmatched_rows = len(unmatched_csv_files)

        # Global unique ED2K in CSVs
        csv_unique_global: Set[str] = set()
        for s in self.csv_unique_by_file.values():
            csv_unique_global |= s
        total_csv_unique = len(csv_unique_global)

        # Unique ED2K in known.met
        known_unique_global: Set[str] = {e['ed2k_hash'] for e in self.known_met_data if e.get('ed2k_hash')}
        total_known_unique = len(known_unique_global)

        # Unique matched ED2K
        matched_unique: Set[str] = {m['ed2k_hash'] for m in self.matches}
        total_matched_unique = len(matched_unique)

        # Match percentages
        pct_rows_matched = (matched_rows / total_csv_rows * 100) if total_csv_rows else 0.0
        pct_rows_unmatched = 100.0 - pct_rows_matched if total_csv_rows else 0.0
        pct_unique_matched = (total_matched_unique / total_csv_unique * 100) if total_csv_unique else 0.0
        pct_unique_unmatched = 100.0 - pct_unique_matched if total_csv_unique else 0.0

        # Intra-CSV dedup stats (per file)
        intra_csv_stats: List[Dict[str, Any]] = []
        for csv_name, unique_set in sorted(self.csv_unique_by_file.items()):
            rows_in_file = sum(1 for r in self.csv_data if r.get('source_csv') == csv_name)
            unique_count = len(unique_set)
            dup_count = rows_in_file - unique_count
            pct_dup = (dup_count / rows_in_file * 100) if rows_in_file else 0.0
            pct_unique = (unique_count / rows_in_file * 100) if rows_in_file else 0.0
            intra_csv_stats.append({
                'csv': csv_name,
                'rows': rows_in_file,
                'unique_ed2k': unique_count,
                'unique_rows_pct': pct_unique,       # will be printed after DupRows
                'duplicate_rows': dup_count,
                'duplicate_rows_pct': pct_dup
            })

        # Inter-CSV dedup (global)
        dup_global = total_csv_rows - total_csv_unique
        pct_dup_global = (dup_global / total_csv_rows * 100) if total_csv_rows else 0.0

        # Unique ED2K that appear in >= 2 different CSV files (cross-file overlap)
        overlap_multi_csv = sum(1 for ed2k, files in self.ed2k_to_csvfiles.items() if len(files) > 1)
        pct_overlap_multi_csv = (overlap_multi_csv / total_csv_unique * 100) if total_csv_unique else 0.0

        # Per-exhibit (matched): count unique matched ED2K per exhibit (from CSV)
        per_exhibit_counts: DefaultDict[str, int] = defaultdict(int)
        matched_set = { (r.get('source_csv'), (r.get('ed2k_hash') or '').strip(), (r.get('exhibit') or r.get('Exhibit') or '').strip())
                        for r in self.csv_data if (r.get('ed2k_hash') or '') in matched_unique }
        for _src, _ed2k, ex in matched_set:
            if ex:
                per_exhibit_counts[ex] += 1

        # Per known.met source file (on matches)
        per_known_source: DefaultDict[str, int] = defaultdict(int)
        for m in self.matches:
            src = m.get('source_known', '')
            if src:
                per_known_source[src] += 1

        # Top 10 most common matched ED2K (FULL hash)
        hash_counts: Dict[str, int] = defaultdict(int)
        for m in self.matches:
            hash_counts[m['ed2k_hash']] += 1
        top10 = sorted(hash_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        top10_list = [{'hash': h, 'count': c,
                       'filename': next((mm['filename_csv'] for mm in self.matches if mm['ed2k_hash'] == h and mm.get('filename_csv')), 'Unknown')}
                      for h, c in top10]

        # Bytes uploaded (raw and unique on matches)
        unique_matches: Dict[str, Dict[str, Any]] = {}
        for m in self.matches:
            unique_matches.setdefault(m['ed2k_hash'], m)

        bytes_total_matches = sum(to_int(m.get('bytes_uploaded', 0)) for m in self.matches)
        bytes_total_unique  = sum(to_int(m.get('bytes_uploaded', 0)) for m in unique_matches.values())

        # Temporal breakdown on unique matches
        def _year(s: str) -> Optional[str]:
            return s[:4] if isinstance(s, str) and len(s) >= 4 else None
        def _ym(s: str) -> Optional[str]:
            return s[:7] if isinstance(s, str) and len(s) >= 7 else None

        ls_year_count: DefaultDict[str, int] = defaultdict(int)
        ls_ym_count: DefaultDict[str, int] = defaultdict(int)
        lp_year_count: DefaultDict[str, int] = defaultdict(int)
        lp_ym_count: DefaultDict[str, int] = defaultdict(int)

        ls_year_bytes: DefaultDict[str, int] = defaultdict(int)
        ls_ym_bytes: DefaultDict[str, int] = defaultdict(int)
        lp_year_bytes: DefaultDict[str, int] = defaultdict(int)
        lp_ym_bytes: DefaultDict[str, int] = defaultdict(int)

        for um in unique_matches.values():
            bu = to_int(um.get('bytes_uploaded', 0))

            ls = um.get('last_shared') or ""
            y = _year(ls)
            if y:
                ls_year_count[y] += 1
                ls_year_bytes[y] += bu
            ym = _ym(ls)
            if ym:
                ls_ym_count[ym] += 1
                ls_ym_bytes[ym] += bu

            lp = um.get('last_posted') or ""
            y2 = _year(lp)
            if y2:
                lp_year_count[y2] += 1
                lp_year_bytes[y2] += bu
            ym2 = _ym(lp)
            if ym2:
                lp_ym_count[ym2] += 1
                lp_ym_bytes[ym2] += bu

        # ---------------- CSV-only stats (size & counts) ----------------
        total_size_bytes_all_rows = 0
        unique_size_map: Dict[str, int] = {}  # ed2k -> representative size (max seen)
        per_exhibit_csv_rows: DefaultDict[str, int] = defaultdict(int)
        per_exhibit_csv_unique: DefaultDict[str, Set[str]] = defaultdict(set)

        for row in self.csv_data:
            ex = (row.get('exhibit') or row.get('Exhibit') or '').strip()
            ed = (row.get('ed2k_hash') or '').strip()
            size = to_int(row.get('size_bytes') or row.get('filesize') or 0)

            total_size_bytes_all_rows += size
            if ed and (ed not in unique_size_map or size > unique_size_map[ed]):
                unique_size_map[ed] = size

            if ex:
                per_exhibit_csv_rows[ex] += 1
                if ed:
                    per_exhibit_csv_unique[ex].add(ed)

        total_size_bytes_unique = sum(unique_size_map.values())
        duplicate_size_bytes = max(0, total_size_bytes_all_rows - total_size_bytes_unique)
        potential_savings_pct = (duplicate_size_bytes / total_size_bytes_all_rows * 100) if total_size_bytes_all_rows else 0.0

        # CSV unique/duplicate counts
        csv_dup_instances = max(0, total_csv_rows - total_csv_unique)
        csv_pct_unique = (total_csv_unique / total_csv_rows * 100) if total_csv_rows else 0.0
        csv_pct_dup = 100.0 - csv_pct_unique if total_csv_rows else 0.0

        # Per-exhibit CSV (rows and unique ED2K)
        per_exhibit_csv_unique_counts = {ex: len(s) for ex, s in per_exhibit_csv_unique.items()}

        self.statistics = {
            'total_csv_rows': total_csv_rows,
            'total_known_rows': total_known_rows,
            'matched_rows': matched_rows,
            'unmatched_rows': unmatched_rows,
            'pct_rows_matched': pct_rows_matched,
            'pct_rows_unmatched': pct_rows_unmatched,

            'total_csv_unique': total_csv_unique,
            'total_known_unique': total_known_unique,
            'matched_unique': total_matched_unique,
            'unmatched_unique': total_csv_unique - total_matched_unique,
            'pct_unique_matched': pct_unique_matched,
            'pct_unique_unmatched': pct_unique_unmatched,

            'intra_csv_stats': intra_csv_stats,
            'dup_global_rows': dup_global,
            'pct_dup_global_rows': pct_dup_global,

            'overlap_multi_csv_unique': overlap_multi_csv,
            'pct_overlap_multi_csv_unique': pct_overlap_multi_csv,

            'per_exhibit_counts': dict(sorted(per_exhibit_counts.items())),
            'per_known_source': dict(sorted(per_known_source.items())),
            'top10': top10_list,

            'bytes_uploaded_total_matches': bytes_total_matches,
            'bytes_uploaded_total_unique': bytes_total_unique,

            'last_shared_by_year_count': dict(sorted(ls_year_count.items())),
            'last_shared_by_month_count': dict(sorted(ls_ym_count.items())),
            'last_posted_by_year_count': dict(sorted(lp_year_count.items())),
            'last_posted_by_month_count': dict(sorted(lp_ym_count.items())),

            'last_shared_by_year_bytes': {k: ls_year_bytes[k] for k in sorted(ls_year_bytes)},
            'last_shared_by_month_bytes': {k: ls_ym_bytes[k] for k in sorted(ls_ym_bytes)},
            'last_posted_by_year_bytes': {k: lp_year_bytes[k] for k in sorted(lp_year_bytes)},
            'last_posted_by_month_bytes': {k: lp_ym_bytes[k] for k in sorted(lp_ym_bytes)},

            # CSV-only
            'csv_file_counts_total': total_csv_rows,
            'csv_file_counts_unique': total_csv_unique,
            'csv_file_counts_duplicates': csv_dup_instances,
            'csv_pct_unique': csv_pct_unique,
            'csv_pct_duplicates': csv_pct_dup,

            'csv_total_size_bytes_all_rows': total_size_bytes_all_rows,
            'csv_total_size_bytes_unique': total_size_bytes_unique,
            'csv_duplicate_size_bytes': duplicate_size_bytes,
            'csv_potential_savings_pct': potential_savings_pct,

            'csv_files_per_exhibit_rows': dict(sorted(per_exhibit_csv_rows.items())),
            'csv_files_per_exhibit_unique': dict(sorted(per_exhibit_csv_unique_counts.items())),
        }

        # Cache unique matches for export
        self._unique_matches_cache = unique_matches

    def export_results(self, output_dir: str):
        """Export matches CSV, unique matches CSV, and the summary TXT."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        os.makedirs(output_dir, exist_ok=True)

        # Matches CSV
        matched_csv = os.path.join(output_dir, f'known_met_matches_{timestamp}.csv')
        fieldnames = [
            'ed2k_hash', 'filename_csv', 'filename_known', 'filesize',
            'exhibit_csv', 'exhibit_known', 'source_csv', 'source_known',
            'last_written', 'last_posted', 'last_shared', 'bytes_uploaded'
        ]
        if self.matches:
            with open(matched_csv, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(self.matches)
            print(f"Exported matches: {matched_csv}")

        # Unique matches CSV (one per ED2K)
        unique_matches = getattr(self, '_unique_matches_cache', {})
        dedup_csv = os.path.join(output_dir, f'known_met_unique_{timestamp}.csv')
        if unique_matches:
            with open(dedup_csv, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(unique_matches.values())
            print(f"Exported unique files: {dedup_csv}")

        # Summary TXT
        stats_file = os.path.join(output_dir, f'known_met_summary_{timestamp}.txt')
        s = self.statistics

        def line(txt=""): return txt + "\n"

        def fmt_map_count(d: Dict[str, int], key_title: str, val_title: str = "Count") -> str:
            out = ""
            if d:
                key_w = max(len(key_title), *(len(k) for k in d.keys())) if d else len(key_title)
                out += f"{key_title:<{key_w}}  {val_title:>12}\n"
                for k, v in d.items():
                    out += f"{k:<{key_w}}  {v:12d}\n"
            return out

        def fmt_map_bytes(d: Dict[str, int], key_title: str) -> str:
            out = ""
            if d:
                key_w = max(len(key_title), *(len(k) for k in d.keys())) if d else len(key_title)
                out += f"{key_title:<{key_w}}  {'Bytes':>18}  {'Human':>18}\n"
                for k, v in d.items():
                    out += f"{k:<{key_w}}  {v:18,d}  {fmt_bytes(v):>18}\n"
            return out

        with open(stats_file, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("KNOWN.MET ANALYSIS SUMMARY\n")
            f.write("=" * 80 + "\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            # OVERVIEW
            f.write("OVERVIEW\n")
            f.write("-" * 40 + "\n")
            f.write(line(f"Total CSV rows:                {s.get('total_csv_rows', 0):,}"))
            f.write(line(f"Total known.met rows:          {s.get('total_known_rows', 0):,}"))
            f.write(line(f"Total CSV unique ED2K:         {s.get('total_csv_unique', 0):,}"))
            f.write(line(f"Total known.met unique ED2K:   {s.get('total_known_unique', 0):,}"))
            f.write("\n")

            # CSV-ONLY STATISTICS (right after OVERVIEW)
            f.write("CSV-ONLY STATISTICS\n")
            f.write("-" * 40 + "\n")

            # FILE COUNTS
            f.write("FILE COUNTS\n")
            f.write("-" * 40 + "\n")
            f.write(line(f"Total files processed:         {s.get('csv_file_counts_total', 0):,}"))
            f.write(line(f"Unique files (deduplicated):   {s.get('csv_file_counts_unique', 0):,}"))
            f.write(line(f"Duplicate instances:           {s.get('csv_file_counts_duplicates', 0):,}"))
            f.write("\n")

            # PERCENTAGES
            f.write("PERCENTAGES\n")
            f.write("-" * 40 + "\n")
            f.write(line(f"Unique files:                  {s.get('csv_pct_unique', 0.0):.2f}%"))
            f.write(line(f"Duplicate files:               {s.get('csv_pct_duplicates', 0.0):.2f}%"))
            f.write("\n")

            # SIZE ANALYSIS
            f.write("SIZE ANALYSIS\n")
            f.write("-" * 40 + "\n")
            tot = s.get('csv_total_size_bytes_all_rows', 0)
            uni = s.get('csv_total_size_bytes_unique', 0)
            dup = s.get('csv_duplicate_size_bytes', 0)
            save_pct = s.get('csv_potential_savings_pct', 0.0)
            f.write(line(f"Total size (all files):        {bytes_to_mb_gb(tot)}"))
            f.write(line(f"Unique files size:             {bytes_to_mb_gb(uni)}"))
            f.write(line(f"Duplicate data size:           {bytes_to_mb_gb(dup)}"))
            f.write(line(f"Potential storage savings:     {save_pct:.2f}% if deduplicated"))
            f.write("\n")

            # FILES PER EXHIBIT (CSV rows)
            per_ex_rows = s.get('csv_files_per_exhibit_rows', {})
            if per_ex_rows:
                f.write("FILES PER EXHIBIT (CSV rows)\n")
                f.write("-" * 40 + "\n")
                for ex, count in per_ex_rows.items():
                    f.write(line(f"{ex}: {count:,} files"))
                f.write("\n")

            # FILES PER EXHIBIT (CSV unique ED2K — deduplicated within exhibit)
            per_ex_uni = s.get('csv_files_per_exhibit_unique', {})
            if per_ex_uni:
                f.write("FILES PER EXHIBIT (CSV unique ED2K — deduplicated within exhibit)\n")
                f.write("-" * 40 + "\n")
                for ex, count in per_ex_uni.items():
                    f.write(line(f"{ex}: {count:,} files"))
                f.write("\n")

            # DEDUP INTRA-CSV (per file) with requested column order
            f.write("DEDUP INTRA-CSV (per file)\n")
            f.write("-" * 40 + "\n")
            intra = s.get('intra_csv_stats', [])
            if intra:
                f.write(line(f"{'CSV File':40s}  {'Rows':>8s}  {'Unique':>8s}  {'DupRows':>8s}  {'Uniq%':>6s}  {'Dup%':>6s}"))
                for it in intra:
                    f.write(line(
                        f"{it['csv'][:40]:40s}  "
                        f"{it['rows']:8d}  "
                        f"{it['unique_ed2k']:8d}  "
                        f"{it['duplicate_rows']:8d}  "
                        f"{it['unique_rows_pct']:6.2f}  "
                        f"{it['duplicate_rows_pct']:6.2f}"
                    ))
            f.write("\n")

            # DEDUP INTER-CSV
            f.write("DEDUP INTER-CSV (global)\n")
            f.write("-" * 40 + "\n")
            f.write(line(f"Global duplicate rows:         {s.get('dup_global_rows', 0):,}  ({s.get('pct_dup_global_rows', 0.0):.2f}%)"))
            f.write(line(f"Unique ED2K present in \u22652 CSV files (cross-file overlap): {s.get('overlap_multi_csv_unique', 0):,}  ({s.get('pct_overlap_multi_csv_unique', 0.0):.2f}%)"))
            f.write("\n")

            # MATCH PERCENTAGES
            f.write("MATCHES (percentages)\n")
            f.write("-" * 40 + "\n")
            f.write(line(f"Matched rows:                  {s.get('matched_rows', 0):,}  ({s.get('pct_rows_matched', 0.0):.2f}%)"))
            f.write(line(f"Unmatched rows:                {s.get('unmatched_rows', 0):,}  ({s.get('pct_rows_unmatched', 0.0):.2f}%)"))
            f.write(line(f"Matched unique ED2K:           {s.get('matched_unique', 0):,}  ({s.get('pct_unique_matched', 0.0):.2f}%)"))
            f.write(line(f"Unmatched unique ED2K:         {s.get('unmatched_unique', 0):,}  ({s.get('pct_unique_unmatched', 0.0):.2f}%)"))
            f.write("\n")

            # BYTES UPLOADED
            f.write("BYTES UPLOADED (on matches)\n")
            f.write("-" * 40 + "\n")
            raw_b = s.get('bytes_uploaded_total_matches', 0)
            uniq_b = s.get('bytes_uploaded_total_unique', 0)
            f.write(line(f"Total (raw matches):           {raw_b:,} bytes  ({fmt_bytes(raw_b)})"))
            f.write(line(f"Total (unique ED2K):           {uniq_b:,} bytes  ({fmt_bytes(uniq_b)})"))
            f.write("\n")

            # TEMPORAL BREAKDOWN (counts)
            f.write("TEMPORAL BREAKDOWN (unique ED2K) – COUNTS\n")
            f.write("-" * 40 + "\n")
            f.write("last_shared by YEAR\n")
            f.write(fmt_map_count(s.get('last_shared_by_year_count', {}), "Year"))
            f.write("\nlast_shared by YEAR-MONTH\n")
            f.write(fmt_map_count(s.get('last_shared_by_month_count', {}), "Year-Month"))
            f.write("\nlast_posted by YEAR\n")
            f.write(fmt_map_count(s.get('last_posted_by_year_count', {}), "Year"))
            f.write("\nlast_posted by YEAR-MONTH\n")
            f.write(fmt_map_count(s.get('last_posted_by_month_count', {}), "Year-Month"))
            f.write("\n")

            # TEMPORAL BREAKDOWN (bytes)
            f.write("TEMPORAL BREAKDOWN (unique ED2K) – BYTES UPLOADED\n")
            f.write("-" * 40 + "\n")
            f.write("last_shared by YEAR (bytes)\n")
            f.write(fmt_map_bytes(s.get('last_shared_by_year_bytes', {}), "Year"))
            f.write("\nlast_shared by YEAR-MONTH (bytes)\n")
            f.write(fmt_map_bytes(s.get('last_shared_by_month_bytes', {}), "Year-Month"))
            f.write("\nlast_posted by YEAR (bytes)\n")
            f.write(fmt_map_bytes(s.get('last_posted_by_year_bytes', {}), "Year"))
            f.write("\nlast_posted by YEAR-MONTH (bytes)\n")
            f.write(fmt_map_bytes(s.get('last_posted_by_month_bytes', {}), "Year-Month"))
            f.write("\n")

            # MATCHED BY EXHIBIT
            per_ex = s.get('per_exhibit_counts', {})
            if per_ex:
                f.write("MATCHED BY EXHIBIT\n")
                f.write("-" * 40 + "\n")
                for exhibit, count in per_ex.items():
                    f.write(line(f"{exhibit}: {count:,}"))
                f.write("\n")

            # MATCHES BY KNOWN.MET SOURCE
            per_src = s.get('per_known_source', {})
            if per_src:
                f.write("MATCHES BY KNOWN.MET SOURCE\n")
                f.write("-" * 40 + "\n")
                for src, count in per_src.items():
                    f.write(line(f"{src}: {count:,}"))
                f.write("\n")

            # TOP 10 with full hashes
            top10 = s.get('top10', [])
            if top10:
                f.write("TOP 10 MOST COMMON MATCHED FILES\n")
                f.write("-" * 40 + "\n")
                for i, info in enumerate(top10, 1):
                    f.write(line(f"{i}. {info['filename']}"))
                    f.write(line(f"   Hash: {info['hash']}"))
                    f.write(line(f"   Occurrences: {info['count']}"))
                f.write("\n")

            f.write("=" * 80 + "\n")
            f.write("END OF SUMMARY\n")
            f.write("=" * 80 + "\n")

        print(f"Exported summary: {stats_file}")

# ----------------------------------- CLI -----------------------------------

def main():
    parser = argparse.ArgumentParser(
        description='Known.met Analyzer (dedup intra/inter CSV, percentages, AICH-free summary, full hashes in Top 10)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s -c ./csv_outputs -k ./known_dir -o ./analysis
  %(prog)s --csv-dir ./forensics/csv --known-dir ./evidence/emule -o ./results --verbose
        '''
    )
    parser.add_argument('-c', '--csv-dir', required=True, help='Directory containing ForEmHash CSV files')
    parser.add_argument('-k', '--known-dir', required=True, help='Directory containing known.met / known2.met')
    parser.add_argument('-o', '--output', required=True, help='Output directory')
    parser.add_argument('--verbose', action='store_true', help='Verbose parsing logs')

    args = parser.parse_args()

    if not os.path.isdir(args.csv_dir):
        print(f"Error: CSV directory not found: {args.csv_dir}")
        sys.exit(1)
    if not os.path.isdir(args.known_dir):
        print(f"Error: Known.met directory not found: {args.known_dir}")
        sys.exit(1)
    os.makedirs(args.output, exist_ok=True)

    print("=" * 80)
    print("KNOWN.MET ANALYZER (DEDUP + PERCENTAGES, AICH-FREE SUMMARY)")
    print("=" * 80)
    print(f"CSV Directory:    {args.csv_dir}")
    print(f"Known Directory:  {args.known_dir}")
    print(f"Output Directory: {args.output}")
    print("=" * 80 + "\n")

    analyzer = KnownMetAnalyzer()

    print("Step 1: Loading ForEmHash CSV files...")
    csv_count = analyzer.load_csv_files(args.csv_dir)
    print(f"  Loaded {csv_count} CSV rows\n")
    if csv_count == 0:
        print("Error: No CSV data loaded")
        sys.exit(1)

    print("Step 2: Loading known.met files...")
    known_count = analyzer.load_known_met_files(args.known_dir, verbose=args.verbose)
    print(f"  Loaded {known_count} known.met rows\n")
    if known_count == 0:
        print("Warning: No known.met data loaded")

    print("Step 3: Analyzing matches...")
    analyzer.analyze_matches()
    print(f"  Matched rows: {analyzer.statistics.get('matched_rows', 0)} "
          f"({analyzer.statistics.get('pct_rows_matched', 0.0):.2f}%)\n")

    print("Step 4: Exporting results...")
    analyzer.export_results(args.output)

    print("\n" + "=" * 80)
    print("ANALYSIS COMPLETE")
    print("=" * 80)
    print(f"Total CSV rows:          {analyzer.statistics.get('total_csv_rows', 0):,}")
    print(f"CSV unique ED2K:         {analyzer.statistics.get('total_csv_unique', 0):,}")
    print(f"Matched rows:            {analyzer.statistics.get('matched_rows', 0):,} "
          f"({analyzer.statistics.get('pct_rows_matched', 0.0):.2f}%)")
    print(f"Matched unique ED2K:     {analyzer.statistics.get('matched_unique', 0):,} "
          f"({analyzer.statistics.get('pct_unique_matched', 0.0):.2f}%)")
    print(f"Bytes uploaded (unique): {fmt_bytes(analyzer.statistics.get('bytes_uploaded_total_unique', 0))}")
    print("\nResults saved to: " + args.output)
    print("=" * 80)

if __name__ == '__main__':
    main()
