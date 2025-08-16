#!/usr/bin/env python3
"""
Simple CSV Merger for ForEmHash outputs
Merges multiple CSV files with different column counts and finds unique files
"""

import os
import sys
import csv
import argparse
from datetime import datetime
from collections import defaultdict

def read_csv_with_variable_columns(filepath):
    """Read CSV file and return list of dictionaries"""
    data = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                data.append(dict(row))
    except Exception as e:
        print(f"Error reading {filepath}: {e}")
    return data

def merge_csv_files(csv_files):
    """Merge multiple CSV files with different column counts"""
    all_data = []
    all_columns = set()
    
    # Read all CSV files
    for csv_file in csv_files:
        print(f"Reading: {csv_file}")
        file_data = read_csv_with_variable_columns(csv_file)
        
        if file_data:
            # Collect all unique column names
            for row in file_data:
                all_columns.update(row.keys())
            all_data.extend(file_data)
    
    # Ensure all rows have all columns (fill missing with empty string)
    all_columns = sorted(list(all_columns))
    for row in all_data:
        for col in all_columns:
            if col not in row:
                row[col] = ''
    
    return all_data, all_columns

def find_unique_files(all_data):
    """Find unique files based on ED2K hash"""
    # Group files by ED2K hash
    hash_groups = defaultdict(list)
    
    for row in all_data:
        if 'ed2k_hash' in row and row['ed2k_hash']:
            hash_groups[row['ed2k_hash']].append(row)
    
    # Get one representative for each unique hash
    unique_files = []
    for ed2k_hash, group in hash_groups.items():
        # Take the first occurrence as representative
        unique_files.append(group[0])
    
    return unique_files, hash_groups

def calculate_statistics(all_data, unique_files, hash_groups):
    """Calculate statistics for the report"""
    stats = {}
    
    # Basic counts
    stats['total_files'] = len(all_data)
    stats['unique_files'] = len(unique_files)
    stats['duplicate_files'] = stats['total_files'] - stats['unique_files']
    
    # Percentages
    if stats['total_files'] > 0:
        stats['unique_percentage'] = (stats['unique_files'] / stats['total_files']) * 100
        stats['duplicate_percentage'] = (stats['duplicate_files'] / stats['total_files']) * 100
    else:
        stats['unique_percentage'] = 0
        stats['duplicate_percentage'] = 0
    
    # Size statistics
    total_size_all = 0
    total_size_unique = 0
    
    for row in all_data:
        if 'size_mb' in row and row['size_mb']:
            try:
                total_size_all += float(row['size_mb'])
            except:
                pass
    
    for row in unique_files:
        if 'size_mb' in row and row['size_mb']:
            try:
                total_size_unique += float(row['size_mb'])
            except:
                pass
    
    stats['total_size_mb'] = total_size_all
    stats['unique_size_mb'] = total_size_unique
    stats['duplicate_size_mb'] = total_size_all - total_size_unique
    
    # Find most duplicated files
    most_duplicated = []
    for ed2k_hash, group in hash_groups.items():
        if len(group) > 1:
            most_duplicated.append({
                'filename': group[0].get('filename', 'Unknown'),
                'count': len(group),
                'exhibits': list(set([g.get('exhibit', 'Unknown') for g in group]))
            })
    
    most_duplicated.sort(key=lambda x: x['count'], reverse=True)
    stats['most_duplicated'] = most_duplicated[:10]  # Top 10
    
    # Exhibit statistics
    exhibit_counts = defaultdict(int)
    for row in all_data:
        if 'exhibit' in row:
            exhibit_counts[row['exhibit']] += 1
    stats['exhibit_counts'] = dict(exhibit_counts)
    
    return stats

def write_merged_csv(all_data, all_columns, output_file):
    """Write merged data to CSV"""
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=all_columns)
        writer.writeheader()
        writer.writerows(all_data)
    print(f"Written merged data: {output_file}")

def write_unique_csv(unique_files, all_columns, output_file):
    """Write unique files to CSV"""
    # Filter to essential columns only for readability
    essential_cols = ['exhibit', 'filename', 'filepath', 'size_bytes', 'size_mb', 
                     'ed2k_hash', 'aich_hash', 'num_chunks', 'status']
    
    # Use all columns but prioritize essential ones
    output_columns = []
    for col in essential_cols:
        if col in all_columns:
            output_columns.append(col)
    
    # Add any chunk columns
    for col in all_columns:
        if col.startswith('chunk_') and col not in output_columns:
            output_columns.append(col)
    
    # Add remaining columns
    for col in all_columns:
        if col not in output_columns:
            output_columns.append(col)
    
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=output_columns)
        writer.writeheader()
        writer.writerows(unique_files)
    print(f"Written unique files: {output_file}")

def write_statistics(stats, output_file):
    """Write statistics report to text file"""
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("=" * 70 + "\n")
        f.write("FOREMHASH CSV MERGE STATISTICS REPORT\n")
        f.write("=" * 70 + "\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("\n")
        
        f.write("FILE COUNTS\n")
        f.write("-" * 40 + "\n")
        f.write(f"Total files processed:     {stats['total_files']:,}\n")
        f.write(f"Unique files (deduplicated): {stats['unique_files']:,}\n")
        f.write(f"Duplicate instances:       {stats['duplicate_files']:,}\n")
        f.write("\n")
        
        f.write("PERCENTAGES\n")
        f.write("-" * 40 + "\n")
        f.write(f"Unique files:    {stats['unique_percentage']:.2f}%\n")
        f.write(f"Duplicate files: {stats['duplicate_percentage']:.2f}%\n")
        f.write("\n")
        
        f.write("SIZE ANALYSIS\n")
        f.write("-" * 40 + "\n")
        f.write(f"Total size (all files):      {stats['total_size_mb']:,.2f} MB ({stats['total_size_mb']/1024:.2f} GB)\n")
        f.write(f"Unique files size:           {stats['unique_size_mb']:,.2f} MB ({stats['unique_size_mb']/1024:.2f} GB)\n")
        f.write(f"Duplicate data size:         {stats['duplicate_size_mb']:,.2f} MB ({stats['duplicate_size_mb']/1024:.2f} GB)\n")
        if stats['total_size_mb'] > 0:
            savings_percent = (stats['duplicate_size_mb'] / stats['total_size_mb']) * 100
            f.write(f"Potential storage savings:   {savings_percent:.2f}% if deduplicated\n")
        f.write("\n")
        
        if stats['exhibit_counts']:
            f.write("FILES PER EXHIBIT\n")
            f.write("-" * 40 + "\n")
            for exhibit, count in sorted(stats['exhibit_counts'].items()):
                f.write(f"{exhibit}: {count:,} files\n")
            f.write("\n")
        
        if stats['most_duplicated']:
            f.write("TOP 10 MOST DUPLICATED FILES\n")
            f.write("-" * 40 + "\n")
            for i, item in enumerate(stats['most_duplicated'], 1):
                f.write(f"{i}. {item['filename']}\n")
                f.write(f"   Copies: {item['count']}\n")
                f.write(f"   Exhibits: {', '.join(item['exhibits'])}\n")
            f.write("\n")
        
        f.write("=" * 70 + "\n")
        f.write("END OF REPORT\n")
        f.write("=" * 70 + "\n")
    
    print(f"Written statistics: {output_file}")

def main():
    parser = argparse.ArgumentParser(
        description='Simple CSV Merger for ForEmHash - Merges CSVs and finds unique files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s file1.csv file2.csv file3.csv
  %(prog)s *.csv
  %(prog)s report1.csv report2.csv -o output_dir
        '''
    )
    
    parser.add_argument('csv_files', nargs='+', help='CSV files to merge')
    parser.add_argument('-o', '--output', default='.', help='Output directory (default: current)')
    
    args = parser.parse_args()
    
    # Verify CSV files exist
    csv_files = []
    for pattern in args.csv_files:
        if '*' in pattern:
            # Handle wildcards
            import glob
            csv_files.extend(glob.glob(pattern))
        else:
            if os.path.exists(pattern):
                csv_files.append(pattern)
            else:
                print(f"Warning: File not found: {pattern}")
    
    if not csv_files:
        print("Error: No valid CSV files found")
        sys.exit(1)
    
    # Remove duplicates
    csv_files = list(set(csv_files))
    
    print("=" * 70)
    print("FOREMHASH CSV MERGER")
    print("=" * 70)
    print(f"Processing {len(csv_files)} CSV files")
    print()
    
    # Create output directory if needed
    os.makedirs(args.output, exist_ok=True)
    
    # Generate output filenames with timestamp
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    merged_output = os.path.join(args.output, f'all_files_{timestamp}.csv')
    unique_output = os.path.join(args.output, f'unique_files_{timestamp}.csv')
    stats_output = os.path.join(args.output, f'statistics_{timestamp}.txt')
    
    # Process files
    print("Step 1: Merging CSV files...")
    all_data, all_columns = merge_csv_files(csv_files)
    print(f"  Merged {len(all_data)} total records with {len(all_columns)} columns\n")
    
    print("Step 2: Finding unique files...")
    unique_files, hash_groups = find_unique_files(all_data)
    print(f"  Found {len(unique_files)} unique files (deduplicated by ED2K hash)\n")
    
    print("Step 3: Calculating statistics...")
    stats = calculate_statistics(all_data, unique_files, hash_groups)
    print(f"  Statistics calculated\n")
    
    print("Step 4: Writing output files...")
    write_merged_csv(all_data, all_columns, merged_output)
    write_unique_csv(unique_files, all_columns, unique_output)
    write_statistics(stats, stats_output)
    
    print()
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"Total files:      {stats['total_files']:,}")
    print(f"Unique files:     {stats['unique_files']:,}")
    print(f"Duplicates:       {stats['duplicate_files']:,}")
    print(f"Unique percentage: {stats['unique_percentage']:.2f}%")
    print(f"Total size:       {stats['total_size_mb']:,.2f} MB")
    print(f"Unique size:      {stats['unique_size_mb']:,.2f} MB")
    print()
    print("Output files:")
    print(f"  - All files:    {merged_output}")
    print(f"  - Unique files: {unique_output}")
    print(f"  - Statistics:   {stats_output}")
    print()
    print("Done!")

if __name__ == '__main__':
    main()