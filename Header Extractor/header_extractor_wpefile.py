import pefile
import json
import csv
import os
import argparse
from datetime import datetime

def extract_dos_header(file_path):
    try:
        pe = pefile.PE(file_path)
        dos_header = {
            "e_magic": hex(pe.DOS_HEADER.e_magic),
            "e_cblp": pe.DOS_HEADER.e_cblp,
            "e_cp": pe.DOS_HEADER.e_cp,
            "e_crlc": pe.DOS_HEADER.e_crlc,
            "e_cparhdr": pe.DOS_HEADER.e_cparhdr,
            "e_minalloc": pe.DOS_HEADER.e_minalloc,
            "e_maxalloc": pe.DOS_HEADER.e_maxalloc,
            "e_ss": hex(pe.DOS_HEADER.e_ss),
            "e_sp": hex(pe.DOS_HEADER.e_sp),
            "e_csum": pe.DOS_HEADER.e_csum,
            "e_ip": hex(pe.DOS_HEADER.e_ip),
            "e_cs": hex(pe.DOS_HEADER.e_cs),
            "e_lfarlc": pe.DOS_HEADER.e_lfarlc,
            "e_ovno": pe.DOS_HEADER.e_ovno,
            "e_oemid": pe.DOS_HEADER.e_oemid,
            "e_oeminfo": pe.DOS_HEADER.e_oeminfo,
            "e_lfanew": hex(pe.DOS_HEADER.e_lfanew)
        }
        return dos_header
    except Exception as e:
        print(f"Error processing DOS Header: {str(e)}")
        return None

def extract_rich_header(file_path):
    try:
        pe = pefile.PE(file_path)
        if not hasattr(pe, 'RICH_HEADER') or pe.RICH_HEADER is None:
            return {"present": False, "message": "No Rich Header found"}
        
        rich_header = {
            "present": True,
            "checksum": hex(pe.RICH_HEADER.checksum),
            "entries": []
        }
        
        # Extract Rich Header entries
        for entry in pe.RICH_HEADER.values:
            rich_header["entries"].append({
                "id": hex(entry.id),  # Product ID or build number
                "count": entry.times  # Number of times this ID appears
            })
        
        return rich_header
    except Exception as e:
        print(f"Error processing Rich Header: {str(e)}")
        return None

def extract_file_header(file_path):
    try:
        pe = pefile.PE(file_path)
        file_header = {
            "Machine": hex(pe.FILE_HEADER.Machine),
            "NumberOfSections": pe.FILE_HEADER.NumberOfSections,
            "TimeDateStamp": pe.FILE_HEADER.TimeDateStamp,
            "PointerToSymbolTable": hex(pe.FILE_HEADER.PointerToSymbolTable),
            "NumberOfSymbols": pe.FILE_HEADER.NumberOfSymbols,
            "SizeOfOptionalHeader": pe.FILE_HEADER.SizeOfOptionalHeader,
            "Characteristics": hex(pe.FILE_HEADER.Characteristics)
        }
        return file_header
    except Exception as e:
        print(f"Error processing File Header: {str(e)}")
        return None

def extract_nt_header(file_path):
    try:
        pe = pefile.PE(file_path)
        nt_header = {
            "Signature": hex(pe.NT_HEADERS.Signature),
            "Magic": hex(pe.OPTIONAL_HEADER.Magic),
            "MajorLinkerVersion": pe.OPTIONAL_HEADER.MajorLinkerVersion,
            "MinorLinkerVersion": pe.OPTIONAL_HEADER.MinorLinkerVersion,
            "SizeOfCode": pe.OPTIONAL_HEADER.SizeOfCode,
            "SizeOfInitializedData": pe.OPTIONAL_HEADER.SizeOfInitializedData,
            "SizeOfUninitializedData": pe.OPTIONAL_HEADER.SizeOfUninitializedData,
            "AddressOfEntryPoint": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "BaseOfCode": hex(pe.OPTIONAL_HEADER.BaseOfCode),
            "ImageBase": hex(pe.OPTIONAL_HEADER.ImageBase),
            "SectionAlignment": pe.OPTIONAL_HEADER.SectionAlignment,
            "FileAlignment": pe.OPTIONAL_HEADER.FileAlignment,
            "MajorOperatingSystemVersion": pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
            "MinorOperatingSystemVersion": pe.OPTIONAL_HEADER.MinorOperatingSystemVersion,
            "MajorImageVersion": pe.OPTIONAL_HEADER.MajorImageVersion,
            "MinorImageVersion": pe.OPTIONAL_HEADER.MinorImageVersion,
            "MajorSubsystemVersion": pe.OPTIONAL_HEADER.MajorSubsystemVersion,
            "MinorSubsystemVersion": pe.OPTIONAL_HEADER.MinorSubsystemVersion,
            "SizeOfImage": pe.OPTIONAL_HEADER.SizeOfImage,
            "SizeOfHeaders": pe.OPTIONAL_HEADER.SizeOfHeaders,
            "CheckSum": hex(pe.OPTIONAL_HEADER.CheckSum),
            "Subsystem": hex(pe.OPTIONAL_HEADER.Subsystem),
            "DllCharacteristics": hex(pe.OPTIONAL_HEADER.DllCharacteristics),
            "SizeOfStackReserve": pe.OPTIONAL_HEADER.SizeOfStackReserve,
            "SizeOfStackCommit": pe.OPTIONAL_HEADER.SizeOfStackCommit,
            "SizeOfHeapReserve": pe.OPTIONAL_HEADER.SizeOfHeapReserve,
            "SizeOfHeapCommit": pe.OPTIONAL_HEADER.SizeOfHeapCommit,
            "LoaderFlags": hex(pe.OPTIONAL_HEADER.LoaderFlags),
            "NumberOfRvaAndSizes": pe.OPTIONAL_HEADER.NumberOfRvaAndSizes
        }
        return nt_header
    except Exception as e:
        print(f"Error processing NT Header (Optional Header): {str(e)}")
        return None

def save_to_json(data, output_file):
    try:
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=4)
        print(f"JSON data saved to {output_file}")
    except Exception as e:
        print(f"Error saving JSON: {str(e)}")

def save_to_csv(data, output_file):
    try:
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            if "present" in data and not data["present"]:
                writer.writerow(['Field', 'Value'])
                writer.writerow(['present', 'False'])
                writer.writerow(['message', data['message']])
            else:
                writer.writerow(['Field', 'Value'])
                for key, value in data.items():
                    if key != "entries":
                        writer.writerow([key, value])
                    else:
                        for i, entry in enumerate(value):
                            writer.writerow([f"entry_{i}_id", entry["id"]])
                            writer.writerow([f"entry_{i}_count", entry["count"]])
        print(f"CSV data saved to {output_file}")
    except Exception as e:
        print(f"Error saving CSV: {str(e)}")
def process_pe_file(input_path, output_dir=None):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = os.path.splitext(os.path.basename(input_path))[0]
    
    # Determine output directory
    if output_dir is None:
        output_dir = os.path.dirname(input_path) or "."
    
    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)
    
    # Output filenames
    dos_json_output = os.path.join(output_dir, f"{base_name}_dos_header_{timestamp}.json")
    dos_csv_output = os.path.join(output_dir, f"{base_name}_dos_header_{timestamp}.csv")
    rich_json_output = os.path.join(output_dir, f"{base_name}_rich_header_{timestamp}.json")
    rich_csv_output = os.path.join(output_dir, f"{base_name}_rich_header_{timestamp}.csv")
    file_json_output = os.path.join(output_dir, f"{base_name}_file_header_{timestamp}.json")
    file_csv_output = os.path.join(output_dir, f"{base_name}_file_header_{timestamp}.csv")
    nt_json_output = os.path.join(output_dir, f"{base_name}_nt_optional_header_{timestamp}.json")
    nt_csv_output = os.path.join(output_dir, f"{base_name}_nt_optional_header_{timestamp}.csv")
    
    # Extract and save headers
    dos_header_data = extract_dos_header(input_path)
    if dos_header_data:
        save_to_json(dos_header_data, dos_json_output)
        save_to_csv(dos_header_data, dos_csv_output)
    
    rich_header_data = extract_rich_header(input_path)
    if rich_header_data:
        save_to_json(rich_header_data, rich_json_output)
        save_to_csv(rich_header_data, rich_csv_output)
    
    file_header_data = extract_file_header(input_path)
    if file_header_data:
        save_to_json(file_header_data, file_json_output)
        save_to_csv(file_header_data, file_csv_output)
    
    nt_header_data = extract_nt_header(input_path)
    if nt_header_data:
        save_to_json(nt_header_data, nt_json_output)
        save_to_csv(nt_header_data, nt_csv_output)

# pip install pefile
# python3 header_extractor_wpefile.py <pe_file_or_directory>
def main():
    # Set up command-line argument parsing
    parser = argparse.ArgumentParser(description="Extract PE header information from a file or directory.")
    parser.add_argument("input_path", help="Path to a single PE file or a directory containing PE files (e.g., bin/pe)")
    args = parser.parse_args()
    
    input_path = args.input_path
    
    # Check if input is a file or directory
    if os.path.isfile(input_path):
        # Single file processing
        process_pe_file(input_path)
    elif os.path.isdir(input_path):
        # Directory processing
        output_dir = os.path.join(os.path.dirname(__file__), "bin", "pe_extracted")
        os.makedirs(output_dir, exist_ok=True)
        
        # Process all PE files in the directory
        for filename in os.listdir(input_path):
            file_path = os.path.join(input_path, filename)
            if os.path.isfile(file_path) and filename.lower().endswith(('.exe', '.dll')):
                print(f"Processing {file_path}")
                process_pe_file(file_path, output_dir)
    else:
        print(f"Error: {input_path} is neither a file nor a directory")
        return

if __name__ == "__main__":
    main()