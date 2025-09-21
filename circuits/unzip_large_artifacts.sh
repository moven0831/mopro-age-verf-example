#!/bin/bash

# Script to unzip all tar compressed files in specified folders
# Usage: ./unzip_large_artifacts.sh [folder1] [folder2] ...
# If no folders are specified, it will process the current directory

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to extract tar files
extract_tar_file() {
    local tar_file="$1"
    local extract_dir="$(dirname "$tar_file")"
    
    print_info "Extracting: $tar_file"
    
    # Check if file exists
    if [[ ! -f "$tar_file" ]]; then
        print_error "File not found: $tar_file"
        return 1
    fi
    
    # Determine extraction method based on file extension
    case "$tar_file" in
        *.tar.gz|*.tgz)
            if tar -tzf "$tar_file" >/dev/null 2>&1; then
                tar -xzf "$tar_file" -C "$extract_dir"
                print_success "Extracted: $tar_file"
            else
                print_error "Invalid or corrupted tar.gz file: $tar_file"
                return 1
            fi
            ;;
        *.tar.bz2|*.tbz2)
            if tar -tjf "$tar_file" >/dev/null 2>&1; then
                tar -xjf "$tar_file" -C "$extract_dir"
                print_success "Extracted: $tar_file"
            else
                print_error "Invalid or corrupted tar.bz2 file: $tar_file"
                return 1
            fi
            ;;
        *.tar.xz|*.txz)
            if tar -tJf "$tar_file" >/dev/null 2>&1; then
                tar -xJf "$tar_file" -C "$extract_dir"
                print_success "Extracted: $tar_file"
            else
                print_error "Invalid or corrupted tar.xz file: $tar_file"
                return 1
            fi
            ;;
        *.tar)
            if tar -tf "$tar_file" >/dev/null 2>&1; then
                tar -xf "$tar_file" -C "$extract_dir"
                print_success "Extracted: $tar_file"
            else
                print_error "Invalid or corrupted tar file: $tar_file"
                return 1
            fi
            ;;
        *)
            print_warning "Unsupported file type: $tar_file"
            return 1
            ;;
    esac
}

# Function to process a directory
process_directory() {
    local dir="$1"
    local found_files=0
    local extracted_files=0
    local failed_files=0
    
    print_info "Processing directory: $dir"
    
    # Check if directory exists
    if [[ ! -d "$dir" ]]; then
        print_error "Directory not found: $dir"
        return 1
    fi
    
    # Find all tar files recursively
    while IFS= read -r -d '' tar_file; do
        found_files=$((found_files + 1))
        if extract_tar_file "$tar_file"; then
            extracted_files=$((extracted_files + 1))
        else
            failed_files=$((failed_files + 1))
        fi
    done < <(find "$dir" -type f \( -name "*.tar" -o -name "*.tar.gz" -o -name "*.tgz" -o -name "*.tar.bz2" -o -name "*.tbz2" -o -name "*.tar.xz" -o -name "*.txz" \) -print0)
    
    # Summary for this directory
    if [[ $found_files -eq 0 ]]; then
        print_warning "No tar files found in: $dir"
    else
        print_info "Directory summary for $dir:"
        echo "  - Files found: $found_files"
        echo "  - Successfully extracted: $extracted_files"
        if [[ $failed_files -gt 0 ]]; then
            echo "  - Failed extractions: $failed_files"
        fi
    fi
    
    return 0
}

# Main script
main() {
    local total_dirs=0
    local processed_dirs=0
    
    print_info "Starting tar file extraction script..."
    
    # If no arguments provided, use current directory
    if [[ $# -eq 0 ]]; then
        print_info "No directories specified, using current directory"
        set -- "."
    fi
    
    # Process each directory argument
    for dir in "$@"; do
        total_dirs=$((total_dirs + 1))
        
        # Convert to absolute path for clarity
        if [[ "$dir" != /* ]]; then
            dir="$(cd "$dir" 2>/dev/null && pwd)" || {
                print_error "Cannot access directory: $dir"
                continue
            }
        fi
        
        if process_directory "$dir"; then
            processed_dirs=$((processed_dirs + 1))
        fi
        
        echo  # Add blank line between directories
    done
    
    # Final summary
    print_info "Script completed!"
    echo "  - Total directories specified: $total_dirs"
    echo "  - Successfully processed: $processed_dirs"
    
    if [[ $processed_dirs -lt $total_dirs ]]; then
        print_warning "Some directories could not be processed"
        exit 1
    else
        print_success "All directories processed successfully"
    fi
}

# Help function
show_help() {
    cat << EOF
Tar File Extraction Script

USAGE:
    $0 [OPTIONS] [DIRECTORY...]

DESCRIPTION:
    Recursively finds and extracts all tar compressed files in the specified directories.
    Supports: .tar, .tar.gz, .tgz, .tar.bz2, .tbz2, .tar.xz, .txz

OPTIONS:
    -h, --help    Show this help message

EXAMPLES:
    $0                          # Extract from current directory
    $0 ./circuits              # Extract from circuits directory
    $0 /path/to/dir1 /path/to/dir2  # Extract from multiple directories

EOF
}

# Check for help flag
if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    show_help
    exit 0
fi

# Run main function
main "$@"
