#!/bin/bash

# Smart Log Analyzer
# Created by: Md Kamre Aallam and Abhinav Gautam
# Features: Batch processing + Safe log file deletion

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# Configuration
OUTPUT_DIR="$HOME/smart_log_analysis"
REPORT_FILE="$OUTPUT_DIR/analysis_report_$(date +%Y%m%d_%H%M%S).txt"
ERROR_PATTERNS_FILE="$OUTPUT_DIR/error_patterns.txt"
SUMMARY_FILE="$OUTPUT_DIR/summary_$(date +%Y%m%d_%H%M%S).txt"
TEMP_DIR="$OUTPUT_DIR/temp_$(date +%s)"
BACKUP_DIR="$OUTPUT_DIR/backup_$(date +%Y%m%d_%H%M%S)"
MAX_LINES_PER_FILE=2000

# Create directories
mkdir -p "$OUTPUT_DIR" "$TEMP_DIR" "$BACKUP_DIR"

# Severity levels with priority order
declare -A SEVERITY_LEVELS=(
    ["CRITICAL"]=1
    ["ERROR"]=2
    ["SECURITY"]=3
    ["WARNING"]=4
    ["INFO"]=5
)

# Function to display banner
show_banner() {
    clear
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║           SMART LOG ANALYZER v4.0                          ║${NC}"
    echo -e "${BLUE}║     Batch Processing + Safe Log Deletion                   ║${NC}"
    echo -e "${BLUE}║     Created by: Md Kamre Aallam & Abhinav Gautam           ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# Function to log messages
log_message() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "[$timestamp] [$level] $message" | tee -a "$REPORT_FILE"
}

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${YELLOW}Warning: Not running as root. Some system logs may not be accessible.${NC}"
        echo -e "Consider running with: sudo $0\n"
        sleep 2
    fi
}

# Function to create pattern file
create_pattern_file() {
    cat > "$ERROR_PATTERNS_FILE" << 'EOF'
# Critical Patterns (System down, crashes, immediate attention)
CRITICAL:kernel panic|system freezing|out of memory|killed process|segfault|oom-killer|emergency|shutdown|reboot|hard lockup|cpu stuck|machine check

# Error Patterns (Functional issues, failures)
ERROR:error|failed|failure|fatal|exception|unable to|can't|cannot|denied|not found|permission denied|connection refused|timeout|no space left on device|read-only file system

# Security Patterns (Attacks, breaches, auth issues)
SECURITY:unauthorized|authentication failure|invalid user|brute force|attack|hack|intrusion|failed password|illegal user|hacking attempt|break-in attempt

# Warning Patterns (Potential issues, resource warnings)
WARNING:warning|deprecated|obsolete|slow|high usage|threshold exceeded|low memory|disk full|cpu usage high|load average high

# Info Patterns (Notable events)
INFO:started|stopped|restarted|connected|disconnected|mounted|unmounted|updated|upgraded|installed|removed
EOF
    log_message "INFO" "Created error patterns file"
}

# Function to find all log files
find_log_files() {
    local log_files=()
    
    echo -e "${CYAN}🔍 Searching for log files...${NC}"
    
    # Common log locations
    local log_locations=(
        "/var/log/*.log"
        "/var/log/syslog*"
        "/var/log/messages*"
        "/var/log/auth.log*"
        "/var/log/kern.log*"
        "/var/log/dpkg.log*"
        "/var/log/apt/*.log"
        "/var/log/installer/*.log"
        "/var/log/gpu-manager*.log"
    )
    
    # Use find command to locate log files
    for location in "${log_locations[@]}"; do
        local dir=$(dirname "$location")
        local pattern=$(basename "$location")
        
        if [[ -d "$dir" ]]; then
            while IFS= read -r file; do
                if [[ -f "$file" && -r "$file" ]]; then
                    log_files+=("$file")
                    echo -e "  ${GREEN}✓${NC} Found: $(basename "$file")"
                fi
            done < <(find "$dir" -name "$pattern" -type f 2>/dev/null | head -20)
        fi
    done
    
    # Remove duplicates
    log_files=($(printf "%s\n" "${log_files[@]}" | sort -u))
    
    echo -e "\n${GREEN}📊 Total log files found: ${#log_files[@]}${NC}"
    log_message "INFO" "Found ${#log_files[@]} log files to analyze"
    
    printf '%s\n' "${log_files[@]}"
}

# Function to scan a single log file
scan_log_file() {
    local file=$1
    local filename=$(basename "$file")
    local temp_file="$TEMP_DIR/${filename}.txt"
    local line_count=0
    local file_issues=0
    
    # Get file info
    local file_size=$(du -h "$file" 2>/dev/null | cut -f1)
    local total_lines=$(wc -l < "$file" 2>/dev/null || echo "0")
    local file_date=$(date -r "$file" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "Unknown")
    
    # Process the file line by line
    while IFS= read -r line || [[ -n "$line" ]]; do
        ((line_count++))
        
        # Skip empty lines
        [[ -z "$line" ]] && continue
        
        # Limit processing for very large files
        if [[ $total_lines -gt $MAX_LINES_PER_FILE && $line_count -gt $MAX_LINES_PER_FILE ]]; then
            echo "[TRUNCATED] File truncated at $MAX_LINES_PER_FILE lines" >> "$temp_file.truncated"
            break
        fi
        
        # Check each pattern category
        while IFS=: read -r category patterns; do
            # Skip comments and empty lines
            [[ "$category" =~ ^#.*$ || -z "$category" ]] && continue
            
            # Check if line matches any pattern in this category
            IFS='|' read -ra pattern_array <<< "$patterns"
            for pattern in "${pattern_array[@]}"; do
                if echo "$line" | grep -qi "$pattern"; then
                    # Found a match
                    echo "$filename|$line" >> "$TEMP_DIR/${category}.txt"
                    ((file_issues++))
                    break 2
                fi
            done
        done < "$ERROR_PATTERNS_FILE"
        
    done < "$file"
    
    # Store metadata about this file
    echo "$filename|$file|$file_size|$total_lines|$file_issues|$file_date" >> "$TEMP_DIR/file_metadata.txt"
    
    return $file_issues
}

# Function to display results by severity
display_severity_results() {
    echo -e "\n${WHITE}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${WHITE}║                    ANALYSIS RESULTS                        ║${NC}"
    echo -e "${WHITE}╚════════════════════════════════════════════════════════════╝${NC}\n"
    
    local total_critical=0
    local total_error=0
    local total_security=0
    local total_warning=0
    local total_info=0
    
    # Count issues by severity
    [[ -f "$TEMP_DIR/CRITICAL.txt" ]] && total_critical=$(wc -l < "$TEMP_DIR/CRITICAL.txt")
    [[ -f "$TEMP_DIR/ERROR.txt" ]] && total_error=$(wc -l < "$TEMP_DIR/ERROR.txt")
    [[ -f "$TEMP_DIR/SECURITY.txt" ]] && total_security=$(wc -l < "$TEMP_DIR/SECURITY.txt")
    [[ -f "$TEMP_DIR/WARNING.txt" ]] && total_warning=$(wc -l < "$TEMP_DIR/WARNING.txt")
    [[ -f "$TEMP_DIR/INFO.txt" ]] && total_info=$(wc -l < "$TEMP_DIR/INFO.txt")
    
    local total_issues=$((total_critical + total_error + total_security + total_warning + total_info))
    
    # Display summary dashboard
    echo -e "${WHITE}📊 SUMMARY DASHBOARD${NC}"
    echo -e "${WHITE}────────────────────${NC}"
    echo -e "Total Issues Found: ${YELLOW}$total_issues${NC}\n"
    
    # Show severity distribution
    echo -e "${WHITE}Severity Distribution:${NC}"
    [[ $total_critical -gt 0 ]] && echo -e "  ${RED}● CRITICAL : $total_critical issues${NC}"
    [[ $total_error -gt 0 ]] && echo -e "  ${RED}● ERROR    : $total_error issues${NC}"
    [[ $total_security -gt 0 ]] && echo -e "  ${MAGENTA}● SECURITY : $total_security issues${NC}"
    [[ $total_warning -gt 0 ]] && echo -e "  ${YELLOW}● WARNING  : $total_warning issues${NC}"
    [[ $total_info -gt 0 ]] && echo -e "  ${BLUE}● INFO     : $total_info issues${NC}"
    
    echo ""
    
    # Display files analyzed with issues count
    if [[ -f "$TEMP_DIR/file_metadata.txt" ]]; then
        echo -e "${WHITE}📁 Files Analyzed:${NC}"
        echo -e "${WHITE}────────────────${NC}"
        local file_count=0
        local files_with_issues=0
        
        while IFS='|' read -r filename fullpath size lines issues date; do
            ((file_count++))
            local status="${GREEN}✓${NC}"
            [[ $issues -gt 0 ]] && status="${RED}⚠${NC}" && ((files_with_issues++))
            echo -e "  $status $filename (${size}, ${lines} lines, ${YELLOW}$issues issues${NC})"
        done < "$TEMP_DIR/file_metadata.txt"
        echo -e "  ${BLUE}Total files: $file_count | Files with issues: $files_with_issues${NC}\n"
    fi
    
    # Display CRITICAL issues first
    if [[ -f "$TEMP_DIR/CRITICAL.txt" && $total_critical -gt 0 ]]; then
        echo -e "${WHITE}🔥 CRITICAL ISSUES (Immediate Attention Required)${NC}"
        echo -e "${RED}────────────────────────────────────────────────${NC}"
        local count=0
        while IFS='|' read -r filename line; do
            ((count++))
            echo -e "${RED}$count. [$filename]${NC} ${line:0:150}..."
            echo "[CRITICAL] $filename: $line" >> "$REPORT_FILE"
        done < "$TEMP_DIR/CRITICAL.txt"
        echo ""
    fi
    
    # Display SECURITY issues
    if [[ -f "$TEMP_DIR/SECURITY.txt" && $total_security -gt 0 ]]; then
        echo -e "${WHITE}🔒 SECURITY ISSUES${NC}"
        echo -e "${MAGENTA}─────────────────${NC}"
        local count=0
        while IFS='|' read -r filename line; do
            ((count++))
            echo -e "${MAGENTA}$count. [$filename]${NC} ${line:0:150}..."
            echo "[SECURITY] $filename: $line" >> "$REPORT_FILE"
        done < "$TEMP_DIR/SECURITY.txt"
        echo ""
    fi
    
    # Display ERROR issues
    if [[ -f "$TEMP_DIR/ERROR.txt" && $total_error -gt 0 ]]; then
        echo -e "${WHITE}❌ ERROR ISSUES${NC}"
        echo -e "${RED}──────────────${NC}"
        local count=0
        while IFS='|' read -r filename line; do
            ((count++))
            echo -e "${RED}$count. [$filename]${NC} ${line:0:150}..."
            echo "[ERROR] $filename: $line" >> "$REPORT_FILE"
            
            # Limit display to prevent overwhelming
            [[ $count -ge 20 ]] && echo -e "${YELLOW}   ... and $((total_error - 20)) more errors (see report file)${NC}" && break
        done < "$TEMP_DIR/ERROR.txt"
        echo ""
    fi
    
    # Display WARNING issues
    if [[ -f "$TEMP_DIR/WARNING.txt" && $total_warning -gt 0 ]]; then
        echo -e "${WHITE}⚠️  WARNING ISSUES${NC}"
        echo -e "${YELLOW}────────────────${NC}"
        local count=0
        while IFS='|' read -r filename line; do
            ((count++))
            echo -e "${YELLOW}$count. [$filename]${NC} ${line:0:150}..."
            echo "[WARNING] $filename: $line" >> "$REPORT_FILE"
            
            [[ $count -ge 15 ]] && echo -e "${YELLOW}   ... and $((total_warning - 15)) more warnings (see report file)${NC}" && break
        done < "$TEMP_DIR/WARNING.txt"
        echo ""
    fi
}

# ==================== NEW: SAFE LOG DELETION FEATURE ====================

# Function to ask user about log deletion
ask_log_deletion() {
    echo -e "\n${WHITE}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${WHITE}║               LOG FILE MANAGEMENT OPTION                   ║${NC}"
    echo -e "${WHITE}╚════════════════════════════════════════════════════════════╝${NC}"
    
    echo -e "\n${YELLOW}⚠️  WARNING: Deleting log files is permanent!${NC}"
    echo -e "${BLUE}Options:${NC}"
    echo -e "  ${GREEN}1.${NC} Keep all log files (Safe option)"
    echo -e "  ${GREEN}2.${NC} Delete old log files (> 30 days)"
    echo -e "  ${GREEN}3.${NC} Delete empty log files (0 bytes)"
    echo -e "  ${GREEN}4.${NC} Delete specific log files (choose interactively)"
    echo -e "  ${GREEN}5.${NC} Backup then delete all analyzed logs"
    echo -e "  ${GREEN}6.${NC} Skip deletion (Continue)"
    
    echo -e "\n${CYAN}Enter your choice (1-6):${NC} "
    read -r choice
    
    case $choice in
        1)
            echo -e "${GREEN}✅ Keeping all log files.${NC}"
            log_message "INFO" "User chose to keep all log files"
            return 0
            ;;
        2)
            delete_old_logs
            ;;
        3)
            delete_empty_logs
            ;;
        4)
            interactive_deletion
            ;;
        5)
            backup_and_delete_all
            ;;
        6)
            echo -e "${GREEN}✅ Skipping deletion.${NC}"
            log_message "INFO" "User skipped log deletion"
            return 0
            ;;
        *)
            echo -e "${RED}Invalid choice. Skipping deletion.${NC}"
            return 0
            ;;
    esac
}

# Function to delete old log files
delete_old_logs() {
    echo -e "\n${YELLOW}🗑️  Deleting log files older than 30 days...${NC}"
    
    local deleted_count=0
    local total_size=0
    
    if [[ -f "$TEMP_DIR/file_metadata.txt" ]]; then
        while IFS='|' read -r filename fullpath size lines issues date; do
            # Get file age in days
            if [[ -f "$fullpath" ]]; then
                local file_age=$(( ( $(date +%s) - $(date -r "$fullpath" +%s) ) / 86400 ))
                
                if [[ $file_age -gt 30 ]]; then
                    # Ask for confirmation
                    echo -e "  ${YELLOW}Found old file: $filename (${file_age} days old, ${size})${NC}"
                    echo -e "  ${CYAN}Delete this file? (y/n):${NC} "
                    read -r confirm
                    
                    if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
                        # Create backup first
                        cp "$fullpath" "$BACKUP_DIR/" 2>/dev/null
                        
                        # Get file size before deletion
                        local file_size_bytes=$(stat -c%s "$fullpath" 2>/dev/null || echo 0)
                        
                        # Delete the file
                        if rm "$fullpath" 2>/dev/null; then
                            ((deleted_count++))
                            total_size=$((total_size + file_size_bytes))
                            echo -e "  ${GREEN}✓ Deleted: $filename${NC}"
                            log_message "INFO" "Deleted old log file: $filename (${file_age} days old)"
                        else
                            echo -e "  ${RED}✗ Failed to delete: $filename (permission denied)${NC}"
                        fi
                    fi
                fi
            fi
        done < "$TEMP_DIR/file_metadata.txt"
    fi
    
    # Show summary
    echo -e "\n${GREEN}✅ Deleted $deleted_count old log files${NC}"
    echo -e "${GREEN}💾 Freed space: $(numfmt --to=iec $total_size)${NC}"
    echo -e "${GREEN}📦 Backup saved in: $BACKUP_DIR${NC}"
    
    log_message "INFO" "Deleted $deleted_count old log files, freed $(numfmt --to=iec $total_size)"
}

# Function to delete empty log files
delete_empty_logs() {
    echo -e "\n${YELLOW}🗑️  Deleting empty log files (0 bytes)...${NC}"
    
    local deleted_count=0
    
    if [[ -f "$TEMP_DIR/file_metadata.txt" ]]; then
        while IFS='|' read -r filename fullpath size lines issues date; do
            if [[ "$size" == "0" || "$lines" == "0" ]]; then
                echo -e "  ${YELLOW}Found empty file: $filename${NC}"
                echo -e "  ${CYAN}Delete this file? (y/n):${NC} "
                read -r confirm
                
                if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
                    # Create backup
                    cp "$fullpath" "$BACKUP_DIR/" 2>/dev/null
                    
                    if rm "$fullpath" 2>/dev/null; then
                        ((deleted_count++))
                        echo -e "  ${GREEN}✓ Deleted: $filename${NC}"
                        log_message "INFO" "Deleted empty log file: $filename"
                    else
                        echo -e "  ${RED}✗ Failed to delete: $filename (permission denied)${NC}"
                    fi
                fi
            fi
        done < "$TEMP_DIR/file_metadata.txt"
    fi
    
    echo -e "\n${GREEN}✅ Deleted $deleted_count empty log files${NC}"
    echo -e "${GREEN}📦 Backup saved in: $BACKUP_DIR${NC}"
    
    log_message "INFO" "Deleted $deleted_count empty log files"
}

# Function for interactive deletion
interactive_deletion() {
    echo -e "\n${YELLOW}🗑️  Interactive Log File Deletion${NC}"
    echo -e "${BLUE}Select files to delete:${NC}\n"
    
    local file_list=()
    local index=1
    
    # Display files with numbers
    if [[ -f "$TEMP_DIR/file_metadata.txt" ]]; then
        while IFS='|' read -r filename fullpath size lines issues date; do
            echo -e "  ${GREEN}$index.${NC} $filename (${size}, ${lines} lines, ${YELLOW}$issues issues${NC})"
            file_list+=("$fullpath")
            ((index++))
        done < "$TEMP_DIR/file_metadata.txt"
    fi
    
    echo -e "\n${CYAN}Enter numbers to delete (e.g., 1 3 5) or 'all' for all files:${NC} "
    read -r selection
    
    local deleted_count=0
    
    if [[ "$selection" == "all" ]]; then
        echo -e "${RED}⚠️  Are you sure you want to delete ALL log files? (yes/no):${NC} "
        read -r confirm
        if [[ "$confirm" == "yes" ]]; then
            for fullpath in "${file_list[@]}"; do
                # Create backup
                cp "$fullpath" "$BACKUP_DIR/" 2>/dev/null
                
                if rm "$fullpath" 2>/dev/null; then
                    ((deleted_count++))
                    echo -e "  ${GREEN}✓ Deleted: $(basename "$fullpath")${NC}"
                else
                    echo -e "  ${RED}✗ Failed: $(basename "$fullpath") (permission denied)${NC}"
                fi
            done
        fi
    else
        for num in $selection; do
            if [[ $num -le ${#file_list[@]} && $num -gt 0 ]]; then
                local fullpath="${file_list[$((num-1))]}"
                echo -e "  ${YELLOW}Delete $(basename "$fullpath")? (y/n):${NC} "
                read -r confirm
                
                if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
                    # Create backup
                    cp "$fullpath" "$BACKUP_DIR/" 2>/dev/null
                    
                    if rm "$fullpath" 2>/dev/null; then
                        ((deleted_count++))
                        echo -e "  ${GREEN}✓ Deleted: $(basename "$fullpath")${NC}"
                        log_message "INFO" "Deleted log file: $(basename "$fullpath")"
                    else
                        echo -e "  ${RED}✗ Failed: $(basename "$fullpath") (permission denied)${NC}"
                    fi
                fi
            fi
        done
    fi
    
    echo -e "\n${GREEN}✅ Deleted $deleted_count log files${NC}"
    echo -e "${GREEN}📦 Backup saved in: $BACKUP_DIR${NC}"
}

# Function to backup and delete all
backup_and_delete_all() {
    echo -e "\n${YELLOW}📦 Creating backup of all log files...${NC}"
    
    local backup_count=0
    local total_size=0
    
    # Create backup directory with timestamp
    local backup_dir="$BACKUP_DIR/all_logs"
    mkdir -p "$backup_dir"
    
    # Backup all files
    if [[ -f "$TEMP_DIR/file_metadata.txt" ]]; then
        while IFS='|' read -r filename fullpath size lines issues date; do
            if [[ -f "$fullpath" ]]; then
                cp "$fullpath" "$backup_dir/" 2>/dev/null
                ((backup_count++))
                
                # Get file size
                local file_size_bytes=$(stat -c%s "$fullpath" 2>/dev/null || echo 0)
                total_size=$((total_size + file_size_bytes))
            fi
        done < "$TEMP_DIR/file_metadata.txt"
    fi
    
    echo -e "${GREEN}✅ Backup complete: $backup_count files (Total: $(numfmt --to=iec $total_size))${NC}"
    
    # Ask for deletion confirmation
    echo -e "\n${RED}⚠️  Backup completed. Delete original log files? (yes/no):${NC} "
    read -r confirm
    
    if [[ "$confirm" == "yes" ]]; then
        local deleted_count=0
        
        while IFS='|' read -r filename fullpath size lines issues date; do
            if rm "$fullpath" 2>/dev/null; then
                ((deleted_count++))
                echo -e "  ${GREEN}✓ Deleted: $filename${NC}"
            else
                echo -e "  ${RED}✗ Failed: $filename (permission denied)${NC}"
            fi
        done < "$TEMP_DIR/file_metadata.txt"
        
        echo -e "\n${GREEN}✅ Deleted $deleted_count log files${NC}"
        echo -e "${GREEN}📦 Backup location: $backup_dir${NC}"
        
        log_message "INFO" "Backed up and deleted $deleted_count log files"
    else
        echo -e "${GREEN}✅ Keeping original files. Backup saved in: $backup_dir${NC}"
    fi
}

# Function to generate report
generate_report() {
    echo -e "\n${WHITE}📝 Generating detailed report...${NC}"
    
    {
        echo "========================================="
        echo "SMART LOG ANALYZER - DETAILED REPORT"
        echo "Generated: $(date)"
        echo "========================================="
        echo ""
        
        # Add summary statistics
        echo "SUMMARY STATISTICS"
        echo "------------------"
        [[ -f "$TEMP_DIR/CRITICAL.txt" ]] && echo "CRITICAL: $(wc -l < "$TEMP_DIR/CRITICAL.txt")"
        [[ -f "$TEMP_DIR/ERROR.txt" ]] && echo "ERROR: $(wc -l < "$TEMP_DIR/ERROR.txt")"
        [[ -f "$TEMP_DIR/SECURITY.txt" ]] && echo "SECURITY: $(wc -l < "$TEMP_DIR/SECURITY.txt")"
        [[ -f "$TEMP_DIR/WARNING.txt" ]] && echo "WARNING: $(wc -l < "$TEMP_DIR/WARNING.txt")"
        [[ -f "$TEMP_DIR/INFO.txt" ]] && echo "INFO: $(wc -l < "$TEMP_DIR/INFO.txt")"
        echo ""
        
        # Add file list
        echo "FILES ANALYZED"
        echo "--------------"
        if [[ -f "$TEMP_DIR/file_metadata.txt" ]]; then
            cat "$TEMP_DIR/file_metadata.txt"
        fi
        echo ""
        
        # Add all findings
        echo "DETAILED FINDINGS"
        echo "-----------------"
        for severity in CRITICAL SECURITY ERROR WARNING INFO; do
            if [[ -f "$TEMP_DIR/${severity}.txt" ]]; then
                echo ""
                echo "[$severity]"
                echo "--------"
                cat "$TEMP_DIR/${severity}.txt"
            fi
        done
        
    } > "$REPORT_FILE"
    
    echo -e "${GREEN}✅ Report saved to: $REPORT_FILE${NC}"
}

# Function to cleanup temporary files
cleanup() {
    echo -e "\n${CYAN}🧹 Cleaning up temporary files...${NC}"
    rm -rf "$TEMP_DIR" 2>/dev/null
    log_message "INFO" "Cleanup completed"
}

# Main execution function
main() {
    show_banner
    check_root
    
    # Initialize
    log_message "INFO" "=== Smart Log Analyzer Started ==="
    log_message "INFO" "Output directory: $OUTPUT_DIR"
    
    # Create pattern file if it doesn't exist
    if [[ ! -f "$ERROR_PATTERNS_FILE" ]]; then
        create_pattern_file
    fi
    
    # Find all log files
    mapfile -t log_files < <(find_log_files)
    total_files=${#log_files[@]}
    
    if [[ $total_files -eq 0 ]]; then
        echo -e "${RED}No log files found to analyze!${NC}"
        log_message "ERROR" "No log files found"
        exit 1
    fi
    
    echo -e "\n${GREEN}🚀 Starting batch analysis of $total_files log files...${NC}\n"
    
    # Initialize progress counter
    local current=0
    
    # Process each log file
    for log_file in "${log_files[@]}"; do
        ((current++))
        
        # Show progress bar
        local percent=$((current * 100 / total_files))
        local bar=$(printf "%*s" $((percent / 2)) | tr ' ' '=')
        printf "\r${CYAN}Progress: [%-50s] %d%% (%d/%d files)${NC}" "$bar" "$percent" "$current" "$total_files"
        
        # Scan the file
        scan_log_file "$log_file" >/dev/null 2>&1
    done
    
    echo -e "\n${GREEN}✅ Batch analysis complete!${NC}\n"
    
    # Display results by severity
    display_severity_results
    
    # Generate report
    generate_report
    
    # Ask about log deletion
    ask_log_deletion
    
    # Show backup location if any files were deleted
    if [[ -d "$BACKUP_DIR" && $(ls -A "$BACKUP_DIR" 2>/dev/null) ]]; then
        echo -e "\n${GREEN}📦 Backup files are stored in: $BACKUP_DIR${NC}"
        echo -e "${YELLOW}You can restore them later if needed.${NC}"
    fi
    
    # Final summary
    echo -e "\n${WHITE}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${WHITE}║                    ANALYSIS COMPLETE                        ║${NC}"
    echo -e "${WHITE}╚════════════════════════════════════════════════════════════╝${NC}"
    echo -e "\n${GREEN}📊 Report: $REPORT_FILE${NC}"
    
    # Cleanup
    cleanup
    
    log_message "INFO" "=== Smart Log Analyzer Finished ==="
}

# Run main function
main "$@"