# Smart Log Analyzer

**Authors:** Abhinav Gautam and Md Kamre Aallam 
**Language:** Bash  

## Overview

Smart Log Analyzer is a Bash-based tool designed to automatically scan and analyze system log files. It helps developers and system administrators quickly detect system errors, warnings, security threats, and unusual patterns within large log files.

Instead of manually searching through thousands of log entries, the script processes log files automatically and highlights important events. The results are organized by severity levels, making it easier to identify and troubleshoot issues.

## Features

- Automatic discovery of system log files
- Batch processing of multiple log files
- Pattern-based issue detection
- Severity classification:
  - CRITICAL
  - ERROR
  - SECURITY
  - WARNING
  - INFO
- Summary dashboard displayed in terminal
- Detailed report generation
- Safe log file management options
- Backup before deletion of logs
- Colored terminal output for readability

## smart_log_analysis (output)

This directory contains:
- Analysis reports
- Summary files
- Temporary analysis files
- Backup files (if logs are deleted)

## Requirements

The script uses standard Linux utilities:

- bash
- grep
- awk
- sed
- find
- sort
- uniq

These tools are preinstalled on most Linux and macOS systems.

## Installation

Clone or download the project files.

Then give execution permission to the script:

```bash
chmod +x smart_log_analyzer.sh
./smart_log_analyzer.sh
sudo ./smart_log_analyzer.sh
```

## How it works 

1.The script searches common system log directories.
2.It reads log files line by line.
3.Each line is checked against predefined error patterns.
4.Detected issues are categorized into severity levels.
5.Results are displayed in a summary dashboard.
6.A detailed report is generated and saved.
7.Users can optionally manage or delete old log files safely.


## Log Management Options

After analysis, the script provides options to:

1.Keep all log files
2.Delete log files older than 30 days
3.Delete empty log files
4.Select specific log files to delete
5.Backup and delete all analyzed logs
6.Skip deletion

If logs are deleted, they are automatically backed up first.