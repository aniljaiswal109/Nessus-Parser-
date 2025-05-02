The script is a Python tool designed to parse Nessus vulnerability scan reports, process and merge vulnerability data, and generate HTML reports. Here's a description of its functionality:

Script Description

Overview This script parses Nessus XML scan reports to extract vulnerability details, including CVE/CWE IDs, severity levels, and other pertinent information. It then generates two HTML reports: one summarizing vulnerabilities in a table format and another providing detailed findings for each vulnerability. The script ensures readability and ease of use, integrating best practices for security analysis and reporting.

Features

Parsing Nessus Files:

The script reads and parses Nessus XML files to extract detailed information about each reported vulnerability.
It captures details such as affected IPs, vulnerability names, CVE/CWE IDs, severity levels, recommendations, references, descriptions, and ports.
Adjusting Severity Levels:

The script adjusts the severity levels of specific vulnerabilities based on predefined conditions. For example:
"SSLv3 Padding Oracle On Downgraded Legacy Encryption Vulnerability (POODLE)" is marked as Low.
"SSL Version 2 and 3 Protocol Detection" is marked as High.
Merging Vulnerabilities:

Vulnerabilities are merged based on their names to consolidate data, preventing redundancy. This includes merging affected IPs and CVE/CWE IDs.
Sorting by Severity:

The vulnerabilities are sorted by severity levels (Critical, High, Medium, Low) for clear prioritization.
Generating HTML Reports:

Summary Report: A table summarizing the vulnerabilities, sorted by severity, with color-coded severity levels.
Detailed Findings Report: A detailed report for each vulnerability, including descriptions, recommendations, and proof of concept.
User Interaction:

The script prompts the user to input the path of the Nessus file.
It provides feedback on the generated reports' locations.
Dependencies:

Standard Python libraries: os, xml.etree.ElementTree, collections.defaultdict.
Example Execution
$ python nessus_parser.py
