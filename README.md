
# OSForensicator

OSForensicator is a PowerShell script that leverages Osquery to collect forensic data from Windows systems. It is designed to aid in security investigations, system troubleshooting, and compliance checks by gathering a comprehensive set of system information.

## Features

OSForensicator collects data across various categories, including but not limited to:

1. System Information
2. IP Information
3. Open Connections
4. Autorun Information
5. Drivers
6. Users Information
7. Process Information
8. Process Hashes
9. Security Events
10. Network Shares
11. DNS Cache
12. RDP Sessions
13. Installed Software
14. Running Services
15. Scheduled Tasks
16. Connected Devices
17. Browser History
18. Windows Defender Data
19. PowerShell History
20. Additional System Info

Users can select specific categories of data to collect and specify a time window for data retrieval, making it flexible for different use cases.

## Usage

1. **Prerequisites:**
   - Osquery must be installed on the system and accessible via the system's PATH. Download Osquery from [Osquery's official website](https://osquery.io/downloads).
   - PowerShell 5.1 or later is recommended.

2. **Running the Script:**
   - Open PowerShell as an administrator for full data collection capabilities.
   - Navigate to the script's directory and run it using `.\OSForensicator.ps1`.
   - Follow the on-screen prompts to select the data categories and specify the time window for data collection.

3. **Output:**
   - The script creates a timestamped folder containing the collected data in both JSON and CSV formats.
   - A ZIP archive of the output folder is also generated for easy sharing.
   - An execution log is maintained in `ExecutionLog.txt` within the output folder.

## Notes

- Running the script without administrative privileges may limit the data that can be collected.
- Ensure that Osquery is properly configured and functional on the system before running the script.

## Troubleshooting

- **Osquery not found:** Ensure Osquery is installed and the `osqueryi` executable is in the system's PATH.
- **Data collection failures:** Some data categories require administrative privileges. Run the script as an administrator for complete data collection.
- **Compatibility issues:** Ensure you are using a compatible version of Osquery. Check the [Osquery documentation](https://osquery.readthedocs.io/en/stable/) for version-specific features.
