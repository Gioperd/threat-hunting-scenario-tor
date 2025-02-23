<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/Gioperd/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that contained the string "tor" and discovered that the user "labuser" downloaded a Tor installer, executed it, and created multiple Tor-related files on the desktop. One of these files was `tor-shopping-list.txt`, created at `2025-02-22T13:52:03.6189482Z`. These events started at `2025-02-22T13:37:08.3135929Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where FileName contains "tor"
| where InitiatingProcessAccountName == "labuser"
| where DeviceName == "giov-windows-on"
| where Timestamp >= datetime(2025-02-22T13:37:08.3135929Z)
| order by Timestamp desc 
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
![image](https://github.com/user-attachments/assets/be7b286b-a181-4f83-8c9c-8bbaf0868568)

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any ProcessCommandLine that contained `tor-browser-windows-x86_64-portable-14.0.6.exe`. Logs confirmed that at `2025-02-22T07:42:04Z`, the user "labuser" on the `giov-windows-on` device ran the file `tor-browser-windows-x86_64-portable-14.0.6.exe` from the Downloads folder. The file was executed with the silent installation flag `(/S)`, indicating an unattended installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "giov-windows-on"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.6.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
![image](https://github.com/user-attachments/assets/4d795dbc-6e5d-482e-b1a6-9f95b301bc82)

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that the user "labuser" actually opened the Tor browser. Logs confirmed that `tor-browser.exe` was executed at `2025-02-22T13:37:53.7946665Z`. Additional instances of `firefox.exe` (Tor browser) and `tor.exe` were also spawned afterward, confirming active usage of the Tor browser.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "giov-windows-on"
| where FileName has_any ("tor-browser.exe", "tor.exe", "firefox.exe")
| order by Timestamp desc
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
![image](https://github.com/user-attachments/assets/3809aff7-c754-4f1c-a358-276dda7cd5a8)

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication that the Tor browser was used to establish connections over known Tor network ports. Logs confirmed that at `2025-02-22T13:42:54.0410892Z`, the user "labuser" successfully connected to a remote IP address `146.70.120.58` via port `9001`. The connection was initiated by `tor.exe`, located in `C:\Users\labuser\Desktop\Tor Browser\Browser\TorBrowser\Tor`.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "threat-hunt-lab"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/a5adc416-7b7b-423d-bc8a-6406c664fab7)

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-02-22T07:37:08.3135929Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.6.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\labuser\Downloads\tor-browser-windows-x86_64-portable-14.0.6.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-02-22T07:39:50.0000000Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.0.6.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.6.exe /S`
- **File Path:** `C:\Users\labuser\Downloads\tor-browser-windows-x86_64-portable-14.0.6.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-02-22T13:37:53.7946665Z`
- **Event:** User "labuser" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\labuser\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-02-22T13:42:54.0410892Z`
- **Event:** A network connection to IP `146.70.120.58` on port `9001` by user "labuser" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `C:\Users\labuser\Desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-02-22T13:43:01Z` - Connected to `148.251.151.125` on port `9001`.
  - `2025-02-22T13:43:09Z` - Local connection to `107.174.138.172` on port `9001`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "labuser" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-02-22T13:52:03.6189482Z`
- **Event:** The user "labuser" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\labuser\Desktop\tor-shopping-list.txt`

---

## Summary

The user "labuser" on the "giov-windows-on" device initiated and completed the installation of the Tor browser. They proceeded to launch the browser, establish multiple connections within the Tor network, and created various files related to Tor on their desktop, including a file named "tor-shopping-list.txt."
This sequence of activities indicates that the user actively installed, configured, and used the Tor browser, likely for anonymous browsing purposes, with possible documentation or notes recorded in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `giov-windows-on` by the user `labuser`. The device was isolated, and the user's direct manager was notified.

---
