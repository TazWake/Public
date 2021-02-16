# Public Repository
Previous repos have become a bit cluttered with a mix of scripts other people might be interested in and ones only I am ever going to use and even then for very specific tasks. As a result I have created this as a home for things other people might be interested in.

This README will act as the parent index with a summary of "how to use" if appropriate.

Sections will include:
- [x] Volatility 2.x Plugins
- [ ] Volatility 3.x Plugins 
- [ ] Powershell Scripts
- [x] Bash Scripts
- [X] Python Scripts
- [ ] DFIR Notes


# Volatility 2.x Plugins
*Note: the plugins here have only ever been tested with volatility 2.6*
## RAMSCAN
The first volatility plugin is `ramscan.py`. 
This plugin lists running processes with PID and Parent PID, Command Line used to invoke the process and a check to see what the VAD settings are. If the VAD is set to Read, Write, Execute it is marked as suspicious.

### How to use ramscan.py
1. Download the plugin to a folder on your local machine.
2. Invoke volatility calling the plugins folder before anything else. eg: `python vol.py --plugins={path/to/plugins} --profile={profile for memory image} -f {path to image} ramscan`
3. A more useable method is to set an output format and output file as the data presented by this plugin can quickly fill a console window.

*recommended use*

`python vol.py --plugins={path/to/plugins} --profile={profile for memory image} -f {path to image} ramscan --output=html --output-file=ramscan.html`

### Example output

```
Name           PID  Parent Command Line   VAD               
conhost.exe    6248    748 \??\C:\WINDOWS\system32\conhost.exe "9131723291973856416-156581232056986786412445124951738786652-244451647283318875 Suspicious RWX VAD
scPopup.exe    6284   4616 "C:\Program Files\Xerox\scPopup.exe" /s /k /t /g Suspicious RWX VAD
GROOVE.EXE     6384   4616 "C:\Program Files\Microsoft Office 15\root\office15\GROOVE.EXE" /RunFolderSync /TrayOnly  Suspicious RWX VAD
mobsync.exe    6672    936 C:\WINDOWS\System32\mobsync.exe -Embedding Suspicious RWX VAD
ucmapi.exe     5748    936 "C:\Program Files\Microsoft Office 15\Root\Office15\UcMapi.exe" -Embedding Suspicious RWX VAD
powershell.exe 5772   6188 powershell -nop -exec bypass -EncodedCommand SQBFAFgAIAAoACgAbgBlAHcALQBvAGIA...ACcAaAB0AHQAcAA6AC8ALwAxADIANwAuADAALgAwAC4AMQA6ADUAMgA4ADAAOAAvACcAKQApAA== Suspicious RWX VAD
```
### IR Notes
* Look for command execution from unusual locations
* Look for suspicious command execution: Eg encoded Powershell
* Look for memory sections which allow read-write-execute

## CMDCHECK

This volatility plugin scans memory for `cmd.exe` execution and checks the standard handles.

If cmd.exe is being used for data exfiltration (or other unwanted activity) it is likely that the handles will change. This is a good way to check for backdoors / modification (Pages 230 - 232 of The Art of Memory Forensics).

### Use

1. Download the plugin to a local filesystem
2. Run the plugin against a memory image: `python vol.py --plugins={path/to/plugin} --profile={image profile} -f {memory.img} cmdcheck`
3. Any deviation from the norm will be annotated with **!*!**
4. Note: *This does not work if the process has exited memory*

### IR Notes

* Modified handles in cmd.exe is an indicator of malice.

## Fast VAD Scan

This is a volatility plugin, similar to malfind, which looks at the number of pages committed and the VAD settings. It **does not** extract files so may run faster.

When executed this plugin will return the process name and PID for any process which has more than 30 pages committed and RWX set.

### How to use Fast VAD Scan

1. Download the plugin to a local filesystem location
2. Run volatility calling the plugin: `python vol.py --plugins={path/to/plugins} --profile={image profile} -f {filename} fastvadscan`
3. Review output and determine if any files warrant further investigation

### IR Notes

* This is a triage tool and works best if you have suspicious files
* It can narrow down files for further analysis
* If file extraction is required, run malfind

## Path Check

This plugin scans the capture and identifies an executables which appear to have been loaded from a temp, download or user location. The choice of locations is arbritrary and can be adjusted to suit the investigation.
The location matching is case insensitive so will match `temp`, `Temp` and `TEMP` in a path.

### How to use Path Check

1. Download the plugin to a local files store
2. Invoke volatility (with the plugins folder before anything else) calling pathcheck. For example: `python vol.py --plugins={path/to/plugins} --profile={profile for memory image} -f {path to image} pathcheck`
3. Review the output - processes executed from temp / download or user locations are more likely to be malware and should be subject to further investigation.

### IR Use

This tool is best used as part of the triage process to get a quick feel for what suspicious activity is on the system.

Alternatively, it can be used as part of a threat hunting review via a remote access agent (such as F-Response)

## Triagecheck

This volatility plugin is designed to quickly parse the process list and identify some **obvious** signs of malicious activity. It is not designed to act as an indepth assessment tool and works best for investigators looking to triage multiple platforms quickly. 

The plugin highlights the following events:
+ SMSS - there should only be one instance and it runs from system 32
+ CSRSS - should be running from system32
+ SERVICES - this should be running from system32
+ SVCHOST - check for impersonation (e.g. scvhost / svch0st etc)
+ LSASS - there should only be one instance and it should be running from system32
+ DLLHOST - check for impersonataion (e.g. dl1host.exe)
+ SHORT FILE NAMES - look for 1 or 2 character file names (e.g. a.exe)
+ UNUSUAL EXTENSIONS - look for non exe files running in memory (e.g. c99shell.php)

### How to use triagecheck
1. Download the file to a local plugin store.
2. Invoke volatility calling the plugin. Eg `python vol.py --plugins={path/to/plugins} --profile={profile for memory image} -f {path to image} triagecheck`
3. Where the plugin generates a warning message, prioritise this for further investigation

# Powershell Scripts
TBC

# Bash Scripts
## Memory Precook
This is a script designed to run a standard range of data extraction commands against a memory image. Each command output is saved to a text file and a running log of activity is maintained.
The objective of this script is to ensure a consistent approach to information capture across a team of multiple investigators with multiple memory images and reduce the need to re-run specific commands.
After the script has completed, the investigator should analyse the data and determine if additional, targeted, collection is required.

### How to use
1. Save the script to the same folder as the memory image.
2. Ensure `vol.py` is in the path - if not modify the script
3. Ensure `bulk_extractor` is in the path - if not modify the script
4. Determine the correct volatility profile
5. Make sure the script is executable (`chmod +x scriptname.sh`)
6. Invoke the script: `scriptname.sh imagefilename volatilityprofile`
7. Wait
8. Analyse the resulting data
### IR Notes
This is a tool for collecting data, the output needs to be analysed.

## Evidence Collector
This script captures process details, netstat, arp cache, routing tables and a disk image from a target linux machine. With modification it can capture the contents of /proc or take a memory image. However it is probably easier to do this with LMG.
The objective of this script is to capture data in alignment to RFC3227 in an automated fashion to allow responders to capture at scale and record their actions.
### How to use
1. Store the script somewhere with access to the target system.
2. Ensure there is an evidence storage drive mounted (consider capacity as a full disk image will be taken)
3. Ensure elevated privs are available.
4. Run the script from an elevated account (or via `sudo`) with: `evidence_collector.sh /path/to/storage/media`
5. Wait.
### IR Notes
This is a tool for collecting evidence. The output needs to be analysed.

## IP LOOKUPS
This is a script to gather basic data when an incident responder or CTI analyst is trying to work through a large volume of suspicious addresses. 
It is based on a script used in Investigate Like Rockstar which is definitely worth reading (ISBN-10: 1549527622 // ISBN-13: 978-1549527623).
Note: The checks are carried out against WHOIS.
### How to use
1. Save the script
2. Create a list of ips called `ips.txt` - **Make sure there are no blank lines**
3. Invoke the script
4. Analyse the resulting CSV
### IR Notes
This can be used to narrow down IP addresses of interest. Be aware that CDN use and privacy controls make the data dubious.
# Python Scripts
TBC
