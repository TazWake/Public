# DFIR Data Collection Guidance
*Note: This is guidance aimed at supporting your DFIR collection plans and policies. It should not be read as endorsement of a specific tool or process. All tools used must be correctly licenced for use.*

## Tooling
### Ram Collection
* Magnet Ram Capturer https://www.magnetforensics.com/resources/magnet-ram-capture/
* MoonSols DumpIt https://moonsols.com/resources.html
* Belkasoft RamCapturer https://belkasoft.com/ram-capturer

### Disk Collection
* FTKImager Lite https://accessdata.com/product-download
* Magnet Acquire https://www.magnetforensics.com/resources/magnet-acquire/

### Triage collection
* Kansa https://github.com/davehull/Kansa
* CyLR https://github.com/orlikoski/CyLR (no longer being developed)
* KAPE https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape
* DFIRTriage https://github.com/travisfoley/dfirtriage
* Trident https://reposhub.com/dotnet/cli/nov3mb3r-trident.html

### Specific collection tools
* Sysinternals https://docs.microsoft.com/en-us/sysinternals/downloads/
  * Sysinternals tools
    * psinfo
    * psloggedon
    * handle
    * listdlls
    * tcpview
    * autoruns

# Workflow
*It is important that the workflow here is decided in advance.*
Reference: https://datatracker.ietf.org/doc/html/rfc3227

There is no "right" answer here, this has to be based on organisational priorities and, if litigation is likely, legal guidance. Every option is a trade off between the types of data available.

## Option 1 - Prioritise RAM collection
This approach collects system RAM before any other evidence. This has the benefit of minimising any changes to the volatile data but can create a significant time delay until evidence is available for analysis. For reference, a 16Gb memory image will take > 60 minutes to collect and then needs to be made available to the investigators.

1.  Collect RAM
2.  Command line data collection
3.  Collect triage data
4.  Collect disk image

With this option, the RAM image will be free of any IR activities (other than the memory capture tool and associated activity) but the subsequent data collection may be pointless. While the memory image is being collected, network connections will age out and processes are likely to suspend.

## Option 2 - Prioritise live data collection
As an alternative, this approach prioritises the collection of system data which can then be analysed while RAM is being collected. It can speed up the response time but results in a memory capture that contains incident responder activities. Depending on system RAM, the commands used by the responders may overwrite artifacts relating to an attack.

1.  Command line data collection
2.  Collect RAM
3.  Collect triage data
4.  Collect disk image

This gives the best quality data regarding system information, running processes and network connections. The delay to capturing RAM might result in additional processes paging out of memory.

## Option 3 - Remote collection only
A hybrid approach, where possible, is to use remote collection tools to gather the system data before the responder accesses the device to collect RAM. This has the advantage of allowing a faster collection of initial data while mininmising the footprints.

1. Remote system data collection (Powershell/WMIC)
2. Collect system RAM (locally)
3. Remote triage data collection
4. Collect disk image (locall)

If this is an option, based on network/ACLs etc, this can provide the best compromise. Be aware that the remote connections used to gather data will show up and need to be recorded/deconflicted.

## Commandline data collection
**Note**: This requires an elevated command prompt. 

### Profile system
1. hostname && date /t && time /t > profile.txt
2. psinfo -accepteula > system.txt

### Collect network data
1. netstat -ano > netstat.txt
2. netstat -b > netstat_exes.txt
3. tcpvcon -nac > tcpview_output.csv
4. ipconfig /displaydns > dnsresults.txt
5. ipconfig /all > ipconfig.txt
6. arp -a > arp.txt
7. nbtstat -S > nbtstat.txt

### Collect process & task info
1. psinfo -accepteula -h -s -c -d > psinfo.csv
2. tasklist /V /FO:csv > tasklist.csv
3. tasklist /SC /FO:csv > tasklist-services.csv
4. wmic process list /format:csv > processes.csv
5. wmic service list /format:csv > services.csv
6. schtasks /Query /FO csv /V > scheduledtasks.csv
7. sc.exe query state=all > sc_query.csv
8. wmic startup list /format:csv < startup.csv
9. autorunsc.exe -accepteula -a * -s -h -vr -c > autoruns.csv
10. handle -accepteula -u > handles.txt
11. listdlls -accepteula -u > unsignedDLLs.txt

### Collect logged in user data
1. wmic sysaccount list /format:csv > systemaccounts.csv
2. wmic netlogin list /format:csv > networklogins.csv
3. wmic useraccount list /format:csv > users.csv
4. psloggedon.exe -accepteula > logged_on_users.txt
