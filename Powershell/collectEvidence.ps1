<#
collectEvidence.ps1

Purpose:
    This script will capture essential triage data from a device and store the resulting files on a removable disk.
    
Requirements:
    1. A USB or other storage location large enough to store output. 
        NOTE: Bear in mind, memory capture can result in a file approximately 5-10% larger than the system memory. The triage VHDX can be approximately 0.5gb in size.
    2. This script on the root of the USB.
    3. A correctly licenced copy of KAPE with appropriate targets/modules on in a folder called Kape at the root of the USB.
    4. A copy of Magnet Ram Capture (MRC.exe) on root of the USB.

Exectution:
    1. Run powershell with Administrator privileges.
    2. Navigate to the USB.
    3. .\collectEvidence.ps1
#>
