#
# This script creates a context menu in windows, which allows you to right click and call up specific DFIR tools.
#
# This is based on an idea by Mohamed Talaat, posted on LinkedIn:
# https://www.linkedin.com/posts/muhammadtalaat_dfir-forensics-windows-activity-7300469718484750337-Vk_J?utm_source=share&utm_medium=member_desktop&rcm=ACoAAABPis0BeukDSo7q0iORZRKjpbUPDnIlCUU
#
# The only change is that I have tried to make it a bit more modular for the following reasons:
# - You can easily modify the tools (names and paths are just in a hash table)
# - You could create this as part of a build script to auto-deploy to a team
# 
# The original idea came from Mohamed, so please take a moment and share some love on the LinkedIn post.
#
# First define the base registry path for the DFIR tools menu
$dfirPath = "HKLM:\SOFTWARE\Classes\Directory\Background\shell\DFIR"

# Now we create the main DFIR menu entry
New-Item -Path $dfirPath -Force | Out-Null
Set-ItemProperty -Path $dfirPath -Name "MUIVerb" -Value "DFIR Tools"
Set-ItemProperty -Path $dfirPath -Name "Icon" -Value "shell32.dll,-27"
Set-ItemProperty -Path $dfirPath -Name "SubCommands" -Value ""

# Next, lets define applications in a hashtable
# This is the IMPORTANT bit to modify.
# For each entry, you need to decide on the name you want to pop up and the link to the application
$apps = @{
    "Timeline Explorer"   = "D:\DFIR\TimelineExplorer\TimelineExplorer.exe"
    "PEStudio"  = "D:\DFIR\pestudio\pestudio.exe"
    "Registry Explorer" = "D:\DFIR\RegistryExplorer\RegistryExplorer.exe"
    "ShellBags Explorer" = "D:\DFIR\ShellBagsExplorer\ShellBagsExplorer.exe"
    "OllyDBG" = "D:\DFIR\OllyDBG\OLLYDBG.exe"
}
# You can go wild here, but keep in mind how the menu will work. Pointing to a tool that needs command line arguments might not be the best idea...

# OK, now we loop through each application and create the registry entries themselves.
foreach ($App in $apps.Keys) {
    $AppPath = "`"$($apps[$App])`""  # Thsi should ensure proper quoting of the path - if you get an error, it is probably with this.
    $RegPath = "$dfirPath\shell\$App"

    New-Item -Path $RegPath -Force | Out-Null
    Set-ItemProperty -Path $RegPath -Name "MUIVerb" -Value $App
    New-Item -Path "$RegPath\command" -Force | Out-Null
    Set-ItemProperty -Path "$RegPath\command" -Name "(Default)" -Value $AppPath
}
# And we. are. done!
Write-Output "DFIR Tools menu items created successfully."
