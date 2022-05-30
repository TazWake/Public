from typing import List

from volatility3.framework import renderers, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.plugins.windows import pslist, dlllist

class FastTriage(plugins.PluginInterface):
    _required_framework_version = (2, 0, 0)
    
    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(name = 'primary',
                           description = 'Memory layer for the kernel',
                           architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "nt_symbols",
                           description = "Windows kernel symbols"),
        ]
        
    def run(self):
        tasks = pslist.PsList.list_processes(self.context,
                                                self.config['primary'],
                                                self.config['nt_symbols'])        
        return renderers.TreeGrid([("PID", int), 
                                   ("Image", str),
                                   ("Handles", int),
                                   ("Threads", int),
                                   ("File Path", str),
                                   ("Status", str)
                                   ], self._generator(tasks))

    def _generator(self, data):
        lsasscount = 0
        smsscount = 0
        for task in data:
            status="" # set variables before use
            bypass="" # set variables before use
            filepath="" # set variables before use
            # Check for short filenames
            procname = str(task.ImageFileName.cast("string",max_length = task.ImageFileName.vol.count, errors= 'replace'))
            if "." not in procname:
                bypass = "bypass" # filename is incomplete, skip this check
            else:
                exename, extension = procname.split('.') # Split the filename
                if len(exename) < 3: 
                    status = status + "Short filename. "
            # Establish file path
            for entry in task.load_order_modules():
                BaseDllName = FullDllName = renderers.UnreadableValue() # Slightly more complex than needed to allow for future development
                try:
                    BinaryName = entry.BaseDllName.get_string()
                    BinaryPath = entry.FullDllName.get_string()
                    if "exe" in BinaryName:
                        filepath = BinaryPath
                        filepath = filepath.lower()
                except exceptions.InvalidAddressException:
                    pass
            # check for extra lsass
            filename = "lsass.exe"
            if procname.lower() == filename:
               lsasscount = lsasscount+1
               if lsasscount > 1:
                   status = "Multiple instances of lsass. "
               if "\\windows\\system32\\lsass.exe" not in filepath:
                   status = status + "Unusual path. "
            # Check for impersonation
            # CSRSS
            filename = "csrss.exe"
            if procname.lower() == filename:
                if "\\windows\\system32\\csrss.exe" not in filepath:
                    status = status + "Unusual path. "
            check = ["cssrss.exe", "cssrs.exe", "csrs.exe", "crss.exe", "csrsss.exe", "csrrs.exe"]
            if procname.lower() in check:
                status = status + "Possible impersonation of csrss.exe. "
            # SVCHOST 
            filename = "svchost.exe"
            if procname.lower() == filename:
                if "\\windows\\system32\\svchost.exe" not in filepath:
                    status = status + "Unusual path. "
            check = ["scvhost.exe", "svch0st.exe", "sscvhost.exe", "svcchost.exe", "scvh0st.exe", "svchozt.exe", "svchot.exe", "scvhot.exe", "svcnot.exe", "scvnot.exe", "svcnost.exe", "scvnost.exe"]
            if procname.lower() in check:
                status = status + "Possible impersonation of svchost.exe. "
            # DLLHOST
            filename = "dllhost.exe"
            if procname.lower() == filename:
                if "\\Windows\\System32\\dllhost" not in filepath:
                    status = status + "Unusual path. "
            check = ["dllh0st.exe", "dllhot.exe", "d1lhost.exe", "dl1host.exe", "d11host.exe", "d11h0st.exe", "diihost.exe", "diih0st.exe", "dilhost.exe", "dlihost.exe"]
            if procname.lower() in check:
                status = status + "Possible impersonation of dllhost.exe. "
            # Check for temp folder use
            tempfolders = ["temp","appdata\\local", "appdata\\roaming", "spool\\drivers\\color", "tmp"] # Add folders as needed
            for fp in tempfolders:
                if fp in filepath:
                    status = status + "Possible temp folder. "
            yield (0, [
                   int(task.UniqueProcessId),
                   procname,
                   task.get_handle_count(),
                   task.ActiveThreads,
                   filepath,
                   status
                   ])
