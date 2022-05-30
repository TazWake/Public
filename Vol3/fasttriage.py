from typing import List

from volatility3.framework import renderers, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.plugins.windows import pslist

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
                                   ("Status", str)
                                   ], self._generator(tasks))

    def _generator(self, data):
        lsasscount = 0
        smsscount = 0
        for task in data:
            status=""
            bypass=""
            # Check for short filenames
            procname = str(task.ImageFileName.cast("string",max_length = task.ImageFileName.vol.count, errors= 'replace'))
            if "." not in procname:
                bypass = "bypass" # filename is incomplete, skip this check
            else:
                exename, extension = procname.split('.') # Split the filename
                if len(exename) < 4: 
                    status = "Short filename"
            # check for extra lsass
            filename = "lsass.exe"
            if procname == filename:
               lsasscount = lsasscount+1
               if lsasscount > 1:
                   status = "Multiple instances of lsass"
            # Check for impersonation
            check = ["cssrss.exe", "cssrs.exe", "csrs.exe", "crss.exe", "csrsss.exe", "csrrs.exe"]
            if procname.lower() in check:
                status = "Possible impersonation of csrss.exe"
            check = ["scvhost.exe", "svch0st.exe", "sscvhost.exe", "svcchost.exe", "scvh0st.exe", "svchozt.exe", "svchot.exe", "scvhot.exe", "svcnot.exe", "scvnot.exe", "svcnost.exe", "scvnost.exe"]
            if procname.lower() in check:
                status = "Possible impersonation of svchost.exe"
            check = ["dllh0st.exe", "dllhot.exe", "d1lhost.exe", "dl1host.exe", "d11host.exe", "d11h0st.exe", "diihost.exe", "diih0st.exe", "dilhost.exe", "dlihost.exe"]
            if procname in check:
                status = "Possible impersonation of dllhost.exe"
            
            yield (0, [
                   int(task.UniqueProcessId),
                   procname,
                   task.get_handle_count(),
                   task.ActiveThreads,
                   status
                   ])
