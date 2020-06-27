# Triage Check
#
# This plugin highlights obvious signs of malicious activity.
# #############################
# #### !!! LIMITATIONS !!! ####
# #############################
#
# This is not an indepth tool that checks for hollowing, injection etc.
# It makes lots of assumptions. It uses pslist.
# Malware can evade this scan. This checks for LOW HANGING FRUIT.
# Do not think a clean scan with this plugin means the
# system is free from tampering.
# This plugin WILL, however, find some common characteristics
# of attacker behaviour. Use it as PART of your arsenal.
#
# ############################
# ############################
# ############################
#
# Authors:
# Taz Wake (t.wake@halkynconsulting.co.uk)
#
# This file is part of Volatility.
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Volatility is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Volatility.  If not, see <http://www.gnu.org/licenses/>.
#

import volatility.win32 as win32
import volatility.utils as utils
import volatility.plugins.common as common

from volatility.renderers import TreeGrid


class TriageCheck(common.AbstractWindowsCommand):
    '''Checks for OBVIOUS signs of tampering - please note limitations'''

    def calculate(self):
        addr_space = utils.load_as(self._config)
        tasks = win32.tasks.pslist(addr_space)

        return tasks

    def generator(self, data):
        lsasscount = 0
        smsscount = 0
        for task in data:
            response = "-"
            holder = ""
            procname = str(task.ImageFileName)
            pid = int(task.UniqueProcessId)

            # Check smss for known attacks
            # Should only be 1 instance of smss, running from system32
            check = "smss.exe"
            if procname == check:
                smsscount = smsscount+1
                # Check number of instances
                if smsscount > 1:
                    # multiple smss found
                    response = "Multiple instances of SMSS found"
                # Check location
                imgpath = str(task.Peb.ProcessParameters.ImagePathName)
                path = str("\system32\smss.exe")
                if path in imgpath.lower():
                    # valid path
                    holder = "bypass"
                else:
                # invalid path
                    response = "SMSS launched from invalid path"

            # Check csrss is running from system32
            check = "csrss.exe"
            if procname == check:
                # Check location
                imgpath = str(task.Peb.ProcessParameters.ImagePathName)
                path = str("\system32\csrss.exe")
                if path in imgpath.lower():
                    # valid path
                    holder = "bypass"
                else:
                # invalid path
                    response = "CSRSS launched from invalid path"

            # Check services.exe is running from system32
            check = "services.exe"
            if procname.lower() == check:
                path = "\system32\services.exe"
                imgpath = str(task.Peb.ProcessParameters.ImagePathName)
                if path in imgpath.lower():
                    # valid path
                    holder = "bypass"
                else:
                    # invalid path
                    response = "Services.exe running from unusual location"

            # Check for impersonation
            # Check for CSRSS impersonation
            check = ["cssrss.exe", "cssrs.exe", "csrss.exe"]
            if procname == check:
            # if task.ImageFilename == [cssrss.exe, cssrs.exe, csrss.exe]:
                # looks suspicious
                response = "Possible impersonation attempt - CSRSS"
            # Check for SVCHost impersonation
            check = ["scvhost.exe", "svch0st.exe", "sscvhost.exe", "svcchost.exe", "scvh0st.exe", "svchozt.exe", "svchot.exe", "scvhot.exe"]
            if procname.lower() == check:
                # possible impersonation
                response = "Posible impersonation of SVCHOST.EXE"
            # Check for DLLHOST impersonation
            check = ["dllh0st.exe", "dllhot.exe", "d1lhost.exe", "dl1host.exe", "d11host.exe", "d11h0st.exe", "dIIhost.exe", "dIIh0st.exe", "dIlhost.exe", "dlIhost.exe"]
            if procname.lower() == check:
                # possible impersonation
                response = "Posible impersonation of DLLHOST.EXE"
            # Check for LSASS impersonation
            check = ["lsas.exe", "lssas.exe", "ls4ss.exe", "lsasss.exe", "lssass.exe", "lsaas.exe"]
            if procname.lower() == check:
                # possible impersonation
                response = "Posible impersonation of LSASS.EXE"

            # Scan for LSASS oddities
            # Check for multiple lsass, eg Stuxnet :-)
            check = "lsass.exe"
            if procname == check:
                lsasscount = lsasscount+1
                path = str("\system32\lsass.exe")
                imgpath = str(task.Peb.ProcessParameters.ImagePathName)
                # Check number of instances
                if lsasscount > 1:
                    # multiple lsass found
                    response = "Multiple instances of LSASS found"
                # Check lsass is running from system32
                if path in imgpath.lower():
                    # valid path
                    holder = "bypass"
                else:
                    # invalid path
                    response = "lsass.exe running from unusual location"

            # Check for oddly short file length executables - eg. a.exe
            # first, account for system process being the odd one out
            if procname.lower() == "system":
                holder = "bypass"
                # Bypass other checks here.
            else:
                # check for data collection issues 
                # where procname doesn't contain full file name
                if "." not in procname:
                    holder = "bypass"  # Bypass other checks here.
                else:
                    exename, extension = procname.split('.')  # split first bit
                    if len(exename) < 3:
                        response = "Unusually short filename"
                    # Check the extension
                    if extension.lower() != "exe":
                        # possibly suspicious
                        response = "Possibly suspicious extension"

            # output in "Unified Output format"
            if response != "-":
                yield (0, [
                    int(pid),
                    str(procname),
                    str(response),
                    ])
            else:
                continue

    def unified_output(self, data):
        tree = [
            ("PID", int),
            ("Filename", str),
            ("Triage Response", str),
            ]

        return TreeGrid(tree, self.generator(data))
    
