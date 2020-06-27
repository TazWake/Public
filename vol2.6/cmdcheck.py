# Command Excution Check
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

import volatility.plugins.common as common
import volatility.win32 as win32
import volatility.utils as utils

from volatility.renderers import TreeGrid


class CmdCheck(common.AbstractWindowsCommand):
    '''Checks the handles on any running cmd.exe processes'''

    def calculate(self):
        addr_space = utils.load_as(self._config)
        tasks = win32.tasks.pslist(addr_space)

        return tasks

    def generator(self, data):
        # Normal behaviour for cmd.exe is 0x3L 0x7L 0xbL
        pid = ""
        stdinp = ""
        stdoutp = ""
        stderror = ""

        for proc in data:
            if str(proc.ImageFileName) != "cmd.exe":
                continue
            if proc.Peb:
                pid = proc.UniqueProcessId
                stdinp = hex(proc.Peb.ProcessParameters.StandardInput)
                if stdinp != "0x3L":
                    stdinp = stdinp + "!*!"
                stdoutp = hex(proc.Peb.ProcessParameters.StandardOutput)
                if stdoutp != "0x7L":
                    stdoutp = stdoutp + "!*!"
                stderror = hex(proc.Peb.ProcessParameters.StandardError)
                if stderror != "0xbL":
                    stderror = stderror + "!*!"
            else:
                stdinp = "-"
                stdoutp = "-"
                stderror = "-"

            yield (0, [
                str(proc.ImageFileName),
                str(pid),
                str(stdinp),
                str(stdoutp),
                str(stderror),
            ])

    def unified_output(self, data):

        tree = [
            ("Process", str),
            ("PID", str),
            ("StdInput", str),
            ("StdOutput", str),
            ("StdError", str),
            ]

        return TreeGrid(tree, self.generator(data))
