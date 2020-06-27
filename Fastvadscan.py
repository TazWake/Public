# Fast VAD Scan
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


class FastVadScan(common.AbstractWindowsCommand):
    '''Quick search for suspicious memory sections'''

    def calculate(self):
        addr_space = utils.load_as(self._config)
        tasks = win32.tasks.pslist(addr_space)

        return tasks

    def generator(self, data):
        vf = ""
        for task in data:
            process_space = task.get_process_address_space()
            for vad in task.VadRoot.traverse():
                data = process_space.read(vad.Start, 1024)
                if vad.u.VadFlags.CommitCharge.v() > 30:
                    if vad.u.VadFlags.Protection.v() == 6:
                        vf = "Suspicious VAD Flags"
            if vf == "Suspicious VAD Flags":
                yield (0, [
                    str(task.ImageFileName),
                    int(task.UniqueProcessId),
                    str(vf),
                ])

    def unified_output(self, data):
        tree = [
            ("Process", str),
            ("PID", int),
            ("VAD status", str),
        ]

        return TreeGrid(tree, self.generator(data))
