# Copyright (c) 2025 StarSphere. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ...core.memory_map import FlashRegion, RamRegion, MemoryMap
from ...debug.svd.loader import SVDFile
from ..family.target_nRF54L import NRF54L

FLASH_ALGO = {
    'load_address' : 0x20000000,

    # Flash algorithm as a hex string
    'instructions': [
    0xe7fdbe00, 0xf8d24a02, 0x2b003400, 0x4770d0fb, 0x5004e000, 0x47702000, 0x47702000, 0x49072001,
    0xf8c1b508, 0xf7ff0500, 0xf8c1ffed, 0x20000540, 0xffe8f7ff, 0x0500f8c1, 0xbf00bd08, 0x5004e000,
    0x47702000, 0x43f8e92d, 0x0301f242, 0x4e152400, 0xf8c64615, 0xf7ff3500, 0x4627ffd5, 0x0801f04f,
    0xd305428c, 0x20004b0f, 0x7500f8c3, 0x83f8e8bd, 0xf5b21b0a, 0xbf287f00, 0x7200f44f, 0xeb052300,
    0xeb040904, 0xf8590c00, 0xf84ce003, 0x3304e003, 0xd8f8429a, 0x8008f8c6, 0xffb4f7ff, 0x7400f504,
    0xbf00e7de, 0x5004e000
    ],

    # Relative function addresses
    'pc_init': 0x20000015,
    'pc_unInit': 0x20000019,
    'pc_program_page': 0x20000045,
    'pc_erase_sector': 0x20000041,
    'pc_eraseAll': 0x2000001d,

    'static_base' : 0x20000000 + 0x00000004 + 0x000000a4,
    'begin_stack' : 0x20002000,
    # Big pages amortize the ~100 ms fixed cost per ProgramPage call on the
    # LM20 RRAM controller (measured flat from 64 B to 4 KB).
    'page_size' : 0x8000,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    # Single buffer only: writing the second page buffer while a program call is
    # running corrupts the in-flight page on LM20B silicon. Kept clear of the
    # stack (top at 0x20002000, growing down).
    'page_buffers' : [0x20004000],
    'min_program_length' : 0x4,

    # Relative region addresses and sizes
    'ro_start': 0x4,
    'ro_size': 0xa8,
    'rw_start': 0xa8,
    'rw_size': 0x0,
    'zi_start': 0xa8,
    'zi_size': 0x0,

    # Flash information
    'flash_start': 0x0,
    'flash_size': 0x1fd000,
    'sector_sizes': (
        (0x0, 0x1fd000),
        (0xffd000, 0x1000),
    )
}

class NRF54LM20A(NRF54L):
    MEMORY_MAP = MemoryMap(
        FlashRegion(
            start=0x0,
            length=0x1FD000,  # 2 MB Flash
            blocksize=0x1000,
            page_size=0x8000,  # 32 KB pages; see FLASH_ALGO note.
            is_boot_memory=True,
            algo=FLASH_ALGO,
        ),
        # User Information Configuration Registers (UICR) as a flash region
        FlashRegion(
            start=0x00FFD000,
            length=0x1000,
            blocksize=0x4,
            is_testable=False,
            is_erasable=False,
            algo=FLASH_ALGO,
        ),
        RamRegion(start=0x20000000, length=0x80000),  # 512 KB RAM
    )

    def __init__(self, session):
        super(NRF54LM20A, self).__init__(session, self.MEMORY_MAP)
        self._svd_location = SVDFile.from_builtin("nrf54lm20a.svd")

    def check_flash_security(self):
        """Override to relax ID check for nRF54LM20A."""
        import logging
        LOG = logging.getLogger(__name__)

        target_id = self.dp.read_dp(0x24)

        if target_id & 0xFFF != 0x289:
            LOG.error("This doesn't look like a Nordic Semiconductor device!")

        if target_id & 0xF0000 not in (0x90000, 0x30000):
            LOG.error("This doesn't look like an nRF54LM20A/B device!")

        if not self.ap_is_enabled():
            if self.session.options.get('auto_unlock'):
                LOG.warning("%s APPROTECT enabled: will try to unlock via mass erase", self.part_number)
                self.mass_erase()
        else:
            LOG.warning("%s is not in a secure state", self.part_number)
