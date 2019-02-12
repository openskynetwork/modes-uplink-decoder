#   Copyright (C)
# 
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
# 
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
# 
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see http://www.gnu.org/licenses/. 
# 
#   Authors: Vasileios Dimitrakis <dimitrva [at] student [dot] ethz [dot] ch>
#            Daniel Moser <daniel [dot] moser [at] inf [dot] ethz [dot] ch>

import re
# Functions for CRC calculation and ICAO address
# Based on CRC calculation for Mode-S transponders, 1 December 1994, Hunt P.

# This function transorms input message into byte by byte representation.
def parse_hex(m):
    m = m[2:]
    m = m.zfill(len(m) + len(m) % 2)
    m_sliced =  ' '.join(m[i:i+2] for i in range(0, len(m), 2))
    data = m_sliced.split(' ')
    data_updated = [0]*len(data)
    for i in range(len(data)):
        data_updated[i] = int(data[i], 16)
    return uplink_bitshift_crc(data_updated)

# This function returns the calculated ICAO24 address.
def uplink_bitshift_crc(data):
    p = 0xFFF409 #polynomial
    a = data  #rx'ed uplink data (32 or 88 bits)
    crc = 0

    for byte in a:
        crc = crc ^ (byte << 16)
        for j in range(8):
            if (crc & 0x800000):
                crc = (crc << 1) ^ p
            else:
                crc = (crc << 1)

    crc = crc >> 24
    final_crc = hex(crc)

    if len(final_crc) == 7:
        final_crc = re.sub(r"x","0",final_crc)
    if final_crc[-1] == 'L':
        return final_crc[-7:-1]
    else:
        return final_crc[-6:]

