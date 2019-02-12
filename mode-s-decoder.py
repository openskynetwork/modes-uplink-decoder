#   Copyright (C) Electrosense 2019
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
#	     Roberto Calvo-Palomino <roberto [dot] calvo [at] imdea [dot] org>


import pickle
from icao_calculation import parse_hex
from matplotlib import rc
from itertools import izip
import sys


icao_file=None
input_file=None


try:
    icao_file = str(sys.argv[2])
    input_file = str(sys.argv[1])
except:
    print "Error in the input files"
    exit(-1)


    
with open(icao_file) as f:
    ICAO_downlink = f.read().splitlines()

ICAO_downlink = [item.lower() for item in ICAO_downlink]
ICAO_downlink.append('ffffff')

ICAO_downlink = dict(izip(ICAO_downlink,ICAO_downlink))

#print ICAO_downlink

class Packet:
    pass
time = []
power = []
flag = True

time_2 = []
power_2 = []
flag_2 = True

time_3 = []
power_3 = []
flag_3 = True

dict_uf_11 = {}


packet_counter = 0
valid_packets = 0 # Total number of valid packets.
valid_icao_packets = 0
pkt_error_bit = 0

f = open('decoded_msg.pkl', 'wb')
f2 = open('packets.txt', 'wb')



def uplink_bitshift_crc(data):
    p = 0xFFF409 #polynomial (0x1FFF409 shifted left 7 bits)
    a = data  #rx'ed uplink data (32 bits)
    crc = 0

    for byte in a:
        crc = crc ^ (byte << 16)
        for j in range(8):
            if (crc & 0x800000):
                crc = (crc << 1) ^ p
            else:
                crc = (crc << 1)

    crc = crc >> 24
    return hex(crc)


for line in open(input_file, 'r'):
    # Create a new uplink packet
    pkt = Packet()
    packet_counter += 1 # Total number of received packets
    message = line.rstrip()
    message_split = message.split(' ')
    # Separate information data from metadata
    if len(message_split) == 14:
        metadata = message_split[7:]
        message_split = message_split[0:7]
    else:
        metadata = message_split[14:]
        message_split = message_split[0:14]


    mes_bin = map(lambda x: "{0:08b}".format(int(x, 16)), message_split)
    message_binary = "".join(mes_bin)

    # Prepare the payload in bytes
    # Implementation by rocapal of the CRC (already done in parseHEX)
    
#   msg_hex = []
#   step=8
#    for i in range(0,len(message_binary),step):
#        msg_hex.append(int(hex(int(message_binary[i:i+step],2)),16))
               
#    icao_hex = uplink_bitshift_crc(msg_hex)
#    icao_bin = bin(int(icao_hex,16))[2:]
    
#    mask = list("0".zfill(24)))
#    m_list = list(message_binary)
#    m_list[-24:]=mask
#    m_list[-len(icao_bin):]=list(icao_bin)
#    message_binary = ''.join(m_list)

    uf_format = int(message_binary[0:5],2)
    pkt_len = len(message_binary)
    # Check packet length.
    if pkt_len == 56:
        print uf_format
        if uf_format == 0:
            # UF Format: 0

            if int(message_binary[5:8], 2) == 0 and int(message_binary[9:13], 2) == 0 and int(message_binary[22:32], 2) == 0:				
                pkt.uf_format = uf_format
                pkt.RL = int(message_binary[8], 2)
                pkt.AQ = int(message_binary[13], 2)
                pkt.DS = int(message_binary[14:22], 2)
                data = int(message_binary[0:32], 2)
                ap = int(message_binary[32:], 2)
                pkt.ICAO = parse_hex(hex(int(message_binary, 2)))
                pkt.time = metadata[1]
                print "#############################"
                print "Average power (dB): " + str(metadata[2])
                print "Time (in samples): " + str(metadata[0])
                print "Time (in microseconds): " + str( float(metadata[0])*(1/4.0))
                print "Received Mode-S uplink packet with UF format: " + str(pkt.uf_format)
                print "RL reply length: " + str(pkt.RL)
                print "AQ Acquisition special: " + str(pkt.AQ)
                print "DS Comm-B Data Selector: " + str(pkt.DS)
                sys.stdout.write('ICAO24 address: ' + str(pkt.ICAO))

                f2.write(str(pkt.__dict__))
                f2.write('\n')
                valid_packets += 1
                pickle.dump(pkt, f, pickle.HIGHEST_PROTOCOL)

                if ICAO_downlink.has_key(str(pkt.ICAO).lower()) :
                    valid_icao_packets += 1
                    print " (valid)"
                else:
                    print " (not valid)"
                    
            else:
                # Invalid values in UF format: 0
                count1 = bin(int(message_binary[5:8],2)).count("1")
                count2 = bin(int(message_binary[9:13], 2)).count("1")
                count3 = bin(int(message_binary[22:32], 2)).count("1")
                total_count = count1 + count2 + count3
                errors_per_packet = ((total_count)/float(pkt_len)*100)
                pkt_error_bit += 1

        elif uf_format == 4 or uf_format == 5:
            # UF format: 4 or 5
            pkt.uf_format = uf_format
            pkt.PC = int(message_binary[5:8], 2)
            pkt.RR = int(message_binary[8:13], 2)
            pkt.DI = int(message_binary[13:16], 2)
            pkt.SD = int(message_binary[16:32], 2)
            data = int(message_binary[0:32], 2)
            ap = int(message_binary[32:], 2)
            pkt.ICAO = parse_hex(hex(int(message_binary, 2)))
            pkt.time = metadata[1]
            print "#############################"
            print "Average power (dB): " + str(metadata[2])
	    print "Time (in samples): " + str(metadata[0])
            print "Time (in microseconds): " + str( float(metadata[0])*(1/4.0))
            print "Received Mode-S uplink packet with UF format: " + str(pkt.uf_format)
            if pkt.uf_format == 4:
                print "Surveillance, Altitude Request"
            else:
                print "Surveillance, Identity Request"

            if pkt.PC == 0:
                print "PC protocol: " + str(pkt.PC) + ". No changes in transponder state"
            elif pkt.PC == 1:
                print "PC protocol: " + str(pkt.PC) + ". Non-selective all-call lockout"
            else:
                print "PC protocol: " + str(pkt.PC) + ". Ignored by the transponder."

            if pkt.RR <= 15:
                print "RR Reply Request: " + str(pkt.RR) + ". Reply length: Short"
            elif pkt.RR == 16:
                print "RR Reply Request: " + str(pkt.RR) + ". Reply length: Long / MB Content: Air Initiated Comm B"
            elif pkt.RR == 17:
                print "RR Reply Request: " + str(pkt.RR) + ". Reply length: Long / MB Content: Data Link Capability report"
            elif pkt.RR == 18:
                print "RR Reply Request: " + str(pkt.RR) + ". Reply length: Long / MB Content: Flight ID"
            elif pkt.RR == 19:
                print "RR Reply Request: " + str(pkt.RR) + ". Reply length: Long / MB Content: TCAS Resolution Advisory Report"
            elif pkt.RR == 20:
                print "RR Reply Request: " + str(pkt.RR) + ". Reply length: Long / MB Content: Selected Vertical Intention"
            elif pkt.RR == 21:
                print "RR Reply Request: " + str(pkt.RR) + ". Reply length: Long / MB Content: Air Initiated Comm B"
            elif pkt.RR == 22:
                print "RR Reply Request: " + str(pkt.RR) + ". Reply length: Long / MB Content: Heading and Speed Report"
            elif pkt.RR >=23 and pkt.RR <=31:
                print "RR Reply Request: " + str(pkt.RR) + ". Reply length: Long / MB Content: Reserved"

            print "DI Designator identification: " + str(pkt.DI)
            if pkt.DI == 0:
                print "SD contains IIS"
                pkt.IIS = int(message_binary[16:20], 2)
                print "Interrogator Identifier Subfield: " + str(pkt.IIS)
                pkt.OVC = int(message_binary[27], 2)
                print "Overlay Command: " + str(pkt.OVC)
            elif pkt.DI == 1:
                print "SD contains multisite II lockout and multisite data link protocol"
                pkt.IIS = int(message_binary[16:20], 2)
                print "Interrogator Identifier Subfield: " + str(pkt.IIS)
                if pkt.IIS == 0:
                    "Not valid interrogator identifier"
                pkt.MBS = int(message_binary[20:22], 2)
                print "Multisite Comm-B Subfield: " + str(pkt.MBS)
                if pkt.MBS == 0:
                    print "No Comm-B action"
                elif pkt.MBS == 1:
                    print "Comm-B reservation"
                else:
                    print "Comm-B closeout"
                pkt.MES = int(message_binary[22:25], 2)
                print "Multisite ELM Subfield: " + str(pkt.MES)
                if pkt.MES == 0:
                    print "No ELM action"
                elif pkt.MES == 1:
                    print "Comm-C reservation"
                elif pkt.MES == 2:
                    print "Comm-C closeout"
                elif pkt.MES == 3:
                    print "Comm-D reservation"
                elif pkt.MES == 4:
                    print "Comm-D closeout"
                elif pkt.MES == 5:
                    print "Comm-C reservation and Comm-D closeout"
                elif pkt.MES == 6:
                    print "Comm-C closeout and Comm-D reservation"
                else:
                    print "Comm-C and Comm-D closeout"
                pkt.LOS = int(message_binary[25], 2)
                print "Lockout Subfield: " + str(pkt.LOS)
                if pkt.LOS == 0:
                    print "No change in lockout state"
                else:
                    print "Initiate multisite All-Call lockout"
                pkt.RSS = int(message_binary[26:28], 2)
                print "Reservation Status Subfield: " + str(pkt.RSS)
                if pkt.RSS == 0:
                    print "No request"
                elif pkt.RSS == 1:
                    print "Report Comm-B reservation status in UM"
                elif pkt.RSS == 2:
                    print "Report Comm-C reservation status in UM"
                else:
                    print "Report Comm-D reservation status in UM"
                pkt.TMS = int(message_binary[29:33], 2)
                print "Tactical Message Subfield: " + str(pkt.TMS)
                if pkt.TMS == 0:
                    print "Unlinked message"
            elif pkt.DI == 2:
                print "SD contains Extended Squitter control information"
                pkt.TCS = int(message_binary[20:23], 2)
                print "Type Control Subfield: " + str(pkt.TCS)
            elif pkt.DI == 3:
                print "SD contains multisite SI lockout and extended data readout"
                pkt.SIS = int(message_binary[16:23], 2)
                print "Assigned Code of the interrogator: " + str(pkt.SIS)
                pkt.LSS = int(message_binary[22], 2)
                if pkt.LSS == 0:
                    print "Signify a multisite lockout command"
                else:
                    print "No change in lockout state"
                pkt.RRS = int(message_binary[23:27], 2)
                print "Reply Request: " + str(pkt.RRS)
                pkt.OVC = int(message_binary[27], 2)
                print "Overlay Command: " + str(pkt.OVC)
            elif pkt.DI >= 4 and pkt.DI <= 6:
                print "SD not assigned"
            else:
                print "SD contains extended data readout request"
                pkt.IIS = int(message_binary[16:20], 2)
                print "Interrogator Identifier Subfield: " + str(pkt.IIS)

                pkt.RRS = int(message_binary[16:20], 2)
                print "Reply Request: " + str(pkt.RRS)
                if pkt.RRS <= 15:
                    print "RR Reply Request: " + str(pkt.RRS) + ". Reply length: Short"
                elif pkt.RRS == 16:
                    print "RR Reply Request: " + str(pkt.RRS) + ". Reply length: Long / MB Content: Air Initiated Comm B"
                elif pkt.RRS == 17:
                    print "RR Reply Request: " + str(
                        pkt.RRS) + ". Reply length: Long / MB Content: Data Link Capability report"
                elif pkt.RRS == 18:
                    print "RR Reply Request: " + str(pkt.RRS) + ". Reply length: Long / MB Content: Flight ID"
                elif pkt.RRS == 19:
                    print "RR Reply Request: " + str(
                        pkt.RRS) + ". Reply length: Long / MB Content: TCAS Resolution Advisory Report"
                elif pkt.RRS == 20:
                    print "RR Reply Request: " + str(
                        pkt.RR) + ". Reply length: Long / MB Content: Selected Vertical Intention"
                elif pkt.RRS == 21:
                    print "RR Reply Request: " + str(pkt.RRS) + ". Reply length: Long / MB Content: Air Initiated Comm B"
                elif pkt.RRS == 22:
                    print "RR Reply Request: " + str(
                        pkt.RRS) + ". Reply length: Long / MB Content: Heading and Speed Report"
                elif pkt.RRS >= 23 and pkt.RRS <= 31:
                    print "RR Reply Request: " + str(pkt.RRS) + ". Reply length: Long / MB Content: Reserved"
                pkt.LOS = int(message_binary[25], 2)
                print "Lockout Subfield: " + str(pkt.LOS)
                if pkt.LOS == 0:
                    print "No change in lockout state"
                else:
                    print "Initiate multisite All-Call lockout"
                pkt.TMS = int(message_binary[29:33], 2)
                print "Tactical Message Subfield: " + str(pkt.TMS)
                if pkt.TMS == 0:
                    print "Unlinked message"
                pkt.OVC = int(message_binary[27], 2)
                print "Overlay Command: " + str(pkt.OVC)

            sys.stdout.write('ICAO24 address: ' + str(pkt.ICAO))
            f2.write(str(pkt.__dict__))
            f2.write('\n')
            valid_packets += 1
            if ICAO_downlink.has_key(str(pkt.ICAO).lower()) :
                valid_icao_packets += 1
                print " (valid)"
            else:
                print " (not valid)"
                
            pickle.dump(pkt, f, pickle.HIGHEST_PROTOCOL)

        elif uf_format == 11:
            if parse_hex(hex(int(message_binary, 2))) == 'ffffff':
                # UF format 11
                if int(message_binary[16:32], 2) == 0:
                    pkt.uf_format = uf_format
                    pkt.PR = int(message_binary[5:9], 2)
                    pkt.IC = int(message_binary[9:13], 2)
                    pkt.CL = int(message_binary[13:16], 2)
                    data = int(message_binary[0:32], 2)
                    ap = int(message_binary[32:], 2)
                    pkt.ICAO = parse_hex(hex(int(message_binary, 2)))
                    pkt.time = metadata[1]

                    # Plot Average power vs time.
                    if str(pkt.ICAO) == 'ffffff' and int(pkt.IC) == 1 and int(pkt.CL) == 0:
                        if flag == True:
                            start_time = metadata[1]
                            flag = False
                        time.append(int(metadata[1]) / 1000000.0 - int(start_time) / 1000000.0)
                        power.append(metadata[4])
                    if str(pkt.ICAO) == 'ffffff' and int(pkt.IC) == 5 and int(pkt.CL)==2:
                        if flag_2 == True:
                            start_time_2 = metadata[1]
                            flag_2 = False
                        time_2.append(int(metadata[1]) / 1000000.0 - int(start_time_2) / 1000000.0)
                        power_2.append(metadata[4])

                    print "#############################"
                    print "Average power (dB): " + str(metadata[2])
	            print "Time (in samples): " + str(metadata[0])
                    print "Time (in microseconds): " + str( float(metadata[0])*(1/4.0))
                    print "Received Mode-S uplink packet with UF format: " + str(pkt.uf_format)

                    if pkt.PR == 0:
                        print "Reply with probability = 1"
                    elif pkt.PR == 1:
                        print "Reply with probability = 1/2"
                    elif pkt.PR == 2:
                        print "Reply with probability = 1/4"
                    elif pkt.PR == 3:
                        print "Reply with probability = 1/8"
                    elif pkt.PR == 4:
                        print "Reply with probability = 1/16"
                    elif pkt.PR == 5 or pkt.PR == 6 or pkt.PR == 7:
                        print "Do not reply"
                    elif pkt.PR == 8:
                        print "Disregard lockout. Reply with probability = 1"
                    elif pkt.PR == 9:
                        print "Disregard lockout. Reply with probability = 1/2"
                    elif pkt.PR == 10:
                        print "Disregard lockout. Reply with probability = 1/4"
                    elif pkt.PR == 11:
                        print "Disregard lockout. Reply with probability = 1/8"
                    elif pkt.PR == 12:
                        print "Disregard lockout. Reply with probability = 1/16"
                    else:
                        print "Do not reply"
                    if pkt.CL == 0:
                        print "CL Code Label: " + str(pkt.CL)
                        print "IC Field contains the II Code: " + str(pkt.IC)
                        pkt.ID = pkt.IC
                    elif pkt.CL == 1:
                        print "CL Code Label: " + str(pkt.CL) + ". IC field contains codes 1 to 15"
                        print "IC Field contains SI code: " + str(pkt.IC)
                        pkt.ID = pkt.IC
                    elif pkt.CL == 2:
                        print "CL Code Label: " + str(pkt.CL) + ". IC field contains codes 16 to 31"
                        print "IC Field contains SI code: " + str(pkt.IC+16)
                        pkt.ID = pkt.IC+16
                    elif pkt.CL == 3:
                        print "CL Code Label: " + str(pkt.CL) + ". IC field contains codes 32 to 47"
                        print "IC Field contains SI code: " + str(pkt.IC + 32)
                        pkt.ID = pkt.IC + 32
                    elif pkt.CL == 4:
                        print "CL Code Label: " + str(pkt.CL) + ". IC field contains codes 48 to 63"
                        print "IC Field contains SI code: " + str(pkt.IC + 48)
                        pkt.ID = pkt.IC + 48
                    else:
                        print "Invalid value for CL code"
                        pkt.ID = -1

                    if str(pkt.ICAO) == 'ffffff':
                        if (pkt.uf_format, pkt.ID) not in dict_uf_11.keys():
                            dict_uf_11[(pkt.uf_format, pkt.ID)] = 1
                        else:
                            dict_uf_11[(pkt.uf_format, pkt.ID)] += 1

                    sys.stdout.write('ICAO24 address: ' + str(pkt.ICAO))
                    
                    f2.write(str(pkt.__dict__))
                    f2.write('\n')
                    valid_packets += 1
                    if ICAO_downlink.has_key(str(pkt.ICAO).lower()) :
                        valid_icao_packets += 1
                        print " (valid) "
                    else:
                        print " (not valid) "
                        
                    pickle.dump(pkt, f, pickle.HIGHEST_PROTOCOL)
                else:
                    # Invalid values in UF format: 11
                    count3 = bin(int(message_binary[16:32], 2)).count("1")
                    total_count = count3
                    errors_per_packet = ((total_count) / float(pkt_len) * 100)
                    pkt_error_bit += 1

        elif (uf_format > 0 and uf_format < 4) or (uf_format > 5 and uf_format < 11) \
               or (uf_format > 11 and uf_format < 16) or (uf_format > 16 and uf_format < 19) \
               or (uf_format > 21 and uf_format < 24):
            # UF format: 1,2,3,6,7,8,9,10,12,13,14,15,17,18,22,23
            if int(message_binary[5:32], 2) == 0:
                pkt.uf_format = uf_format
                data = int(message_binary[0:32], 2)
                ap = int(message_binary[32:], 2)
                pkt.time = metadata[1]

                print "#############################"
                print "Average power (dB): " + str(metadata[2])
	        print "Time (in samples): " + str(metadata[0])
                print "Time (in microseconds): " + str( float(metadata[0])*(1/4.0))                
                print "Received Mode-S uplink packet with UF format: " + str(pkt.uf_format)
                pkt.ICAO = parse_hex(hex(int(message_binary, 2)))
                sys.stdout.write('ICAO24 address: ' + str(pkt.ICAO))
                pkt.time = metadata[1]
                f2.write(str(pkt.__dict__))
                f2.write('\n')
                valid_packets += 1
                if ICAO_downlink.has_key(str(pkt.ICAO).lower()) :
                    valid_icao_packets += 1
                    print " (valid)"
                else:
                    print " (not valid)"
                    
                pickle.dump(pkt, f, pickle.HIGHEST_PROTOCOL)
            else:
                # Invalid packets for uplink format: 1,2,3,6,7,8,9,10,12,13,14,15,17,18,22,23
                count1 = bin(int(message_binary[5:32], 2)).count("1")
                total_count = count1
                errors_per_packet = ((total_count) / float(pkt_len) * 100)
		pkt_error_bit += 1

    else:
        if uf_format == 16:
            if parse_hex(hex(int(message_binary, 2))[:-1]) == 'ffffff':
                # UF format: 16
                if int(message_binary[5:8], 2) == 0 and int(message_binary[9:13], 2) == 0 and int(message_binary[14:32], 2) == 0:
                    pkt.uf_format = uf_format
                    pkt.RL = int(message_binary[8], 2)
                    pkt.AQ = int(message_binary[13], 2)
                    pkt.MU = int(message_binary[32:88], 2)
                    data = int(message_binary[0:88], 2)
                    ap = int(message_binary[88:], 2)
                    pkt.ICAO = parse_hex(hex(int(message_binary, 2))[:-1])
                    pkt.time = metadata[1]

                    print "#############################"
                    print "Average power (dB): " + str(metadata[4])
                    print "Time (in microseconds): " + str(metadata[1])
                    print "Received Mode-S uplink packet with UF format: " + str(pkt.uf_format)
                    print "RL reply length: " + str(pkt.RL)
                    print "AQ Acquisition special: " + str(pkt.AQ)
                    pkt.transponder_address = hex(int(message_binary[64:88],2))
                    print "Transponder address: " + str(pkt.transponder_address)
                    pkt.UDS = int(message_binary[32:40], 2)
                    print "UDS field: " + str(pkt.UDS)
                    if pkt.UDS == 50:
                        print "Broadcast Interrogation Message"
                        sys.stdout.write('ICAO24 address: ' + str(pkt.ICAO) + ", Broadcast address")
                    elif pkt.UDS == 48:
                        print "TCAS resolution messages"
                        sys.stdout.write('ICAO24 address: ' + str(pkt.ICAO))
                    else:
                        sys.stdout.write('ICAO24 address: ' + str(pkt.ICAO))

                    f2.write(str(pkt.__dict__))
                    f2.write('\n')
                    valid_packets += 1
                    if ICAO_downlink.has_key(str(pkt.ICAO).lower()) :
                        valid_icao_packets += 1
                        print " (valid) "
                    else:
                        print " (not valid) "
                                         
                    pickle.dump(pkt, f, pickle.HIGHEST_PROTOCOL)
                else:
                    count1 = bin(int(message_binary[5:8], 2)).count("1")
                    count2 = bin(int(message_binary[9:13], 2)).count("1")
                    count3 = bin(int(message_binary[14:32], 2)).count("1")
                    total_count = count1 + count2 + count3
                    errors_per_packet = ((total_count) / float(pkt_len) * 100)
                    pkt_error_bit += 1

        elif uf_format == 19:
            pkt.uf_format = uf_format
            pkt.Military = int(message_binary[5:112], 2)
            pkt.time = metadata[1]
            valid_packets += 1
            if ICAO_downlink.has_key(str(pkt.ICAO).lower()) :
                valid_icao_packets += 1
            print "#############################"
            print "Average power (dB): " + str(metadata[2])
	    print "Time (in samples): " + str(metadata[0])
            print "Time (in microseconds): " + str( float(metadata[0])*(1/4.0))
            print "Received Mode-S uplink packet with UF format: " + str(pkt.uf_format)
            print "Reserved for military use"
            f2.write(str(pkt.__dict__))
            f2.write('\n')
            pickle.dump(pkt, f, pickle.HIGHEST_PROTOCOL)

        elif uf_format == 20 or uf_format == 22:
            pkt.uf_format = uf_format
            pkt.PC = int(message_binary[5:8], 2)
            pkt.RR = int(message_binary[8:13], 2)
            pkt.DI = int(message_binary[13:16], 2)
            pkt.SD = int(message_binary[16:32], 2)
            pkt.MA = int(message_binary[32:88], 2)
            pkt.ICAO = parse_hex(hex(int(message_binary, 2))[:-1])
            pkt.time = metadata[1]

            print "#############################"
            print "Average power (dB): " + str(metadata[2])
	    print "Time (in samples): " + str(metadata[0])
            print "Time (in microseconds): " + str( float(metadata[0])*(1/4.0))
            print "Received Mode-S uplink packet with UF format: " + str(pkt.uf_format)

            if pkt.uf_format == 20:
                print "Comm-A, Altitude Request"
            else:
                print "Comm-A, Identity Request"

            if pkt.PC == 0:
                print "PC protocol: " + str(pkt.PC) + ". No changes in transponder state"
            elif pkt.PC == 1:
                print "PC protocol: " + str(pkt.PC) + ". Non-selective all-call lockout"
            else:
                print "PC protocol: " + str(pkt.PC) + ". Ignored by the transponder."

            if pkt.RR <= 15:
                print "RR Reply Request: " + str(pkt.RR) + ". Reply length: Short"
            elif pkt.RR == 16:
                print "RR Reply Request: " + str(pkt.RR) + ". Reply length: Long / MB Content: Air Initiated Comm B"
            elif pkt.RR == 17:
                print "RR Reply Request: " + str(
                    pkt.RR) + ". Reply length: Long / MB Content: Data Link Capability report"
            elif pkt.RR == 18:
                print "RR Reply Request: " + str(pkt.RR) + ". Reply length: Long / MB Content: Flight ID"
            elif pkt.RR == 19:
                print "RR Reply Request: " + str(
                    pkt.RR) + ". Reply length: Long / MB Content: TCAS Resolution Advisory Report"
            elif pkt.RR == 20:
                print "RR Reply Request: " + str(
                    pkt.RR) + ". Reply length: Long / MB Content: Selected Vertical Intention"
            elif pkt.RR == 21:
                print "RR Reply Request: " + str(pkt.RR) + ". Reply length: Long / MB Content: Air Initiated Comm B"
            elif pkt.RR == 22:
                print "RR Reply Request: " + str(pkt.RR) + ". Reply length: Long / MB Content: Heading and Speed Report"
            elif pkt.RR >= 23 and pkt.RR <= 31:
                print "RR Reply Request: " + str(pkt.RR) + ". Reply length: Long / MB Content: Reserved"

            print "DI Designator identification: " + str(pkt.DI)
            if pkt.DI == 0:
                print "SD contains IIS"
                pkt.IIS = int(message_binary[16:20], 2)
                print "Interrogator Identifier Subfield: " + str(pkt.IIS)
                pkt.OVC = int(message_binary[27], 2)
                print "Overlay Command: " + str(pkt.OVC)
            elif pkt.DI == 1:
                print "SD contains multisite II lockout and multisite data link protocol"
                pkt.IIS = int(message_binary[16:20], 2)
                print "Interrogator Identifier Subfield: " + str(pkt.IIS)
                if pkt.IIS == 0:
                    "Not valid interrogator identifier"
                pkt.MBS = int(message_binary[20:22], 2)
                print "Multisite Comm-B Subfield: " + str(pkt.MBS)
                if pkt.MBS == 0:
                    print "No Comm-B action"
                elif pkt.MBS == 1:
                    print "Comm-B reservation"
                else:
                    print "Ccomm-B closeout"
                pkt.MES = int(message_binary[22:25], 2)
                print "Multisite ELM Subfield: " + str(pkt.MES)
                if pkt.MES == 0:
                    print "No ELM action"
                elif pkt.MES == 1:
                    print "Comm-C reservation"
                elif pkt.MES == 2:
                    print "Comm-C closeout"
                elif pkt.MES == 3:
                    print "Comm-D reservation"
                elif pkt.MES == 4:
                    print "Comm-D closeout"
                elif pkt.MES == 5:
                    print "Comm-C reservation and Comm-D closeout"
                elif pkt.MES == 6:
                    print "Comm-C closeout and Comm-D reservation"
                else:
                    print "Comm-C and Comm-D closeout"
                pkt.LOS = int(message_binary[25], 2)
                print "Lockout Subfield: " + str(pkt.LOS)
                if pkt.LOS == 0:
                    print "No change in lockout state"
                else:
                    print "Initiate multisite All-Call lockout"
                pkt.RSS = int(message_binary[26:28], 2)
                print "Reservation Status Subfield: " + str(pkt.RSS)
                if pkt.RSS == 0:
                    print "No request"
                elif pkt.RSS == 1:
                    print "Report Comm-B reservation status in UM"
                elif pkt.RSS == 2:
                    print "Report Comm-C reservation status in UM"
                else:
                    print "Report Comm-D reservation status in UM"
                pkt.TMS = int(message_binary[29:33], 2)
                print "Tactical Message Subfield: " + str(pkt.TMS)
                if pkt.TMS == 0:
                    print "Unlinked message"
            elif pkt.DI == 2:
                print "SD contains Extended Squitter control information"
                pkt.TCS = int(message_binary[20:23], 2)
                print "Type Control Subfield: " + str(pkt.TCS)
            elif pkt.DI == 3:
                print "SD contains multisite SI lockout and extended data readout"
                pkt.SIS = int(message_binary[16:23], 2)
                print "Assigned Code of the interrogator: " + str(pkt.SIS)
                pkt.LSS = int(message_binary[22], 2)
                if pkt.LSS == 0:
                    print "Signify a multisite lockout command"
                else:
                    print "No change in lockout state"
                pkt.RRS = int(message_binary[23:27], 2)
                print "Reply Request: " + str(pkt.RRS)
                pkt.OVC = int(message_binary[27], 2)
                print "Overlay Command: " + str(pkt.OVC)
            elif pkt.DI >= 4 and pkt.DI <= 6:
                print "SD not assigned"
            else:
                print "SD contains extended data readout request"
                pkt.IIS = int(message_binary[16:20], 2)
                print "Interrogator Identifier Subfield: " + str(pkt.IIS)

                pkt.RRS = int(message_binary[16:20], 2)
                print "Reply Request: " + str(pkt.RRS)
                if pkt.RRS <= 15:
                    print "RR Reply Request: " + str(pkt.RRS) + ". Reply length: Short"
                elif pkt.RRS == 16:
                    print "RR Reply Request: " + str(
                        pkt.RRS) + ". Reply length: Long / MB Content: Air Initiated Comm B"
                elif pkt.RRS == 17:
                    print "RR Reply Request: " + str(
                        pkt.RRS) + ". Reply length: Long / MB Content: Data Link Capability report"
                elif pkt.RRS == 18:
                    print "RR Reply Request: " + str(pkt.RRS) + ". Reply length: Long / MB Content: Flight ID"
                elif pkt.RRS == 19:
                    print "RR Reply Request: " + str(
                        pkt.RRS) + ". Reply length: Long / MB Content: TCAS Resolution Advisory Report"
                elif pkt.RRS == 20:
                    print "RR Reply Request: " + str(
                        pkt.RR) + ". Reply length: Long / MB Content: Selected Vertical Intention"
                elif pkt.RRS == 21:
                    print "RR Reply Request: " + str(
                        pkt.RRS) + ". Reply length: Long / MB Content: Air Initiated Comm B"
                elif pkt.RRS == 22:
                    print "RR Reply Request: " + str(
                        pkt.RRS) + ". Reply length: Long / MB Content: Heading and Speed Report"
                elif pkt.RRS >= 23 and pkt.RRS <= 31:
                    print "RR Reply Request: " + str(pkt.RRS) + ". Reply length: Long / MB Content: Reserved"
                pkt.LOS = int(message_binary[25], 2)
                print "Lockout Subfield: " + str(pkt.LOS)
                if pkt.LOS == 0:
                    print "No change in lockout state"
                else:
                    print "Initiate multisite All-Call lockout"
                pkt.TMS = int(message_binary[29:33], 2)
                print "Tactical Message Subfield: " + str(pkt.TMS)
                if pkt.TMS == 0:
                    print "Unlinked message"
                pkt.OVC = int(message_binary[27], 2)
                print "Overlay Command: " + str(pkt.OVC)

            pkt.ADS = int(message_binary[32:40], 2)
            pkt.ADS1 = int(message_binary[32:36], 2)
            pkt.ADS2 = int(message_binary[36:40], 2)
            print "A-Definition Subfield ADS1: " + str(pkt.ADS1)
            print "A-Definition Subfield ADS2: " + str(pkt.ADS2)

            pkt.SLC = int(message_binary[40:44], 2)
            print "TCAS Sensitivity Level: " + str(pkt.SLC)
            f2.write(str(pkt.__dict__))
            f2.write('\n')

            valid_packets += 1
            if ICAO_downlink.has_key(str(pkt.ICAO).lower()) :
                valid_icao_packets += 1
            pickle.dump(pkt, f, pickle.HIGHEST_PROTOCOL)

        elif uf_format >= 24:

            pkt.uf_format = 24
            pkt.RC = int(message_binary[2:4], 2)
            pkt.NC = int(message_binary[4:8], 2)
            pkt.MC = int(message_binary[8:88], 2)
            pkt.ICAO = parse_hex(hex(int(message_binary, 2))[:-1])
            pkt.time = metadata[1]
            print "#############################"
            print "Average power (dB): " + str(metadata[2])
	    print "Time (in samples): " + str(metadata[0])
            print "Time (in microseconds): " + str( float(metadata[0])*(1/4.0))
            print "Received Mode-S uplink packet with UF format: " + str(pkt.uf_format)

            if pkt.RC == 0:
                print "Transmitted segment - initial"
                pkt.IIS = int(message_binary[8:12], 2)
                print "IIS subfield: " + str(pkt.IIS)
            elif pkt.RC == 1:
                print "Transmitted segment - intermediate"
                pkt.IIS = int(message_binary[8:12], 2)
                print "IIS subfield: " + str(pkt.IIS)
            elif pkt.RC == 1:
                print "Transmitted segment - final"
                pkt.IIS = int(message_binary[8:12], 2)
                print "IIS subfield: " + str(pkt.IIS)
            else:
                print "Request Comm-D downlink action by transponder"
                pkt.SRS = int(message_binary[8:24], 2)
                pkt.IIS = int(message_binary[24:28], 2)

            print "Number of C-Segment: " + str(pkt.NC)
            sys.stdout.write('ICAO24 address: ' + str(pkt.ICAO))

            f2.write(str(pkt.__dict__))
            f2.write('\n')
            valid_packets += 1
            if ICAO_downlink.has_key(str(pkt.ICAO).lower()) :
                valid_icao_packets += 1
                print " (valid) "
            else:
                print " (not valid) "
                
            pickle.dump(pkt, f, pickle.HIGHEST_PROTOCOL)

        elif (uf_format > 0 and uf_format < 4) or (uf_format > 5 and uf_format < 11) \
               or (uf_format > 11 and uf_format < 16) or (uf_format > 16 and uf_format < 19) \
               or (uf_format > 21 and uf_format < 24):
            if int(message_binary[5:88], 2) == 0:
                pkt.uf_format = uf_format
                parse_hex(hex(int(message_binary, 2))[:-1])
                pkt.time = metadata[1]
                valid_packets += 1
                if ICAO_downlink.has_key(str(pkt.ICAO).lower()) :
                    valid_icao_packets += 1
                print "#############################"
                print "Average power (dB): " + str(metadata[2])
	        print "Time (in samples): " + str(metadata[0])
                print "Time (in microseconds): " + str( float(metadata[0])*(1/4.0))
                print "Received Mode-S uplink packet with UF format: " + str(pkt.uf_format)
                sys.stdout.write('ICAO24 address: ' + str(pkt.ICAO))
                pickle.dump(pkt, f, pickle.HIGHEST_PROTOCOL)

                valid_packets += 1
                if ICAO_downlink.has_key(str(pkt.ICAO).lower()) :
		    valid_icao_packets += 1
                    print " (valid) "
                else:
                    print " (not valid) "
                
                count1 = bin(int(message_binary[5:88], 2)).count("1")
                total_count = count1
                errors_per_packet = ((total_count) / float(pkt_len) * 100)
       


# Plot power over time for the interrogators in our range

#if time!=[] and power != []:
#    fig1 = plt.figure()
#    ax1 = fig1.add_subplot(111)
#    ax1.set_xlabel('Time (us)', fontsize='larger')
#    ax1.set_ylabel('Average Power (dB)', fontsize='larger')
#    ax1.set_xlim([0, 60])
#    ax1.set_title('Average power as a function of time', fontsize='larger')
#    ax1.plot(time, power)
#    plt.show()
#
#if time!=[] and power != []:
#    fig2 = plt.figure()
#    ax2 = fig2.add_subplot(111)
#    ax2.set_xlabel('Time (us)', fontsize='larger')
#    ax2.set_ylabel('Average Power (dB)', fontsize='larger')
#    ax2.set_xlim([0, 60])
#    ax2.set_title('Average power as a function of time', fontsize='larger')
#    ax2.plot(time_2, power_2)
#    plt.show()

f.close()
f2.close()

pkt_list = []
f = open('decoded_msg.pkl', 'rb')
while 1:
    try:
        pkt_list.append(pickle.load(f))
    except (EOFError):
        break
f.close()

# Create dictionary for the number of different ICAOs
pkt_dict = {}
icao_dict = {}
for pkt in pkt_list:
    if not pkt.uf_format in pkt_dict:
        pkt_dict[pkt.uf_format] = 1
    else:
        pkt_dict[pkt.uf_format] += 1

    if pkt.uf_format != 19:
        if not pkt.ICAO in icao_dict:
            icao_dict[pkt.ICAO] = 1
        else:
            icao_dict[pkt.ICAO] += 1


valid_pkt_rate = (valid_packets/float(packet_counter))*100
valid_icao_rate = (valid_icao_packets/float(packet_counter))*100
error_bit_uf = (pkt_error_bit/float(packet_counter))*100
print ""
print "Number of detected packets: " + str(packet_counter)
print "   - Number of packets with error bits format: " + str(pkt_error_bit) + " (" + str(error_bit_uf)+"%)"
print "   - Number of decoded packets: " + str(valid_packets) + " (" + str(valid_pkt_rate)+"%)"
print "        - Number of decoded packets + correct ICAO: " + str(valid_icao_packets) + " (" + str(valid_icao_rate)+"%)"
print ""


#plt.bar(pkt_dict.keys(), pkt_dict.values())
#plt.xlabel('Uplink Format', fontsize='larger')
#plt.ylabel('Number of packets', fontsize='larger')
#plt.yscale('log')
#plt.axis([0,24,0,max(pkt_dict.values())])
#plt.title('Number of packets for each uplink format', fontsize='larger')
#plt.show()

#print pkt_dict
#print dict_uf_11
