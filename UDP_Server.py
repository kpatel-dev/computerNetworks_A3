import binascii
import socket
import struct
import sys
import hashlib
import random
import time

"""
getChecksum

This function can be called to compute the checksum for the packet.
The inputs are the ACK#, SEQ#, and Data
"""
def getChecksum(ack, seq, data):
    #Create the Checksum
    values = (ack,seq,data)
    UDP_Data = struct.Struct('I I 8s')
    packed_data = UDP_Data.pack(*values)
    chksum =  bytes(hashlib.md5(packed_data).hexdigest(), encoding="UTF-8")
    return chksum

"""
compareChecksum

This function can be called to compute the checksum for the packet and make sure it is correct.
This will help to check if the data is currupt or not
The inputs are the ACK#, SEQ#, and Data
"""
def compareChecksum(ack, seq, data, checksumReceived):
    #compute the checksum
    chksum =  getChecksum(ack, seq, data)

    if checksumReceived == chksum:
        #return true if the checksum is correct
        return True
    else:
        #return false if the checksum is not correct (data is curropt)
        return False

"""
createUDPPacket

This function can be called to create the UDP packet to reply with.
The inputs are the ACK#, SEQ#, and Data and the computed checksum
"""
def createUDPPacket(ack, seq, data):
    #get the check sum
    checksum = getChecksum(ack, seq, data)

    #Build the UDP Packet
    values = (ack,seq,data ,checksum)
    UDP_Packet_Data = struct.Struct('I I 8s 32s')
    UDP_Packet = UDP_Packet_Data.pack(*values)

    values = (ack,seq,data.decode("utf-8") ,checksum.decode("utf-8"))
    return UDP_Packet, values

"""
sendPacket

This function is used to send data. 
The input is the UDPPacket
"""
def sendPacket(UDP_Packet, addr):
    #Send the UDP Packet
    sock = socket.socket(socket.AF_INET, # Internet
                        socket.SOCK_DGRAM) # UDP
    sock.sendto(UDP_Packet, addr)

"""
Network_Delay

This method will provide a way to mimic a delay on the server side. It will delay the server ACK.
This should cause a timeout on the client side.
"""
def Network_Delay():
    if True and random.choice([0,1,0]) == 1: # Set to False to disable Network Delay. Default is 33% packets are delayed
        time.sleep(.01)
        print("Packet Delayed")

"""
Network_Loss

This method will provide a way to mimic a lost ack from the server side. It will not send the server ack.
This should cause a timeout on the client side.
"""
def Network_Loss():
    if True and random.choice([0,1,1,0]) == 1: # Set to False to disable Network Loss. Default is 50% packets are lost
        print("Packet Lost Simulated From Server Side (ACK won't be actually sent)", "\n")
        return(1)
    else:
        return(0)

"""
Packet_Checksum_Corrupter

This method will provide a way to mimic a curropted ACK. It will curropt the server ACK before sending it.
"""
def Packet_Checksum_Corrupter(packet):
    #get the check sum
    if True and random.choice([0,1,0,1]) == 1: # # Set to False to disable Packet Corruption. Default is 50% packets are corrupt
        print ('Packet corruption simulated!')
        UDP_PacketData = unpacker.unpack(packet)
        packet_data =(UDP_PacketData[0], UDP_PacketData[1], b'Corrupt!', UDP_PacketData[3])
        UDP_Packet_Data = struct.Struct('I I 8s 32s')
        UDP_Packet = UDP_Packet_Data.pack(*packet_data)
        return True, UDP_Packet
    else:
        return False, packet

#*******************************#
##____MAIN______##
#*******************************#
UDP_IP = "127.0.0.1"
UDP_PORT = 5005
unpacker = struct.Struct('I I 8s 32s')


#Create the socket and listen
sock = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP
sock.bind((UDP_IP, UDP_PORT))

print('Server waiting to connect\n')

#initialize the expected sequence number, initially, we should expect seq 0
expectedSeq=0

while True:
    #Receive Data
    data, addr = sock.recvfrom(1024) # buffer size is 1024 bytes
    UDP_Packet = unpacker.unpack(data)
    values = (UDP_Packet[0],UDP_Packet[1],UDP_Packet[2].decode("utf-8"),UDP_Packet[3].decode("utf-8"))
    print("received from:", addr)
    print("received message:", values)

    #Compare Checksums to test for corrupt data
    if  compareChecksum(UDP_Packet[0],UDP_Packet[1],UDP_Packet[2],UDP_Packet[3]):
        print('CheckSums Match, Packet OK')

        if UDP_Packet[1] == expectedSeq:
            print('Expected sequence number received')
            expectedSeq = (expectedSeq + 1) % 2  # since it was the expected sequence number, the next expected should be the flipped value
        else:
            # since it was not the expected sequence number, it means it was a duplicate packet
            # dont need to flip the bit for the expected seq number
            print('Duplicate sequence number received')

        UDPResponse, values=createUDPPacket(1, UDP_Packet[1], UDP_Packet[2])
        if not Network_Loss():
            Network_Delay()
            corrupt, UDPResponse = Packet_Checksum_Corrupter(UDPResponse)
            if corrupt:
                values= (values[0], values [1],'Corrupt!',  values[3])
            sendPacket(UDPResponse, addr)
            print('Packet sent: ', values,"\n")	#Display sent packet

    else:
        print('Checksums Do Not Match, Packet Corrupt')

        UDPResponse, values=createUDPPacket(1, (UDP_Packet[1] + 1) % 2, UDP_Packet[2]) #the seq number should be flipped in the response
        if not Network_Loss():
            Network_Delay()
            corrupt, UDPResponse = Packet_Checksum_Corrupter(UDPResponse)
            if corrupt:
                values= (values[0], values [1],'Corrupt!',  values[3])
            sendPacket(UDPResponse, addr)
            print('Packet sent: ', values, "\n")	#Display message
