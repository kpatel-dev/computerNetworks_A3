import binascii
import socket
import struct
import sys
import hashlib
import socket
import time

"""
getChecksum

This function can be called to compute the checksum for the packet.
The inputs are the ACK#, SEQ#, and Data
"""
def getChecksum(ack, seq, data):
    # Create the Checksum
    values = (ack, seq, data)
    UDP_Data = struct.Struct('I I 8s')
    packed_data = UDP_Data.pack(*values)
    chksum = bytes(hashlib.md5(packed_data).hexdigest(), encoding="UTF-8")
    return chksum


"""compareChecksum

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

This function can be called to create the UDP packet.
The inputs are the ACK#, SEQ#, and Data and the computed checksum
"""
def createUDPPacket(ack, seq, data):
    # get the check sum
    checksum = getChecksum(ack, seq, data)

    # Build the UDP Packet
    values = (ack, seq, data, checksum)
    UDP_Packet_Data = struct.Struct('I I 8s 32s')
    UDP_Packet = UDP_Packet_Data.pack(*values)

    values = (ack, seq, data.decode("utf-8"), checksum.decode("utf-8"))
    return UDP_Packet, values


"""
sendPacket

This function is used to send data. 
The input is the UDPPacket and its sequence number
Once, a response is received, the packet received will be returned 
"""
def sendPacket(UDP_Packet):
    UDP_IP = "127.0.0.1"  # server IP
    UDP_PORT = 5005  # server port
    unpacker = struct.Struct('I I 8s 32s')

    UDP_Packet_Data = unpacker.unpack(UDP_Packet)
    valueSent= (UDP_Packet_Data[0],UDP_Packet_Data[1],UDP_Packet_Data[2].decode("utf-8"),UDP_Packet_Data[3].decode("utf-8"))
    print('Packet sent: ', valueSent)  # Display message


    # Send the UDP Packet
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP

    sock.sendto(UDP_Packet, (UDP_IP, UDP_PORT))
    sock.settimeout(0.009)  # Create Timer

    try:
        #Receive Data
        retData, addr = sock.recvfrom(1024) # buffer size is 1024 bytes
        UDP_PacketRet = unpacker.unpack(retData)
        values = (UDP_PacketRet[0],UDP_PacketRet[1],UDP_PacketRet[2].decode("utf-8"),UDP_PacketRet[3].decode("utf-8"))
        print("received from:", addr)
        print("received message:", values)
        #Compare Checksums to test for corrupt data
        if  compareChecksum(UDP_PacketRet[0],UDP_PacketRet[1],UDP_PacketRet[2],UDP_PacketRet[3]):
            print('CheckSums Match, Packet OK')
            if UDP_PacketRet[1] == UDP_Packet_Data[1]:
                print('Expected Sequence Number Received')
            else:
                print('Expected sequence number was not received. Packet must have been curropted when sent. Will resend data. "\n"')
                #don't do anything, wait for a timeout in the client side, after which the packet should be resent
                sendPacket(UDP_Packet)

        else:
            print('Checksums Do Not Match, Packet Corrupt, will resend packet \n')
            #don't do anything, wait for a timeout in the client side, after which the packet should be resent 
            sendPacket(UDP_Packet)


    except socket.timeout as e:
        # catch a timeout if it occurs, resend the packet and print an error message
        print('Time out occurred, resending the packet ........\n')
        sendPacket(UDP_Packet)
    

# *******************************#
##____MAIN______##
# *******************************#
UDP_IP = "127.0.0.1"  # server IP
UDP_PORT = 5005  # server port

# initialize socket
sock = socket.socket(socket.AF_INET,  # Internet
                     socket.SOCK_DGRAM)  # UDP

# Display the information about the connection
print("CONNECTION INFO: ")
print("UDP target IP:", UDP_IP)
print("UDP target port:", UDP_PORT, "\n")

# put the list of data to send in an array
dataList = (b'NCC-1701', b'NCC-1422', b'NCC-1017')
# initialize the sequence number
seq = 0

# Loop through all the data that needs to be sent and send it using the rdt protocol
for data in dataList:
    # Build the UDP Packet
    UDP_Packet, values = createUDPPacket(0, seq, data)
    
    # Send the UDP Packet
    sendPacket(UDP_Packet)

    # Flip sequence number
    seq = (seq + 1) % 2
    print ("\n")
