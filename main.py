# !/usr/bin/python
import subprocess
import os
import sys

from lib.common.compare import comapreIpaddress
from lib.packet.packet import Packet
from lib.training.train import trainModel

portHTTPS = 443

p = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'third_party', 'dpkt')
if p not in sys.path:
    sys.path.insert(0, p)
import nfqueue
import dpkt
from socket import inet_ntoa
from dpkt import ip

try:
    import ipaddress as ipaddr
except ImportError:
    import ipaddr
import math
from datetime import *
import numpy as np
import datetime
from collections import defaultdict
import numpy


def main():
    global BCRT
    global flowsCounter
    global FCRT
    global stopCollect
    global savedKeys
    global modelSystem
    global ACC
    global RIdent
    global allLength
    global targetList
    global timer
    global listKeys
    global blocking
    fileTrainingDataSet = "training-dataset.csv"
    process1 = subprocess.Popen(["iptables", "-I", "INPUT", "-p", "tcp", "-m", "state", "--state", "ESTABLISHED,RELATED,NEW", "-j", "NFQUEUE", "--queue-num", "0"], stdout=subprocess.PIPE)

    process2 = subprocess.Popen(["iptables", "-I", "OUTPUT", "-p", "tcp", "-m", "state", "--state", "ESTABLISHED,RELATED,NEW", "-j", "NFQUEUE", "--queue-num", "0"], stdout=subprocess.PIPE)

    output, err = process1.communicate()
    process2.communicate()

    print "Start real time monitor https"

    queue = nfqueue.queue()
    queue.open()  # 0 is the number of Queue
    queue.set_callback(updateQueue)  # input queue
    queue.create_queue(0)
    queue.set_queue_maxlen(307200)

    flowsCounter = []
    FCRT = defaultdict(list)
    stopCollect = []
    savedKeys = []
    BCRT = defaultdict(list)
    ACC = defaultdict(list)
    RIdent = []
    timer = 0
    listKeys = []
    blocking = []

    modelSystem = trainModel(fileTrainingDataSet)

    try:
        while True:
            queue.try_run()
    except KeyboardInterrupt:
        process2 = subprocess.Popen(["iptables", "-F"], stdout=subprocess.PIPE)
        process2.communicate()

# Callback function NFqueue Queue input/output
def updateQueue(payload):  # Update Queue
    data = payload.get_data()

    pkt = ip.IP(data)

    sport = int(pkt.tcp.sport)
    dport = int(pkt.tcp.dport)

    key = ""
    if sport == portHTTPS or dport == portHTTPS:

        # get only https
        Info = readPackets(payload, (datetime.datetime.now().microsecond))

        if Info.SYN:  # and Info.hashID not in stopcollect:

            R = False
            result = BCRT[Info.hashID]
            for pkt in result:
                if pkt.hashID == Info.hashID:
                    R = True  # It means the packet is valid
                    break

            if not R and not Info.ACK:
                BCRT[Info.hashID].append(Info)
            elif R:
                if Info.ACK:
                    for pkt in BCRT[Info.hashID]:
                        if pkt.hashID == Info.hashID:
                            pkt.ACK = True
                            break
                    FCRT[Info.hashID].append(Info)
                    listKeys.insert(0, Info.hashID)
        else:
            valid = False
            if Info.hashID in listKeys:
                valid = True

            if valid and Info.hashID not in stopCollect and (
                    Info.Handshake or Info.APPData) and Info.hashID not in blocking:
                FCRT[Info.hashID].append(Info)
                listKeys.insert(0, Info.hashID)
                if len(FCRT[Info.hashID]) >= 7:  # 5 #and Info.APPData:
                    r = serviceIdentification(Info.hashID)
        if Info.hashID not in blocking:
            payload.set_verdict(nfqueue.NF_ACCEPT)
        else:
            payload.set_verdict(nfqueue.NF_DROP)
            p2 = subprocess.Popen(
                ["iptables", "-I", "INPUT", "-s", Info.ipdst, "-j", "DROP"], stdout=subprocess.PIPE)
            p2.communicate()

            p3 = subprocess.Popen(
                ["iptables", "-I", "OUTPUT", "-d", Info.ipdst, "-j", "DROP"], stdout=subprocess.PIPE)
            p3.communicate()

    else:
        payload.set_verdict(nfqueue.NF_ACCEPT)


# Reading packets
def readPackets(payload, time):
    try:
        data = payload.get_data()
        packet = ip.IP(data)
        ipsrc = inet_ntoa(packet.src)
        sport = packet.tcp.sport
        ipdst = inet_ntoa(packet.dst)
        dport = packet.tcp.dport
        SYN = (packet.tcp.flags & dpkt.tcp.TH_SYN)
        ACK = (packet.tcp.flags & dpkt.tcp.TH_ACK)
        SYNEND = (packet.tcp.flags & dpkt.tcp.TH_FIN)
        type1 = 0
        APP = (len(packet.tcp.data) > 0 and int(ord(packet.tcp.data[0])) == 23)
        HS = (len(packet.tcp.data) > 0 and (
                int(ord(packet.tcp.data[0])) == 22 or int(ord(packet.tcp.data[0])) == 20) and digitalFootprint(packet))
        length = packet.len
        APPlength = len(packet.tcp.data)
        sni = ""
        if int(packet.tcp.dport) == 443 and len(packet.tcp.data) > 0 and int(ord(packet.tcp.data[0])) == 22:
            sni = getSNI(packet)
            # length=length-19 #remove the length of SNI
        pak = Packet(ipsrc, sport, ipdst, dport, SYN, ACK, time, APP, HS, length, sni, SYNEND, type1, packet, APPlength)
        return pak
    except:
        pass

# SNI packet
def getSNI(pkt):
    sni = ""
    try:
        if int(pkt.tcp.dport) == 443 and len(pkt.tcp.data) > 0 and int(ord(pkt.tcp.data[0])) == 22:
            records, bytes_used = dpkt.ssl.TLSMultiFactory(pkt.tcp.data)
            if len(records) > 0:
                for record in records:
                    if int(record.type) == 22 and len(record.data) > 0 and int(ord(record.data[0])) == 1:
                        digitalFootprintSample = dpkt.ssl.TLSHandshake(record.data)
                    if isinstance(digitalFootprintSample.data, dpkt.ssl.TLSClientHello):
                        client = dpkt.ssl.TLSClientHello(str(digitalFootprintSample.data))
                        for ext in client.extensions:
                            if int(ext.value) == 0:
                                sni = ext.data[5:]
                                break
    except:
        pass
    return sni

# Start service identification
def serviceIdentification(key):
    Ide = False
    if key not in savedKeys:
        packets = FCRT[key]
        if len(packets) >= 3:
            cache1, cache2, cache3, cache4, cache5, cache6 = [], [], [], [], [], []
            APPfile5 = []
            APPfile6 = []
            firstpacket = packets[0]
            sni = ""
            clienthellofeatures = []
            serverhellofeatures = []

            ipsrc = firstpacket.ipsrc
            for pkt in packets:
                if pkt.sni != "":
                    sni = pkt.sni
                if len(clienthellofeatures) == 0:
                    clienthellofeatures = clientFirstConnectServer(pkt.payload)
                if len(serverhellofeatures) == 0:
                    serverhellofeatures = serverGetDigitalFootprintFeatures(pkt.payload)
                if pkt.length > 0 and pkt.Handshake:
                    cache1.append(pkt.length)
                    cache2.append(pkt.timestamp)

                    if comapreIpaddress(pkt.ipsrc, ipsrc):
                        cache3.append(pkt.length)
                        cache4.append(pkt.timestamp)
                    elif comapreIpaddress(pkt.ipdst, ipsrc):
                        cache5.append(pkt.length)
                        cache6.append(pkt.timestamp)
                if pkt.APPData:
                    if comapreIpaddress(pkt.ipsrc, ipsrc):
                        APPfile5.append(pkt.APPlength)
                    elif comapreIpaddress(pkt.ipdst, ipsrc):
                        APPfile6.append(pkt.APPlength)

            # Features Collection
            features = calculatePacketSize(cache1) + calculateTimeArrivalAndStatistic(cache2) + calculatePacketSize(
                cache3) + \
                       calculateTimeArrivalAndStatistic(cache4) + calculatePacketSize(
                cache5) + calculateTimeArrivalAndStatistic(cache6)

            Handshakefeatures = features + clienthellofeatures[:3] + serverhellofeatures + appdataStatistics(
                APPfile5) + appdataStatistics(APPfile6)
            NumberofApp = len(APPfile5) + len(APPfile6)
            totalCache = len(APPfile5) + len(APPfile6) + len(cache1)
            Handshakefeatures.append(NumberofApp)
            Handshakefeatures.append(totalCache)
            Handshakefeatures.append(sni)
            flowsCounter.append("1")

            if len(Handshakefeatures) > 48 and len(sni) > 0:
                target = np.array(Handshakefeatures[0:38])

                Ide = True
                target = target.reshape(1, -1)
                resu = modelSystem.predict(target)[0]
                store = [resu, sni]
                print "Service: " + resu + " -> " + sni
                flowsCounter.append("1")
                ACC[key].append(store)

            del cache1
            del cache2
            del cache3
            del cache4
            del cache5
            del cache6
            del APPfile5
            del APPfile6
        return Ide

# Digital footprint
def clientFirstConnectServer(packets):
    features = []
    if len(packets.tcp.data) > 0 and int(ord(packets.tcp.data[0])) == 22:
        records, bytes_used = dpkt.ssl.TLSMultiFactory(packets.tcp.data)
        if len(records) > 0:
            for record in records:
                if record.type == 22 and len(record.data) > 0 and ord(record.data[0]) == 1:
                    digitalFootprint = dpkt.ssl.TLSHandshake(record.data)
                    # Client Hello
                    if isinstance(digitalFootprint.data, dpkt.ssl.TLSClientHello):
                        client = dpkt.ssl.TLSClientHello(str(digitalFootprint.data))
                        features.append(len(client.session_id))
                        features.append(client.num_ciphersuites)
                        features.append(len(client.extensions))
                        features.append(inet_ntoa(packets.dst))
    return features


# Extracting features from the packet of the first connection to the server
def serverGetDigitalFootprintFeatures(packets):
    features = []
    if int(packets.tcp.sport) == 443 and len(packets.tcp.data) > 0 and int(ord(packets.tcp.data[0])) == 22:
        records, bytes_used = dpkt.ssl.TLSMultiFactory(packets.tcp.data)
        if len(records) > 0:
            for record in records:
                if record.type == 22 and len(record.data) > 0 and ord(record.data[0]) == 2:
                    handshake = dpkt.ssl.TLSHandshake(record.data)
                    # Server connect client
                    if isinstance(handshake.data, dpkt.ssl.TLSServerHello):
                        server = dpkt.ssl.TLSServerHello(str(handshake.data))
                        features.append(len(server.session_id))
                        features.append(server.cipher_suite)
                        features.append(len(server.extensions))
    return features


# Extract Features From Application Data Packets
def appdataStatistics(packetSize):
    result = []
    if len(packetSize) == 0:
        packetSize.append(0)
    result.append(math.ceil(numpy.mean(packetSize)))
    result.append(math.ceil(numpy.percentile(packetSize, 25)))
    result.append(math.ceil(numpy.percentile(packetSize, 50)))
    result.append(math.ceil(numpy.percentile(packetSize, 75)))
    result.append(math.ceil(numpy.var(packetSize)))
    result.append(math.ceil(numpy.max(packetSize)))
    del packetSize
    return result


# Function for packet size statistics
def calculatePacketSize(packetSize):
    result = []
    if len(packetSize) == 0:
        packetSize.append(0)
    result.append(len(packetSize))
    result.append(math.ceil(numpy.mean(packetSize)))
    result.append(math.ceil(numpy.percentile(packetSize, 25)))
    result.append(math.ceil(numpy.percentile(packetSize, 50)))
    result.append(math.ceil(numpy.percentile(packetSize, 75)))
    result.append(math.ceil(numpy.var(packetSize)))
    result.append(math.ceil(numpy.max(packetSize)))
    return result


# Function for Calculating the Inter Arrival Time and make statistics
def calculateTimeArrivalAndStatistic(arrival):
    arrivalTime = sorted(arrival)
    if len(arrivalTime) == 0:
        arrivalTime.append(0)
    counter = 1
    IAT = []
    result = []
    for _ in arrivalTime:
        if counter != len(arrivalTime):
            IAT.append((arrivalTime[counter] - arrivalTime[counter - 1]) / 1000.0)
            counter = counter + 1
    if len(IAT) != 0:
        result.append(round(numpy.percentile(IAT, 25), 2))
        result.append(round(numpy.percentile(IAT, 50), 2))
        result.append(round(numpy.percentile(IAT, 75), 2))
    else:
        result.append(round(numpy.percentile(arrivalTime, 25), 2))
        result.append(round(numpy.percentile(arrivalTime, 50), 2))
        result.append(round(numpy.percentile(arrivalTime, 75), 2))
    del IAT
    return result

def digitalFootprint(packets):
    result = False
    try:
        if len(packets.tcp.data) > 0 and (int(ord(packets.tcp.data[0])) == 22 or int(ord(packets.tcp.data[0])) == 20) \
                and (int(packets.tcp.dport) == 443 or int(packets.tcp.sport) == 443):
            records, bytes_used = dpkt.ssl.TLSMultiFactory(packets.tcp.data)
            if len(records) > 0:
                for record in records:
                    if (record.type == 22 or record.type == 20) and len(record.data) > 0:
                        result = True
    except:
        pass
    return result

if __name__ == "__main__":
    main()
