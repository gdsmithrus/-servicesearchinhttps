import hashlib
import socket


class Packet:
    ipsrc = ""
    sport = ""
    ipdst = None
    dport = ""
    hashID = ""
    SYN = False
    ACK = False
    timestamp = ""
    APPData = False
    Handshake = False
    length = 0
    sni = ""
    SYNEND = False
    type = 0
    payload = None
    APPlength = 0

    def __init__(self, ipsrc, sport, ipdst, dport, SYN, ACK, timestamp, APP, HS, length, sni, snyend, type, payload,
                 APPlength):
        self.ipsrc = ipsrc
        self.sport = sport
        self.ipdst = ipdst
        self.dport = dport
        temp = hashlib.sha1(str(int(socket.inet_aton(self.ipsrc).encode('hex'), 16) + self.sport + int(
            socket.inet_aton(self.ipdst).encode('hex'), 16) + self.dport))
        self.hashID = temp.hexdigest()
        self.SYN = SYN
        self.ACK = ACK
        self.timestamp = timestamp
        self.APPData = APP
        self.Handshake = HS
        self.length = length
        self.sni = sni
        self.SYNEND = snyend
        self.type = type
        self.payload = payload
        self.APPlength = APPlength

    def compare(self, ipsrc, sport, ipdst, dport):
        if self.ipsrc == int(socket.inet_aton(ipsrc).encode('hex'), 16) and self.sport == sport and self.ipdst == int(
                socket.inet_aton(ipdst).encode('hex'), 16) and self.dport == dport:
            return True
        elif self.ipsrc == int(socket.inet_aton(ipdst).encode('hex'), 16) and self.sport == dport and self.ipdst == int(
                socket.inet_aton(ipsrc).encode('hex'), 16) and self.dport == sport:
            return True
        else:
            return False

    def showPacket(self):
        x = self.sni + "," + str(self.length) + "," + str(self.Handshake) + "," + str(self.APPData) + "," + str(
            self.timestamp) + "," + str(self.ipsrc) + "," + str(self.ipdst) + "," + str(self.sport) + "." + str(
            self.dport)
        return x
