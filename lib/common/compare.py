import ipaddress as ipaddr

# IP comparison
def comapreIpaddress(ip1, ip2):
    IP1 = ipaddr.ip_address(ip1.decode('unicode-escape'))
    IP2 = ipaddr.ip_address(ip2.decode('unicode-escape'))
    return IP1 == IP2
