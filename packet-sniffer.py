import socket, sys, time, csv
from struct import unpack

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
count = 0
ipcount = 0
tcpcount = 0
udpcount = 0
dnscount = 0
httpcount = 0
httpscount = 0
icmpcount = 0
quiccount = 0

end_time = time.time() + 30

while time.time() < end_time:

	packet = s.recvfrom(65565)
	count = count + 1
	packet = packet[0]

	#ethernet check for ipv4 protocol
	header = packet[12:14]
	network = int.from_bytes(header, 'big')
	if network == 2048:
		ipcount = ipcount + 1

	#confirm ipv4 header length
	iplength = packet[14:15]
	iplength = unpack('!B', iplength)[0]
	iplength = iplength & 0x0F
	iplength = iplength * 4

	#confirm total length of the packet
	totallength = packet[16:18]
	totallength = unpack('!H', totallength)[0]
	#print(totallength)
	

	#retrieve protocol definitions (either tcp or udp or etc)
	protocol = packet[23:24]
	protocol = int.from_bytes(protocol, 'big')
	if protocol == 6:
		tcpcount = tcpcount + 1
		tcpdestport = packet[14 + iplength:16 + iplength]
		tcpdestport = int.from_bytes(tcpdestport, 'big')
		#print(tcpdestport)
		if tcpdestport == 53:
			dnscount = dnscount + 1
		elif tcpdestport == 80:
			httpcount = httpcount + 1
		elif tcpdestport == 443:
			httpscount = httpscount + 1
	elif protocol == 17:
		udpcount = udpcount + 1
		udpdestport = packet[16 + iplength:18 + iplength]
		udpdestport = int.from_bytes(udpdestport, 'big')
		if udpdestport == 53:
			dnscount = dnscount + 1
		elif udpdestport == 80 or udpdestport == 443:
			quiccount = quiccount + 1
	elif protocol == 1:
		icmpcount = icmpcount + 1
"""	
print("\n" + "Total packets = " + str(count))
print("IP packets = " + str(ipcount))
print("TCP packets = " + str(tcpcount))
print("UDP packets = " + str(udpcount))
print("ICMP packets = " + str(icmpcount))
print("DNS packets = " + str(dnscount))
print("HTTP packets = " + str(httpcount))
print("HTTPS packets = " + str(httpscount))
print("QUIC packets = " + str(quiccount))
"""

list1 = ['protocol', 'ip', 'tcp', 'udp', 'dns', 'icmp', 'http', 'https', 'quic']
list2 = ['count', ipcount, tcpcount, udpcount, dnscount, icmpcount, httpcount, httpscount, quiccount]
rows = zip(list1, list2)

with open('sniffer_count.csv', 'w+', encoding='utf-8') as f:
	writer = csv.writer(f)
	for row in rows:
		writer.writerow(row)

