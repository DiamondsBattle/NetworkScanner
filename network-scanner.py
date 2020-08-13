# PROG.DSB ++ PROG.DLB

import scapy.all as scapy
import argparse as argp


def getArguments():
	parser = argp.ArgumentParser()
	parser.add_argument('-t', '--target', dest='target', help='Target IP / IP Range.')
	options = parser.parse_args()
	return options

def scan(target_ip: str):
	arp_request = scapy.ARP(pdst=target_ip)
	broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
	arp_request_broadcast = broadcast/arp_request
	answered = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
	clients = []


	for element in answered:
		client = {'ip': element[1].psrc, 'mac': element[1].hwsrc}
		clients.append(client)
	return clients

def printScanResult(results: list):
	print('IP\t\t\tMAC Address\n-----------------------------------')
	for client in results:
		print('%s\t\t%s' % (client['ip'], client['mac']))


options = getArguments()
scane_results = scan(target_ip=options.target)
printScanResult(results=scane_results)


'''
Niccest printing option :
print(',----------------------------------------')
	for element in answered:
		print('| ID : %s' % answered.index(element))
		print('| IP : %s' % (element[1].psrc))
		print('| MAC : %s' % (element[1].hwsrc))
		print('`---------------------------------------')
		if (answered.index(element) + 1) == len(answered):
			pass
		else:
			print('`----------------------------------------')
'''