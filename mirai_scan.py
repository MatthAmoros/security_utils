#!/usr/bin/env python
#pip3 install python-nmap, paramiko
import nmap
import paramiko
import sys

if __name__=='__main__':
	if len(sys.argv) == 2:
		target = sys.argv[1]
	else:
		print("Usage : mirai_scan.py --ip [Single or range nmap-formated]")
		sys.exit(-1)

	creds = [
				{"user":"root", "pass":"xc3511"},
				{"user":"root", "pass":"vizxv"},
				{"user":"root", "pass":"admin"},
				{"user":"admin", "pass":"admin"},
				{"user":"root", "pass":"888888"},
				{"user":"root", "pass":"xmhdipc"},
				{"user":"root", "pass":"default"},
				{"user":"root", "pass":"jauntech"},
				{"user":"root", "pass":"123456"},
				{"user":"root", "pass":"54321"},
				{"user":"support", "pass":"support"},
				{"user":"root", "pass":"(none)"},
				{"user":"admin", "pass":"password"},
				{"user":"root", "pass":"root"},
				{"user":"root", "pass":"12345"},
				{"user":"user", "pass":"user"},
				{"user":"admin", "pass":"(none)"},
				{"user":"root", "pass":"pass"},
				{"user":"admin", "pass":"admin1234"},
				{"user":"root", "pass":"1111"},
				{"user":"admin", "pass":"smcadmin"},
				{"user":"admin", "pass":"1111"},
				{"user":"root", "pass":"666666"},
				{"user":"root", "pass":"password"},
				{"user":"root", "pass":"1234"},
				{"user":"root", "pass":"klv123"},
				{"user":"Administrator", "pass":"admin"},
				{"user":"service", "pass":"service"},
				{"user":"supervisor", "pass":"supervisor"},
				{"user":"guest", "pass":"guest"},
				{"user":"guest", "pass":"12345"},
				{"user":"admin1", "pass":"password"},
				{"user":"administrator", "pass":"1234"},
				{"user":"666666", "pass":"666666"},
				{"user":"888888", "pass":"888888"},
				{"user":"ubnt", "pass":"ubnt"},
				{"user":"root", "pass":"klv1234"},
				{"user":"root", "pass":"Zte521"},
				{"user":"root", "pass":"hi3518"},
				{"user":"root", "pass":"jvbzd"},
				{"user":"root", "pass":"anko"},
				{"user":"root", "pass":"zlxx."},
				{"user":"root", "pass":"7ujMko0vizxv"},
				{"user":"root", "pass":"7ujMko0admin"},
				{"user":"root", "pass":"system"},
				{"user":"root", "pass":"ikwb"},
				{"user":"root", "pass":"dreambox"},
				{"user":"root", "pass":"user"},
				{"user":"root", "pass":"realtek"},
				{"user":"root", "pass":"000000"},
				{"user":"admin", "pass":"1111111"},
				{"user":"admin", "pass":"1234"},
				{"user":"admin", "pass":"12345"},
				{"user":"admin", "pass":"54321"},
				{"user":"admin", "pass":"123456"},
				{"user":"admin", "pass":"7ujMko0admin"},
				{"user":"admin", "pass":"pass"},
				{"user":"admin", "pass":"meinsm"},
				{"user":"tech", "pass":"tech"},
				{"user":"mother", "pass":"fucker"},
				{"user":"ubnt", "pass":"ubnt"},
				{"user":"admin", "pass":"ubnt"}
			]

	""" Scan using NMAP for opened ssh port """
	print("Running...")
	nm = nmap.PortScanner()
	nm.scan(target, '22')
	hosts = nm.all_hosts()
	""" SSH client """
	client = paramiko.SSHClient()
	client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

	for host in hosts:
		my_host = nm[host]
		if my_host['tcp'][22]['state'] == 'open':
			print(my_host['addresses']['ipv4'] + ' opened with ' + my_host['tcp'][22]['product'])

	for host in hosts:
		my_host = nm[host]
		if my_host['tcp'][22]['state'] == 'open':
			print("Procesing " + my_host['addresses']['ipv4'] + "...")
			for def_cred in creds:
				status = 0
				""" Try ssh default creds """
				try:
					client.connect(my_host['addresses']['ipv4'], username=def_cred["user"], password=def_cred["pass"], timeout=0.2)
					print(my_host['addresses']['ipv4'] + ' vulnerable to ' + def_cred["user"] + ':' + def_cred["pass"])
				except paramiko.AuthenticationException:
					""" Default password didn't work """
					status = 1
				except paramiko.ssh_exception.SSHException:
					""" Usually banner exception, ssh server not supported by paramiko """
					status = 2
				except Exception as e:
					""" Other """
					status = 3

				client.close()

	sys.exit(0)
