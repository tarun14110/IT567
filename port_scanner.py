import sys
from scapy.all import *
import argparse
from netaddr import IPNetwork
import pygubu
from fpdf import FPDF
import PySimpleGUI as sg
import shlex
from tqdm import tqdm

# To avoid kernel from sending RST messages
# iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP


class Scanner:
	def __init__(self):
		self.hostsToScan = []
		self.portsToScan = []
		self.protocolsToCheck = []
		self.TCP_timeout = 2
		self.ICMP_timeout = 2
		self.outputFileName = "scanReport"
		self.outputFileType = "html"
		self.tcpFullConnect = False 

	# used for parsing space separated ports
	def parseNumList(self, string):
	    m = re.match(r'(\d+)(?:-(\d+))?$', string)
	    # ^ (or use .split('-'). anyway you like.)
	    if not m:
	        raise ArgumentTypeError("'" + string + "' is not a range of number. Expected forms like '0-5' or '2'.")
	    start = m.group(1)
	    end = m.group(2) or start
	    return list(range(int(start,10), int(end,10)+1))

	# parses Ip subnets and space sperated host names
	def parseIPList(self, string):
		resultList = []
		for subnets in string.split(" "):
			if '/' in subnets:
				for ip in IPNetwork(string):
					resultList.append(str(ip))
			else:
				resultList.append(subnets)
		return resultList

	def GUI(self):
		sg.ChangeLookAndFeel('GreenTan')   
		layout = [      
		    [sg.Text('Port Scanner', size=(30, 1), font=("Helvetica", 25), justification='center')],
		    [sg.Text(' '  * 80)], 
		    [sg.Text('Hosts:', font=("Arial", 10, "bold")),     
		    sg.InputText('192.168.1.6/30'),
		    sg.Text('or')],
		    [sg.Text('host file name:', size=(15, 1), auto_size_text=False, justification='right'),      
		     sg.InputText(''), sg.FileBrowse()],
		    [sg.Text(' '  * 80)], 
		    [sg.Text('Ports:', font=("Arial", 10, "bold")),      
		    sg.InputText('80 25 443')],
		    [sg.Text(' '  * 80)], 
		    [sg.Text('Protocols:', font=("Arial", 10, "bold")), 
		    sg.Checkbox('ICMP', default=True), sg.Checkbox('UDP'), sg.Checkbox('TCP'), sg.Checkbox('ARP')],
		    [sg.Text(' '  * 80)], 
		    [sg.Text('Generate report:', font=("Arial", 10, "bold")),
		    sg.InputText('outputReport', size=(15, 1)), 
		    sg.Radio('HTML', "RADIO1", default=True), sg.Radio('PDF', "RADIO1")],
		    [sg.Text(' '  * 80)],         
		    [sg.Submit("Start Scan")],
		    [sg.Text(' '  * 80)],
		    [sg.Text('Progress:', font=("Arial", 10, "bold")),
		    sg.ProgressBar(10000, orientation='h', size=(20, 20), key='progressbar')]     
		]
		self.window = sg.Window('Scanner', default_element_size=(40, 1)).Layout(layout)

		#Creating parameter list through GUI values to pass into arg parser
		button, values = self.window.Read()
		param_string = ""
		param_string += " -host " +values[0]
		if values[1] !="":
			param_string += " -host_file " +values[1]
		param_string += " -p " +values[2]
		param_string += " -proto "
		if values[3]:
			param_string += "ICMP "
		if values[4]:
			param_string += "UDP "
		if values[5]:
			param_string += "TCP "
		if values[6]:
			param_string += "ARP "
		param_string += " -out " +values[7]
		if values[8]:
			param_string += " -out_file_type HTML"
		else:
			param_string += " -out_file_type PDF"
		return param_string

	def readParams(self, argument):
		if argument.host:
			self.hostsToScan = []
			for hosts in argument.host:
				self.hostsToScan = self.hostsToScan + hosts
		if argument.host_filename:
			self.hostsToScan = self.hostsToScan + [line.rstrip('\n') for line in open(argument.host_filename)]
		if argument.TCP_full_connect:
			self.tcpFullConnect = True
		if argument.port:
			self.portsToScan = argument.port
		if argument.port_list:
			self.portsToScan = self.portsToScan + argument.port_list
		if argument.protocol:
			self.protocolsToCheck = [x.lower() for x in argument.protocol]
		if argument.tcp_timeout:
			self.TCP_timeout = argument.tcp_timeout
		if argument.icmp_timeout:
			self.ICMP_timeout = argument.icmp_timeout
		if argument.output_filename:
			self.outputFileName = argument.output_filename
		if argument.output_file_type:
			self.outputFileType = argument.output_file_type
	
	#parses command line arguments
	def parser(self, parameter_string=""):
		parser = argparse.ArgumentParser(description = "Description for my parser")
		parser.add_argument("-H", "--Help", help = "Help argument", required = False, default = "")
		parser.add_argument("-GUI", "--GUI", help = "starts GUI", action='store_true')
		parser.add_argument("-tcp_full_con", "--TCP_full_connect", help = "do complete handshake scan", action='store_true')
		parser.add_argument("-host", "--host", help = "Specify hostnames to scan either space separated or subnets", nargs='+', type=self.parseIPList, required = False)
		parser.add_argument("-host_file", "--host_filename", help = "Specify file with a hostname in each line", required = False)
		parser.add_argument("-p", "--port", help = "Specify port to scan", nargs='+', type=int, required = False)
		parser.add_argument("-pl", "--port_list", help = "Specify port to scan", type=self.parseNumList, required = False)
		parser.add_argument("-proto", "--protocol", help = "Specify protocols for the scanning, Like 'TCP', 'UDP'", nargs='+', required = False)
		parser.add_argument("-tcp_t", "--tcp_timeout", help = "TCP timeout after which to consider the port as closed. Default is 2 sec", required = False, default = 2)
		parser.add_argument("-out", "--output_filename", help = "output file name", required = False)
		parser.add_argument("-out_file_type", "--output_file_type", help = "output file type", required = False, default = "html")
		parser.add_argument("-icmp_t", "--icmp_timeout", help = "ICMP timeout after which to consider the machine is considered down. Default is 1 sec", required = False, default = 1)
		return parser


	#Generates PDF report
	def pdf_report(self, data, filename, spacing=1):
	    pdf = FPDF()
	    pdf.set_font("Arial", size=8)
	    pdf.add_page()
	    col_width = pdf.w / (len(results[0]) +0.5)
	    row_height = pdf.font_size
	    for row in data:
	        for item in row:
	            pdf.cell(col_width, row_height*spacing,
	                     txt=item, border=1)
	        pdf.ln(row_height*spacing)
	    pdf.output(filename+'.pdf')


	def TCP_scan(self, hostToScan, portToScan, isFullConnect = False):
		src_port = RandShort()._fix()
		# sending SYN packet
		ip_packet = IP(dst=hostToScan)
		SYN_TCP_packet=TCP(sport=src_port, dport=portToScan, seq=1, flags="S")
		#Sendig ACK packet
		server_ACK_packet= sr1(ip_packet/ SYN_TCP_packet, timeout=self.TCP_timeout, verbose=0)

		if not server_ACK_packet or server_ACK_packet[TCP].flags.F or server_ACK_packet[TCP].flags.R: # If we get a packet with Fin, Reset or don't get a packet it means the connection is closed
			return False, ip_packet.dst
		if isFullConnect: # if full connect send 3-Way handshake Ack and Reset to close the close the connection
			my_ACK_TCP_packet = TCP(sport=src_port, dport=portsToScan, seq=server_ACK_packet.ack ,ack=server_ACK_packet.seq+1, flags="AR")
		else: # otherwise Send resent to close the connection
			my_ACK_TCP_packet = TCP(sport=src_port, dport=portToScan, seq=server_ACK_packet.ack ,ack=server_ACK_packet.seq+1, flags="R")
		send(ip_packet/my_ACK_TCP_packet, verbose=0)
		return True, ip_packet.dst


	def UDP_scan(self, hostToScan, portToScan):
		src_port = RandShort()._fix()
		ip_packet = IP(dst=hostToScan)
		# sending UDP packet
		pckt = sr1(ip_packet/UDP(dport=portToScan)/Raw(load="abc"),  timeout=self.TCP_timeout, verbose=0) 
		if pckt:
			return True, ip_packet.dst
		return False, ip_packet.dst

	def ICMP_scan(self, hostToScan):
		ip_packet = IP(dst=hostToScan)
		# sending ICMP packet
		response = sr1(ip_packet/ICMP(),  timeout=self.ICMP_timeout, verbose=0)
		if response:
			return True, ip_packet.dst
		return False, ip_packet.dst

	def ARP_scan(self, hostToScan):
	    # sending ARP packet
	    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=hostToScan)
	    res, unes = srp(pkt, timeout=0.8, verbose=False)
	    if res:
	    	for x, recv in res:
	        	print("Host Alive: %s - %s" % (recv[ARP].psrc, recv[Ether].src))
	        	return True, recv[Ether].src
	    else:
	        print("Host Down: ", hostToScan)
	        return False, ""

	def start_scan(self):
		total_scans = 0
		if "arp" in self.protocolsToCheck:
			total_scans += len(self.hostsToScan)
		if "icmp" in self.protocolsToCheck:
			total_scans += len(self.hostsToScan)
		if "udp" in self.protocolsToCheck:
			total_scans += len(self.hostsToScan)*len(self.portsToScan)
		if "tcp" in self.protocolsToCheck:
			total_scans += len(self.hostsToScan)*len(self.portsToScan)

		if 'window' in self.__dict__:
			progress_bar = self.window.FindElement('progressbar')
			update_val = 10000.0/total_scans
			progress_bar.UpdateBar(1000)
			progress_bar_val = 0

		# `results` variable stores all the results of the scans in a 2D list.It makes it easier to generate report with it.
		results = [["Hosts scanned"]]
		for host in self.hostsToScan:
			results.append([host])

		if "icmp" in self.protocolsToCheck:
			if len(results[0])==1:
				results[0].append("IP's")
			results[0].append("ICMP")
			print("\nICMP scan results:")
			i = 0
			for host in self.hostsToScan:
				i += 1
				boo, ip = self.ICMP_scan(host)
				if len(results[i])==1:
					results[i].append(str(ip))
				if boo:
					results[i].append("reachable")
					print("Host: "+ host + " ("+str(ip)+") is reachable")
				else:
					results[i].append("unreachable")
					print("Host: "+ host + " ("+str(ip)+") is unreachable")
				if 'window' in self.__dict__:
					progress_bar_val += update_val
					progress_bar.UpdateBar(progress_bar_val)


		if "udp" in self.protocolsToCheck:
			if len(results[0])==1:
				results[0].append("IP's")
			results[0].append("UDP (open)")
			results[0].append("UDP (closed)")

			print("\nUDP scan results:")
			i = 0
			for host in self.hostsToScan:
				i += 1
				ports_open = ""
				ports_closed = ""
				host_ip = "-"
				for port in self.portsToScan:
					is_open, ip = self.UDP_scan(host, port)
					host_ip  = ip
					if is_open:
						ports_open = ports_open + ", " + str(port)
						print("Host: "+ host + " ("+str(ip)+") port: "+str(port)+ " is open")
					else:
						ports_closed = ports_closed + ", " + str(port)
						print("Host: "+ host + " ("+str(ip)+") port: "+str(port)+ " is closed")
					if 'window' in self.__dict__:
						progress_bar_val += update_val
						progress_bar.UpdateBar(progress_bar_val)

				if len(results[0])==1:
					results[i].append(host_ip)
				results[i].append(ports_open.strip(','))
				results[i].append(ports_closed.strip(','))


		if "tcp" in self.protocolsToCheck:
			if len(results[0])==1:
				results[0].append("IP's")
			results[0].append("TCP (open)")
			results[0].append("TCP (closed)")
			print("\nTCP scan results:")
			i = 0
			for host in self.hostsToScan:
				i += 1
				ports_open = ""
				ports_closed = ""
				host_ip = "-"
				for port in self.portsToScan:
					is_open, ip = self.TCP_scan(host, port, self.tcpFullConnect )
					if len(results[1])==1:
						results[i][1] =ip
					if is_open:
						ports_open = ports_open + ", " + str(port)
						print("Host: "+ host + " ("+str(ip)+") port: "+str(port)+ " is open")
					else:
						ports_closed = ports_closed + ", " + str(port)
						print("Host: "+ host + " ("+str(ip)+") port: "+str(port)+ " is closed")
					
					if 'window' in self.__dict__:
						progress_bar_val += update_val
						progress_bar.UpdateBar(progress_bar_val)

				if len(results[0])==1:
					results[i].append(host_ip)
				results[i].append(ports_open.strip(','))
				results[i].append(ports_closed.strip(','))

		if "arp" in self.protocolsToCheck:
			results[0].append("ARP")
			print("\nARP scan results:")
			i = 0
			for host in self.hostsToScan:
				i += 1
				res, mac = self.ARP_scan(host)
				if res:
					results[i].append("Alive ("+ mac+")")
				else:
					results[i].append("Down")
				if 'window' in self.__dict__:
					progress_bar_val += update_val
					progress_bar.UpdateBar(progress_bar_val)
		return results

	def generate_report(self, results):
		html_code = '''<style type="text/css">.tg  {border-collapse:collapse;border-spacing:0;border-color:#9ABAD9;text-align:center;}
		.tg td{font-family:Arial, sans-serif;font-size:14px;padding:10px 5px;border-style:solid;border-width:1px;overflow:hidden;word-break:normal;border-color:#9ABAD9;color:#444;background-color:#EBF5FF;}
		.tg th{font-family:Arial, sans-serif;font-size:14px;font-weight:normal;padding:10px 5px;border-style:solid;border-width:1px;overflow:hidden;word-break:normal;border-color:#9ABAD9;color:#fff;background-color:#409cff;}
		.tg .tg-baqh{text-align:center;vertical-align:top}
		h1 {
			font-size: 36px;
			line-height: 40px;
			margin: 1em 0 .6em 0;
			font-weight: normal;
			color: white;
			font-family: 'Hammersmith One', sans-serif;
			text-shadow: 0 -1px 0 rgba(0,0,0,0.4);
			position: relative;
			color: #6Cf;
		}
		h4 { 
			margin: 1em 0 .6em 0;
			padding: 0 0 0 20px;
			font-weight: normal;
			color: white;
			font-family: 'Hammersmith One', sans-serif;
			text-shadow: 0 -1px 0 rgba(0,0,0,0.4);
			position: relative;
			font-size: 12px;
			line-height: 20px;
			font-family: 'Questrial', sans-serif;
		}
		html {
		  background-color: #000000; 
		}
		</style>
		<section class="main">
		<h1>Scan results:</h1>

		<h4>Scanned hosts: '''+ str(self.hostsToScan).strip('[]').replace("'", "") +''' <br> Scanned ports: '''+ str(self.portsToScan).strip('[]') +''' <br> Scanned Protocols: '''+ str(self.protocolsToCheck).strip('[]').replace("'", "") +''' <br> </h4>

		</section>
		<body>
		<table class="tg" width="80%">
		'''

		html_code += "<tr>"
		for head in results[0]:
			html_code += '<th class="tg-baqh">'+head+'</th>'
		html_code += "</tr>"

		for x in results[1:]:
			html_code += "<tr>"
			for y in x:
				html_code += '<td class="tg-baqh">'+y+'</td>'
			html_code += "</tr>"

		html_code += '</table"></body>'

		# creating report files
		if self.outputFileType.lower() == "html":
			file1 = open(self.outputFileName+ ".html","w") 
			file1.write(html_code)
		else:
			self.pdf_report(results, self.outputFileName)
		print("Report generated by name " + self.outputFileName)



scanner = Scanner()
parser = scanner.parser()
argument = parser.parse_args()
if argument.GUI: # if -GUI in command line arguments
	parameters = scanner.GUI()
	argument = parser.parse_args(shlex.split(parameters)) #update parameters from GUI and add those paramters to parser
scanner.readParams(argument)

results = scanner.start_scan()
scanner.generate_report(results)
