# Port Scanner


It's a simple port scanner created using Scapy in Python. It works for protocols ARP, ICMP, UDP, TCP. It also have a simple GUI.

## Usage example
		sudo python3 port_scanner.py -host 192.168.1.6/30 google.com -p 56 80 443 -proto arp ICMP TCP UDP -out scanReport
The above command scans subnet 192.168.1.6/30 and google.com. It scans for the protocols ICMP and ARP for every host specified. It also scans TCP and and UDP for every port (56, 80, 443) on every host specified. This command generated a HTML report named `scanReport.html`
## Command line arguments 
		("-GUI", "--GUI"):  "starts GUI"
		("-tcp_full_con", "--TCP_full_connect"): "TCP scan works in stealth mode by sending RST after getting Ack.It forces the scanner to do complete 3-way handshake"		
		("-host", "--host"): "Specify hostnames to scan either space separated or subnets"
		("-host_file", "--host_filename"): "Specify file with a hostname in each line"
		("-p", "--port"): "Specify ports to scan. Space separated"
		("-pl", "--port_list"): "Specify ports range to scan"
		("-proto", "--protocol"): "Specify protocols for the scanning, Like 'TCP', 'UDP'"
		("-tcp_t", "--tcp_timeout"): "TCP timeout after which to consider the port as closed. Default is 2 sec"
		("-out", "--output_filename"): "output file name. Default is 'scanReport'"
		("-out_file_type", "--output_file_type"): "output file type. HTML or PDF"
		("-icmp_t", "--icmp_timeout"): "ICMP timeout after which to consider the machine is considered down. Default is 1 sec"
		

## GUI

A simple GUI, that takes as input hostnames, ports, protocols to scan, and output file name. It also show the progress of the scan. 
		sudo python3 port_scanner.py -GUI

## What all this port Scanner can do
- Allow command-line switches to specify a host and port.
 - Allow more than one host to be scanned. A user can pass either a subnet or a hostname or a combination of both separated by spaces in argument `-host`
 - Allows different ways to specify hosts (subnet mask and range) .
 - Reads a text file of host IP’s. A user can specify both hosts on command line and also input a file. The scanner scans all the hosts.
 - Allow multiple ports to be specified. A user can either enter space separated ports using `-p` argument or can specify a range of ports  using `-pl` argument.
 -  Multiple Protocols supported TCp, ICMP.
 -  Users can generate an HTML or PDF report. A user can specify the type of format that they want for the report. 
 - GUI 
 - Other ideas or concepts not mentioned  (ARP scanning, TCP full connect scan - by default it's in stealth mode, progress bar in GUI, Can specify timeouts for ICMP and TCP scans, Combination of Subnet and ips in hosts, Both report options)
