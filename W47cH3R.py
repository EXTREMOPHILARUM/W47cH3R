#!/usr/bin/env python
import os, time, netifaces, sys, logging
from sys import platform
from scapy.all import sniff
request_threshold = 10
if os.geteuid() != 0:
	exit("Root permisson is required to operate on network interfaces. \nNow Aborting.")
filename = "spoof.log"
logging.basicConfig(format='%(levelname)s: %(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p', filename=filename, filemode="a", level=logging.DEBUG)
available_interfaces = netifaces.interfaces()
interface = netifaces.gateways()['default'][netifaces.AF_INET][1]
if not interface in available_interfaces:
    exit("Interface {} not available.".format(interface))
addrs = netifaces.ifaddresses(interface)
try:
    local_ip = addrs[netifaces.AF_INET][0]["addr"]
    broadcast = addrs[netifaces.AF_INET][0]["broadcast"]
except KeyError:
    exit("Cannot read address/broadcast address on interface {}".format(interface))
requests = []
replies_count = {}
notification_issued = []
logging.info("ARP Spoofing Detection Started on {}".format(local_ip))
def check_spoof (source, mac, destination):
    if destination == broadcast:
        if not mac in replies_count:
            replies_count[mac] = 0
    if not source in requests and source != local_ip:
        if not mac in replies_count:
            replies_count[mac] = 0
        else:
            replies_count[mac] += 1
        logging.warning("ARP replies detected from MAC {}. Request count {}".format(mac, replies_count[mac]))
        if (replies_count[mac] > request_threshold)and (not mac in notification_issued):
            logging.error("ARP Spoofing Detected from MAC Address {}".format(mac,source))
            notification_issued.append(mac)
    else:
        if source in requests:
            requests.remove(source)
def packet_filter (packet):
    source = packet.sprintf("%ARP.psrc%")
    dest = packet.sprintf("%ARP.pdst%")
    source_mac = packet.sprintf("%ARP.hwsrc%")
    operation = packet.sprintf("%ARP.op%")
    if source == local_ip:
        requests.append(dest)
    if operation == 'who-has':
	    return check_spoof (source, source_mac, dest)
print("ARP Spoofing Detection Started. Any output is redirected to log file.")
sniff(filter = "arp", prn = packet_filter, store = 0)
