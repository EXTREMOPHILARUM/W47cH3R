#!/usr/bin/env python
#importing necessary libraries
import os, time, netifaces, sys, logging
from sys import platform
from scapy.all import sniff
from tkinter import *
from tkinter import messagebox
import pandas as pd
import scapy
# added 2 useless libraries.

#creating arrays to store data from the sniffed packets
requests = []
replies_count = {}
notification_issued = []

#setting limit for arp replies
request_threshold = 10

root = Tk()#creating a tkinter object
if os.name != "nt":
    if os.geteuid()!=0:#checking for root permissions on now nt systems
        exit("Root permisson is required to operate on network interfaces. \nNow Aborting.")

#setting log file name
filename = "spoof.log"

# Set logging structure
logging.basicConfig(format='%(levelname)s: %(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p', filename=filename, filemode="a", level=logging.DEBUG)

# Read available network interfaces
available_interfaces = netifaces.interfaces()

# Check the connected interface
interface = netifaces.gateways()['default'][netifaces.AF_INET][1]

# Check if specified interface is valid
if not interface in available_interfaces:
     exit("Interface {} not available.".format(interface))

# Retrieve network addresses (IP, broadcast) from the network interfaces
addrs = netifaces.ifaddresses(interface)

#handling keyerror 2 which is cause due to netifaces
try:
    local_ip = addrs[netifaces.AF_INET][0]["addr"]
    broadcast = addrs[netifaces.AF_INET][0]["broadcast"]
except KeyError:
    exit("Cannot read address/broadcast address on interface {}".format(interface))

# Function checks if a specific ARP reply is part of an ARP spoof attack or not
def check_spoof (source, mac, destination):
    request_threshold = 50
    if destination == broadcast:
        if not mac in replies_count:
            replies_count[mac] = 0
    if not source in requests and source != local_ip:
        if not mac in replies_count:
            replies_count[mac] = 0
        else:
            replies_count[mac] += 1
            # Logs ARP Reply
            logging.warning("ARP replies detected from MAC {}. Request count {}".format(mac, replies_count[mac]))
        if (replies_count[mac] > request_threshold) and (not mac in notification_issued):
            # Check number of replies reaches threshold or not, and whether or not we have sent a notification for this MAC addr
            logging.error("ARP Spoofing Detected from MAC Address {} & IP {} ".format(mac,source))
            notification_issued.append(mac)
            # Issue OS Notification for nt systems
            if os.name == "nt":
                from win10toast import ToastNotifier
                toaster = ToastNotifier()
                toaster.show_toast("W47cH3R","IP : "+f"{source}"+"\n"+"Mac : "+f"{mac}",icon_path="stanlee.ico",duration = 5,threaded = True)
                while toaster.notification_active(): time.sleep(0.1)
            # Issue OS Notification for posix systems
            if os.name =="posix":
                import notify2
                notify2.init("W47cH3R")
                n = notify2.Notification("W47cH3R","IP : "+f"{source}"+"\n"+"Mac : "+f"{mac}")
                n.set_timeout(5000)
                n.show()
            # Add to sent list to prevent repeated notifications.
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
    if (operation == 'who-has') and (not source_mac in notification_issued) and (source != '0.0.0.0' ) and (source != '169.254.166.147'):
       return check_spoof (source, source_mac, dest)
print("ARP Spoofing Detection Started. Any output is redirected to log file also a notification will be shown.")
logging.info("ARP Spoofing Detection Started on {}".format(local_ip))
sniff(filter = "arp", prn = packet_filter, store = 0)

