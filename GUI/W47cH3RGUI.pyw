#!/usr/bin/env python
import os, time, netifaces, sys, logging
from sys import platform
from scapy.all import sniff
from tkinter import *
from tkinter import messagebox
import threading
requests = []
replies_count = {}
notification_issued = []
root = Tk()
if os.name != "nt":
    if os.geteuid()!=0:
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
        if (replies_count[mac] > request_threshold) and (not mac in notification_issued):
            logging.error("ARP Spoofing Detected from MAC Address {} & IP {} ".format(mac,source))
            notification_issued.append(mac)
            if os.name == "nt":
                from win10toast import ToastNotifier
                toaster = ToastNotifier()
                toaster.show_toast("W47cH3R","IP : "+f"{source}"+"\n"+"Mac : "+f"{mac}",icon_path="stanlee.ico",duration = 5,threaded = True)
                while toaster.notification_active(): time.sleep(0.1)
            if os.name =="posix":
                import notify2
                notify2.init("W47cH3R")
                n = notify2.Notification("W47cH3R","IP : "+f"{source}"+"\n"+"Mac : "+f"{mac}")
                n.set_timeout(5000)
                n.show()
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
    if (operation == 'who-has') and (not source_mac in notification_issued):
       return check_spoof (source, source_mac, dest)
class MyFirstGUI(threading.Thread):
    def __init__(self, master):
        self.master = master
        master.title("W47cH3R")

        self.label = Label(master, text="Click To Enable",font=("David Libre", 15),fg = "#57A0D2")
        self.label.pack()
        self.greet_button = Button(master, text="Enable", command=self.Enable,bg = "#29AB87",font=("David Libre", 15))
        self.greet_button.pack()

        self.close_button = Button(master, text="Close", command=self.Close,bg = "red",font=("David Libre", 15))
        self.close_button.pack()
        self.master.protocol("WM_DELETE_WINDOW",self.Close)
    def Enable(self):
        logging.info("ARP Spoofing Detection Started on {}".format(local_ip))
        print("ARP Spoofing Detection Started. Any output is redirected to log file.")
        messagebox.showinfo("W47cH3R","Notification will be shown automatically when an Attack is Detected")
        self.master.destroy()
    def Close(self):
        exit()
root.geometry('350x300')
if os.name == "nt":
    root.iconbitmap(r'C:/Users/saurabh/Downloads/stanlee.ico')
my_gui = MyFirstGUI(root)
root.mainloop()
sniff(filter = "arp", prn = packet_filter, store = 0)
