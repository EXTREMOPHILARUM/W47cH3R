#!/usr/bin/env python
import os, time, netifaces, sys, logging
from sys import platform
from scapy.all import sniff
import wx
requests = []
replies_count = {}
notification_issued = []   
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
def check_spoof (source, mac, destination):
    request_threshold = 10
    if destination == broadcast:
        if not mac in replies_count:
            replies_count[mac] = 0
    if not source in requests and source != local_ip:
        if not mac in replies_count:
            replies_count[mac] = 0
        else:
            replies_count[mac] += 1
        #logging.warning("ARP replies detected from MAC {}. Request count {}".format(mac, replies_count[mac]))
        if (replies_count[mac] > request_threshold) and (not mac in notification_issued):
            logging.error("ARP Spoofing Detected from MAC Address {}".format(mac,source))
            notification_issued.append(mac)
            wx.MessageBox("IP : "+f"{source}"+"\n"+"Mac : "+f"{mac}", "Message" ,wx.OK | wx.ICON_INFORMATION)
    else:
        if source in requests:
            requests.remove(source)
def packet_filter (packet):
    source = packet.sprintf("%ARP.psrc%")
    dest = packet.sprintf("%ARP.pdst%")
    source_mac = packet.sprintf("%ARP.hwsrc%")
    operation = packet.sprintf("%ARP.op%")
    if source == local_ip:
        self.requests.append(dest)
    if operation == 'who-has':
       return check_spoof (source, source_mac, dest) 
class Mywin(wx.Frame): 
   def __init__(self, parent, title): 
      super(Mywin, self).__init__(parent, title = title, size = (350,350))
      self.InitUI()
         
   def InitUI(self):    
      panel = wx.Panel(self) 
      vbox = wx.BoxSizer(wx.VERTICAL) 
      self.tbtn = wx.ToggleButton(panel , -1, "Enable",size = (100,100),pos = (100,100))   
      self.SetBackgroundColour("#29AB87")
      vbox.Add(self.tbtn,0,wx.EXPAND|wx.ALIGN_CENTER) 
      self.tbtn.Bind(wx.EVT_TOGGLEBUTTON,self.OnToggle)   
      self.Centre() 
      self.Show() 
      self.Fit()
      self.Centre() 
      self.Show(True)
  
   def OnToggle(self,event): 
      state = event.GetEventObject().GetValue() 
      logging.info("ARP Spoofing Detection Started on {}".format(local_ip))
      if state == True: 
         print("Toggle button state off" )
         print("ARP Spoofing Detection Started. Any output is redirected to log file.")
         sniff(filter = "arp", prn = packet_filter, store = 0)
         event.GetEventObject().SetLabel("Disable")
         event.GetEventObject().SetBackgroundColour("#FF2400")
      else: 
         print(" Toggle button state on")
         event.GetEventObject().SetLabel("Enable") 
         event.GetEventObject().SetBackgroundColour("WHITE")   

app = wx.App() 
Mywin(None,'W47cH3R') 
app.MainLoop()