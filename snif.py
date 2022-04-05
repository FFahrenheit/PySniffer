#pip install winpcapy
#install winpcap

from winpcapy import WinPcapUtils, WinPcapDevices
from sniffer import Sniffer
from datetime import datetime
import sys

interface = "*Wireless*"
interface = "*Realtek*"

with WinPcapDevices() as devices:
    for device in devices:
        print(f"{device.name} {device.description} {device.flags}")

def packet_callback(win_pcap, param, header, pkt_data):
    try:
        Sniffer(packet=pkt_data).handle()
    except Exception as e:
        print(e)
        print('Error al procesar el paquete')

filename = "logs/log-" + str(datetime.now()).replace(':','-') + ".txt"

sys.stdout = open(filename, 'w', encoding='utf-8')

WinPcapUtils.capture_on(interface, packet_callback)

sys.stdout.close()