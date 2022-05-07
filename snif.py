#pip install winpcapy
#install winpcap

from winpcapy import WinPcapUtils, WinPcapDevices
from sniffer import Sniffer
from datetime import datetime
import sys

def packet_callback(win_pcap, param, header, pkt_data):
    try:
        Sniffer(packet=pkt_data).handle()
    except Exception as e:
        print(e)
        print('Error al procesar el paquete')


def start_sniffer():
    with WinPcapDevices() as devices:
        print('Tarjetas de red conectadas:')
        for device in devices:
            # print(f"{device.name} {device.description} {device.flags}")
            print(f"\t{device.description}")
        
        interface = input('Escriba la interfaz seleccionada (Parte del nombre identificable): ')
        interface = '*' + interface + '*'
        console = input('Desea guardar los paquetes en un archivo de texto? (y/n): ')

    if console == 'n' or console == 'N':
        WinPcapUtils.capture_on(interface, packet_callback)
    else:
        filename = "logs/log-" + str(datetime.now()).replace(':','-') + ".log"
        sys.stdout = open(filename, 'w', encoding='utf-8')
        
        WinPcapUtils.capture_on(interface, packet_callback)

        sys.stdout.close()
    
    print("No se pudo encontrar la tarjeta de red")