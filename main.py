from sniffer import Sniffer

filename = 'ethernet_3.bin'
filename = 'tests/' + filename

sniffer = Sniffer(filename)
sniffer.handle()

sniffer_2 = Sniffer('tests/ethernet_1.bin')
sniffer_2.handle()

sniffer_3 = Sniffer('tests/ethernet_3.bin')
sniffer_3.handle()