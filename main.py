filename = 'ethernet_3.bin'
filename = 'tests/' + filename

with open(filename, 'rb') as file:
    bytes = []
    byte = file.read(1) #bytes (1)

    while byte:
        hex_digit = byte.hex().upper()
        bytes.append(hex_digit)
        byte = file.read(1)

    print(bytes)


destino = bytes[0:6]
origen = bytes[6:12]
tipo = tuple(bytes[12:14])
datos = bytes[14:]

print('Destino: ' + str(destino))
print('Origen: ' + str(origen))
print('Tipo: ' + str(tipo))
print('Datos: ' + str(datos))


if tipo == ('08', '00'):
    print('ARP')
elif tipo == ('08', '06'):
    print('IPv4')
elif tipo == ('08', '35'):
    print('RARP')
elif tipo == ('86', 'DD'):
    print('IPv6')