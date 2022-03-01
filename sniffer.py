from recursos import *

class Sniffer:
    def __init__(self, filename):
        print(f"{'*'*20} ETHERNET ({ filename }) {'*'*20}")
        self.filename = filename

        try:
            with open(self.filename, 'rb') as file:
                self.bytes = []
                self.raw_bytes = []
                byte = file.read(1) #Leer 1 byte

                while byte:         #Mientras haya mas contenido
                    hex_digit = byte.hex().upper()  #Representación del string
                    
                    self.bytes.append(hex_digit)                
                    self.raw_bytes.append(byte)
                    
                    byte = file.read(1)
                
                print('Contenido: ' + ' '.join(self.bytes), end='\n')
                print(f"Longitud: {str(len(self.bytes))} bytes", end = '\n\n')
        except Exception as e:
            print(e)
            self.bytes = None
            print('Error al leer el archivo')
            return

    def handle(self):
        if not self.is_valid():
            return
        
        self.destino = ':'.join(self.bytes[0:6])
        self.origen =  ':'.join(self.bytes[6:12])
        self.tipo = tuple(self.bytes[12:14])
        self.datos =  self.bytes[14:]
        self.protocolo = TIPOS.get(self.tipo, 'Por definir')

        print(f"Destino: {str(self.destino)}\n")
        print(f"Origen: {str(self.origen)}\n")
        print(f"Tipo: {''.join(self.tipo)} => {self.protocolo}\n")
        print(f"Datos: {' '.join(self.datos)}\n")

        print(f"{'*'*40} {self.protocolo} {'*'*40}")

        if self.protocolo == 'IPv4':        
            self.ipv4()

        elif self.protocolo == 'ARP':        
            self.arp()

        elif self.protocolo == 'RARP':
            self.arp()

        elif self.protocolo == 'IPv6':
            self.ipv6()

        else:
            
            print('No soportado aun')

    def ipv6(self):
        datos = self.raw_bytes[14:14+40]
        datos_hex = self.bytes[14:14+40]
        print(f"Datos: {' '.join(datos_hex)}")

        self.clase_trafico = self.bits(datos[0] + datos[1], 4, 12, 16)
        clase_trafico_bytes = bytes([int(self.clase_trafico, 2)])
        self.prioridad = self.bits(clase_trafico_bytes, 0, 3)
        self.caracteristicas = self.bits(clase_trafico_bytes, 3, 8)
        self.etiqueta_flujo = self.bits_int(datos[1] + datos[2] + datos[3], 4, 24, 24)
        #Tamaño: 4-5
        #Siguiente: 6
        #Alcance: 7
        self.ip_origen = [i + j for i, j in zip(datos_hex[8:24:2], datos_hex[9:24:2])]

        print(f"Clase de tráfico: {self.clase_trafico}")
        print(f"Prioridad: {PRIORIDADES.get(self.prioridad, 'No encontrada')} ({self.prioridad})")
        print(f"Caracteristicas de servicio: {self.caracteristicas}")
        for index, c in enumerate(self.caracteristicas):
            if index == 0:
                print(f"\tRetardo: {'Normal' if c == '0' else 'Bajo'} ({c})")
            elif index == 1:
                print(f"\tRendimiento: {'Normal' if c == '0' else 'Alto'} ({c})")
            elif index == 2:
                print(f"\tFiabilidad: {'Normal' if c == '0' else 'Alta'} ({c})")

        print(f"Etiqueta de flujo: {self.etiqueta_flujo}")
        #
        print(f"IP origen: {':'.join(self.ip_origen)}")

    def arp(self):
        datos = self.raw_bytes[14:]
        datos_hex = self.bytes[14:]
        print(f"Datos: {' '.join(datos_hex)}")
        
        self.tipo_hardware_arp = int.from_bytes(datos[0] + datos[1], byteorder='big')
        self.tipo_protocolo_arp = tuple(datos_hex[2:4])
        x = int.from_bytes(datos[4], byteorder='big')
        y = int.from_bytes(datos[5], byteorder='big')
        self.codigo_operacion_arp = int.from_bytes(datos[6] + datos[7], byteorder='big')
        self.mac_emisor_arp = ':'.join(datos_hex[8 : 8+x])
        self.mac_receptor_arp = ':'.join(datos_hex[8+x+y : 8+2*x+y])
        to_int = lambda x : str(int.from_bytes(x, byteorder='big'))
        self.ip_emisor_arp = '.'.join(map(to_int, datos[8+x : 8+x+y]))
        self.ip_receptor_arp = '.'.join(map(to_int, datos[8+2*x+y : 8+2*(x+y)]))


        print(f"Tipo de hardware: {ARP_HARDWARE.get(self.tipo_hardware_arp, 'Unassigned')} ({self.tipo_hardware_arp})")
        print(f"Tipo de protocolo: {''.join(self.tipo_protocolo_arp)} => {TIPOS.get(self.tipo_protocolo_arp, 'No definido')}")
        print(f"Longitud direccion de hardware: {x} bytes")
        print(f"Longitud direccion de protocolo: {y} bytes")
        print(f"Codigo de operación: {ARP_OPERACION.get(self.codigo_operacion_arp, 'Unassigned')} ({self.codigo_operacion_arp})")
        print(f"Direccion hardware del emisor: {self.mac_emisor_arp}")
        print(f"Direccion IP del emisor: {self.ip_emisor_arp}")
        print(f"Direccion hardware del receptor: {self.mac_receptor_arp}")
        print(f"Direccion IP del receptor: {self.ip_receptor_arp}")


    def ipv4(self):
        datos = self.raw_bytes[14:14+20]
        datos_hex = self.bytes[14:14+20]
        print(f"Datos: {' '.join(self.bytes[14:14+20])}")

        self.version = self.bits_int(datos[0], 0, 4)
        self.longitud = self.bits_int(datos[0], 4, 8)
        self.prioridad = self.bits(datos[1], 0, 3)
        self.caracteristicas = self.bits(datos[1], 3, 8)
        self.longitud_total = datos[2] + datos[3]
        self.identificador = datos[4] + datos[5]
        self.flags = self.bits(datos[6], 0, 3)
        self.posicion = self.bits(datos[6], 4, 8) + self.bits(datos[7], 0, 8)
        self.posicion = int(self.posicion, base=2)
        self.ttl = int.from_bytes(datos[8], byteorder='big')
        self.protocolo = int.from_bytes(datos[9], byteorder='big')
        self.checksum = datos_hex[10:12]
        to_int = lambda x : str(int.from_bytes(x, byteorder='big'))
        self.ip_origen = list(map(to_int, datos[12:16]))
        self.ip_destino = list(map(to_int, datos[16:20]))
        self.opciones = self.bytes[36:36 + self.longitud * 4 - 20]

        print(f"Version: {self.version}")
        print(f"Longitud del encabezado: {self.longitud} palabras ({self.longitud * 4} bytes)")
        print(f"Prioridad: {PRIORIDADES.get(self.prioridad, 'No encontrada')} ({self.prioridad})")
        print(f"Caracteristicas de servicio: {self.caracteristicas}")
        for index, c in enumerate(self.caracteristicas):
            if index == 0:
                print(f"\tRetardo: {'Normal' if c == '0' else 'Bajo'} ({c})")
            elif index == 1:
                print(f"\tRendimiento: {'Normal' if c == '0' else 'Alto'} ({c})")
            elif index == 2:
                print(f"\tFiabilidad: {'Normal' if c == '0' else 'Alta'} ({c})")

        print(f"Longitud total: {int.from_bytes(self.longitud_total, byteorder='big')} bytes")
        print(f"Identificador: {int.from_bytes(self.identificador, byteorder='big')}")
        print(f"Banderas: {self.flags}")
        for index, f in enumerate(self.flags):
            if index == 0:
                print(f"\tReservado: {f}")
            if index == 1:
                print(f"\tDF: {'Divisible' if f == '0' else 'No divisible'} ({f})")
            elif index == 2:
                print(f"\tMF: {'Ultimo fragmento' if f == '0' else 'Fragmento intermedio'} ({f})")
        
        print(f"Posicion: {self.posicion}")
        print(f"Tiempo de vida: {self.ttl}")
        
        print(f"Protocolo: {PROTOCOLOS.get(self.protocolo, 'No definido')} ({self.protocolo})")
        if self.protocolo == 1:
            self.icmpv4(34 + len(self.opciones))
        else:
            pass

        print(f"Checksum: {' '.join(self.checksum)}")
        print(f"IP origen: {'.'.join(self.ip_origen)}")
        print(f"IP destino: {'.'.join(self.ip_destino)}")
        print(f"Opciones: {' '.join(self.opciones)}")


    def icmpv4(self, idx_inicio):
        self.icmpv4_tipo = self.bits_int(self.raw_bytes[idx_inicio], 0, 8)
        self.icmpv4_codigo = self.bits_int(self.raw_bytes[idx_inicio + 1], 0, 8)
        self.icmpv_checksum = self.bytes[idx_inicio + 2: idx_inicio + 4]

        print(f"\tTipo: {ICMPV4_TIPOS.get(self.icmpv4_tipo, 'No especificado')} ({self.icmpv4_tipo})")
        print(f"\tCodigo: {ICMPV4_CODIGOS.get(self.icmpv4_codigo, 'No especificado')} ({self.icmpv4_codigo})")
        print(f"\tChecksum: {' '.join(self.icmpv_checksum)}")

    def bits_int(self, byte, inicio, fin, fill = 8):
        return int(self.bits(byte, inicio, fin, fill), base=2)

    def bits(self, byte, inicio, fin, fill = 8):
        return bin(int(byte.hex(), base=16)).lstrip('0b').zfill(fill)[inicio:fin]

    def is_valid(self):
        return self.bytes is not None