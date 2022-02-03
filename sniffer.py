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
        self.protocolo = tipos[self.tipo]

        print(f"Destino: {str(self.destino)}\n")
        print(f"Origen: {str(self.origen)}\n")
        print(f"Tipo: {''.join(self.tipo)} => {self.protocolo}\n")
        print(f"Datos: {' '.join(self.datos)}\n")

        if self.protocolo == 'IPv4':        
            print('*'*40 + ' IPv4 ' + '*'* 40)
            self.ipv4()

        elif self.protocolo == 'ARP':
        
            print('Aqui se va a manejar ARP')
        
        elif self.protocolo == 'RARP':
        
            print('Aqui se va a manejar RARP')

        elif self.protocolo == 'IPv6':
        
            print('Aqui se va a manejar IPv6')
        
        else:
            
            print('No soportado aun')

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
        print(f"Prioridad: {prioridades.get(self.prioridad, 'No encontrada')} ({self.prioridad})")
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
        print(f"Protocolo: {protocolos.get(self.protocolo, 'No definido')} ({self.protocolo})")
        print(f"Checksum: {' '.join(self.checksum)}")
        print(f"IP origen: {'.'.join(self.ip_origen)}")
        print(f"IP destino: {'.'.join(self.ip_destino)}")
        print(f"Opciones: {' '.join(self.opciones)}")


    def bits_int(self, byte, inicio, fin, fill = 8):
        return int(self.bits(byte, inicio, fin, fill), base=2)

    def bits(self, byte, inicio, fin, fill = 8):
        return bin(int(byte.hex(), base=16)).lstrip('0b').zfill(fill)[inicio:fin]

    def is_valid(self):
        return self.bytes is not None