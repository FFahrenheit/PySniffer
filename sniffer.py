from recursos import *
from datetime import datetime

class Sniffer:
    def __init__(self, filename = None, packet = None):
        if filename is not None:
            self.from_file(filename)
        if packet is not None:
            self.from_packet(packet)
    
    def from_packet(self, packet):
        print(f"{'='*10} ETHERNET ({ str(datetime.now()) }) {'='*10}")
        self.packet = packet

        self.bytes = []
        self.raw_bytes = []
        try:
            for data in packet:
                byte = data.to_bytes(1, byteorder='big')
                hex_digit = byte.hex().upper()  #Representación del string    
                self.bytes.append(hex_digit)                
                self.raw_bytes.append(byte)

            print('Contenido: ' + ' '.join(self.bytes), end='\n')
            print(f"Longitud: {str(len(self.bytes))} bytes", end = '\n\n')
        except Exception as e:
            print(e)
            self.bytes = None
            print('Error al leer el paquete')
            return

    def from_file(self, filename):
        print(f"{'='*20} ETHERNET ({ filename }) {'='*20}")
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

        print(f"Destino: {str(self.destino)}")
        print(f"Origen: {str(self.origen)}")
        print(f"Tipo: {''.join(self.tipo)} => {self.protocolo}")
        # print(f"Datos: {' '.join(self.datos)}\n")

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

    def tcp(self, idx_inicio):
        datos_hex = self.bytes[idx_inicio:]
        datos = self.raw_bytes[idx_inicio:]

        self.tcp_puerto_origen = int.from_bytes(datos[0] + datos[1], byteorder='big')
        self.tcp_puerto_destino = int.from_bytes(datos[2] + datos[3], byteorder='big')
        self.tcp_secuencia = int.from_bytes(self.bit_sum(datos, 4, 8), byteorder='big')
        self.tcp_ack = int.from_bytes(self.bit_sum(datos, 8, 12), byteorder='big')
        self.tcp_longitud = self.bits_int(datos[12], 0, 4)      # *4 bytes
        self.tcp_reservado = self.bits(datos[12], 4, 7)
        self.tcp_flags = self.bits(datos[12] + datos[13], 7, 16, 16)
        self.tcp_ventana = int.from_bytes(datos[14] + datos[15], byteorder='big')
        self.tcp_checksum = ' '.join(datos_hex[16:18])
        self.tcp_puntero_urg = int.from_bytes(datos[18] + datos[19], byteorder='big')
        self.tcp_opciones = datos_hex[20 : self.tcp_longitud * 4 ]
        offset_datos = len(self.tcp_opciones)
        self.tcp_datos = datos_hex[20 + offset_datos : ]

        origen = self.tcp_puerto_origen
        print(f"Puerto origen: {TCP_UDP_PUERTOS.get(origen, 'Servicio desconocido')} ({self.port_type(origen)}) ({origen})")
        destino = self.tcp_puerto_destino
        print(f"Puerto destino: {TCP_UDP_PUERTOS.get(destino, 'Servicio desconocido')} ({self.port_type(destino)}) ({destino})")
        print(f"Número de secuencia: {self.tcp_secuencia}")
        print(f"Número de acuse de recibido: {self.tcp_ack}")
        print(f"Longitud de cabecera: {self.tcp_longitud * 4} bytes")
        print(f"Banderas reservadas: {self.tcp_reservado}")

        print(f"Banderas: {self.tcp_flags}")
        for i, flag in enumerate(self.tcp_flags):
            print(f"{TCP_FLAGS[i]}: {'Habilitado ✔' if flag == '1' else 'Deshabilitado ❌'} ({flag})")      #✔ y ❌

        print(f"Longitud de ventana: {self.tcp_ventana}")
        print(f"Checksum: {self.tcp_checksum}")
        print(f"Puntero urgente: {self.tcp_puntero_urg}")
        print(f"Opciones: {' '.join(self.tcp_opciones)}")
        print(f"Datos: {' '.join(self.tcp_datos)}")

        idx_data = idx_inicio + self.tcp_longitud * 4
        self.check_port(idx_data, [self.tcp_puerto_destino, self.tcp_puerto_origen])

    def udp(self, idx_inicio):
        datos_hex = self.bytes[idx_inicio:]
        datos = self.raw_bytes[idx_inicio:]

        self.udp_puerto_origen = int.from_bytes(datos[0] + datos[1], byteorder='big')
        self.udp_puerto_destino = int.from_bytes(datos[2] + datos[3], byteorder='big')
        self.udp_longitud = int.from_bytes(datos[4] + datos[5], byteorder='big')
        self.udp_checksum = " ".join(datos_hex[6:8])
        self.udp_datos = " ".join(datos_hex[8:])
        origen = self.udp_puerto_origen
        destino = self.udp_puerto_destino

        print(f"Puerto de origen: {TCP_UDP_PUERTOS.get(origen, 'Servicio desconocido')} ({self.port_type(origen)}) ({origen})")
        print(f"Puerto de destino: {TCP_UDP_PUERTOS.get(destino, 'Servicio desconocido')} ({self.port_type(destino)}) ({destino})")
        print(f"Longitud total: {self.udp_longitud} bytes")
        print(f"Checksum: {self.udp_checksum}")
        print(f"Datos: {self.udp_datos}")

        self.check_port(idx_inicio + 8, [self.udp_puerto_destino, self.udp_puerto_origen])

    def check_port(self, idx_inicio, ports):
        if 53 in ports:
            self.dns(idx_inicio)

    def dns(self, idx_inicio):
        print(f"{'_'*40} DNS {'_'*40}")
        datos_hex = self.bytes[idx_inicio:]     #Hex - string 0A, 0B
        datos = self.raw_bytes[idx_inicio:]     #Raw - 0x01, 0x0A binarios 

        print(' '.join(datos_hex))
        self.dns_id = ' '.join(datos_hex[0:2])
        self.dns_flags = self.bits(datos[2] + datos[3], 0, 16, 16)
        self.dns_qr = self.dns_flags[0]
        self.dns_op_code = self.bits_int(datos[2], 1, 5)
        self.dns_rcode = self.bits_int(datos[3], 4, 8)
        self.dns_qdcount = int.from_bytes(datos[4] + datos[5], byteorder='big')
        self.dns_ancount = int.from_bytes(datos[6] + datos[7], byteorder='big')
        self.dns_nscount = int.from_bytes(datos[8] + datos[9], byteorder='big')
        self.dns_arcount = int.from_bytes(datos[10] + datos[11], byteorder='big')

        print(f"ID: {self.dns_id}")
        print(f"Banderas: {self.dns_flags}")
        print(f"\tQR: {'Respuesta' if self.dns_qr == '1' else 'Consulta'} ({self.dns_qr})")
        print(f"\tOP Code: {DNS_OP_CODES.get(self.dns_op_code, 'Reservado')} ({self.dns_op_code})")
        for index, flag in enumerate(self.dns_flags[5:9]):
            print(f"\t{DNS_BIT_FLAGS[index]}: {'Activa' if flag == '1' else 'Inactiva'} ({flag})")
        print(f"\tZ: {self.dns_flags[9:12]}")
        print(f"\tRCode: {DNS_RCODES.get(self.dns_rcode, 'No definido')} ({self.dns_rcode})")

        print(f"QDcount: {self.dns_qdcount}")
        print(f"ANcount: {self.dns_ancount}")
        print(f"NScount: {self.dns_nscount}")
        print(f"ARcount: {self.dns_arcount}")
        
        i = 12
        print('Questions:')
        for j in range(self.dns_qdcount):    
            dominio, i = self.get_domain(datos, i)

            tipo = int.from_bytes(datos[i] + datos[i+1], byteorder='big')
            i += 2
            clase = int.from_bytes(datos[i] + datos[i+1], byteorder='big')
            i += 2
            print(f"\tPregunta #{ j + 1 }")
            print(f"\t\tDominio: {dominio}")
            print(f"\t\tTipo: {DNS_TIPOS.get(tipo, 'Tipo desconocido')} ({tipo})")
            print(f"\t\tClase: {DNS_CLASES.get(clase, 'Clase desconocida')} ({clase})")

        print('Answers: ')
        for j in range(self.dns_ancount):
            print(f"\tRespuesta #{ j + 1 }")

            puntero_hex = ' '.join(datos_hex[i:i+2])
            puntero = int.from_bytes(datos[i] + datos[i+1], byteorder='big')
            puntero = puntero - idx_inicio - 1 #-1 para saber cuánto leer...
            dominio, puntero = self.get_domain(datos, puntero)
            # for j in range(self.dns_qdcount):    
            #     longitud = int.from_bytes(datos[puntero], byteorder='big') 
            #     dominio = ''
            #     while longitud != 0:
            #         puntero += 1
            #         dominio += self.bits_str(datos[puntero : puntero+longitud])
            #         puntero += longitud
            #         print(puntero)
            #         longitud = int.from_bytes(datos[puntero], byteorder='big')
            #         if longitud != 0:
            #             dominio += '.'  
            #     else:
            #         puntero += 1
            i += 2
            tipo = int.from_bytes(datos[i] + datos[i+1], byteorder='big')
            i += 2
            clase = int.from_bytes(datos[i] + datos[i+1], byteorder='big')
            i += 2
            ttl = int.from_bytes(self.bit_sum(datos, i, i+4), byteorder='big')
            i += 4
            longitud = int.from_bytes(datos[i] + datos[i+1], byteorder='big')
            i += 2
            print(f"\t\tPuntero: {puntero_hex}")
            print(f"\t\tNombre del dominio: {dominio}")
            print(f"\t\tTipo: {DNS_TIPOS.get(tipo, 'Tipo desconocido')} ({tipo})")
            print(f"\t\tClase: {DNS_CLASES.get(clase, 'Clase desconocida')} ({clase})")
            print(f"\t\tTTL: {ttl} segundos")
            print(f"\t\tLongitud de datos: {longitud} bytes")            

            data = self.handle_dns_answer(datos, DNS_TIPOS.get(tipo, None), longitud, i)
            i += longitud
            print(f"\t\tDatos: {data}")

    def handle_dns_answer(self, datos, tipo, longitud_datos, idx_inicio):
        data = datos[idx_inicio:idx_inicio + longitud_datos]
        # print(data)
        # print(len(data))
        if tipo is None:
            return ''
        if tipo == 'A':
            to_int = lambda x : str(int.from_bytes(x, byteorder='big'))
            ip = list(map(to_int, data[0:4]))
            # print(ip)
            return 'IP servidor: ' + '.'.join(ip)

        elif tipo == 'CNAME':
            dominio, _ = self.get_domain(data, 0)
            return 'Dominio: ' + dominio
        
        elif tipo == 'MX':
            pass
        elif tipo == 'NS':
            pass

    def get_domain(self, data, begin=0, end=None):
        if end is None:
            end = len(data)
        i = begin
        longitud = int.from_bytes(data[i], byteorder='big')
        dominio = ''
        while longitud != 0:

            if i + longitud > end: #No debería ser usado, pero por si acaso
                if b'\x00' in data[i+1:]:
                    end = data[i+1:].index(b'\x00') + i + 1
                return dominio + self.bits_str(data[i + 1: end]), end

            i += 1
            dominio += self.bits_str(data[i : i+longitud])
            i += longitud
            longitud = int.from_bytes(data[i], byteorder='big')

            if longitud != 0:
                dominio += '.'

        return dominio, i + 1

    def ipv6(self):
        datos = self.raw_bytes[14:14+40]
        datos_hex = self.bytes[14:14+40]
        print(f"Datos: {' '.join(datos_hex)}")

        self.version = self.bits_int(datos[0], 0, 4)
        self.clase_trafico = self.bits(datos[0] + datos[1], 4, 12, 16)
        self.prioridad = self.clase_trafico[:3]
        self.caracteristicas = self.clase_trafico[3:]
        self.etiqueta_flujo = self.bits_int(datos[1] + datos[2] + datos[3], 4, 24, 24)
        self.carga_util = int.from_bytes(datos[4] + datos[5], byteorder='big')
        self.siguiente = int.from_bytes(datos[6], byteorder='big')
        self.limite_saltos = int.from_bytes(datos[7], byteorder='big')        
        self.ip_origen = [i + j for i, j in zip(datos_hex[8:24:2], datos_hex[9:24:2])]
        self.ip_destino = [i + j for i, j in zip(datos_hex[24:40:2], datos_hex[25:40:2])]

        print(f"Versión: {self.version}")
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
        print(f"Carga útil: {self.carga_util} bytes")
        print(f"Protocolo: {PROTOCOLOS.get(self.siguiente, 'No definido')} ({self.siguiente})")
        print(f"Limite de saltos: {self.limite_saltos}")
        print(f"IP origen: {':'.join(self.ip_origen)}")
        print(f"IP destino: {':'.join(self.ip_destino)}")
        
        print(f"{'-'*30} {PROTOCOLOS.get(self.siguiente, 'Protocolo no definido')} ({self.siguiente}) {'-' *30}")
        if self.siguiente == 58:
            self.icmpv6()
        elif self.siguiente == 6:
            self.tcp(54)
        elif self.siguiente == 17:
            self.udp(54)

    def icmpv6(self):
        datos = self.raw_bytes[54:58]
        datos_hex = self.bytes[54:58]

        self.icmpv6_tipo = int.from_bytes(datos[0], byteorder='big')
        self.icmpv6_codigo = int.from_bytes(datos[1], byteorder='big')
        self.icmpv6_checksum = datos_hex[2:4]

        codigo = ICMPV6_CODIGOS.get(self.icmpv6_tipo, {}).get(self.icmpv6_codigo, 'No especificado')

        print(f"Tipo: {ICMPV6_TIPOS.get(self.icmpv6_tipo, 'No especificado')} ({self.icmpv6_tipo})")
        print(f"Codigo: { codigo } ({self.icmpv6_codigo})")
        print(f"Checksum: {' '.join(self.icmpv6_checksum)}")

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
        # print(f"Datos: {' '.join(self.bytes[14:14+20])}")

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
        self.opciones = self.bytes[34:34 + self.longitud * 4 - 20]

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

        print(f"Checksum: {' '.join(self.checksum)}")
        print(f"IP origen: {'.'.join(self.ip_origen)}")
        print(f"IP destino: {'.'.join(self.ip_destino)}")
        print(f"Opciones: {' '.join(self.opciones)}")

        print(f"{'-'*30} {PROTOCOLOS.get(self.protocolo, 'Protocolo no definido')} ({self.protocolo}) {'-' *30}")
        if self.protocolo == 1:
            self.icmpv4(34 + len(self.opciones))
        elif self.protocolo == 6:
            self.tcp(34 + self.longitud * 4 - 20)
        elif self.protocolo == 17:
            self.udp(34 + self.longitud * 4 - 20)


    def icmpv4(self, idx_inicio):
        self.icmpv4_tipo = int.from_bytes(self.raw_bytes[idx_inicio], byteorder='big')
        self.icmpv4_codigo = int.from_bytes(self.raw_bytes[idx_inicio + 1], byteorder='big')
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

    def bit_sum(self, bytes, inicio, fin):
        total = bytes[inicio]
        for i in range(inicio + 1, fin):
            total += bytes[i]
        return total

    def port_type(self, port : int):
        if port >= 0 and port <= 1023:
            return 'Bien conocido'
        if port >= 1024 and port <= 49151:
            return 'Registrado'
        if port >= 49152 and port <= 65535:
            return 'Dinámico'
        return 'Inválido'

    def bits_str(self, bytes):
        return ''.join(map(lambda x : chr(int.from_bytes(x, byteorder='big')), bytes))