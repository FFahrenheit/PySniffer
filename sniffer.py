import os

tipos = {
    ('08', '00') : 'IPv4',
    ('08', '06') : 'ARP',
    ('08', '35') : 'RARP',
    ('86', 'DD') : 'IPv6',
}

class Sniffer:
    def __init__(self, filename):
        print('*'*100)
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
                
                print('Contenido: ' + ' '.join(self.bytes))
        except Exception as e:
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

        print(f"Destino: {str(self.destino)}")
        print(f"Origen: {str(self.origen)}")
        print(f"Tipo: {''.join(self.tipo)} => {self.protocolo}")
        print(f"Datos: {' '.join(self.datos)}")

        if self.protocolo == 'IPv4':
            
            print('Aqui se va a manejar IPv4')
        
        elif self.protocolo == 'ARP':
        
            print('Aqui se va a manejar ARP')
        
        elif self.protocolo == 'RARP':
        
            print('Aqui se va a manejar RARP')

        elif self.protocolo == 'IPv6':
        
            print('Aqui se va a manejar IPv6')
        
        else:
            
            print('No soportado aun')

    def is_valid(self):
        return self.bytes is not None