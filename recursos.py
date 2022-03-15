TIPOS = {
    ('08', '00') : 'IPv4',
    ('08', '06') : 'ARP',
    ('08', '35') : 'RARP',
    ('86', 'DD') : 'IPv6',
}

PRIORIDADES = {
    '000' : 'De rutina.',
    '001' : 'Prioritario.',
    '010' : 'Inmediato.',
    '011' : 'Relámpago.',
    '100' : 'Invalidación relámpago.',
    '101' : 'Procesando llamada crítica y de emergencia.',
    '110' : 'Control de trabajo de Internet.',
    '111' : 'Control de red.'
}

PROTOCOLOS = {
    1 : 'ICMP v4',
    6 : 'TCP',
    17 : 'UDP',
    58 : 'ICMPv6',
    118 : 'STP',
    121 : 'SMP'
}

ICMPV4_TIPOS = {
    0	: 'Echo Reply (respuesta de eco) ',
    3	: 'Destination Unreacheable (destino inaccesible) ',
    4	: 'Source Quench (disminución del tráfico desde el origen) ',
    5	: 'Redirect (redireccionar - cambio de ruta) ',
    8	: 'Echo (solicitud de eco) ',
    11	: 'Time Exceeded (tiempo excedido para un datagrama) ',
    12	: 'Parameter Problem (problema de parámetros ',
    13	: 'Timestamp (solicitud de marca de tiempo) ',
    14	: 'Timestamp Reply (respuesta de marca de tiempo) ',
    15	: 'Information Request (solicitud de información) - obsoleto- ',
    16	: 'Information Reply (respuesta de información) - obsoleto- ',
    17	: 'Addressmask (solicitud de máscara de dirección) ',
    18	: 'Addressmask Reply (respuesta de máscara de dirección'
}

ICMPV4_CODIGOS = {
    0	: 'no se puede llegar a la red ',
    1	: 'no se puede llegar al host o aplicación de destino ',
    2	: 'el destino no dispone del protocolo solicitado ',
    3	: 'no se puede llegar al puerto destino o la aplicación destino no está libre ',
    4	: 'se necesita aplicar fragmentación, pero el flag correspondiente indica lo contrario',
    5	: 'la ruta de origen no es correcta ',
    6	: 'no se conoce la red destino ',
    7	: 'no se conoce el host destino ',
    8	: 'el host origen está aislado ',
    9	: 'la comunicación con la red destino está prohibida por razones administrativas ',
    10	: 'la comunicación con el host destino está prohibida por razones administrativas ',
    11	: 'no se puede llegar a la red destino debido al Tipo de servicio',
    12	: 'no se puede llegar al host destino debido al Tipo de servicio '
}

ARP_HARDWARE = {
    0 : 'Reserved',
    1 : 'Ethernet (10Mb)',	
    2 : 'Experimental Ethernet (3Mb)',	
    3 : 'Amateur Radio AX.25',
    4 : 'Proteon ProNET Token Ring',
    5 : 'Chaos',
    6 : 'IEEE 802 Networks',
    7 : 'ARCNET',
    8 : 'Hyperchannel',
    9 : 'Lanstar',
    10 : 'Autonet Short Address',
    11 : 'LocalTalk',
    12 : 'LocalNet (IBM PCNet or SYTEK LocalNET)',	
    13 : 'Ultra link',
    14 : 'SMDS',
    15 : 'Frame Relay',
    16 : 'Asynchronous Transmission Mode (ATM)',	
    17 : 'HDLC	',
    18 : 'Fibre Channel	',
    19 : 'Asynchronous Transmission Mode (ATM)',	
    20 : 'Serial Line',
    21 : 'Asynchronous Transmission Mode (ATM)',
    22 : 'MIL-STD-188-220',
    23 : 'Metricom',
    24 : 'IEEE 1394.1995',
    25 : 'MAPOS',
    26 : 'Twinaxial',
    27 : 'EUI-64',
    28 : 'HIPARP',
    29 : 'IP and ARP over ISO 7816-3',
    30 : 'ARPSec',
    31 : 'IPsec tunnel',
    32 : 'InfiniBand (TM)',
    33 : 'TIA-102 Project 25 Common Air Interface (CAI)',
    34 : 'Wiegand Interface',
    35 : 'Pure IP',
    36 : 'HW_EXP1',
    37 : 'HFI',
    # 38-255 : Unassigned,
    256 : 'HW_EXP2',
    257 : 'AEthernet',
    # 258-65534 : Unassigned,
    65535 :	'Reserved'
}

ARP_OPERACION = {
    0 : 'Reserved',
    1 : 'ARP Request',
    2 : 'ARP Reply',
    3 : 'RARP Request',
    4 : 'RARP Reply',
    5 : 'DRARP Request',
    6 : 'DRARP Reply',
    7 : 'DRARP Error',
    8 : 'InARP Request',
    9 : 'InARP Reply',
    10 : 'ARP-NAK',
    11 : 'MARS-Request',
    12 : 'MARS-Multi',
    13 : 'MARS-MServ',
    14 : 'MARS-Join',
    15 : 'MARS-Leave',
    16 : 'MARS-NAK',
    17 : 'MARS-Unserv',
    18 : 'MARS-SJoin',
    19 : 'MARS-SLeave',
    20 : 'MARS-Grouplist-Reques',
    21 : ' MARS-Grouplist-Reply',
    22 : 'MARS-Redirect-Map',
    23 : 'MAPOS-UNARP',
    24 : 'OP_EXP1',
    25 : 'OP_EXP2',
    # 266 - 65534 : Unassigned,
    65535 : 'Reserved',
}

ICMPV6_TIPOS = {
    1: 'Mensaje de destino inalcanzable',
    2: 'Mensaje de paquete demasiado grande',
    3: 'Time exceeded message',
    4: 'Mensaje de problema de parámetro',
    128: 'Mensaje del pedido de eco',
    129: 'Mensaje de respuesta de eco',
    133: 'Mensaje de solicitud de router',
    134: 'Mensaje de anuncio del router',
    135: 'Mensaje de solicitud vecino',
    136: 'Mensaje de anuncio de vecino',
    137: 'Reoriente del mensaje'
}

ICMPV6_CODIGOS = {
    1: {
        0: 'No existe ruta de destino',
        1: 'Comunicación con el destino administrativamente prohibida',
        2: 'No asignado',
        3: 'Direccion inalcanzable'
    },
    3: {
        0: 'El limite del salto excedido',
        1: 'Tiempo de reensamble del fragmento excedido'
    },
    4: {
        0: 'El campo del encabezado erroneo encontró',
        1: 'El tipo siguiente desconocido del encabezado encontró',
        2: 'Opción desconocida del IPv6 encontrada'
    },
}

TCP_UDP_PUERTOS = {
    20: 'FTP',
    21: 'FTP',
    22: 'SSH',
    23: 'TELNET',
    25: 'SMTP',
    53: 'DNS',
    67: 'DHCP',
    68: 'DHCP',
    69: 'TFTP',
    80: 'HTTP',
    110: 'POP3',
    143: 'IMAP',
    443: 'HTTPS',
    993: 'IMAP SSL',
    995: 'POP SSL',
}

TCP_FLAGS = ['NS', 'CWR', 'ECE', 'URG', '\tACK', '\tPSH', '\tRST', '\tSYN', '\tFIN']