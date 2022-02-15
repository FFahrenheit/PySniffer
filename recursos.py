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