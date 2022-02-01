tipos = {
    ('08', '00') : 'IPv4',
    ('08', '06') : 'ARP',
    ('08', '35') : 'RARP',
    ('86', 'DD') : 'IPv6',
}

prioridades = {
    '000' : 'De rutina.',
    '001' : 'Prioritario.',
    '010' : 'Inmediato.',
    '011' : 'Relámpago.',
    '100' : 'Invalidación relámpago.',
    '101' : 'Procesando llamada crítica y de emergencia.',
    '110' : 'Control de trabajo de Internet.',
    '111' : 'Control de red.'
}

protocolos = {
    1 : 'ICMP v4',
    6 : 'TCP',
    17 : 'UDP',
    58 : 'ICMPv6',
    118 : 'STP',
    121 : 'SMP'
}