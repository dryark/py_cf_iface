# Copyright (c) 2024 Dry Ark LLC
# License AGPL 3.0

# This code is only intended to work on MacOS
# It may work on Posix platforms

import ctypes
import ctypes.util
import socket

# Define structures from ifaddrs.h
class sockaddr(ctypes.Structure):
    _fields_ = [
        ('sa_len',    ctypes.c_uint8),
        ('sa_family', ctypes.c_uint8),
        ('sa_data',   ctypes.c_char * 14),
    ]

class sockaddr_in6(ctypes.Structure):
    _fields_ = [
        ('sin6_len',      ctypes.c_uint8),
        ('sin6_family',   ctypes.c_uint8),
        ('sin6_port',     ctypes.c_uint16),
        ('sin6_flowinfo', ctypes.c_uint32),
        ('sin6_addr',     ctypes.c_uint8 * 16),
        ('sin6_scope_id', ctypes.c_uint32),
    ]

class ifaddrs(ctypes.Structure):
    pass

ifaddrs._fields_ = [
    ('ifa_next',    ctypes.POINTER(ifaddrs)),
    ('ifa_name',    ctypes.c_char_p),
    ('ifa_flags',   ctypes.c_uint),
    ('ifa_addr',    ctypes.POINTER(sockaddr)),
    ('ifa_netmask', ctypes.POINTER(sockaddr)),
    ('ifa_dstaddr', ctypes.POINTER(sockaddr)),
    ('ifa_data',    ctypes.c_void_p),
]

# Load libc
libc = ctypes.CDLL(ctypes.util.find_library('c'))

# Define getifaddrs function from ifaddrs.h
getifaddrs = libc.getifaddrs
getifaddrs.argtypes = [ctypes.POINTER(ctypes.POINTER(ifaddrs))]
getifaddrs.restype = ctypes.c_int

# Define freeifaddrs function from ifaddrs.h
freeifaddrs = libc.freeifaddrs
freeifaddrs.argtypes = [ctypes.POINTER(ifaddrs)]

IFF_UP = 0x1

def get_network_interfaces():
    ifap = ctypes.POINTER(ifaddrs)()
    result = getifaddrs(ctypes.byref(ifap))
    if result != 0:
        raise OSError(f"getifaddrs failed with error code {result}")

    interfaces = {}
    try:
        while ifap:
            interface_name = ifap.contents.ifa_name.decode()
            flags = ifap.contents.ifa_flags
            if flags & IFF_UP and interface_name.startswith('en'):
                addr = ifap.contents.ifa_addr.contents
                
                if addr.sa_family == socket.AF_INET6:
                    ipv6_addr = ctypes.cast(ifap.contents.ifa_addr, ctypes.POINTER(sockaddr_in6)).contents.sin6_addr
                    ipv6_address = socket.inet_ntop(socket.AF_INET6, ipv6_addr)
                    
                    if interface_name in interfaces:
                        interfaces[interface_name]['ipv6'].append(ipv6_address)
                    else:
                        interfaces[ interface_name ] = { 'ipv6': [ipv6_address], 'ipv4': 0 }
                if addr.sa_family == socket.AF_INET:
                    if interface_name in interfaces:
                        interfaces[interface_name]['ipv4'] = 1
                    else:
                        interfaces[interface_name] = { 'ipv6': [], 'ipv4': 1 }
            ifap = ifap.contents.ifa_next
    finally:
        freeifaddrs(ifap)

    return interfaces

def get_potential_remoted_ifaces():
    interfaces = get_network_interfaces()
    iface_out = []
    for interface, info in interfaces.items():
        if len( info['ipv6'] ) == 1:
            ipv4 = info['ipv4']
            if ipv4 == 0:
                iface_out.append( interface )
    return iface_out

