# This software released into the public domain. Anyone is free to copy,
# modify, publish, use, compile, sell, or distribute this software,
# either in source code form or as a compiled binary, for any purpose,
# commercial or non-commercial, and by any means.

import socket
import os
import sys


def inject_into_socket():

    class in_addr(ctypes.Structure):
        _fields_ = [("S_addr", ctypes.c_ubyte * 4)]

    class in6_addr(ctypes.Structure):
        _fields_ = [("Byte", ctypes.c_ubyte * 16)]

    if hasattr(ctypes, "windll"):
        # InetNtopW(
        #   INT         family,
        #   const VOID  *pAddr,
        #   PWSTR       pStringBuf,
        #   size_t      StringBufSize
        # ) -> PCWSTR
        InetNtopW = ctypes.windll.ws2_32.InetNtopW

        # InetPtonW(
        #   INT         family,
        #   PCWSTR      pszAddrString,
        #   PVOID       pAddrBuf
        # ) -> INT
        InetPtonW = ctypes.windll.ws2_32.InetPtonW

        # WSAGetLastError() -> INT
        WSAGetLastError = ctypes.windll.ws2_32.WSAGetLastError
    else:

        def not_windows():
            raise SystemError("Invalid platform. ctypes.windll must be available.")

        InetNtopW = not_windows
        InetPtonW = not_windows
        WSAGetLastError = not_windows

    def inet_pton(address_family, ip_string):
        if sys.version_info[0] > 2 and isinstance(ip_string, bytes):
            raise TypeError("inet_pton() argument 2 must be str, not bytes")

        if address_family == socket.AF_INET:
            family = 2
            addr = in_addr()
        elif address_family == socket.AF_INET6:
            family = 23
            addr = in6_addr()
        else:
            raise socket.error("unknown address family")

        ip_string = ctypes.c_wchar_p(ip_string)
        ret = InetPtonW(ctypes.c_int(family), ip_string, ctypes.byref(addr))

        if ret == 1:
            if address_family == socket.AF_INET:
                return ctypes.string_at(addr.S_addr, 4)
            else:
                return ctypes.string_at(addr.Byte, 16)
        elif ret == 0:
            raise socket.error("illegal IP address string passed to inet_pton")
        else:
            err = WSAGetLastError()
            if err == 10047:
                e = socket.error("unknown address family")
            elif err == 10014:
                e = OSError("bad address")
            else:
                e = OSError("unknown error from inet_ntop")
            e.errno = err
            raise e

    def inet_ntop(address_family, packed_ip):
        if address_family == socket.AF_INET:
            addr = in_addr()
            if len(packed_ip) != ctypes.sizeof(addr.S_addr):
                raise socket.error("packed IP wrong length for inet_ntop")

            ctypes.memmove(addr.S_addr, packed_ip, 4)
            buffer_len = 16
            family = 2

        elif address_family == socket.AF_INET6:
            addr = in6_addr()
            if len(packed_ip) != ctypes.sizeof(addr.Byte):
                raise socket.error("packed IP wrong length for inet_ntop")

            ctypes.memmove(addr.Byte, packed_ip, 16)
            buffer_len = 46
            family = 23
        else:
            raise socket.error("unknown address family")

        buffer = ctypes.create_unicode_buffer(buffer_len)

        ret = InetNtopW(
            ctypes.c_int(family),
            ctypes.byref(addr),
            ctypes.byref(buffer),
            ctypes.sizeof(buffer),
        )
        if ret is None:
            err = WSAGetLastError()
            if err == 10047:
                e = socket.error("unknown address family")
            else:
                e = socket.error("unknown error from inet_ntop")
            e.errno = err

        return ctypes.wstring_at(buffer, buffer_len).rstrip("\x00")

    # Adding our two functions to the socket library
    socket.inet_pton = inet_pton
    socket.inet_ntop = inet_ntop

def inject_into_xp_socket():
    # For Windows Xp

    class SockAddr(ctypes.Structure):
        _fields_ = [("sa_family", ctypes.c_short),
                    ("__pad1", ctypes.c_ushort),
                    ("ipv4_addr", ctypes.c_byte * 4),
                    ("ipv6_addr", ctypes.c_byte * 16),
                    ("__pad2", ctypes.c_ulong)]

    if hasattr(ctypes, 'windll'):
        WSAStringToAddressA = ctypes.windll.ws2_32.WSAStringToAddressA
        WSAAddressToStringA = ctypes.windll.ws2_32.WSAAddressToStringA
    else:
        def not_windows():
            raise SystemError(
                "Invalid platform. ctypes.windll must be available."
            )

        WSAStringToAddressA = not_windows
        WSAAddressToStringA = not_windows

    def inet_pton(address_family, ip_string):
        addr = SockAddr()
        addr.sa_family = address_family
        addr_size = ctypes.c_int(ctypes.sizeof(addr))
        ip_string = ctypes.c_char_p(ip_string)

        if WSAStringToAddressA(
                ip_string,
                address_family,
                None,
                ctypes.byref(addr),
                ctypes.byref(addr_size)
        ) != 0:
            raise socket.error(ctypes.FormatError())

        if address_family == socket.AF_INET:
            return ctypes.string_at(addr.ipv4_addr, 4)
        if address_family == socket.AF_INET6:
            return ctypes.string_at(addr.ipv6_addr, 16)

        raise socket.error('unknown address family')

    def inet_ntop(address_family, packed_ip):
        addr = SockAddr()
        addr.sa_family = address_family
        addr_size = ctypes.c_int(ctypes.sizeof(addr))

        if address_family == socket.AF_INET:
            if len(packed_ip) != ctypes.sizeof(addr.ipv4_addr):
                raise socket.error('packed IP wrong length for inet_ntoa')
            ctypes.memmove(addr.ipv4_addr, packed_ip, 4)
            #  15: IPv4 address
            #   1: Terminating null byte
            buffer_len = 16
        elif address_family == socket.AF_INET6:
            if len(packed_ip) != ctypes.sizeof(addr.ipv6_addr):
                raise socket.error('packed IP wrong length for inet_ntoa')
            ctypes.memmove(addr.ipv6_addr, packed_ip, 16)
            #  45: IPv6 address including embedded IPv4 address
            #  11: Scope Id
            #   1: Terminating null byte
            buffer_len = 57
        else:
            raise socket.error('unknown address family')

        ip_string = ctypes.create_string_buffer(buffer_len)
        ip_string_size = ctypes.c_int(ctypes.sizeof(ip_string))

        if WSAAddressToStringA(
                ctypes.byref(addr),
                addr_size,
                None,
                ip_string,
                ctypes.byref(ip_string_size)
        ) != 0:
            raise socket.error(ctypes.FormatError())

        return ip_string[:ip_string_size.value - 1]

    # Adding our two functions to the socket library
    socket.inet_pton = inet_pton
    socket.inet_ntop = inet_ntop


if os.name == "nt" and not hasattr(socket, "inet_pton"):
    import ctypes
    if not hasattr(ctypes.windll.ws2_32, "InetNtopW") or not hasattr(ctypes.windll.ws2_32, "InetPtonW"):
        inject_into_socket = inject_into_xp_socket
    inject_into_socket()
