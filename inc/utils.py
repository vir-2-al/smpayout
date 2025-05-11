from serial import Serial, SerialException
from sys import platform
from glob import glob
from time import time, sleep
from typing import Any


def get_serial_ports() -> list:
    """
        Lists serial port names
            :raises EnvironmentError:
                On unsupported or unknown platforms
            :returns:
                A list of the serial ports available on the system
    """
    if platform.startswith('win'):
        ports = ['COM%s' % (i + 1) for i in range(256)]
    elif platform.startswith('linux') or platform.startswith('cygwin'):
        # this excludes your current terminal "/dev/tty"
        ports = glob('/dev/tty[A-Za-z]*')
    elif platform.startswith('darwin'):
        ports = glob('/dev/tty.*')
    else:
        raise EnvironmentError('Unsupported platform')
    result = []
    for port in ports:
        try:
            s = Serial(port=port)
            s.close()
            result.append(port)
        except (OSError, SerialException):
            pass
    return result


def get_gs1_crc(data: str) -> str:
    """Calculates GS1 Check Digit.
      GS1 (GS1-13, GS1-14 (ITF-14), GS1-8, UPC)

    Args:
        data: A string of characters
    Returns:
        str: The check digit that was missing
    Examples:
        get_gs1_crc("00199999980000110")
        '7'
        get_gs1_crc("67368623738347505")
        '1'
    """
    if not isinstance(data, str):
        return ""
    if not data.isdigit():
        return ""

    data = data[::-1]  # Reverse the barcode
    v1, v2 = 0, 0
    for idx, v in enumerate(data):
        if idx % 2 == 0:
            v1 += int(v)
        else:
            v2 += int(v)
    crc = 10 - (v1 * 3 + v2) % 10
    return str(crc)


def crc_ccitt_16(data, seed: int, poly: int) -> int:
    crc = seed
    for byte in data:
        crc ^= (byte << 8)
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ poly
            else:
                crc <<= 1
            crc &= 0xFFFF
    return crc


def crc_cal_16(data, seed: int, poly: int) -> int:
    crc = seed

    for idx, byte in enumerate(data):
        crc ^= byte
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ poly
            else:
                crc >>= 1
            crc &= 0xFFFF
    return crc


def flatlist(x: Any) -> list:
    result = []
    if hasattr(x, "value"):
        # return [x.value]
        x = x.value

    if hasattr(x, "__iter__"):
        for el in x:
            if hasattr(el, "value"):
                el = el.value
            if hasattr(el, "__iter__") and not isinstance(el, str):
                result.extend(flatlist(el))
            else:
                result.append(el)
    else:
        result.append(x)

    return result


def thread_sleep(seconds: int):
    time_start = time()
    while time() - time_start < seconds:
        sleep(0)
