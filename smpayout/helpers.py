from enum import EnumMeta
from serial import Serial, SerialException
from sys import platform
from glob import glob
from time import time, sleep
from typing import Any, Tuple
from random import randint

from smpayout.cfg import (
    SSP_SCALE_FACTOR,
    SSP_DEFAULT_CHANNEL_VALUES
)


class MyEnumMeta(EnumMeta):
    def __contains__(cls, item):
        try:
            cls(item)
        except ValueError:
            return False
        else:
            return True


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


def is_it_prime(n: int, a: int) -> bool:
    d = xpow_ymod_n(a, n - 1, n)
    return d == 1


def miller_rabin(n: int, trials: int):
    for i in range(trials):
        a = randint(2, n)
        if not is_it_prime(n, a):
            return False
    return True


def is_prime2(n: int):
    if n == 2 or n == 3:
        return True
    if n % 2 == 0 or n < 2:
        return False
    for i in range(3, int(n ** 0.5) + 1, 2):  # only odd numbers
        if n % i == 0:
            return False
    return True


def generate_prime(max_number: int) -> int:
    """
    Generates a large prime number by choosing a randomly large integer.
    Ensuring the value is odd, then use the miller-rabin primality test on it to see if it is prime
    if not the value gets increased until it is prime
    """

    tmp = randint(0, max_number)
    # ensure it is an odd number
    if not (tmp % 2):
        tmp += 1

    # increment until prime
    while not miller_rabin(tmp, 5):
        # increment until prime
        tmp += 2
    return tmp


def xpow_ymod_n(x: int, y: int, n: int) -> int:
    """
    Raises X to the power Y in modulus N
    the values of X, Y, and N can be massive, and this can be
    acheived by first calculating X to the power of 2 then
    using power chaining over modulus N
    """

    res = pow(x, y, n)
    return res


def get_only_int_str(data: bytes, idx: int) -> (int, str, int):  # amount, currency, bytes
    num_bytes = 7
    amount = int.from_bytes(data[idx: idx + 4], byteorder='little') // SSP_SCALE_FACTOR
    currency = bytes(data[idx + 4: idx + 7]).decode("utf-8")
    return amount, currency, num_bytes


def get_int_str(data: bytes, idx: int) -> (int, str, int):  # amount, currency, bytes
    country_num = data[idx]
    idx += 1
    num_bytes = 1 + country_num * 7
    country_idx = 0
    amount = 0
    currency = ''
    while country_idx < country_num:
        amount = int.from_bytes(data[idx: idx + 4], byteorder='little') // SSP_SCALE_FACTOR
        currency = bytes(data[idx + 4: idx + 7]).decode("utf-8")
        idx += 7
        country_idx += 1
        # support only 1 currency
        break
    return amount, currency, num_bytes


def get_int_int_str(data: bytes, idx: int) -> (list, int):
    country_num = data[idx]
    idx += 1
    num_bytes = 1 + country_num * 11
    country_idx = 0
    dispensed = 0
    requested = 0
    currency = ''
    while country_idx < country_num:
        dispensed = int.from_bytes(data[idx: idx + 4], byteorder='little') // SSP_SCALE_FACTOR
        requested = int.from_bytes(data[idx + 4: idx + 8], byteorder='little') // SSP_SCALE_FACTOR
        currency = bytes(data[idx + 8: idx + 11]).decode("utf-8")
        idx += 11
        country_idx += 1
        break
    return dispensed, requested, currency, num_bytes


def get_channel_no(banknote_nominal: int) -> int:
    """
    Returns the channel number for a given banknote nominal.
    :param banknote_nominal: banknote nominal value
    :return: channel number (1-6) or 0 if not found
    """

    for k, v in SSP_DEFAULT_CHANNEL_VALUES.items():
        if v == banknote_nominal:
            return k
    return 0


def get_channels_mask(banknotes: Tuple[int]) -> int:
    """
    Returns a bitmask of the payout channels that are enabled by default.
    :return: bit mask of enabled payout channels
    """

    mask = 0x00
    for banknote_nominal in banknotes:
        channel_no = get_channel_no(banknote_nominal)
        if channel_no:
            mask |= (1 << (channel_no - 1))
    return mask