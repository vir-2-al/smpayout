import logging
import os
import time
from random import randint
from typing import Union, Tuple, Dict, Any
import serial

from smdevice import aes128
from smdevice.helpers import (
    crc_ccitt_16,
    flatlist,
    generate_prime,
    xpow_ymod_n,
    get_channels_mask
)

from smdevice.cfg import (
    SSP_DEFAULT_CURRENCY,
    SSP_SCALE_FACTOR,
    SSP_MAX_PROTOCOL_VERSION,
    SSP_CRC_SEED,
    SSP_CRC_POLY,
    SSP_STEX,
    SSP_STX,
    SSP_DEFAULT_CHANNEL_VALUES,
    SSP_DEFAULT_ACCEPT_LIMIT,
    SSP_FLOAT_AMOUNT,
    SSP_DEFAULT_KEY,
    MAX_PRIME_NUMBER
)
from smdevice.device_def import (
    SSPResponse,
    SSPKeys,
    SSPState,
    PayoutCmd,
    RouteModes,
    SSPRejectReason,
    EncryptedCmd,
    GenericCmd,
    BNVCmd
)
from smdevice.exceptions import (
    PayoutNotInitializedError
)

logger = logging.getLogger()

class Device:

    def __init__(self,
                 port='/dev/ttyS0',
                 baudrate: int = 9600,
                 parity: str = 'N',
                 bytesize: int = 8,
                 stopbits: int = 1,
                 address: int = 0) -> None:
        """
        Initializes the device with the given parameters.

        :param port: - имя порта устройства (например, '/dev/ttyS0' или 'COM3')
        :param baudrate: - скорость передачи данных
        :param parity: - четность
        :param bytesize: - размерность байта
        :param stopbits: - количество стоповых бит
        :param address: - адрес устройства (от 0 до 255)
        """
        super().__init__()
        port_name = os.path.basename(port)
        logger.info(f'Device.init: {port_name}')
        self._serial_port = port
        self._baudrate = baudrate
        self._parity = parity
        self._bytesize = bytesize
        self._stopbits = stopbits
        self._address = address
        self._device_port: Union[serial.Serial, None] = None
        self._seq = 0x00
        self._encPktCount = dict()
        self._timeout = 5
        self._keys = SSPKeys()
        self._state = set()
        self.encrypted = False


    def encrypt_packet(self, data: Any) -> Any:
        """
        Encrypts the data packet using AES128 encryption.

        :param data: Data to be encrypted, should be a bytes-like object.
        :return: Encrypted data as bytes, or None if encryption fails.
        """
        # STEX | LENGTH | COUNT | DATA… | PACK… | CRCL | CRCH

        data = len(data).to_bytes(1, byteorder='little') + \
               self._encPktCount[self._address].to_bytes(4, byteorder='little') + data

        if ((len(data) + 2) % 16) != 0:
            rc = 16 - (len(data) + 2) % 16
            random_data = os.urandom(rc)
            data = data + random_data

        crc = crc_ccitt_16(data, SSP_CRC_SEED, SSP_CRC_POLY)
        data = data + crc.to_bytes(2, byteorder='little')

        key = bytes(self._keys.FixedKey.to_bytes(8, byteorder='little') +
                    self._keys.EncryptKey.to_bytes(8, byteorder='little'))

        sec_data = b''
        for idx in range(0, len(data), 16):
            data_block = data[idx:idx + 16]
            cipher = aes128.encrypt(data_block, key)
            if not cipher:
                return None
            sec_data += bytes(cipher)

        self._encPktCount[self._address] += 1
        self._encPktCount[self._address] &= 0xFFFF

        res = bytes(SSP_STEX.to_bytes(1, byteorder='little') + sec_data)
        return res

    def decrypt_packet(self, data: bytes) -> Any:
        """
        Decrypts the data packet using AES128 decryption.
        :param data: Data to be decrypted, should be a bytes-like object.
        :return: Tuple containing the response code and decrypted data, or an error code if decryption fails.
        """

        # check for an encrypted packet
        key = bytes(self._keys.FixedKey.to_bytes(8, byteorder='little') +
                    self._keys.EncryptKey.to_bytes(8, byteorder='little'))
        max_block_len = 16  # 128 bit for AES128
        if (len(data) % max_block_len) != 0:
            return SSPResponse.checksum_error, None

        decrypt_data = b''
        for block_no in range(len(data) // max_block_len):
            idx_start = block_no * max_block_len
            idx_stop = block_no * max_block_len + max_block_len
            decrypt_block = bytes(aes128.decrypt(data[idx_start: idx_stop], key))
            if not decrypt_block:
                return SSPResponse.checksum_error, None
            decrypt_data = decrypt_data + decrypt_block
        data = decrypt_data

        # check the checsum
        ans_crc = int.from_bytes(data[-2:], byteorder='little')
        calc_crc = crc_ccitt_16(data[:-2], SSP_CRC_SEED, SSP_CRC_POLY)
        if ans_crc != calc_crc:
            return SSPResponse.checksum_error, None

        # check the slave count against the host count
        slaveCount = int.from_bytes(data[1:4], byteorder='little')
        if slaveCount != self._encPktCount[self._address]:
            return SSPResponse.checksum_error, None

        ans_len = int(data[0])
        data = data[5:5 + ans_len]
        ans_code = int(data[0])
        res_data = data[1:] if ans_len > 1 else None
        return ans_code, res_data

    def check_response(self) -> Tuple[SSPResponse, Union[Union[int, bytes], Any]]:
        """
        Checks the response from the device after sending a command.

        :return: Tuple containing the response code and any data returned by the device.
        """

        try:
            read_header = self._device_port.read(size=3)
            if not isinstance(read_header, bytes) or len(read_header) < 3:
                return SSPResponse.timeout, None
            ans_len = int(read_header[-1])
            read_data = b''
            ans_read = 0
            while ans_read < ans_len + 2:
                b = self._device_port.read(1)
                # byte stuffing
                if int(b[0]) == SSP_STX:
                    self._device_port.read(1)
                read_data += b
                ans_read += 1

            # read_data = self.device_port.read(ans_len + 2)  # add 2 bytes CRC
            if not (len(read_data) == ans_len + 2):
                return SSPResponse.timeout, None
            ans_crc = int.from_bytes(read_data[-2:], byteorder='little')
            calc_crc = crc_ccitt_16(read_header[1:] + read_data[:-2], SSP_CRC_SEED, SSP_CRC_POLY)
            if ans_crc != calc_crc:
                return SSPResponse.checksum_error, None

            if self.encrypted and int(read_data[0]) == SSP_STEX:
                ans_code, res_data = self.decrypt_packet(read_data[:-2][1:])
                self._seq ^= 0x80
                return SSPResponse(ans_code), res_data

            ans_code = int(read_data[0])
            if ans_code in SSPResponse:
                res_data = read_data[:-2][1:] if ans_len > 1 else None
                self._seq ^= 0x80
                return SSPResponse(ans_code), res_data
            return SSPResponse.timeout, None
        except (IOError, TypeError, Exception) as se:
            logger.error(f'check_response: error {se}')
            self.disconnect()
            return SSPResponse.timeout, None

    def CreateHostInterKey(self):
        """
        Creates a host intermediate key
        This function generates a host intermediate key using the generator, modulus, and host random values.
        """

        if not self._keys.Generator or not self._keys.Modulus:
            return False

        self._keys.HostRandom = randint(0, MAX_PRIME_NUMBER)

        self._keys.Generator = 139791917
        self._keys.Modulus = 769202429
        self._keys.HostRandom = 229216279

        self._keys.HostInter = xpow_ymod_n(self._keys.Generator, self._keys.HostRandom, self._keys.Modulus)
        return True

    def InitiateSSPHostKeys(self):
        """
        Initiates the SSP host keys.
        This function generates two random prime numbers for the generator and modulus,
        :return: True if successful, False otherwise.
        """

        self._keys = SSPKeys()
        # create the two random prime numbers
        self._keys.Generator = generate_prime(MAX_PRIME_NUMBER)
        self._keys.Modulus = generate_prime(MAX_PRIME_NUMBER)
        # make sure the Generator is larger than Modulus
        if self._keys.Generator > self._keys.Modulus:
            self._keys.Generator, self._keys.Modulus = self._keys.Modulus, self._keys.Generator

        if not self.CreateHostInterKey():
            return False

        # reset the apcket counter here for a successful key neg
        self._encPktCount[self._address] = 0
        return True

    def CreateSSPHostEncryptionKey(self) -> bool:
        """
        Creates the SSP host encryption key.
        :return: True
        """
        self._keys.KeyHost = xpow_ymod_n(self._keys.SlaveInterKey, self._keys.HostRandom, self._keys.Modulus)
        return True

    def NegotiateKeys(self) -> bool:
        """
        Negotiates the keys for the SSP host.

        :return: True if successful, False otherwise.
        """

        if self.sspSync() != SSPResponse.ok:
            return False
        self.InitiateSSPHostKeys()
        if self.sspSetGenerator(self._keys.Generator) != SSPResponse.ok:
            return False
        if self.sspSetModulus(self._keys.Modulus) != SSPResponse.ok:
            return False
        res, key = self.sspKeyExchange(self._keys.HostInter)
        if res != SSPResponse.ok:
            return False
        self._keys.SlaveInterKey = key
        self.CreateSSPHostEncryptionKey()
        self._keys.FixedKey = SSP_DEFAULT_KEY
        self._keys.EncryptKey = self._keys.KeyHost
        self.encrypted = True
        return True

    def SetNotesRoute(self) -> bool:
        for _, amount in SSP_DEFAULT_CHANNEL_VALUES.items():
            if amount > 0:
                res = self.sspSetNoteRoute(RouteModes.payouts, amount, SSP_DEFAULT_CURRENCY)
                if res != SSPResponse.ok:
                    logger.error(
                        f'SmartPayout.SetNotesRoute: Can''t set note route for {amount} {SSP_DEFAULT_CURRENCY} ...')
                    return False
        return True

    def init_device(self) -> bool:
        """
        Initializes the SmartPayout device.
        This function performs the following steps:
        1. Negotiates keys for encryption.
        2. Sets the protocol version.
        3. Calls the setup request to get device information.
        4. Sets the inhibits for the device channels.
        5. Enables the payout functionality.
        6. Routes all notes to payout.

        :return: True if initialization is successful, False otherwise.
        """

        logger.info('SmartPayout.device_init: initializing ...')

        # Negotiate keys for encryption
        if not self.NegotiateKeys():
            logger.error(f'SmartPayout.device_init: Failed on key negotiation...')
            return False

        # Set the protocol version
        res = self.sspSetProtocolVersion(SSP_MAX_PROTOCOL_VERSION)
        if res != SSPResponse.ok:
            logger.error('SmartPayout.device_init: Failed on setting protocol version...')
            return False

        # Call setup request
        res = self.sspSetupRequest()
        if res != SSPResponse.ok:
            logger.error('Failed on setup request...')
            return False

        # Set inhibits
        mask = get_channels_mask(SSP_DEFAULT_ACCEPT_LIMIT)
        res = self.sspSetInhibits(mask)
        if res != SSPResponse.ok:
            logger.error('SmartPayout.device_init: Failed on setting inhibits...')
            return False

        # Enable payout
        res = self.sspEnablePayout()
        if res != SSPResponse.ok:
            logger.error('SmartPayout.device_init: Failed on enabling payout...')
            return False

        # Route all notes to payout
        self.SetNotesRoute()

        self._state.add(SSPState.error_page)
        logger.info('SmartPayout.device_init: Init complete')
        return True

    def deinit_device(self) -> bool:
        """
        Deinitializes the SmartPayout device.

        :return: True
        """
        self.sspDisablePayout()
        return True

    def connect(self) -> bool:
        logger.info(f'SmartPayout.open_device: try open device [{self._serial_port}]')
        if self._device_port:
            self.disconnect()

        self._device_port = serial.Serial()
        self._device_port.port = self._serial_port
        self._device_port.baudrate = self._baudrate
        self._device_port.parity = self._parity
        self._device_port.bytesize = self._bytesize
        self._device_port.stopbits = self._stopbits
        self._device_port.timeout = self._timeout
        self._device_port.write_timeout = self._timeout

        try:
            self._device_port.open()
            self._device_port.reset_input_buffer()
            self._device_port.reset_output_buffer()
            if self._device_port.is_open:
                if self.connected():
                    if self.init_device():
                        logger.info(f'SmartPayout.open_device: device opened [{self._serial_port}]')
                        return True
            self.disconnect()
            return False
        except (FileNotFoundError, OSError, serial.SerialException) as se:
            logger.error(f'SmartPayout.open_device: {se}')
            time.sleep(3)
            self.disconnect()
            return False

    def disconnect(self) -> None:
        """
        Closes the device port and resets the state.

        :return: None
        """

        # logger.info('SmartPayout.close_device')
        if self._device_port:
            try:
                time.sleep(0.1)
                self._device_port.close()
            except (FileNotFoundError, OSError, serial.SerialException) as se:
                logger.error(f'SmartPayout.close_device: Except: {se}')
            finally:
                logger.info('SmartPayout.close_device: port closed.')
        self.encrypted = False
        self._state.add(SSPState.disconnected)
        self._device_port = None

    def connected(self) -> bool:
        """
        Checks if the device is connected by sending a sync command.
        Updates the device state based on the response.

        :return: True if the device is connected, False otherwise.
        """

        res = self.sspSync() == SSPResponse.ok
        if res:
            self._state.discard(SSPState.disconnected)
        else:
            self._state.add(SSPState.disconnected)
        return res

    def is_device_ok(self) -> bool:
        """
        Checks if the device is in a state where it can accept commands.

        :return: - True if the device is operational, False otherwise.
        """

        res = self._device_port and self.encrypted
        res = res and self._state.isdisjoint({SSPState.disconnected, SSPState.note_path_open, SSPState.cashbox_removed})
        return res

    def exec_command(self, data: Any) -> Tuple[SSPResponse, Union[Union[int, bytes], Any]]:
        """
        Executes a command on the device.
        Transport Layer

        Data and commands are transported between the host and the slave(s) using a
        packet format as shown below.

            STX  | SEQ/SLAVE ID  |  LENGTH  |  DATA  |  CRCL  |  CRCH

            STX          - Single byte indicating the start of a message - 0x7F hex
            SEQ/Slave ID - Bit 7 is the sequence flag of the packet, bits 6-0 represent the address of the slave the
                           packet is intended for, the highest allowable slave ID is 0x7D
            LENGTH       - The length of the data included in the packet - this does not include STX, the CRC or the SLAVE ID
            Slave ID     - Single byte used to identify the address of the slave the packet is intended for
            DATA         - Commands and data to be transferred
            CRCL,        - Low and high byte of a forward CRC-16 algorithm using the Polynomial (X16 + X15 + X2
            CRCH         - +1) calculated on all bytes, except STX.
                           It is initialized using the seed 0xFFFF.
                           The CRC is calculated before byte stuffing.
        """

        # logger.info(f'SmartPayout.exec_command: data: {data}')
        if self._device_port:
            data = flatlist(data)
            byte_list = [[ord(x) for x in i] if isinstance(i, str) else [i] for i in data]
            payload_data = bytes([int(item) for sublist in byte_list for item in sublist])
            if self.encrypted:
                payload_data = self.encrypt_packet(payload_data)
                if not payload_data:
                    return SSPResponse.failure, None

            arr = bytearray([self._address ^ self._seq, len(payload_data)]) + payload_data
            crc = crc_ccitt_16(arr, SSP_CRC_SEED, SSP_CRC_POLY)
            full_command = arr + crc.to_bytes(2, byteorder='little')
            # byte stuffing <STX>
            full_command = b'\x7F' + bytes(flatlist([b if b != SSP_STX else b'\x7F\x7F' for b in full_command]))
            # logger.info(f'send: dev: [{self.device_port.name}] data: {printer_data}')
            try:
                self._device_port.write(full_command)
                self._device_port.flush()
                return self.check_response()
            except (IOError, TypeError, Exception) as se:
                logger.error(f'exec_command: error: {se}')
                self.disconnect()
                return SSPResponse.failure, None
        else:
            logger.error(f'exec_command: error: PayoutNotInitializedError')
            raise PayoutNotInitializedError()

    def sspSetInhibits(self, mask_channels: int = 0xFFFF) -> SSPResponse:
        """
        This function sends the set inhibits command to set the inhibiting on the validator.
        The two bytes after the command byte represent two-bit registers with each bit being a channel.
        1-8 and 9-16 respectively.
        0xFF in binary indicating all channels in this register are able to accept notes.
        """

        logger.info(f'SmartPayout.sspSetInhibits')
        channels_low = mask_channels & 0xFF  # channels 1..8   (10, 50, 100, 200, 500, 1000, 2000, 5000)
        channels_high = (mask_channels >> 8) & 0xFF  # channels 9..16  ()
        return self.exec_command([BNVCmd.set_channel_inhibits, channels_low, channels_high])[0]

    def sspSync(self) -> SSPResponse:
        """
        This single byte command tells the unit that the next sequence ID will be 1.
        This is always the first command sent to a unit, to prepare it to receive any further commands.

        :return: - SSPResponse.ok if the command was successful, otherwise an error response.
        """

        logger.info(f'SmartPayout.sspSync')
        self._seq = 0x80
        return self.exec_command([GenericCmd.sync])[0]

    def sspSetProtocolVersion(self, version: int = 8) -> SSPResponse:
        """
        This function sets the protocol version in the validator to the version passed across. Whoever calls
        this needs to check the response to make sure the version is supported.
        """

        logger.info(f'SmartPayout.sspSetProtocolVersion')
        return self.exec_command([GenericCmd.host_protocol, version])[0]

    def sspSetupRequest(self) -> SSPResponse:
        """
        This function uses the setup request command to get information about the validator.
        The response packet from the validator is a variable length depending on the number
        of channels in the dataset.
        """

        logger.info(f'SmartPayout.sspSetupRequest')
        res, data = self.exec_command([GenericCmd.setup_request])
        return res

    def sspEnablePayout(self) -> SSPResponse:
        """
        Enables the payout facility of the validator which lets it store and payout notes.
        """

        logger.info(f'SmartPayout.sspEnablePayout')
        res = self.exec_command([PayoutCmd.enable])[0]
        self._state.discard(SSPState.disabled)
        return res

    def sspDisablePayout(self) -> SSPResponse:
        """
        Stops the validator from being able to store or payout notes.
        """

        logger.info(f'SmartPayout.sspDisablePayout')
        return self.exec_command([PayoutCmd.disable])[0]

    def sspEnableValidator(self) -> SSPResponse:
        """
        The enable command allows the validator to act on commands sent to it.
        """

        logger.info(f'SmartPayout.sspEnableValidator')
        return self.exec_command([GenericCmd.enable])[0]

    def sspDisableValidator(self) -> SSPResponse:
        """
        Disable command stops the validator acting on commands sent to it.
        """

        logger.info(f'SmartPayout.sspDisableValidator')
        rc, _ = self.exec_command([GenericCmd.disable])
        time.sleep(0.5)
        return rc

    def sspResetValidator(self) -> SSPResponse:
        """
        The reset command instructs the validator to restart
        """

        logger.info(f'SmartPayout.sspResetValidator')
        return self.exec_command([GenericCmd.reset])[0]

    def sspGetMinimumPayout(self) -> (SSPResponse, int):
        """
        Variable byte command causes the validator to report its current minimum payout of a specific currency.

        :return: - SSPResponse, int - The response from the command and the minimum payout amount in the default currency.
        """

        res, data = self.exec_command([PayoutCmd.get_minimum_payout])
        logger.info(f'SmartPayout.sspGetMinimumPayout  data: {data}')
        if isinstance(data, bytes):
            amount = int.from_bytes(data, byteorder='little')
        else:
            amount = 0
        return res, amount

    def sspFloatAmount(self, payout_amount: int = 0) -> SSPResponse:
        """
        Variable byte command that causes the validator to keep a set amount “floating” in the payout
        and specifies a minimum payout value. In a similar way to the Payout Amount command
        there is an option byte at the end to make a “real” float or a “test” float.

        :param payout_amount: - The amount to float in the payout, in the default currency.
        :return: - SSPResponse.ok if the command was successful, otherwise an error response.
        """

        logger.info(f'SmartPayout.sspFloatAmount')
        res, data = self.exec_command([PayoutCmd.float_amount,
                                       (0 * SSP_SCALE_FACTOR).to_bytes(4, 'little'),
                                       (payout_amount * SSP_SCALE_FACTOR).to_bytes(4, 'little'),
                                       SSP_DEFAULT_CURRENCY,
                                       SSP_FLOAT_AMOUNT])
        return res

    def sspFloatByDenomination(self, payout_amount: dict = None) -> SSPResponse:
        """
        Variable byte command that instructs the validator to float individual quantities
        of a denomination in the SMART payout. It follows a similar format to the Payout
        by Denomination command.

        :param payout_amount: - A dictionary where keys are banknote amounts and values are the number of banknotes.
        :return: - SSPResponse.ok if the command was successful, otherwise an error response.
        """

        logger.info(f'SmartPayout.sspFloatByDenomination')
        params = b''
        banknote_count = len(payout_amount)
        params += banknote_count.to_bytes(1, 'little')
        for banknote_amount, banknote_num in payout_amount.items():
            params += banknote_num.to_bytes(2, 'little')
            params += (banknote_amount * SSP_SCALE_FACTOR).to_bytes(4, 'little')
            params += SSP_DEFAULT_CURRENCY.encode()
        res, data = self.exec_command([PayoutCmd.float_by_denomination,
                                       params,
                                       SSP_FLOAT_AMOUNT])
        return res

    def sspEmpty(self) -> SSPResponse:
        """
        This uses the EMPTY command to instruct the SMART Hopper to dump all stored coins into the cashbox.
        The SMART Hopper will not keep track of what coins have been emptied.
        """

        logger.info(f'SmartPayout.sspEmpty')
        return self.exec_command([PayoutCmd.empty])[0]

    def sspSmartEmpty(self) -> SSPResponse:
        """
        This uses the SMART EMPTY command to instruct the SMART Hopper to dump all stored coins into the cashbox.
        The SMART Hopper will keep track of what coins have been emptied,
        this data can be retrieved using the CASHBOX PAYOUT OPERATION DATA command.

        :return - SSPResponse.ok if the command was successful, otherwise an error response.
        """

        logger.info(f'SmartPayout.sspSmartEmpty')
        return self.exec_command([PayoutCmd.smart_empty])[0]

    def sspSetGenerator(self, value: int) -> SSPResponse:
        logger.info(f'SmartPayout.sspSetGenerator')
        res = self.exec_command([EncryptedCmd.set_generator, value.to_bytes(8, 'little')])[0]
        return res

    def sspSetModulus(self, value: int) -> SSPResponse:
        logger.info(f'SmartPayout.sspSetModulus')
        res = self.exec_command([EncryptedCmd.set_modulus, value.to_bytes(8, 'little')])[0]
        return res

    def sspKeyExchange(self, value: int) -> (SSPResponse, int):
        logger.info(f'SmartPayout.sspKeyExchange')
        res, data = self.exec_command([EncryptedCmd.key_exchange, value.to_bytes(8, 'little')])
        key = None
        if isinstance(data, bytes):
            key = int.from_bytes(data, byteorder='little')
        return res, key

    def sspGetSerianNumber(self) -> (SSPResponse, int):
        """
        Single byte command causes the unit to report its unique serial number.

        :return: - SSPResponse, int - The response from the command and the serial number.
        """

        logger.info(f'SmartPayout.sspGetSerialNumber')
        res, data = self.exec_command([GenericCmd.get_serial_number])
        sn = 0
        if isinstance(data, bytes):
            sn = int.from_bytes(data, byteorder='big')
        return res, sn

    def sspGetFirmwareVersion(self) -> (SSPResponse, str):
        """
        Returns the full string detailing the current firmware installed in the device.

        :return: - SSPResponse, str - The response from the command and the firmware version string.
        """

        logger.info(f'SmartPayout.sspGetFirmwareVersion')
        res, data = self.exec_command([GenericCmd.get_firmware_version])
        ver = ''
        if isinstance(data, bytes):
            ver = bytes(data).decode('utf-8')
        return res, ver

    def sspGetBuildRevision(self) -> (SSPResponse, str):
        """
        Returns the build revision of the device, including device type, version, and payout version.

        :return: - SSPResponse, int, int, int - The response from the command, device type, device version, and payout version.
        """

        logger.info(f'SmartPayout.sspGetBuildRevision')
        res, data = self.exec_command([GenericCmd.get_build_revision])
        device_type = 0
        device_version = 0
        payout_version = 0
        if isinstance(data, bytes):
            device_type = data[0]
            device_version = int.from_bytes(data[1:3], byteorder='little')
            payout_version = int.from_bytes(data[4:6], byteorder='little')
        return res, device_type, device_version, payout_version

    def sspGetNoteAmount(self, amount: int, currency: str) -> (SSPResponse, int):
        """
        Gets the number of notes stored and reports them in a string which is passed as a parameter.
        """

        logger.info(f'SmartPayout.sspGetNoteAmount')
        res, data = self.exec_command([PayoutCmd.get_note_amount,
                                       (amount * SSP_SCALE_FACTOR).to_bytes(4, 'little'),
                                       currency])
        num_notes = 0
        if isinstance(data, bytes):
            num_notes = int.from_bytes(data, byteorder='little')
        return res, num_notes

    def sspGetCashboxPayoutOpData(self) -> (SSPResponse, dict):
        """
        This function uses the GET CASHBOX PAYOUT OPERATION DATA command which
        instructs the SMART Hopper to report the number of coins moved and their
        denominations in the last cashbox operation.
        This could be a dispensed, float or SMART empty.
        Return dict {amount: counter, amount: counter, ...}
        """

        logger.info(f'SmartPayout.sspGetCashboxPayoutOpData')
        res, data = self.exec_command([PayoutCmd.cashbox_payout_op_data])
        notes_info = None
        if isinstance(data, bytes):
            notes_info = {}
            num_all_notes = data[0]
            for idx in range(num_all_notes):
                idx_start = 1 + idx * 9
                num_moved = int.from_bytes(data[idx_start: idx_start + 2], byteorder='little')
                amount = int.from_bytes(data[idx_start + 2: idx_start + 6], byteorder='little') // SSP_SCALE_FACTOR
                notes_info[amount] = num_moved
        return res, notes_info

    def sspPayout(self, value: int, currency: str) -> SSPResponse:
        """
        Variable byte command that instructs the payout device to payout a specified amount.
        The developer can specify whether the payout is a “real” payout or a “test” payout.
        This can be useful as it allows the developer to find out whether a payout could be
        made without actually making the payout.
        This is done using an additional byte at the end of the standard data.

        :param value: - Amount to payout
        :param currency: - 3-letter currency code (ISO 4217)
        :return: SSPResponse - The response from the payout command.
        """

        # for i in range(3):
        while True:
            logger.info(f'SmartPayout.sspPayout: try payout amount: {value}')
            res, data = self.exec_command(
                [PayoutCmd.payout_amount, (value * SSP_SCALE_FACTOR).to_bytes(4, 'little'), currency[:3],
                 SSP_FLOAT_AMOUNT])
            if res == SSPResponse.ok:
                break
            error_code = 0xFF
            if isinstance(data, bytes):
                error_code = data[0]
                if error_code == 0x00:
                    error_msg = 'Not enough value in device'
                elif error_code == 0x01:
                    error_msg = 'Cannot pay exact amount'
                elif error_code == 0x02:
                    error_msg = 'Note float empty'
                elif error_code == 0x03:
                    error_msg = 'Device busy'
                elif error_code == 0x04:
                    error_msg = 'Device disabled'
                else:
                    error_msg = 'Payout unknow error code'
            else:
                error_msg = 'Unknow payour error'

            logger.error(f'SmartPayout.sspPayout: msg: {error_msg}, code: {error_code}')
            if error_code != 0x03:
                break
            time.sleep(0.5)
        logger.info(f'SmartPayout.sspPayout: result: {res}')
        return res

    def sspPayoutByDenomination(self, banknotes: Dict[int, int]) -> SSPResponse:  # banknotes = {50: 1, 100: 1, ...}
        """
        Variable byte command that instructs the validator to payout the requested number of a denomination of a note.
        This differs from a standard payout command (0x33) in that the developer specifies exactly
        which notes to payout. In the standard payout, the validator decides,
        based on the total amount the developer sends it.

        :param banknotes: - Dictionary with banknotes {amount: counter, amount: counter, ...}
        :return: SSPResponse - The response from the payout command.
        """

        banknotes_count = len(banknotes)
        if banknotes_count:
            logger.info(f'SmartPayout.sspPayoutByDenomination: try payout amount: {banknotes}')
        else:
            return SSPResponse.incorrect_parameters
        data = [PayoutCmd.payout_by_denomination, banknotes_count.to_bytes(1, 'little')]
        for amount, counter in banknotes.items():
            data.append(int(counter).to_bytes(2, 'little'))
            data.append(int(amount * SSP_SCALE_FACTOR).to_bytes(4, 'little'))
            data.append(SSP_DEFAULT_CURRENCY)
        data.append(SSP_FLOAT_AMOUNT)
        while True:
            res, data = self.exec_command(data)
            if res == SSPResponse.ok:
                break

            error_code = 0xFF
            if isinstance(data, bytes):
                error_code = data[0]
                if error_code == 0x00:
                    error_msg = 'Not enough value in device'
                elif error_code == 0x01:
                    error_msg = 'Cannot pay exact amount'
                elif error_code == 0x02:
                    error_msg = 'Note float empty'
                elif error_code == 0x03:
                    error_msg = 'Device busy'
                elif error_code == 0x04:
                    error_msg = 'Device disabled'
                else:
                    error_msg = 'Payout unknow error code'
            else:
                error_msg = 'Unknow payout error'

            logger.error(f'SmartPayout.sspPayoutByDenomination: msg: {error_msg}, code: {error_code}')
            if error_code != 0x03:
                break
            time.sleep(0.5)
        logger.info(f'SmartPayout.sspPayoutByDenomination: result: {res}')
        return res

    def sspQueryRejection(self) -> (SSPResponse, int, str):
        """
        This function uses the LAST REJECT CODE command to query the validator
        on what the last recorded reason was for rejecting a note. The reason is
        returned as a single byte.
        """

        logger.info(f'SmartPayout.sspQueryRejection')
        res, data = self.exec_command([BNVCmd.last_reject])
        reject_code = None
        reject_msg = None
        if isinstance(data, bytes):
            reject_code = int(data[0])
            reject_msg = SSPRejectReason[reject_code]
        return res, reject_code, reject_msg

    def sspPoll(self) -> (SSPResponse, Union[bytes, None]):
        """
        This uses the SMART EMPTY command to instruct the SMART Hopper to dump all stored coins into the cashbox.
        The SMART Hopper will keep track of what coins have been emptied,
        this data can be retrieved using the CASHBOX PAYOUT OPERATION DATA command.
        """

        # logger.info(f'SmartPayout.sspPoll')
        res, data = self.exec_command([GenericCmd.poll])
        return res, data

    def sspHold(self) -> SSPResponse:
        """
        This uses the SMART EMPTY command to instruct the SMART Hopper to dump all stored coins into the cashbox.
        The SMART Hopper will keep track of what coins have been emptied,
        this data can be retrieved using the CASHBOX PAYOUT OPERATION DATA command.
        """

        logger.info(f'SmartPayout.sspHold')
        res, data = self.exec_command([BNVCmd.hold])
        return res

    def sspSetNoteRoute(self, route: RouteModes, value: int, currency: str):
        """
        The following two functions alter the routing of a note using the SET ROUTING command.
        RouteModes:
            0x00 indicates routing for storage.
            0x01 as the second byte indicates that the selected note should be routed to the cashbox,
        """

        logger.info(f'SmartPayout.sspSetNoteRoute')
        res = self.exec_command(
            [PayoutCmd.set_route, route, (value * SSP_SCALE_FACTOR).to_bytes(4, 'little'), currency.upper()])[0]
        return res


