import os
import time
import inspect
import logging
import queue
import threading
import pickle
import serial

from datetime import datetime, timedelta
from sys import builtin_module_names
from random import randint
from typing import Union, Callable, NoReturn, Tuple, Dict, Any

from cfg import APP_NAME
from payout import aes128
from inc.utils import get_serial_ports, crc_ccitt_16, flatlist, thread_sleep
from payout.smartpayout_def import (
    itl_dev_port, itl_payment_state_file, itl_device_state_file,
    SSPResponse, SSP_DEFAULT_CURRENCY, SSP_SCALE_FACTOR, SSPKeys, SSPState, SSP_MAX_PROTOCOL_VERSION, 
    SSP_CRC_SEED, SSP_CRC_POLY, SSP_STEX, SSP_STX, SSP_DEFAULT_CHANNEL_VALUES, SSP_MAX_PAYOUT_CAPACITY,
    SSP_FLOAT_TIMEOUT, SSP_FLOAT_AMOUNT, SSP_LIMIT_PAYOUT_CAPACITY, SSP_MAX_CASHBOX_CAPACITY, 
    SSP_LIMIT_CASHBOX_CAPACITY, SSP_DEFAULT_KEY, MAX_PRIME_NUMBER,
    DeviceState, PaymentState, PollEvents, PaymentMode, ReportType, PageType, ReportTypeTitle, PayoutCmd,
    RouteModes, SSPRejectReason, EncryptedCmd, GenericCmd, BNVCmd, PayoutNotInitializedError, PaymentCallbackEvents,
    generate_prime, xpow_ymod_n)


class SmartPayout(threading.Thread):

    def __init__(self,
                 serial_port: str = '',
                 baudrate: int = 9600,
                 parity: str = 'N',
                 bytesize: int = 8,
                 stopbits: int = 1,
                 address: int = 0,
                 event_callback: Callable = None) -> None:

        super().__init__()
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])

        if serial_port:
            port_name = os.path.basename(serial_port)
            self.name = f'payout_thread_{port_name}'
        else:
            port_name = ''
            self.name = f'payout_thread_{threading.get_ident():02x}'
        self.daemon = True
        logger.info(f'SmartPayout.init: {port_name}')

        self._on_event_callback = event_callback
        self._global_service_mode = False
        self._device_port: Union[serial.Serial, None] = None
        self._serial_locker = threading.RLock()
        self._payment_locker = threading.RLock()
        self._seq = 0x00
        self._command_queue = queue.Queue()
        self._serial_port = serial_port
        self._baudrate = baudrate
        self._parity = parity
        self._bytesize = bytesize
        self._stopbits = stopbits
        self.timeout = 5
        self.address = address
        self._keys = SSPKeys()
        self._encPktCount = dict()
        self.encrypted = False

        self._terminated = False
        self._state = set()  # SSPState

        self._device = DeviceState()
        self._payment = PaymentState()

        self._disabled_other_payment = False
        self._receipt_no = 0
        return

    def get_receipt_number(self) -> int:
        """
        Получает следующий номер чека/отчета
        """
        self._receipt_no += 1
        return self._receipt_no

    def is_device_connected(self) -> bool:
        # self._seq = 0x00
        # return self.sspSetInhibits() == SSPResponse.ok
        res = self.sspSync() == SSPResponse.ok
        if res:
            self._state.discard(SSPState.disconnected)
        else:
            self._state.add(SSPState.disconnected)
        return res

    def is_device_ok(self) -> bool:
        res = self._device_port and self.encrypted
        res = res and self._state.isdisjoint({SSPState.disconnected, SSPState.note_path_open, SSPState.cashbox_removed})
        return res

    def device_out_of_service(self):
        if SSPState.error_page not in self._state:
            logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
            logger.error('SmartPayout.device_out_of_service')
            try:
                self._state.add(SSPState.error_page)
                self._on_event_callback(event=PaymentCallbackEvents.DeviceOutOfService)
            except Exception as se:
                logger.error(f'SmartPayout.device_out_of_service: error: {se}')
            time.sleep(3)

    def device_in_service(self):
        if SSPState.error_page in self._state:
            logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
            logger.info('SmartPayout.device_in_service')
            try:
                if self._state and self._on_event_callback:
                    self._state.discard(SSPState.error_page)
                    # self.sspEnablePayout()
                    self._on_event_callback(event=PaymentCallbackEvents.DeviceInService)
            except Exception as se:
                logger.error(f'SmartPayout.device_in_service: error: {se}')

    def close_device(self) -> None:
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
        # logger.info('SmartPayout.close_device')
        # with self._locker:
        if self._device_port:
            try:
                # if self.device_port.isOpen():
                # logger.info('SmartPayout.close_device: closing port..')
                # self.deinit_device()
                # self._command_queue.join()
                # self._device_port.flush()
                time.sleep(0.1)
                self._device_port.close()
            except (FileNotFoundError, OSError, serial.SerialException) as se:
                logger.error(f'SmartPayout.close_device: Except: {se}')
            finally:
                logger.info('SmartPayout.close_device: port closed.')
        # else:
        #     logger.error('SmartPayout.close_device: port not open on de_init.')
        self.encrypted = False
        self._state.add(SSPState.disconnected)
        self._device_port = None

    def terminate(self) -> None:
        self._terminated = True
        self.close_device()

    def find_device(self) -> bool:
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
        logger.info('SmartPayout.find_device: try find device')
        list_port = get_serial_ports()
        for port in list_port:
            try:
                self._device_port = serial.Serial(port=port,
                                                  baudrate=self._baudrate,
                                                  bytesize=self._bytesize,
                                                  parity=self._parity,
                                                  stopbits=self._stopbits,
                                                  timeout=self.timeout)
                res = self.is_device_connected()
                if res:
                    self._serial_port = port
                    logger.info(f'SmartPayout.find_device: found {port}')
            except (OSError, serial.SerialException):
                pass
            finally:
                if self._device_port:
                    self._device_port.close()
                self._device_port = None
                if self._serial_port:
                    return True
        return False

    def init_device(self) -> bool:
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
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
        if not self.SetupRequest():
            logger.error('Failed on setup request...')
            return False

        # Set inhibits
        mask = self._device.get_channels_mask()
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

        self.ReadPayoutChannelsInfo()
        self._state.add(SSPState.error_page)
        logger.info('SmartPayout.device_init: Init complete')
        return True

    def deinit_device(self) -> bool:
        # self.sspDisableValidator()
        self.sspDisablePayout()
        return True

    def open_device(self) -> bool:
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
        logger.info(f'SmartPayout.open_device: try open device [{self._serial_port}]')
        if self._device_port:
            self.close_device()

        if not self._serial_port:
            logger.info('SmartPayout.open_device: try search device')
            if not self.find_device():
                logger.error('SmartPayout.open_device: device is not found')
                return False

        self._device_port = serial.Serial()
        self._device_port.port = self._serial_port
        self._device_port.baudrate = self._baudrate
        self._device_port.parity = self._parity
        self._device_port.bytesize = self._bytesize
        self._device_port.stopbits = self._stopbits
        self._device_port.timeout = self.timeout
        self._device_port.write_timeout = self.timeout

        try:
            self._device_port.open()
            self._device_port.reset_input_buffer()
            self._device_port.reset_output_buffer()
            if self._device_port.is_open:
                if self.is_device_connected():
                    if self.init_device():
                        logger.info(f'SmartPayout.open_device: device opened [{self._serial_port}]')
                        # self.device_in_service()
                        return True
            self.close_device()
            return False
        except (FileNotFoundError, OSError, serial.SerialException) as se:
            logger.error(f'SmartPayout.open_device: {se}')
            time.sleep(3)
            self.close_device()
            return False

    def encrypt_packet(self, data: Any) -> Any:
        # STEX | LENGTH | COUNT | DATA… | PACK… | CRCL | CRCH

        data = len(data).to_bytes(1, byteorder='little') + \
               self._encPktCount[self.address].to_bytes(4, byteorder='little') + data

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

        self._encPktCount[self.address] += 1
        self._encPktCount[self.address] &= 0xFFFF
        # res = bytes(SSP_STEX.to_bytes(1, byteorder='little') + bytes(cipher))
        res = bytes(SSP_STEX.to_bytes(1, byteorder='little') + sec_data)
        return res

    def decrypt_packet(self, data: bytes) -> Any:

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
        if slaveCount != self._encPktCount[self.address]:
            return SSPResponse.checksum_error, None

        ans_len = int(data[0])
        data = data[5:5 + ans_len]
        ans_code = int(data[0])
        res_data = data[1:] if ans_len > 1 else None
        return ans_code, res_data

    def check_response(self) -> Tuple[SSPResponse, Union[Union[int, bytes], Any]]:
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
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
            self.close_device()
            return SSPResponse.timeout, None

    def exec_command(self, data: Any) -> Tuple[SSPResponse, Union[Union[int, bytes], Any]]:
        # logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
        # logger.info(f'SmartPayout.exec_command: data: {data}')
        with (self._serial_locker):
            logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
            if self._device_port:
                data = flatlist(data)
                byte_list = [[ord(x) for x in i] if isinstance(i, str) else [i] for i in data]
                payload_data = bytes([int(item) for sublist in byte_list for item in sublist])
                if self.encrypted:
                    payload_data = self.encrypt_packet(payload_data)
                    if not payload_data:
                        return SSPResponse.failure, None

                arr = bytearray([self.address ^ self._seq, len(payload_data)]) + payload_data
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
                    self.close_device()
                    return SSPResponse.failure, None
            else:
                logger.error(f'exec_command: error: PayoutNotInitializedError')
                raise PayoutNotInitializedError()

    @staticmethod
    def get_only_int_str(data: bytes, idx: int) -> (int, str, int):  # amount, currency, bytes
        num_bytes = 7
        amount = int.from_bytes(data[idx: idx + 4], byteorder='little') // SSP_SCALE_FACTOR
        currency = bytes(data[idx + 4: idx + 7]).decode("utf-8")
        return amount, currency, num_bytes

    @staticmethod
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

    @staticmethod
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

    @staticmethod
    def get_channel_no(amount: int) -> int:
        for k, v in SSP_DEFAULT_CHANNEL_VALUES.items():
            if v == amount:
                return k
        return 0

    def poll_device(self) -> bool:
        if not self._device_port or not self.encrypted:
            return False

        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
        res, data = self.sspPoll()
        if res != SSPResponse.ok:
            return False

        self._state.discard(SSPState.note_path_open)

        is_need_read_payout_info = False
        idx = 0
        while data and idx < len(data):
            if not (data[idx] in PollEvents):
                logger.error(f'SmartPayout.poll: WARNING: Unknown poll response detected: {data[idx]}')
                idx += 1
                continue

            event_code = data[idx]
            # reset = 0xF1
            # The device has undergone a power reset.
            if event_code == PollEvents.slave_reset:
                logger.error(f'SmartPayout.poll: slave reset')
                if self._payment.mode == PaymentMode.emptying:
                    self._payment.mode = PaymentMode.ready
                # self.device_in_service()
                idx += 1
                continue

            # note_read = 0xEF
            # A note is being read, if the byte immediately following the response
            # is 0 then the note has not finished reading, if it is greater than 0
            # then this is the channel of that note.
            if event_code == PollEvents.note_read:
                channel = data[idx + 1]
                if channel > 0:
                    logger.info(f'SmartPayout.poll: Note in escrow, amount: {self._device.channels[channel].nominal}')
                else:
                    logger.info('SmartPayout.poll: Reading note...')

                if not self._disabled_other_payment:
                    self._disabled_other_payment = True
                    if self._payment.mode in {PaymentMode.request_payment, PaymentMode.payment}:
                        self._on_event_callback(event=PaymentCallbackEvents.PaymentStart)
                idx += 2
                continue

            # note_credit = 0xEE
            # A note has passed through the device, past the point of possible
            #  recovery, and the host can safely issue its credit amount.
            if event_code == PollEvents.note_credit:
                channel = data[idx + 1]
                self._payment.last_banknote_time = datetime.now()
                if channel < len(self._device.channels):
                    logger.info(
                        f'SmartPayout.poll: credit banknote {self._device.channels[channel].nominal} {self._device.channels[channel].currency}')
                    self._payment.last_banknote_amount = self._device.channels[channel].nominal
                    if self._payment.mode != PaymentMode.filling:
                        self.PaymentProcess(payment_amount=self._device.channels[channel].nominal)
                    #     self.FillProcess(payment_amount=self._device.channels[channel].nominal)
                    # else:
                    #     self.PaymentProcess(payment_amount=self._device.channels[channel].nominal)
                idx += 2
                continue

            # note_rejecting = 0xED
            # The note is in the process of being rejected from the validator.
            if event_code == PollEvents.note_rejecting:
                logger.info('SmartPayout.poll: note rejecting...')
                idx += 1
                continue

            # note_rejected = 0xEC
            # The note has been rejected from the validator and is available for
            # the user to retrieve.
            if event_code == PollEvents.note_rejected:
                logger.info('SmartPayout.poll: note rejected')
                res, reject_code, reject_message = self.sspQueryRejection()
                logger.info(f'SmartPayout.poll: reject code: {reject_code}, message: {reject_message}')
                idx += 1
                continue

            # note_stacking = 0xCC
            # The note is being moved from the escrow position to the host exit
            # section of the device.
            if event_code == PollEvents.note_stacking:
                logger.info('SmartPayout.poll: stacking note...')
                self._payment.last_banknote_time = datetime.now()
                idx += 1
                continue

            # note_stacked = 0xEB
            # The note has exited the device on the host side or has been placed
            # within its note stacker.
            if event_code == PollEvents.note_stacked:
                logger.info('SmartPayout.poll: note stacked')
                self._payment.last_banknote_time = datetime.now()
                channel_no = self.get_channel_no(self._payment.last_banknote_amount)
                if channel_no:
                    self._device.channels[channel_no].cashbox.count += 1
                    self.StateSave(include_session=False)
                    self._device.is_change_cashbox = True
                idx += 1
                continue

            # note_safe_jam = 0xEA
            # The note is stuck in a position not retrievable from the front of the
            # device (user side)
            if event_code == PollEvents.note_safe_jam:
                logger.info('SmartPayout.poll: safe jam detected...')
                idx += 1
                continue

            # note_unsafe_jam = 0xE9
            # The note is stuck in a position where the user could possibly remove
            # it from the front of the device.
            if event_code == PollEvents.note_unsafe_jam:
                logger.info('SmartPayout.poll: Unsafe jam detected...')
                self.device_out_of_service()
                idx += 1
                continue

            # disabled = 0xE8
            # The device is not active and unavailable for normal validation
            # functions.
            if event_code == PollEvents.disabled:
                if SSPState.disabled not in self._state:
                    logger.info('Unit disabled')
                self._state.add(SSPState.disabled)
                idx += 1
                continue

            # fraud_attempt = 0xE6
            # The device has detected an attempt to tamper with the normal
            # validation/stacking/payout process.
            if event_code == PollEvents.fraud_attempt:
                amount, currency, num_bytes = self.get_int_str(data, idx + 1)
                idx += num_bytes + 1
                logger.info(f'Fraud attempt! {amount} {currency}')
                continue

            # stacker_full = 0xE7
            # The banknote stacker unit attached to this device has been detected as at its full limit
            if event_code == PollEvents.stacker_full:
                logger.info('Stacker Full')
                # self.sspSmartEmpty()
                idx += 1
                continue

            # note_cleared_from_front = 0xE1
            # At power-up, a note was detected as being rejected out of the front of the device.
            if event_code == PollEvents.note_cleared_from_front:
                channel = data[idx + 1]
                if channel < len(self._device.channels):
                    logger.info(f'At power-up, a note was detected as being rejected out of the front of the device.'
                                f'channel {channel}, '
                                f'values {self._device.channels[channel].nominal}, '
                                f'currency {self._device.channels[channel].currency}')
                idx += 2
                continue

            # Note_cleared_to_cashbox = 0xE2
            # At power up, a note was detected as being moved into the stacker
            # unit or host exit of the device. The channel number of the note is
            # given in the data byte if known.
            if event_code == PollEvents.note_cleared_to_cashbox:
                channel = data[idx + 1]
                if channel < len(self._device.channels):
                    logger.info(
                        f'At power up, a note was detected as being moved into the stacker unit or host exit of the '
                        f'device channel {channel}, '
                        f'values {self._device.channels[channel].nominal}, '
                        f'currency{self._device.channels[channel].currency}')
                idx += 2
                continue

            # cashbox_removed = 0xE3
            # A device with a detectable cashbox has detected that it has been removed.
            if event_code == PollEvents.cashbox_removed:
                if SSPState.cashbox_removed not in self._state:
                    logger.info('Cashbox removed...')
                    self._state.add(SSPState.cashbox_removed)
                    self.CashboxRemoved()
                    self.ResetCashboxStateInfo()
                idx += 1
                continue

            # cashbox_replaced = 0xE4
            # A device with a detectable cashbox has detected that it has been replaced.
            if event_code == PollEvents.cashbox_replaced:
                logger.info('Cashbox replaced')
                self._state.discard(SSPState.cashbox_removed)
                self.CashboxReplaced()
                idx += 1
                continue

            # barcode_validate = 0xE5
            # A validated barcode ticket has been scanned and is available at the escrow point of the device.
            if event_code == PollEvents.barcode_validate:
                logger.info('Bar Code Ticket Validated')
                idx += 1
                continue

            # barcode_ack = 0xD1
            # The bar code ticket has been passed to a safe point in the device stacker.
            if event_code == PollEvents.barcode_ack:
                logger.info('Bar Code Ticket Acknowledge')
                idx += 1
                continue

            # note_path_open = 0xE0
            # The device has detected that its note transport path has been opened.
            if event_code == PollEvents.note_path_open:
                self._state.add(SSPState.note_path_open)
                logger.info('Note Path Open')
                idx += 1
                continue

            # channel_disable = 0xB5
            # The device has had all its note channels inhibited and has become disabled for note insertion.
            if event_code == PollEvents.channel_disable:
                logger.info('Channel Disable')
                idx += 1
                continue

            # Initialising = 0xB6
            # This event is given only when using the Poll with ACK command. It
            # is given when the BNV is powered up and setting its sensors and
            # mechanisms to be ready for Note acceptance. When the event
            # response does not contain this event, the BNV is ready to be
            # enabled and used.
            if event_code == PollEvents.initialising:
                logger.info('Initialising')
                idx += 1
                continue

            # Dispensing = 0xDA
            # The device is in the process of paying out a requested value. The
            # value paid at the poll is given in the vent data.
            if event_code == PollEvents.dispensing:
                amount, currency, num_bytes = self.get_int_str(data, idx + 1)
                idx += num_bytes + 1
                if amount != self._payment.last_note_dispensing:
                    self._payment.last_note_in_bezel = 0
                self._payment.last_note_dispensing = amount

                self._payment.last_banknote_amount = amount
                self._payment.last_banknote_time = datetime.now()
                logger.info(f'Dispensing. {amount} {currency}')
                continue

            # Dispensed = 0xD2
            # The device has completed its pay-out request. The final value paid is
            # given in the event data.
            if event_code == PollEvents.dispensed:
                amount, currency, num_bytes = self.get_int_str(data, idx + 1)
                logger.info(f'Dispensed. {amount} {currency}')
                idx += num_bytes + 1

                # self._payment.last_banknote_amount = amount
                # self._payment.last_banknote_time = datetime.now()
                # channel_no = self.get_channel_no(amount)
                # if channel_no:
                #     if self._device.channels[channel_no].payout.count > 0:
                #         self._device.channels[channel_no].payout.count -= 1

                is_need_read_payout_info = True
                self._payment.last_note_in_bezel = 0
                self.PaymentProcess(payout_amount=amount)
                self.StateSave()
                # self.sspEnableValidator()
                continue

            # tickets_replaced = 0xA1
            # The ticket stack has been replaced and is above the low level again.
            if event_code == PollEvents.tickets_replaced:
                logger.info('Tickets replaced')
                idx += 1
                continue

            # tickets_low = 0xA0
            # The number of tickets left is low.
            if event_code == PollEvents.tickets_low:
                logger.info('Tickets low')
                idx += 1
                continue

            # Jammed = 0xD5
            # The device has detected that coins are jammed in its mechanism
            # and cannot be removed other than by manual intervention. The
            # value paid at the jam point is given in the event data.
            if event_code == PollEvents.jammed:
                amount, currency, num_bytes = self.get_int_str(data, idx + 1)
                idx += num_bytes + 1
                logger.info(f'Jammed. {amount} {currency}')
                self.device_out_of_service()
                continue

            # Halted = 0xD6
            # This event is given when the host has requested a halt to the
            # device. The value paid at the point of halting is given in the event
            # data.
            if event_code == PollEvents.halted:
                amount, currency, num_bytes = self.get_int_str(data, idx + 1)
                idx += num_bytes + 1
                logger.info(f'Halted. {amount} {currency}')
                self.device_out_of_service()
                continue

            # floating = 0xD7
            # The device is in the process of executing a float command, and the
            # value paid to the cashbox at the poll time is given in the event data.
            if event_code == PollEvents.floating:
                amount, currency, num_bytes = self.get_int_str(data, idx + 1)
                idx += num_bytes + 1
                logger.info(f'Floating. {amount} {currency}')
                # display wait operation
                if self._on_event_callback:
                    self._on_event_callback(event=PaymentCallbackEvents.EnterEmptyingMode)
                continue

            # floated = 0xD8
            # The device has completed its float command and the final value
            # floated to the cashbox is given in the event data.
            if event_code == PollEvents.floated:
                amount, currency, num_bytes = self.get_int_str(data, idx + 1)
                idx += num_bytes + 1
                logger.info(f'Floated. {amount} {currency}')
                self._device.is_change_payout = True
                self._device.is_change_cashbox = True
                # restore display
                if self._on_event_callback:
                    self._on_event_callback(event=PaymentCallbackEvents.CurrentScreen)
                continue

            # Time_out = 0xD9
            # The device has been unable to complete a request. The value paid
            # up until the time-out point is given in the event data.
            if event_code == PollEvents.time_out:
                amount, currency, num_bytes = self.get_int_str(data, idx + 1)
                idx += num_bytes + 1
                logger.info(f'Timeout. {amount} {currency}')
                continue

            # Incomplete_payout = 0xDC
            # The device has detected a discrepancy on power-up that the last
            # payout request was interrupted (possibly due to a power failure).
            # The amounts of the value paid and requested are given in the event data.
            if event_code == PollEvents.incomplete_payout:
                dispensed, requested, currency, num_bytes = self.get_int_int_str(data, idx + 1)
                idx += num_bytes + 1
                logger.info(f'Incomplete payout. requested: {requested}, dispensed: {dispensed} {currency}')
                self.PaymentProcess(payout_amount=dispensed)
                self._device.is_change_payout = True
                continue

            # Incomplete_float = 0xDD
            # The device has detected a discrepancy on power-up that the last
            # float request was interrupted (possibly due to a power failure). The
            # amounts of the value paid and requested are given in the event data.
            if event_code == PollEvents.incomplete_float:
                dispensed, requested, currency, num_bytes = self.get_int_int_str(data, idx + 1)
                idx += num_bytes + 1
                logger.info(f'Incomplete float. requested: {requested}, dispensed: {dispensed} {currency}')
                continue

            # Cashbox_paid = 0xDE
            # This is given at the end of a payout cycle. It shows the value of
            # stored coins that were routed to the cashbox that were paid into the
            # cashbox during the payout cycle.
            if event_code == PollEvents.cashbox_paid:
                amount, currency, num_bytes = self.get_int_str(data, idx + 1)
                idx += num_bytes + 1
                logger.info(f'Cashbox paid. {amount} {currency}')
                continue

            # Coin_credit = 0xDF
            # A coin has been detected as added to the system via the attached
            # coin mechanism. The value of the coin detected is given in the event
            # data.
            if event_code == PollEvents.coin_credit:
                amount, currency, num_bytes = self.get_int_str(data, idx + 1)
                idx += num_bytes + 1
                logger.info(f'Coin credit. {amount} {currency}')
                continue

            # coin_mech_jammed = 0xC4
            # The attached coin mechanism has been detected as having a jam.
            if event_code == PollEvents.coin_mech_jammed:
                logger.info('Coin mech jammed')
                idx += 1
                continue

            # coin_mech_return_pressed = 0xC5
            # The attached coin mechanism has been detected as having been reject
            # or return button pressed.
            if event_code == PollEvents.coin_mech_jammed:
                logger.info('Coin mech return pressed')
                idx += 1
                continue

            # emptying = 0xC2
            # The device is in the process of emptying its content to the system
            # cashbox in response to an Empty command.
            if event_code == PollEvents.emptying:
                logger.info('Emptying')
                idx += 1
                continue

            # emptied = 0xC3
            # The device has completed its Empty process in response to an
            # Empty command from the host.
            if event_code == PollEvents.emptied:
                logger.info('Emptied')
                idx += 1
                self._ExitEmptyMode()
                self._device.is_change_payout = True
                self._device.is_change_cashbox = True
                continue

            # Smart_emptying = 0xB3
            # The device is in the process of carrying out its Smart Empty
            # command from the host. The value emptied at the poll point is given
            # in the event data.
            if event_code == PollEvents.smart_emptying:
                amount, currency, num_bytes = self.get_int_str(data, idx + 1)
                idx += num_bytes + 1
                logger.info(f'Smart emptying. {amount} {currency}')
                continue

            # Smart_emptied = 0xB4
            # The device has completed its Smart Empty command. The total
            # amount emptied is given in the event data.
            if event_code == PollEvents.smart_emptied:
                amount, currency, num_bytes = self.get_int_str(data, idx + 1)
                idx += num_bytes + 1
                logger.info(f'Smart emptied. {amount} {currency}')
                self._ExitEmptyMode()
                self._device.is_change_payout = True
                self._device.is_change_cashbox = True
                continue

            # Coin_mech_error = 0xB7
            # The attached coin mechanism has generated an error. Its code is
            # given in the event data.
            if event_code == PollEvents.coin_mech_error:
                logger.info('Coin mech error')
                idx += 1
                continue

            # note_stored_in_payout = 0xDB
            # The note has been passed into the note store of the payout unit.
            if event_code == PollEvents.note_stored_in_payout:
                self._payment.last_banknote_time = datetime.now()
                channel_no = self.get_channel_no(self._payment.last_banknote_amount)
                logger.info(
                    f'Note stored in payout. Last banknote: {self._payment.last_banknote_amount} ch: {channel_no}')
                if channel_no:
                    self._device.channels[channel_no].payout.count += 1
                    logger.info(
                        f'Note stored in payout. Payout_Info: {self._device.get_payout_info()}')
                    if self._payment.mode == PaymentMode.filling:
                        amount = SSP_DEFAULT_CHANNEL_VALUES.get(channel_no, 0)
                        self.FillProcess(payment_amount=amount)
                    self._device.is_change_payout = True
                idx += 1
                continue

            if event_code == PollEvents.note_credit:
                channel = data[idx + 1]
                self._payment.last_banknote_time = datetime.now()
                if channel < len(self._device.channels):
                    logger.info(
                        f'SmartPayout.poll: credit banknote {self._device.channels[channel].nominal} {self._device.channels[channel].currency}')
                    self._payment.last_banknote_amount = self._device.channels[channel].nominal
                    if self._payment.mode != PaymentMode.filling:
                        self.PaymentProcess(payment_amount=self._device.channels[channel].nominal)
                    #     self.FillProcess(payment_amount=self._device.channels[channel].nominal)
                    # else:
                    #     self.PaymentProcess(payment_amount=self._device.channels[channel].nominal)
                idx += 2
                continue

            # Payout_out_of_service = 0xC6
            # This event is given if the payout goes out of service during
            # operation. If this event is detected after a poll, the host can send
            # the ENABLE PAYOUT DEVICE command to determine if the payout
            # unit comes back into service.
            if event_code == PollEvents.payout_out_of_service:
                logger.info('Payout out of service')
                idx += 1
                continue

            # Jam_recovery = 0xB0
            # The SMART Payout unit is in the process of recovering from a
            # detected jam. This process will typically move five notes to the cash
            # box; this is done to minimize the possibility the unit will go out of
            # service
            if event_code == PollEvents.jam_recovery:
                logger.info('Jam recovery')
                idx += 1
                continue

            # Error_during_payout = 0xB1
            # Returned if an error is detected whilst moving a note inside the
            # SMART Payout unit. The cause of error (1 byte) indicates the source
            # of the condition; 0x00 for note not being correctly detected as it is
            # routed to cashbox or for payout, 0x01 if note is jammed in
            # transport. In the case of the incorrect detection, the response to
            # Cashbox Payout Operation Data request would report the note
            # expected to be paid out.
            if event_code == PollEvents.error_during_payout:
                amount, currency, num_bytes = self.get_int_str(data, idx + 1)
                idx += num_bytes + 1
                if data[idx] == 0x00:
                    msg = 'for note not being correctly detected as it is routed'
                elif data[idx] == 0x01:
                    msg = 'for note jammed in transport'
                elif data[idx] == 0x02:
                    msg = 'while emptying'
                elif data[idx] == 0x04:
                    msg = 'not handled'
                else:
                    msg = f'code = {data[idx]}'
                idx += 1
                logger.info(f'Error during payout. {amount} {currency}, msg: {msg}')

                channel_no = self.get_channel_no(amount)
                if channel_no:
                    if self._device.channels[channel_no].payout.count > 0:
                        self._device.channels[channel_no].payout.count -= 1
                        self.StateSave()
                        self._device.is_change_cashbox = True
                self._ExitEmptyMode()
                continue

            # note_transfered_stacker = 0xC9
            # Reported when a note has been successfully moved from the payout
            # store into the stacker cashbox.
            if event_code == PollEvents.note_transfered_stacker:
                amount, currency, num_bytes = self.get_only_int_str(data, idx + 1)
                idx += num_bytes + 1
                logger.info(f'Note transfered to stacker. {amount} {currency}')
                channel_no = self.get_channel_no(amount)
                if channel_no:
                    try:
                        if self._device.channels[channel_no].payout.count > 0:
                            self._device.channels[channel_no].payout.count -= 1
                            self._device.is_change_payout = True
                        self._device.channels[channel_no].cashbox.count += 1
                        self.StateSave(include_session=False)
                        self._device.is_change_cashbox = True
                    except Exception as se:
                        logger.error(f'poll_device: {se}')
                continue

            # note_held_bezel = 0xCE
            # Reported when a dispensing note is held in the bezel of the payout
            # device.
            if event_code == PollEvents.note_held_bezel:
                amount, currency, num_bytes = self.get_only_int_str(data, idx + 1)
                idx += num_bytes + 1
                self._payment.last_banknote_time = datetime.now()
                logger.info(f'Note held in bezel. {amount} {currency}')
                if not self._payment.last_note_in_bezel:
                    self._payment.last_note_in_bezel = amount
                    self._on_event_callback(event=PaymentCallbackEvents.PayoutNote,
                                            amount_note=self._payment.last_note_in_bezel)
                continue

            # note_paid_store_powerup = 0xCB
            # Reported when a note has been detected as paid into the payout
            # store as part of the power-up procedure.
            if event_code == PollEvents.note_paid_store_powerup:
                amount, currency, num_bytes = self.get_int_str(data, idx + 1)
                idx += num_bytes + 1
                logger.info(f'Note paid into store at power-up. {amount} {currency}')
                continue

            # note_paid_stacker_powerup = 0xCA
            # Reported when a note has been detected as paid into the payout
            # store as part of the power-up procedure.
            if event_code == PollEvents.note_paid_stacker_powerup:
                amount, currency, num_bytes = self.get_int_str(data, idx + 1)
                idx += num_bytes + 1
                logger.info(f'Note paid into stacker at power-up. {amount} {currency}')
                continue

            # note_dispensed_powerup = 0xCD
            # Reported when a note has been dispensed as part of the power-up
            # procedure.
            if event_code == PollEvents.note_dispensed_powerup:
                amount, currency, num_bytes = self.get_int_str(data, idx + 1)
                idx += num_bytes + 1
                logger.info(f'Note Dispensed at power-up. {amount} {currency}')
                continue

            # note_float_removed = 0xC7
            # Reported when a note float unit has been detected as removed from
            # its validator.
            if event_code == PollEvents.note_float_removed:
                logger.info('Note float removed')
                idx += 1
                continue

            # note_float_attached = 0xC8
            # Reported when a note float unit has been detected as removed from
            # its validator.
            if event_code == PollEvents.note_float_attached:
                logger.info('Note float attached')
                idx += 1
                continue

            # Device_full = 0xC9
            # This event is reported when the Note Float has reached its limit of
            # stored notes. This event will be reported until a note is paid out or
            # stacked.
            if event_code == PollEvents.device_full:
                logger.info('Device full')
                idx += 1
                continue

            # printer_head_removed = 0xA2
            # This event is reported when the level of tickets inthe device is
            # detected as low.
            if event_code == PollEvents.printer_head_removed:
                logger.info('Printer head removed')
                idx += 1
                continue

            # ticket_path_opened = 0xA3
            # The Smart Ticket device has been opened, and tickets cant be
            # printed.
            if event_code == PollEvents.ticket_path_opened:
                logger.info('Ticket path opened')
                idx += 1
                continue

            # ticket_printer_jam = 0xA4
            # A jam occured when attempting to print a ticket.
            if event_code == PollEvents.ticket_printer_jam:
                logger.info('Ticket printer jam')
                idx += 1
                continue

            # printing_ticket = 0xA5
            # A ticket is currently being printed.
            if event_code == PollEvents.printing_ticket:
                logger.info('Printing Ticket')
                idx += 1
                continue

            # printed_ticket = 0xA6
            # A ticket has successfully been printed and dispensed.
            if event_code == PollEvents.printed_ticket:
                logger.info('Printed Ticket')
                idx += 1
                continue

            # print_ticket_fail = 0xA8
            # Unable to print the requested ticket. the event includes a data byte
            # indicating the reason for failure
            if event_code == PollEvents.print_ticket_fail:
                logger.info('Print ticket fail')
                idx += 1
                # some bytes or bits
                continue

            # printer_head_replaced = 0xA9
            # The printer head was replaced after being removed.
            if event_code == PollEvents.printer_head_replaced:
                logger.info('Printer head replaced')
                idx += 1
                continue

            # ticket_path_closed = 0xAA
            # The ticket path was closed after being opened.
            if event_code == PollEvents.ticket_path_closed:
                logger.info('Ticket path closed')
                idx += 1
                continue

            # no_ticket_paper = 0xAB
            # There is no paper currently fed into the device.
            if event_code == PollEvents.no_ticket_paper:
                logger.info('No ticket paper')
                idx += 1
                continue

            # coins_low = 0xD3
            if event_code == PollEvents.coins_low:
                logger.info('Coins low')
                idx += 1
                continue

            # empty = 0xD4
            if event_code == PollEvents.empty:
                logger.info('Unit empty')
                idx += 1
                continue

        # check need update payout info
        if is_need_read_payout_info:
            self.ReadPayoutChannelsInfo()

        return res

    def wait_banknote_operation(self):
        res = True
        while res:
            with self._payment_locker:
                res = (self._payment.last_banknote_time + timedelta(seconds=5)) > datetime.now()
            if res:
                time.sleep(0.5)
        return

    def PaymentReset(self, mode: PaymentMode = PaymentMode.ready, save_state: bool = True):
        self._payment.mode = mode  # режим операции
        self._payment.requested_payment = 0  # запрошенная сумма на прием
        self._payment.payment = 0  # принятая сумма
        self._payment.requested_payout = 0  # запрошенная сумма на выдачу
        self._payment.payout = 0  # выданная сумма
        # self._payment.last_banknote_amount = 0  # номинал последней банкноты
        # self._payment.last_banknote_time = datetime.now()  # время последней операции с банкнотой
        self._disabled_other_payment = False  #
        self._payment.last_note_dispensing = 0
        self._payment.last_note_in_bezel = 0
        if save_state:
            self.StateSave()
        # self._on_event_callback(event=PaymentCallbackEvents.CurrentScreen)

    def PaymentRequest(self, amount: int) -> bool:
        """
        Запрос на прием наличности
        """
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
        if not isinstance(amount, int) or amount <= 0:
            logger.error(f'SmartPayout.PaymentRequest: incorrect amount value {amount}')
        if not self.is_device_ok():
            logger.error(f'SmartPayout.PaymentRequest: amount: {amount}, device error')
            return False
        self.EnablePayment()
        with self._payment_locker:
            if self._payment.mode not in {PaymentMode.ready}:
                logger.error(f'SmartPayout.PaymentRequest: amount: {amount}, already process payment operation')
                return False
            logger.info(f'SmartPayout.PaymentRequest: amount: {amount}')
            self.PaymentReset(PaymentMode.request_payment)
            self._payment.requested_payment += amount
        return True

    def PayoutRequest(self, amount: int) -> bool:
        """
        Запрос на выдачу наличности
        """
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
        if not isinstance(amount, int) or amount <= 0:
            logger.error(f'SmartPayout.PayoutRequest: incorrect amount value {amount}')
        if not self.is_device_ok():
            logger.error(f'SmartPayout.PayoutRequest: amount: {amount}, device error')
            return False

        with self._payment_locker:
            if self._payment.mode not in {PaymentMode.ready, PaymentMode.payment}:
                logger.error(f'SmartPayout.PayoutRequest: amount: {amount}, already process payout operation')
                return False
            logger.info(f'SmartPayout.PayoutRequest: amount: {amount}')
            self._payment.mode = PaymentMode.request_payout
            self._payment.requested_payout += amount
        return True

    def CancelRequest(self) -> bool:
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
        # check a device in filling mode
        if self._payment.mode == PaymentMode.filling:
            return self._ExitFillingMode()

        if self._payment.mode not in {PaymentMode.payment,
                                      PaymentMode.request_payment,
                                      PaymentMode.request_payout}:
            logger.error(f'SmartPayout.CancelRequest: payment mode incorrect {self._payment.mode}')
            return False

        amount = self._payment.payment - self._payment.payout
        logger.info(f'SmartPayout.CancelRequest: calc payment amount: {amount}')
        self._payment.mode = PaymentMode.request_cancel
        return True

    def EnterServiceMode(self) -> bool:
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
        self.wait_banknote_operation()
        with self._payment_locker:
            if self._payment.mode != PaymentMode.ready:
                logger.error(f'SmartPayout.EnterServiceMode: Error enter service mode,'
                             f'incorrect mode {self._payment.mode}')
                return False
            logger.info(f'SmartPayout.EnterServiceMode: current mode {self._payment.mode}')
            self._on_event_callback(event=PaymentCallbackEvents.EnterServiceMode,
                                    result=0)
            self._payment.mode = PaymentMode.service
        return True

    def ExitServiceMode(self) -> bool:
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
        self.wait_banknote_operation()
        with self._payment_locker:
            if self._payment.mode != PaymentMode.service:
                logger.error(f'SmartPayout.ExitServiceMode: Error exit service mode,'
                             f'incorrect mode {self._payment.mode}')
                return False
            logger.info(f'SmartPayout.ExitServiceMode: current mode {self._payment.mode}')
            self._on_event_callback(event=PaymentCallbackEvents.ExitServiceMode,
                                    result=0)
            self._payment.mode = PaymentMode.ready
        return True

    def ReadPayoutChannelsInfo(self) -> None:
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
        for channel in self._device.channels:
            if channel.id:
                # Stored notes
                res, counter = self.sspGetNoteAmount(channel.nominal, SSP_DEFAULT_CURRENCY)
                if res == SSPResponse.ok:
                    self._device.is_change_payout = self._device.is_change_payout or (counter != channel.payout.count)
                    channel.payout.count = counter
                    self._device.get_payout_info()
                else:
                    channel.payout.count = 0
        logger.info(f'ReadPayoutChannelsInfo: channels_info={self._device.get_payout_info()}')

    def ResetPayoutStateInfo(self) -> None:
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
        logger.info(f'ResetPayoutStateInfo: ...')
        try:
            for channel in self._device.channels:
                channel.payout.count = 0
            self._device.is_change_payout = True
        except Exception as se:
            logger.error(f'ResetPayoutStateInfo: {se}')

    def UpdatePayoutStateInfo(self) -> None:
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
        logger.info(f'UpdatePayoutStateInfo: ...')
        try:
            if not self._device.is_change_payout:
                return
            # self.ReadPayoutChannelsInfo()
            self._device.is_change_payout = False
            self._on_event_callback(event=PaymentCallbackEvents.UpdatePayoutInfo,
                                    channels_info=self._device.get_payout_info())
        except Exception as se:
            logger.error(f'UpdatePayoutStateInfo: {se}')

    def SetPayoutConfig(self, channels_list: list = None) -> bool:
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
        logger.info(f'SetPayoutConfig: {channels_list}')
        if channels_list is None:
            logger.error(f'SetPayoutConfig: empty config')
            return False

        payout_set = set()
        cashbox_set = set()

        # check config channels_list
        storage_payout = 2
        storage_cashbox = 3
        for row in channels_list:
            if isinstance(row, dict):
                storage_kind_id = row.get('StorageKindId', 0)
                amount = row.get('Value', 0)
                channel_no = list(SSP_DEFAULT_CHANNEL_VALUES.values()).index(amount)
                # channel_id = row.get('ChannelId', 0)
                limit_min = row.get('LimitMin', 0)
                limit_max = row.get('LimitMax', SSP_MAX_PAYOUT_CAPACITY)
            else:
                logger.error(f'SetPayoutConfig: error data {row}')
                return False

            if not channel_no:
                logger.error(f'SetPayoutConfig: skip amount: {amount}')
                continue

            if storage_kind_id == storage_payout:
                payout_set.add(amount)
                self._device.channels[channel_no].payout.limit_min = limit_min
                self._device.channels[channel_no].payout.limit_max = limit_max
            elif storage_kind_id == storage_cashbox:
                cashbox_set.add(amount)

        for channel in self._device.channels:
            channel.enabled = channel.nominal in cashbox_set
            channel.payout.keeping = channel.nominal in payout_set
        return True

    def ResetCashboxStateInfo(self) -> None:
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
        logger.info(f'ResetCashboxStateInfo: ...')
        try:
            for channel in self._device.channels:
                channel.cashbox.count = 0
            self._device.is_change_cashbox = True
        except Exception as se:
            logger.error(f'ResetCashboxStateInfo: {se}')

    def UpdateCashboxStateInfo(self) -> None:
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
        logger.info(f'UpdateCashboxStateInfo: ...')
        try:
            if not self._device.is_change_cashbox:
                return
            self._device.is_change_cashbox = False
            self._on_event_callback(event=PaymentCallbackEvents.UpdateCashboxInfo,
                                    channels_info=self._device.get_cashbox_info(),
                                    report_number=self.get_receipt_number())
        except Exception as se:
            logger.error(f'UpdateCashboxStateInfo: {se}')

    def _EnterFillingMode(self) -> bool:
        self.wait_banknote_operation()
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
        logger.info(f'SmartPayout._EnterFillingMode: payment amount: {self._payment.payment}')
        if self._payment.mode != PaymentMode.ready:
            return False

        # Enable
        self.EnablePayment()

        # Block unsupported banknotes
        mask = self._device.get_payout_mask()
        res = self.sspSetInhibits(mask)
        if res != SSPResponse.ok:
            logger.error('SmartPayout._EnterFillingMode: Failed on setting inhibits...')
            return False

        self._payment.mode = PaymentMode.filling
        self.ReadPayoutChannelsInfo()
        display_lines = self.GetDisplayForm(PageType.Filling)
        print_lines = self.GetReportForm(report_type=ReportType.PayoutInfoEnter)
        self._on_event_callback(event=PaymentCallbackEvents.EnterFillingMode,
                                print_lines=print_lines,
                                display_lines=display_lines,
                                result=0)
        return True
        # return False

    def _ExitFillingMode(self) -> bool:
        self.wait_banknote_operation()
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
        logger.info(f'SmartPayout._ExitFillingMode: payment amount: {self._payment.payment}')

        # channels_info = self.GetPayoutChannelsInfo()
        # print_lines = self.GetReportForm(report_title='PAYOUT INFO EXIT', channels_info=channels_info)

        # Disable
        self.DisablePayment()

        # Enable all banknotes
        mask = self._device.get_channels_mask()
        res = self.sspSetInhibits(mask)
        if res != SSPResponse.ok:
            logger.error('SmartPayout._ExitFillingMode: Failed on setting inhibits...')

        print_lines = self.GetReportForm(report_type=ReportType.PayoutInfoExit)
        self._on_event_callback(event=PaymentCallbackEvents.ExitFillingMode,
                                print_lines=print_lines,
                                result=0,
                                amount_payment=self._payment.payment)
        with self._payment_locker:
            self.PaymentReset(PaymentMode.ready)
            self._device.is_need_smartfloat = True
        return True

    def FillHopper(self) -> bool:
        return self._EnterFillingMode()

    def GetDisplayForm(self, page_type: PageType) -> list:
        display_data = []
        line_no = 0
        balance_value = 0
        if page_type == PageType.Filling:
            for channel in self._device.channels:
                banknote_count = channel.payout.count
                if banknote_count:
                    line_no += 1
                    display_data.append(f'{channel.nominal:>6} : {channel.payout.count:>2}')
                    balance_value += channel.nominal * banknote_count
            if display_data:
                display_data.append(f'')
                display_data.append(f'ИТОГО : {balance_value}')
            else:
                display_data.append(f'ПУСТОЙ')
            # display_data['balance_type'] = 'value'
        return display_data[:]

    def GetReportForm(self, report_type: ReportType) -> list:

        report_title = ReportTypeTitle.get(report_type, '')

        line_width = 30
        paystation_no = 1
        paystation_name = 'Станция'
        receipt_no = self.get_receipt_number()
        date_obj = datetime.now()

        paystation_text = f'Касса №{paystation_no}'
        time_text = f'{date_obj:%d.%m.%Y %H:%M:%S}'
        report_no = f'Отчет №{receipt_no}'
        banknotes_header = f' ' * 12 + f'Кол-во     {SSP_DEFAULT_CURRENCY}'

        form_data = [
            f'{"ООО ""Парковочный оператор"""}',
            f'',
            f'{paystation_text:<{line_width}}',
            f'{paystation_name:<{line_width}}',
            '-' * line_width,
            f'{report_title:<{line_width}}',
            f'{time_text:<{line_width}}',
            f'',
            f'{report_no:<{line_width}}',
            f''
        ]
        # f'{"FILLED BANKNOTES":<{line_width}}',
        # f'{banknotes_header:<{line_width}}',
        # '-' * line_width

        channels_data_payout = [f'{"Сдача":<{line_width}}',
                                f'{banknotes_header:<{line_width}}',
                                '-' * line_width]
        total_num_payout = total_sum_payout = 0
        channels_data_cashbox = [f'{"Кассета":<{line_width}}',
                                 f'{banknotes_header:<{line_width}}',
                                 '-' * line_width]
        total_num_cashbox = total_sum_cashbox = 0

        for channel in self._device.channels:
            if channel.enabled:
                if channel.payout.keeping:
                    notes_num_payout = channel.payout.count
                    channel_text_payout = f'  {channel.nominal:>4}:      {notes_num_payout:>2}     {channel.nominal * notes_num_payout:>6}'
                    channels_data_payout.append(f'{channel_text_payout:<{line_width}}')
                    total_num_payout += notes_num_payout
                    total_sum_payout += channel.nominal * notes_num_payout

                notes_num_cashbox = channel.cashbox.count
                channel_text_cashbox = f'  {channel.nominal:>4}:      {notes_num_cashbox:>2}     {channel.nominal * notes_num_cashbox:>6}'
                channels_data_cashbox.append(f'{channel_text_cashbox:<{line_width}}')
                total_num_cashbox += notes_num_cashbox
                total_sum_cashbox += channel.nominal * notes_num_cashbox

        channels_data_payout.append('-' * line_width)
        total_text = f'  Сумма:    {total_num_payout:>3}    {total_sum_payout:>7}'
        channels_data_payout.append(f'{total_text:<{line_width}}')

        channels_data_cashbox.append('-' * line_width)
        total_text = f'  Сумма:    {total_num_cashbox:>3}    {total_sum_cashbox:>7}'
        channels_data_cashbox.append(f'{total_text:<{line_width}}')

        if report_type in {ReportType.CashboxInfoEnter,
                           ReportType.CashboxInfoExit}:
            form_data.extend(channels_data_cashbox)

        elif report_type in {ReportType.PayoutInfoEnter,
                             ReportType.PayoutInfoExit}:
            form_data.extend(channels_data_payout)

        elif report_type in {ReportType.CashboxRemoved,
                             ReportType.CashboxReplaced,
                             ReportType.PayStationReport}:
            form_data.extend(channels_data_payout)
            form_data.append(f'')
            form_data.extend(channels_data_cashbox)

        return form_data

    def _EnterEmptyMode(self) -> bool:
        self.wait_banknote_operation()
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
        if self._payment.mode != PaymentMode.ready:
            logger.error(f'SmartPayout._EnterEmptyMode: current payment mode: {self._payment.mode}')
            return False

        logger.info(f'SmartPayout._EnterEmptyMode:')
        print_lines = self.GetReportForm(report_type=ReportType.CashboxInfoEnter)
        if self.sspEmpty() == SSPResponse.ok:
            self._payment.mode = PaymentMode.emptying
            self._on_event_callback(event=PaymentCallbackEvents.EnterEmptyingMode,
                                    result=0,
                                    print_lines=print_lines)
            # self.device_out_of_service()
            return True
        return False

    def _ExitEmptyMode(self) -> bool:
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
        logger.info(f'SmartPayout._ExitEmptyMode:')

        print_lines = self.GetReportForm(report_type=ReportType.CashboxInfoExit)
        self._on_event_callback(event=PaymentCallbackEvents.ExitEmptyingMode,
                                print_lines=print_lines,
                                result=0)
        self._payment.mode = PaymentMode.ready
        # self.device_in_service()
        return True

    def CashboxRemoved(self) -> bool:
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
        logger.info(f'SmartPayout.CashboxRemove:')

        print_lines = self.GetReportForm(report_type=ReportType.CashboxRemoved)
        self._on_event_callback(event=PaymentCallbackEvents.CashboxRemoved,
                                print_lines=print_lines)
        return True

    def CashboxReplaced(self) -> bool:
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
        logger.info(f'SmartPayout.CashboxReplaced:')
        print_lines = self.GetReportForm(report_type=ReportType.CashboxReplaced)
        self._on_event_callback(event=PaymentCallbackEvents.CashboxReplaced,
                                print_lines=print_lines)
        return True

    def EmptyHopper(self) -> bool:
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
        logger.info(f'EmptyHopper: ')
        if self.GetPayoutAmount() > 0:
            return self._EnterEmptyMode()
        else:
            return False

    def PrintPayStationReport(self) -> bool:
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
        logger.info(f'SmartPayout.PrintPayStationReport:')
        self.wait_banknote_operation()
        if self._payment.mode != PaymentMode.ready:
            return False

        print_lines = self.GetReportForm(report_type=ReportType.PayStationReport)
        self._on_event_callback(event=PaymentCallbackEvents.PrintPayStationReport,
                                result=0,
                                print_lines=print_lines)
        return True

    def StateSave(self, include_session: bool = True) -> bool:
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
        try:
            with open(itl_payment_state_file, 'wb') as f:
                pickle.dump(self._payment, f)           # type: ignore
                f.flush()
            with open(itl_device_state_file, 'wb') as f:
                pickle.dump(self._device, f)            # type: ignore
                f.flush()
            if 'posix' in builtin_module_names:
                os.sync()
            if include_session:
                self._on_event_callback(event=PaymentCallbackEvents.SaveSessionData)
            return True
        except (OSError, pickle.PickleError):
            logger.error(f'SmartPayout.StateSave: could not persist on local filesystem')
            return False

    def StateRestore(self) -> bool:
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
        try:
            if os.path.isfile(itl_payment_state_file):
                with open(itl_payment_state_file, 'rb') as f:
                    self._payment = pickle.load(f)
            if os.path.isfile(itl_device_state_file):
                with open(itl_device_state_file, 'rb') as f:
                    self._device = pickle.load(f)

            if self._payment.mode in {PaymentMode.payment,
                                      PaymentMode.request_payout,
                                      PaymentMode.payout,
                                      PaymentMode.request_cancel,
                                      PaymentMode.cancel}:
                # and (self._payment.payment != self._payment.payout):
                self._on_event_callback(event=PaymentCallbackEvents.RestoreSessionData)
            else:
                # self.PaymentReset(save_state=False)
                self._on_event_callback(event=PaymentCallbackEvents.ResetSessionData)
            self.PaymentReset(save_state=False)
            # self._on_event_callback(event=PaymentCallbackEvents.ResetSessionData)

            # common operations
            self._payment.last_banknote_amount = 0
            self._payment.last_banknote_time = datetime.now()
            self._device.is_need_smartfloat = True
            return True
        except (OSError, EOFError, pickle.PickleError) as se:
            logger.info(f'SmartPayout.StateRestore: could not load local copy {se}')
        return False

    def FillProcess(self, payment_amount: int = 0) -> bool:
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
        with (self._payment_locker):
            try:
                self._payment.payment += payment_amount
                logger.info(
                    f'SmartPayout.FillProcess: payment: {payment_amount}, sum payment = {self._payment.payment}')
                self.StateSave(include_session=False)
                display_lines = self.GetDisplayForm(PageType.Filling)
                self._on_event_callback(event=PaymentCallbackEvents.FillNote,
                                        amount_note=payment_amount,
                                        amount_payment=self._payment.payment,
                                        display_lines=display_lines,
                                        result=0)

                # check errors (limit payout banknotes)
                if self.ErrorCheck():
                    return False
            except Exception as se:
                logger.error(f'SmartPayout.FillProcess: Except {se}')
        return True

    def PaymentProcess(self, payment_amount: int = 0, payout_amount: int = 0) -> bool:
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
        logger.info(f'SmartPayout.PaymentProcess: payment = {payment_amount}, payout = {payout_amount}')
        # logger.info(f'SmartPayout.PaymentProcess: credit = {credit_amount}, dispensed = {dispensed_amount}')
        with (self._payment_locker):
            try:
                # logger.info(f'TEST: SmartPayout.PaymentProcess: _payment_locker. mode: {self._payment.mode}...')

                # <editor-fold desc="cancel payment operation">
                if self._payment.mode == PaymentMode.request_cancel:
                    amount = self._payment.payment - self._payment.payout
                    if amount == 0:
                        self.PaymentReset()
                        self._on_event_callback(event=PaymentCallbackEvents.CancelComplete)
                    elif amount < 0:
                        logger.error(f'SmartPayout.PaymentProcess: Error cancel payment, amount: {amount}')
                        return False
                    # check filling complete
                    elif (amount > 0) and (self._payment.mode == PaymentMode.filling):
                        # self._payment.mode = PaymentMode.cancel
                        pass
                    # check cancel with payout
                    elif (amount > 0) and (self._payment.mode != PaymentMode.filling):
                        self.EnablePayment()
                        if self.sspPayout(amount, SSP_DEFAULT_CURRENCY) == SSPResponse.ok:
                            self._on_event_callback(event=PaymentCallbackEvents.CancelRequest)
                            self._payment.mode = PaymentMode.cancel
                            return True
                        else:
                            logger.error(f'SmartPayout.PaymentProcess: Error payout amount = {amount}')
                            # self._on_event_callback(event=PaymentCallbackEvents.CancelError,
                            #                         result=0,
                            #                         payment_info={'AmountPaid': amount * SSP_SCALE_FACTOR})
                            return False
                    # self._on_event_callback(event=PaymentCallbackEvents.CancelComplete,
                    #                         result=0,
                    #                         amount_payout=amount)
                    # self._payment.mode = PaymentMode.cancel
                # </editor-fold>

                # check need payout
                if self._payment.mode == PaymentMode.request_payout:
                    amount = self._payment.requested_payout - self._payment.payout
                    self.EnablePayment()
                    if self.sspPayout(amount, SSP_DEFAULT_CURRENCY) != SSPResponse.ok:
                        logger.error(f'SmartPayout.PaymentProcess: Error payout amount = {amount}')
                        self._on_event_callback(event=PaymentCallbackEvents.PayoutError,
                                                amount_payout=amount)
                        self.PaymentReset(PaymentMode.ready)
                        return False
                    self._payment.mode = PaymentMode.payout

                self._payment.payment += payment_amount
                self._payment.payout += payout_amount

                if self._payment.mode == PaymentMode.cancel:
                    if self._payment.payment == self._payment.payout:
                        self._on_event_callback(event=PaymentCallbackEvents.CancelComplete,
                                                amount_payout=self._payment.payout)
                        self.PaymentReset()

                if self._payment.mode == PaymentMode.payout:
                    if self._payment.requested_payout == self._payment.payout:
                        logger.info(f'SmartPayout.PaymentProcess: PayoutComplete amount = {self._payment.payout}')
                        self._on_event_callback(event=PaymentCallbackEvents.PayoutComplete,
                                                amount_payout=self._payment.payout)
                        self.PaymentReset()
                        self._on_event_callback(event=PaymentCallbackEvents.CurrentScreen)

                if self._payment.mode == PaymentMode.payment:
                    # check errors (limit payout banknotes)
                    if self.ErrorCheck():
                        return False

                    calc_amount = self._payment.payment - self._payment.payout
                    if payment_amount > 0:
                        self._on_event_callback(event=PaymentCallbackEvents.PaymentNote,
                                                amount_left=self._payment.requested_payment - calc_amount,
                                                amount_note=payment_amount,
                                                result=0)

                    # complete payment (payment = requested_payment)
                    if self._payment.requested_payment == calc_amount:
                        logger.info(f'SmartPayout.PaymentProcess: PaymentComplete amount = {calc_amount}')
                        # add payout channel
                        if payout_amount > 0:
                            self._on_event_callback(event=PaymentCallbackEvents.PayoutComplete,
                                                    amount_payout=self._payment.payout)

                        self._on_event_callback(event=PaymentCallbackEvents.PaymentComplete,
                                                result=0,
                                                amount_paid=calc_amount,
                                                amount_payment=self._payment.payment,
                                                amount_payout=self._payment.payout,
                                                amount_overpayment=self._payment.payment - self._payment.requested_payment
                                                )
                        self.PaymentReset(PaymentMode.ready)
                        self._device.is_need_smartfloat = True

                    # need payout (payment > requested_payment)
                    elif calc_amount > self._payment.requested_payment:
                        # try payout part payment
                        # requested_payment: 600, payment: 550, payout: 50
                        # self.wait_banknote_operation()
                        amount = self.GetPayoutAmountLeft()
                        if self.sspPayout(amount, SSP_DEFAULT_CURRENCY) == SSPResponse.ok:
                            self._on_event_callback(event=PaymentCallbackEvents.PayoutRequest, amount_payout=amount)
                        else:
                            # payout full payment (cancel payment operation)
                            # requested_payment: 600, payment: 550, payout: 550
                            logger.error(
                                f'SmartPayout.PaymentProcess: Error payout amount = {amount}, cancel full payment')
                            self.CancelRequest()

                        # self.PayoutRequest(amount)
                    # need addition payment (payment < requested_payment)
                    else:
                        # wait payment
                        pass
            except Exception as se:
                logger.error(f'SmartPayout.PaymentProcess: Except {se}')
            finally:
                # save payment state on disk
                self.StateSave()
        return True


    def run(self) -> NoReturn:
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
        logger.info(f'SmartPayout.run: [{self.name}]')
        thread_sleep(1)
        try:
            if self._on_event_callback:
                self._on_event_callback(event=PaymentCallbackEvents.Init)
        except Exception as se:
            logger.error(f'SmartPayout.run: Init error: {se}')
        logger.info(f'SmartPayout.run: set config')
        self.StateRestore()

        while not self._terminated:
            try:
                # small delay
                time.sleep(0.1)

                with (self._serial_locker):
                    # log values
                    # logger.info(f'_state {self._state}, '
                    #             f'mode: {self._payment.mode}, '
                    #             f'requested_payment: {self._payment.requested_payment},'
                    #             f'_payment.payment: {self._payment.payment},'
                    #             f'requested_payout: {self._payment.requested_payout},'
                    #             f'_payment.payout: {self._payment.payout}')

                    # try an open device
                    if not self._device_port:
                        self.open_device()

                    # check device_out_of_service
                    if SSPState.error_page not in self._state:
                        if not self.is_device_ok():
                            self.device_out_of_service()
                            continue

                    # check device_in_service
                    if (SSPState.error_page in self._state) and (
                            self._payment.mode not in {PaymentMode.emptying, PaymentMode.service}):
                        if self.is_device_ok():
                            self.device_in_service()
                            continue

                    # enable/disable accept payment
                    if self._device_port and self.encrypted:
                        # with self._payment_locker:
                        # logger.info(f'SmartPayout.run: SSPState.disabled:{SSPState.disabled},'
                        #             f'_state:{self._state}, _payment.mode: {self._payment.mode},'
                        #             f'_payment.payment: {self._payment.payment},'
                        #             f'_payment.requested_payment: {self._payment.requested_payment}')

                        # check service mode
                        # if (SSPState.error_page in self._state) or (self._payment.mode == PaymentMode.service):
                        #     continue

                        # process request operation cancel/payout/service
                        if self._payment.mode in {PaymentMode.request_cancel,
                                                  PaymentMode.request_payout}:
                            self.PaymentProcess(0, 0)

                        if not self._global_service_mode and \
                                (
                                        (self._payment.mode in {PaymentMode.request_payment, PaymentMode.filling}) or
                                        (self._payment.mode == PaymentMode.payment and
                                         self._payment.payment < self._payment.requested_payment)
                                ):
                            # check the need enable validator
                            if SSPState.disabled in self._state:
                                logger.info(f'SmartPayout.run: try enable validator')
                                if self.sspEnableValidator() == SSPResponse.ok:
                                    self._state.discard(SSPState.disabled)
                                    logger.info(f'SmartPayout.run: state: {self._state}')
                                    if self._payment.mode == PaymentMode.request_payment:
                                        self._payment.mode = PaymentMode.payment
                        else:
                            # check needs to disable validator
                            if SSPState.disabled not in self._state:
                                logger.info(f'SmartPayout.run: try disable validator')
                                if self.sspDisableValidator() == SSPResponse.ok:
                                    self._state.add(SSPState.disabled)
                                    logger.info(f'SmartPayout.run: state: {self._state}')
                                    # send alarms
                                    self.AlarmCheck()

                        # check update payout
                        if self._device.is_change_payout:
                            self.UpdatePayoutStateInfo()
                        # check update cashbox
                        if self._device.is_change_cashbox:
                            self.UpdateCashboxStateInfo()

                        # check need move banknotes to cashbox
                        if self._device.is_need_smartfloat and \
                                self._payment.mode == PaymentMode.ready and \
                                (self._payment.last_banknote_time + timedelta(seconds=SSP_FLOAT_TIMEOUT)) < datetime.now():
                            self.SmartFloat()

                    # poll events in 200..1000 ms
                    if not self.poll_device():
                        self.close_device()
                        continue

            except Exception as se:
                logger.error(f'SmartPayout.run: Exception: {se}')

    def sspSetInhibits(self, mask_channels: int = 0xFFFF) -> SSPResponse:
        """
        This function sends the set inhibits command to set the inhibiting on the validator.
        The two bytes after the command byte represent two-bit registers with each bit being a channel.
        1-8 and 9-16 respectively.
        0xFF in binary indicating all channels in this register are able to accept notes.
        """
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
        logger.info(f'SmartPayout.sspSetInhibits')
        channels_low = mask_channels & 0xFF  # channels 1..8   (10, 50, 100, 200, 500, 1000, 2000, 5000)
        channels_high = (mask_channels >> 8) & 0xFF  # channels 9..16  ()
        return self.exec_command([BNVCmd.set_channel_inhibits, channels_low, channels_high])[0]

    def sspSync(self) -> SSPResponse:
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
        logger.info(f'SmartPayout.sspSync')
        self._seq = 0x80
        return self.exec_command([GenericCmd.sync])[0]

    def sspSetProtocolVersion(self, version: int = 8) -> SSPResponse:
        """
        This function sets the protocol version in the validator to the version passed across. Whoever calls
        this needs to check the response to make sure the version is supported.
        """
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
        logger.info(f'SmartPayout.sspSetProtocolVersion')
        return self.exec_command([GenericCmd.host_protocol, version])[0]

    def sspSetupRequest(self) -> SSPResponse:
        """
        This function uses the setup request command to get information about the validator.
        The response packet from the validator is a variable length depending on the number
        of channels in the dataset.
        """
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
        logger.info(f'SmartPayout.sspSetupRequest')
        res, data = self.exec_command([GenericCmd.setup_request])
        return res

    def sspEnablePayout(self) -> SSPResponse:
        """
        Enables the payout facility of the validator which lets it store and payout notes.
        """
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
        logger.info(f'SmartPayout.sspEnablePayout')
        res = self.exec_command([PayoutCmd.enable])[0]
        self._state.discard(SSPState.disabled)
        return res

    def sspDisablePayout(self) -> SSPResponse:
        """
        Stops the validator from being able to store or payout notes.
        """
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
        logger.info(f'SmartPayout.sspDisablePayout')
        return self.exec_command([PayoutCmd.disable])[0]

    def sspEnableValidator(self) -> SSPResponse:
        """
        The enable command allows the validator to act on commands sent to it.
        """
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
        logger.info(f'SmartPayout.sspEnableValidator')
        return self.exec_command([GenericCmd.enable])[0]

    def sspDisableValidator(self) -> SSPResponse:
        """
        Disable command stops the validator acting on commands sent to it.
        """
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
        logger.info(f'SmartPayout.sspDisableValidator')
        rc, _ = self.exec_command([GenericCmd.disable])
        time.sleep(0.5)
        return rc

    def sspResetValidator(self) -> SSPResponse:
        """
        The reset command instructs the validator to restart
        """
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
        logger.info(f'SmartPayout.sspResetValidator')
        return self.exec_command([GenericCmd.reset])[0]

    def sspGetMinimumPayout(self) -> (SSPResponse, int):
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
        res, data = self.exec_command([PayoutCmd.get_minimum_payout])
        logger.info(f'SmartPayout.sspGetMinimumPayout  data: {data}')
        if isinstance(data, bytes):
            amount = int.from_bytes(data, byteorder='little')
        else:
            amount = 0
        return res, amount

    def sspFloatAmount(self, payout_amount: int = 0) -> SSPResponse:
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
        logger.info(f'SmartPayout.sspFloatAmount')
        res, data = self.exec_command([PayoutCmd.float_amount,
                                       (0 * SSP_SCALE_FACTOR).to_bytes(4, 'little'),
                                       (payout_amount * SSP_SCALE_FACTOR).to_bytes(4, 'little'),
                                       SSP_DEFAULT_CURRENCY,
                                       SSP_FLOAT_AMOUNT])
        return res

    def sspFloatByDenomination(self, payout_amount: dict = None) -> SSPResponse:
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
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
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
        logger.info(f'SmartPayout.sspEmpty')
        return self.exec_command([PayoutCmd.empty])[0]

    def sspSmartEmpty(self) -> SSPResponse:
        """
        This uses the SMART EMPTY command to instruct the SMART Hopper to dump all stored coins into the cashbox.
        The SMART Hopper will keep track of what coins have been emptied,
        this data can be retrieved using the CASHBOX PAYOUT OPERATION DATA command.
        """
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
        logger.info(f'SmartPayout.sspSmartEmpty')
        return self.exec_command([PayoutCmd.smart_empty])[0]

    def sspSetGenerator(self, value: int) -> SSPResponse:
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
        logger.info(f'SmartPayout.sspSetGenerator')
        res = self.exec_command([EncryptedCmd.set_generator, value.to_bytes(8, 'little')])[0]
        return res

    def sspSetModulus(self, value: int) -> SSPResponse:
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
        logger.info(f'SmartPayout.sspSetModulus')
        res = self.exec_command([EncryptedCmd.set_modulus, value.to_bytes(8, 'little')])[0]
        return res

    def sspKeyExchange(self, value: int) -> (SSPResponse, int):
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
        logger.info(f'SmartPayout.sspKeyExchange')
        res, data = self.exec_command([EncryptedCmd.key_exchange, value.to_bytes(8, 'little')])
        key = None
        if isinstance(data, bytes):
            key = int.from_bytes(data, byteorder='little')
        return res, key

    def sspGetSerianNumber(self) -> (SSPResponse, int):
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
        logger.info(f'SmartPayout.sspGetSerialNumber')
        res, data = self.exec_command([GenericCmd.get_serial_number])
        sn = 0
        if isinstance(data, bytes):
            sn = int.from_bytes(data, byteorder='big')
        return res, sn

    def sspGetFirmwareVersion(self) -> (SSPResponse, str):
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
        logger.info(f'SmartPayout.sspGetFirmwareVersion')
        res, data = self.exec_command([GenericCmd.get_firmware_version])
        ver = ''
        if isinstance(data, bytes):
            ver = bytes(data).decode('utf-8')
        return res, ver

    def sspGetBuildRevision(self) -> (SSPResponse, str):
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
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
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
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
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
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
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
        # for i in range(3):
        self.wait_banknote_operation()
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

        #     if error_code != 0x03:
        #         return res
        #     time.sleep(1)
        # return SSPResponse.failure

    def sspPayoutByDenomination(self, banknotes: Dict[int, int]) -> SSPResponse:  # banknotes = {50: 1, 100: 1, ...}
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
        banknotes_count = len(banknotes)
        self.wait_banknote_operation()
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
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
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
        # logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
        # logger.info(f'SmartPayout.sspPoll')
        res, data = self.exec_command([GenericCmd.poll])
        return res, data

    def sspHold(self) -> SSPResponse:
        """
        This uses the SMART EMPTY command to instruct the SMART Hopper to dump all stored coins into the cashbox.
        The SMART Hopper will keep track of what coins have been emptied,
        this data can be retrieved using the CASHBOX PAYOUT OPERATION DATA command.
        """
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
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
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
        logger.info(f'SmartPayout.sspSetNoteRoute')
        res = self.exec_command(
            [PayoutCmd.set_route, route, (value * SSP_SCALE_FACTOR).to_bytes(4, 'little'), currency.upper()])[0]
        return res

    def SmartFloat(self) -> bool:
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
        is_need_float = False
        device_banknote_counter = 0
        float_banknotes = {}
        for channel in self._device.channels:
            channel_banknote_counter = channel.payout.count
            if channel_banknote_counter > 0:
                if channel.payout.keeping:
                    device_banknote_counter += channel_banknote_counter
                    # check exceed payout limits
                    if device_banknote_counter > SSP_LIMIT_PAYOUT_CAPACITY:
                        channel_banknote_counter -= device_banknote_counter - SSP_LIMIT_PAYOUT_CAPACITY
                        float_banknotes[channel.nominal] = channel_banknote_counter
                        is_need_float = True
                        break
                    float_banknotes[channel.nominal] = min(channel.payout.count, channel.payout.limit_max)
                    is_need_float = is_need_float or (channel.payout.count > channel.payout.limit_max)
                else:
                    is_need_float = True
        if is_need_float:
            logger.info(f'SmartFloat: banknotes: {float_banknotes}')
            res = (self.sspFloatByDenomination(float_banknotes) == SSPResponse.ok)
            self._device.is_need_smartfloat = not res
            return res
        else:
            logger.info(f'SmartFloat: nope')
        self._device.is_need_smartfloat = False
        return True

    def AlarmCheck(self) -> bool:

        # one time alarm for SSP_ALARM_TIMEOUT
        # if (self._device.alarm_last_time + timedelta(seconds=SSP_ALARM_TIMEOUT)) > datetime.now():
        #     return False

        is_exist_alarm = False
        payout_banknotes_count = self._device.get_payout_banknotes_count()
        cashbox_banknotes_count = self._device.get_cashbox_banknotes_count()

        if payout_banknotes_count >= SSP_MAX_PAYOUT_CAPACITY:
            # 246 (508) - хоппер полностью заполнен
            self._on_event_callback(event=PaymentCallbackEvents.PayoutFull)
            is_exist_alarm = True
        elif payout_banknotes_count >= SSP_LIMIT_PAYOUT_CAPACITY:
            # 246 (507) - хоппер почти заполнен
            self._on_event_callback(event=PaymentCallbackEvents.PayoutAlarm)
            is_exist_alarm = True

        if cashbox_banknotes_count >= SSP_MAX_CASHBOX_CAPACITY:
            # 144 - кассета заполнена
            self._on_event_callback(event=PaymentCallbackEvents.CashboxFull)
            is_exist_alarm = True
        elif cashbox_banknotes_count >= SSP_LIMIT_CASHBOX_CAPACITY:
            # 284 - кассета почти заполнена
            self._on_event_callback(event=PaymentCallbackEvents.CashboxAlarm)
            is_exist_alarm = True

        for channel in self._device.channels:
            if channel.enabled:
                #	287 - минимальные показания по купюре
                if channel.payout.keeping and channel.payout.count < channel.payout.limit_min:
                    self._on_event_callback(event=PaymentCallbackEvents.BanknoteLow, amount_note=channel.nominal)
                    is_exist_alarm = True
        if is_exist_alarm:
            self._device.alarm_last_time = datetime.now()
        return is_exist_alarm

    def ErrorCheck(self) -> bool:
        # check exceed payout limits
        if self._device.get_payout_banknotes_count() >= SSP_MAX_PAYOUT_CAPACITY:
            if self._payment.mode in {PaymentMode.payment,
                                      PaymentMode.request_payment,
                                      PaymentMode.filling
                                      }:
                self.CancelRequest()
                return True
        return False

    def CreateHostInterKey(self):
        # Creates a host intermediate key
        if not self._keys.Generator or not self._keys.Modulus:
            return False

        self._keys.HostRandom = randint(0, MAX_PRIME_NUMBER)

        self._keys.Generator = 139791917
        self._keys.Modulus = 769202429
        self._keys.HostRandom = 229216279

        self._keys.HostInter = xpow_ymod_n(self._keys.Generator, self._keys.HostRandom, self._keys.Modulus)
        return True

    def InitiateSSPHostKeys(self):
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
        self._encPktCount[self.address] = 0
        return True

    def CreateSSPHostEncryptionKey(self) -> bool:
        self._keys.KeyHost = xpow_ymod_n(self._keys.SlaveInterKey, self._keys.HostRandom, self._keys.Modulus)
        return True

    def NegotiateKeys(self) -> bool:
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

    def GetStoredNotes(self) -> bool:
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
        logger.info('Notes stored:\n')
        for _, amount in SSP_DEFAULT_CHANNEL_VALUES.items():
            if amount > 0:
                # Stored notes
                res, counter = self.sspGetNoteAmount(amount, SSP_DEFAULT_CURRENCY)
                if res == SSPResponse.ok:
                    logger.info(f'Note for {amount} is {counter}')
                else:
                    return False

        logger.info('\nCashbox payout data: \n')
        res, note_info = self.sspGetCashboxPayoutOpData()
        if res == SSPResponse.ok:
            for amount, notes_num in note_info.items():
                logger.info(f'Note for {amount} is {notes_num}')
        return True

    def GetPayoutAmount(self) -> int:
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
        logger.info(f'GetPayoutAmount: ')
        amount = 0
        for channel in self._device.channels:
            if all([channel.nominal, channel.payout.count]):
                amount += channel.nominal * channel.payout.count
        logger.info(f'GetPayoutAmount: amount: {amount}, {self._device.get_payout_info()}')
        return amount

    def GetPayoutMode(self) -> PaymentMode:
        return self._payment.mode

    def GetPayoutAmountLeft(self) -> int:
        amount_payout = self._payment.payment - self._payment.requested_payment - self._payment.payout
        return amount_payout

    def GetPaymentAmountLeft(self) -> int:
        amount_left = self._payment.requested_payment - (self._payment.payment + self._payment.payout)
        return amount_left

    def SetGlobalServiceMode(self, flag: bool):
        self._global_service_mode = flag

    def SetupRequest(self) -> bool:
        res = self.sspSetupRequest()
        if res != SSPResponse.ok:
           return False
        return True

    def UpdateCounterRequest(self):
        self._device.is_change_payout = True
        self._device.is_change_cashbox = True

    def SetNotesRoute(self) -> bool:
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
        for _, amount in SSP_DEFAULT_CHANNEL_VALUES.items():
            if amount > 0:
                res = self.sspSetNoteRoute(RouteModes.payouts, amount, SSP_DEFAULT_CURRENCY)
                if res != SSPResponse.ok:
                    logger.error(
                        f'SmartPayout.SetNotesRoute: Can''t set note route for {amount} {SSP_DEFAULT_CURRENCY} ...')
                    return False
        return True

    def EnablePayment(self) -> bool:
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
        # res = self.SetNotesRoute()
        res = self.sspEnablePayout() == SSPResponse.ok
        if res:
            logger.info(f'SmartPayout.EnablePayment')
        else:
            logger.error(f'SmartPayout.EnablePayment: Error')
        return res

    def DisablePayment(self) -> bool:
        logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
        # res = self.SetNotesRoute()
        res = self.sspDisablePayout() == SSPResponse.ok
        if res:
            logger.info(f'SmartPayout.DisablePayment')
        else:
            logger.error(f'SmartPayout.DisablePayment: Error')
        return res


def smartpayout_on_event(*, event, **kwargs):

    logger = logging.getLogger(APP_NAME + __name__ + '.' + inspect.stack()[0][3])
    logger.info(f'event: {PaymentCallbackEvents(event).name} params: {kwargs}')

    print_lines = kwargs.get('print_lines', '')
    if print_lines:
        print_lines = '\n'.join(print_lines)
        logger.error(f'print_lines: {print_lines}')

    if event == PaymentCallbackEvents.DeviceInService:
        print(f'Событие: устройство в работе')
    elif event == PaymentCallbackEvents.DeviceOutOfService:
        print(f'Событие: устройство не работает')
    elif event == PaymentCallbackEvents.EnterEmptyingMode:
        print(f'Событие: Вход устройства в режим сброса наличности в бокс')
    elif event == PaymentCallbackEvents.ExitEmptyingMode:
        print(f'Событие: Выход устройства из режима сброса наличности в бокс')
    elif event == PaymentCallbackEvents.PaymentStart:
        print(f'Событие: Начат процесс приема банкноты')
    elif event == PaymentCallbackEvents.PaymentNote:
        print(f'Событие: Принята банкнота [{kwargs["amount_note"]}]')
    elif event == PaymentCallbackEvents.PaymentComplete:
        print(f'Событие: Сумма принята полностью, сдача выдана (в случае необходимости) [{kwargs["amount_paid"]}]')
    elif event == PaymentCallbackEvents.PayoutNote:
        print(f'Событие: Выдана банкнота [{kwargs["amount_note"]}]')
    elif event == PaymentCallbackEvents.PayoutComplete:
        print(f'Событие: Вся запрошенная сумма выдана [{kwargs["amount_payout"]}]')
    elif event == PaymentCallbackEvents.CancelRequest:
        print(f'Событие: Запрошена отмена операции')
    elif event == PaymentCallbackEvents.CancelComplete:
        print(f'Событие: Операция отмены произведена успешна [{kwargs["amount_payout"]}]')
    elif event == PaymentCallbackEvents.EnterFillingMode:
        print(f'Событие: Вход устройства в режим внесения наличности')
    elif event == PaymentCallbackEvents.FillNote:
        print(f'Событие: Принята банкнота в режим внесения наличности [{kwargs["amount_note"]}]')
    elif event == PaymentCallbackEvents.ExitFillingMode:
        print(f'Событие: Выход устройства из режима внесения наличности')
    elif event == PaymentCallbackEvents.CashboxRemoved:
        print(f'Событие: Кассета извлечена')
    elif event == PaymentCallbackEvents.CashboxReplaced:
        print(f'Событие: Кассета вставлена')


        # Init = 0  # инициализация купюроприемник
        # PayoutError = 3  # ошибка выдачи сдачи
        # PayoutRequest = 4  # запрошена выдача сдачи
        # CancelError = 6  # ошибка отмены операции
        # EnterServiceMode = 16  # вход в сервисный режим (функциональная карта #1)
        # ExitServiceMode = 17  # выход из сервисного режима (функциональная карта #2)
        # UpdatePayoutInfo = 18  # обновление информации по заполнению хоппера
        # UpdateCashboxInfo = 19  # обновление информации по заполнению кассеты
        # WaitScreen = 20  # вывести экран ожидания завершения операции
        # CurrentScreen = 21  # вывести экран с текущим состоянием
        # PrintPayStationReport = 24  # печать отчета
        # BanknoteLow = 25  # минимальное показания по банкноте

        # PayoutAlarm = 26  # хоппер почти заполнен (более 90%)
        # PayoutFull = 27  # хоппер полностью заполнен
        # CashboxAlarm = 28  # кассета почти заполнена (более 90%)
        # CashboxFull = 29  # кассета полностью заполнена
        #
        # RestoreSessionData = 32  # восстановление состояния сессии после выключения питания
        # ResetSessionData = 33  # удаление данных предыдущей сессии
        # SaveSessionData = 34  # сохранение данных текущей сессии
    pass


def main():
    logging.basicConfig(level=logging.DEBUG)

    # create a recycler object
    payout = SmartPayout(serial_port=itl_dev_port, address=0, event_callback=smartpayout_on_event)
    payout.start()
    time.sleep(1)
    while True:
        try:
            print('commands:                                            functional cards:           tests:')
            print(' r - report              s - serial number            1 - Out of service          8 - test')
            print(' e - enable              f - firmware version         2 - In service              9 - smart float')
            print(' d - disable             a - amount request 100       5 - Fill hoppers            0 - report state')
            print(' p - pay 50              c - cancel request           6 - Empty hoppers')
            print(' b - build revision      x - exit')
            print('---------------------------------------------------------------------------------------------------')

            cmd = input('Press enter command: \n')
            if cmd == 'r':
                payout.GetStoredNotes()
            if cmd == 'e':
                payout.sspEnableValidator()
            if cmd == 'd':
                payout.sspDisableValidator()
            if cmd == 'p':
                # payout.sspPayout(400, SSP_DEFAULT_CURRENCY)
                payout.PayoutRequest(50)
            if cmd == 'x':
                break
            if cmd == 's':
                res, sn = payout.sspGetSerianNumber()
                print(f'Serial number: {sn}')
            if cmd == 'f':
                res, ver = payout.sspGetFirmwareVersion()
                print(f'Firmware version: {ver}')
            if cmd == 'b':
                res, dev_type, dev_ver, pay_ver = payout.sspGetBuildRevision()
                print(f'Build revision: device: {dev_type}, device version: {dev_ver}, payout version: {pay_ver}')

            if cmd == 'a':
                payout.PaymentRequest(100)
            if cmd == 'c':
                payout.CancelRequest()

            if cmd == '1':
                payout.EnterServiceMode()
            if cmd == '2':
                payout.ExitServiceMode()
            if cmd == '5':
                payout.FillHopper()
            if cmd == '6':
                payout.EmptyHopper()
            if cmd == '8':
                # test_payout_config = {100: 30, 500: 20}
                test_payout_config = [
                    {'Value': 50, 'ChannelId': 1, 'LimitMin': 6, 'LimitMax': 81, 'StorageKindId': 2},
                    {'Value': 100, 'ChannelId': 2, 'LimitMin': None, 'LimitMax': None, 'StorageKindId': 3}
                ]
                payout.SetPayoutConfig(test_payout_config)
                # res, amount = payout.sspGetMinimumPayout()
                # amount = payout.GetPayoutAmount()
                # payout.SetGlobalServiceMode(True)
                # payout.GetReportForm(ReportType.CashboxRemoved)

            if cmd == '9':
                # payout.sspFloatAmount(100)
                # payout.sspFloatByDenomination({50: 0, 100: 5})
                payout.SmartFloat()

            if cmd == '0':
                # payout.sspPayoutByDenomination({50: 1, 100: 1})
                # payout.sspFloatAmount(0)
                payout.PrintPayStationReport()
                # payout.sspPayout(150, 'RUB')

        except Exception as se:
            print(f'Error exception: {se}')

    payout.terminate()
    print('Exit program')


if __name__ == "__main__":
    main()
