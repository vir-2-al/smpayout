from enum import IntEnum, EnumMeta
from random import randint
from datetime import datetime, timedelta
from dataclasses import dataclass
from platform import system

current_platform = system()
if current_platform == 'Windows':
    itl_dev_port = 'COM3'
    itl_codec_id = 'cp1251'
    itl_payment_state_file = r'payment_state.dat'
    itl_device_state_file = r'device_state.dat'
elif current_platform == 'Linux':
    itl_dev_port = '/dev/ttyACM1'
    itl_codec_id = 'utf-8'
    itl_payment_state_file = r'/mnt/status/payment_state.dat'
    itl_device_state_file = r'/mnt/status/device_state.dat'
elif current_platform == 'Darwin':
    itl_dev_port = '/dev/tty.usbmodem14201'
    itl_codec_id = 'utf-8'
    itl_payment_state_file = r'/tmp/status/payment_state.dat'
    itl_device_state_file = r'/tmp/status/device_state.dat'



# Transport Layer
# Data and commands are transported between the host and the slave(s) using a
# packet format as shown below.
#
# STX  | SEQ/SLAVE ID  |  LENGTH  |  DATA  |  CRCL  |  CRCH
#
# STX          - Single byte indicating the start of a message - 0x7F hex
# SEQ/Slave ID - Bit 7 is the sequence flag of the packet, bits 6-0 represent the address of the slave the
#                packet is intended for, the highest allowable slave ID is 0x7D
# LENGTH       - The length of the data included in the packet - this does not include STX, the CRC or the SLAVE ID
# Slave ID     - Single byte used to identify the address of the slave the packet is intended for
# DATA         - Commands and data to be transferred
# CRCL,        - Low and high byte of a forward CRC-16 algorithm using the Polynomial (X16 + X15 + X2
# CRCH         - +1) calculated on all bytes, except STX.
#                It is initialized using the seed 0xFFFF.
#                The CRC is calculated before byte stuffing.

# Max protocol version supported by SMART Payout (3/11/11).
SSP_MAX_PROTOCOL_VERSION = 8
SSP_STX = 0x7F
SSP_STEX = 0x7E
SSP_CRC_SEED = 0xFFFF
SSP_CRC_POLY = 0x8005
MAX_PRIME_NUMBER = 0x80000000
SSP_DEFAULT_KEY = 0x0123456701234567
# Каналы устройства и номиналы хранящихся банкнот {номер канала: номинал банкноты}
# SSP_DEFAULT_CHANNEL_VALUES = {0: 0, 1: 10, 2: 50, 3: 100, 4: 200, 5: 500, 6: 1000, 7: 2000, 8: 5000}
SSP_DEFAULT_CHANNEL_VALUES = {0: 0, 1: 10, 2: 50, 3: 100, 4: 500, 5: 1000, 6: 5000}
# Номиналы банкнот хранящихся в хоппере
SSP_DEFAULT_PAYOUT_LIMIT = (50, 100, 500, 1000)
# Максимальное количество банкнот в хоппере
SSP_MAX_PAYOUT_CAPACITY = 70
# Допустимое количество банкнот в хоппере
SSP_LIMIT_PAYOUT_CAPACITY = 60
# Максимальное количество банкнот в кассете
SSP_MAX_CASHBOX_CAPACITY = 500
# Допустимое количество банкнот в кассете
SSP_LIMIT_CASHBOX_CAPACITY = 450
# Интервал отправки Alarm (в секундах)
SSP_ALARM_TIMEOUT = 60

SSP_SCALE_FACTOR = 100
SSP_DEFAULT_CURRENCY = 'RUB'
SSP_TEST_FLOAT_AMOUNT = 0x19
SSP_FLOAT_AMOUNT = 0x58
# Таймаут времени через которое произойдет сброс наличности в кассету (в секундах)
SSP_FLOAT_TIMEOUT = 5
# Идентификатор источника в системе
SSP_DEVICE_SOURCE = 'nv200'


class MyEnumMeta(EnumMeta):
    def __contains__(cls, item):
        try:
            cls(item)
        except ValueError:
            return False
        else:
            return True


class PayoutNotInitializedError(Exception):
    def __init__(self):
        super().__init__('Payout is not initialized!')


class PayoutCommunicationError(Exception):
    def __init__(self):
        super().__init__('Communication to payout is broken!')


# Standard BNV SSP Commands
class GenericCmd(IntEnum):
    custom = 0x00
    reset = 0x01  # +
    setup_request = 0x05  # +
    host_protocol = 0x06
    poll = 0x07  # +
    disable = 0x09  # +
    enable = 0x0A  # +
    program = 0x0B
    get_serial_number = 0x0C  # +
    sync = 0x11  # +
    dispense = 0x12
    program_status = 0x16
    enable_higher_protocol = 0x19
    get_firmware_version = 0x20
    get_dataset_version = 0x21
    get_build_revision = 0x4F
    configure_bezel = 0x54
    poll_ack = 0x56  # +
    event_ack = 0x57  # +
    get_counters = 0x58  # +
    reset_counters = 0x59  # +


class BNVCmd(IntEnum):
    set_channel_inhibits = 0x02
    display_on = 0x03  # +
    display_off = 0x04  # +
    reject_note = 0x08  # +
    unit_data = 0x0D  # +
    channel_values = 0x0E  # +
    channel_security = 0x0F
    channel_reteach = 0x10
    last_reject = 0x17  # +
    hold = 0x18  # +


# PAYOUT and HOPPER COMMANDS
class PayoutCmd(IntEnum):
    host_serial = 0x14
    get_all_levels = 0x22  # +
    set_refill_mode = 0x30  # +
    payout_amount = 0x33  # +
    set_note_amount = 0x34
    get_note_amount = 0x35  # +
    halt_payout = 0x38  # +
    set_route = 0x3B  # +
    get_route = 0x3C  # +
    float_amount = 0x3D  # +
    get_minimum_payout = 0x3E  # +
    empty = 0x3F  # +
    set_coin_inhibit = 0x40
    float_by_denomination = 0x44  # +
    payout_by_denomination = 0x46  # +
    smart_empty = 0x52  # +
    cashbox_payout_op_data = 0x53  # +
    disable = 0x5B  # +
    enable = 0x5C  # +
    get_payout_capacity = 0x6F


class BarcodeCmd(IntEnum):
    get_config = 0x23  # +
    set_config = 0x24  # +
    get_inhibit_status = 0x25  # +
    set_inhibit_status = 0x26  # +
    get_data = 0x27  # +


class KeyCmd(IntEnum):
    set_fixed = 0x60
    reset_fixed = 0x61


class CommunicationCmd(IntEnum):
    set_baudrate = 0x4D


# Programming Type
class ProgrammingType(IntEnum):
    firmware = 0x00
    dataset = 0x01
    ram = 0x03


# channel definitions
class ChannelDef(IntEnum):
    one = 0x01
    two = 0x02
    three = 0x03
    four = 0x04
    five = 0x05
    six = 0x06
    seven = 0x07
    eight = 0x08
    nine = 0x09
    ten = 0x0A
    eleven = 0x0B
    twelve = 0x0C
    thirteen = 0x0D
    fourteen = 0x0E
    fifteen = 0x0F
    sixteen = 0x10


# encrypted
class EncryptedCmd(IntEnum):
    set_generator = 0x4A
    set_modulus = 0x4B
    key_exchange = 0x4C


# poll
class PollEvents(IntEnum, metaclass=MyEnumMeta):
    slave_reset = 0xF1  # +
    note_read = 0xEF  # +
    note_credit = 0xEE  # +
    note_rejecting = 0xED  # +
    note_rejected = 0xEC  # +
    note_stacking = 0xCC  # +
    note_stacked = 0xEB  # +
    note_safe_jam = 0xEA  # +
    note_unsafe_jam = 0xE9  # +
    disabled = 0xE8  # +
    fraud_attempt = 0xE6  # +
    stacker_full = 0xE7  # +
    note_cleared_from_front = 0xE1  # +
    note_cleared_to_cashbox = 0xE2  # +
    cashbox_removed = 0xE3  # +
    cashbox_replaced = 0xE4  # +
    barcode_validate = 0xE5
    barcode_ack = 0xD1
    note_path_open = 0xE0  # +
    channel_disable = 0xB5  # +
    initialising = 0xB6
    dispensing = 0xDA  # +
    dispensed = 0xD2  # +
    tickets_replaced = 0xA1
    tickets_low = 0xA0
    jammed = 0xD5  # +
    halted = 0xD6
    floating = 0xD7
    floated = 0xD8
    time_out = 0xD9
    incomplete_payout = 0xDC  # +
    incomplete_float = 0xDD
    cashbox_paid = 0xDE
    coin_credit = 0xDF
    coin_mech_jammed = 0xC4
    coin_mech_return_pressed = 0xC5
    emptying = 0xC2  # +
    emptied = 0xC3  # +
    smart_emptying = 0xB3  # +
    smart_emptied = 0xB4
    coin_mech_error = 0xB7
    note_stored_in_payout = 0xDB  # +
    payout_out_of_service = 0xC6
    jam_recovery = 0xB0
    error_during_payout = 0xB1
    note_transfered_stacker = 0xC9
    note_held_bezel = 0xCE  # +
    note_paid_store_powerup = 0xCB
    note_paid_stacker_powerup = 0xCA
    note_dispensed_powerup = 0xCD
    note_float_removed = 0xC7
    note_float_attached = 0xC8
    device_full = 0xC9
    printer_head_removed = 0xA2
    ticket_path_opened = 0xA3
    ticket_printer_jam = 0xA4
    printing_ticket = 0xA5
    printed_ticket = 0xA6
    print_ticket_fail = 0xA8
    printer_head_replaced = 0xA9
    ticket_path_closed = 0xAA
    no_ticket_paper = 0xAB
    coins_low = 0xD3
    empty = 0xD4  # +


SSPCmdNames = {
    0x01: 'RESET',
    0x02: 'SET INHIBITS',
    0x03: 'DISPLAY ON',
    0x04: 'DISPLAY OFF',
    0x05: 'SETUP REQUEST',
    0x06: 'HOST PROTOCOL VERSION',
    0x07: 'POLL',
    0x08: 'REJECT',
    0x09: 'DISABLE',
    0x0A: 'ENABLE',
    0x0B: 'PROGRAM FIRMWARE',
    0x0C: 'GET SERIAL NUMBER',
    0x0D: 'UNIT DATA',
    0x0E: 'CHANNEL VALUE DATA',
    0x0F: 'CHANNEL SECURITY DATA',
    0x10: 'CHANNEL RETEACH DATA',
    0x11: 'SYNC',
    0x12: 'UPDATE COIN ROUTE',
    0x13: 'DISPENSE',
    0x14: 'HOST SERIAL NUMBER REQUEST',
    0x15: 'SETUP REQUEST',
    0x17: 'LAST REJECT CODE',
    0x18: 'HOLD',
    0x19: 'ENABLE PROTOCOL VERSION EVENTS',
    0x23: 'GET BAR CODE READER CONFIGURATION',
    0x24: 'SET BAR CODE READER CONFIGURATION',
    0x25: 'GET BAR CODE INHIBIT',
    0x26: 'SET BAR CODE INHIBIT',
    0x27: 'GET BAR CODE DATA',
    0x30: 'SET REFILL MODE',
    0x33: 'PAYOUT AMOUNT',
    0x34: 'SET NOTE/COIN AMOUNT',
    0x35: 'GET NOTE/COIN AMOUNT',
    0x38: 'HALT PAYOUT',
    0x3B: 'SET ROUTING',
    0x3C: 'GET ROUTING',
    0x3D: 'FLOAT AMOUNT',
    0x3E: 'GET MINIMUM PAYOUT',
    0x3F: 'EMPTY ALL',
    0x40: 'SET COIN MECH INHIBITS',
    0x41: 'GET NOTE POSITIONS',
    0x42: 'PAYOUT NOTE',
    0x43: 'STACK NOTE',
    0x44: 'FLOAT BY DENOMINATION',
    0x45: 'SET VALUE REPORTING TYPE',
    0x46: 'PAYOUT BY DENOMINATION',
    0x47: 'SET COMMAND CALIBRATION',
    0x48: 'RUN COMMAND CALIBRATION',
    0x49: 'COIN MECH GLOBAL INHIBIT',
    0x4A: 'SET GENERATOR',
    0x4B: 'SET MODULUS',
    0x4C: 'REQUEST KEY EXCHANGE',
    0x50: 'SET OPTIONS',
    0x51: 'GET OPTIONS',
    0x52: 'SMART EMPTY',
    0x53: 'CASHBOX PAYOUT OPERATION DATA',
    0x54: 'CONFIGURE BEZEL',
    0x56: 'POLL WITH ACK',
    0x57: 'EVENT ACK',
    0x58: 'GET NOTE COUNTERS',
    0x59: 'RESET NOTE COUNTERS',
    0x5C: 'ENABLE PAYOUT DEVICE',
    0x5B: 'DISABLE PAYOUT DEVICE'
}


# generic SSP Responses
class SSPResponse(IntEnum, metaclass=MyEnumMeta):
    ok = 0xF0
    unknown_command = 0xF2          # ssp_response_cmd_unknown
    incorrect_parameters = 0xF3     # ssp_response_cmd_wrong_params
    invalid_parameter = 0xF4        # ssp_response_cmd_param_out_of_range
    command_not_processed = 0xF5    # ssp_response_cmd_cannot_process
    software_error = 0xF6           # ssp_response_cmd_software_error
    checksum_error = 0xF7
    failure = 0xF8                  # ssp_response_cmd_fail
    header_failure = 0xF9
    key_not_set = 0xFA              # ssp_response_cmd_key_not_set
    timeout = 0xFF

    # @classmethod
    # def __contains__(cls, item):
    #     return isinstance(item, cls) or item in [v.value for v in cls.__members__.values()]


# Code Reject Reason
SSPRejectReason = {
    0x00: 'Note accepted',
    0x01: 'Note length incorrect',
    0x02: 'Reject reason 2',
    0x03: 'Reject reason 3',
    0x04: 'Reject reason 4',
    0x05: 'Reject reason 5',
    0x06: 'Channel inhibited',
    0x07: 'Second note inserted',
    0x08: 'Reject reason 8',
    0x09: 'Note recognised in more than one channel',
    0x0A: 'Reject reason 10',
    0x0B: 'Note too long',
    0x0C: 'Reject reason 12',
    0x0D: 'Mechanism slow/stalled',
    0x0E: 'Strimming attempt detected',
    0x0F: 'Fraud channel reject',
    0x10: 'No notes inserted',
    0x11: 'Peak detect fail',
    0x12: 'Twisted note detected',
    0x13: 'Escrow time-out',
    0x14: 'Bar code scan fail',
    0x15: 'Rear sensor 2 fail',
    0x16: 'Slot fail 1',
    0x17: 'Slot fail 2',
    0x18: 'Lens over-sample',
    0x19: 'Width detect fail',
    0x1A: 'Short note detected'
}


class RouteModes(IntEnum):
    payouts = 0x00
    cashbox = 0x01


class PayoutError(IntEnum):
    disconnected = 0x01
    invalid_currency = 0x02
    device_error = 0x03


class SSPKeys:
    Generator: int = 0
    Modulus: int = 0
    HostInter: int = 0
    HostRandom: int = 0
    SlaveInterKey: int = 0
    SlaveRandom: int = 0
    KeyHost: int = 0
    KeySlave: int = 0
    FixedKey: int = 0
    EncryptKey: int = 0


class SSPState(IntEnum, metaclass=MyEnumMeta):
    disconnected = 0x01      # нет связи с устройством
    cashbox_removed = 0x02  # вытащен ящик с деньгами
    note_path_open = 0x03   # открыт отсек с приемом банкнот
    error_page = 0x04       # отображено сообщение об ошибке
    disabled = 0x05         # устройство заблокировано


class PaymentMode(IntEnum, metaclass=MyEnumMeta):
    error = 0x00            # не установлен режим / ошибка связи
    ready = 0x01            # ожидание команды
    request_payment = 0x02  # запрошен прием оплаты
    payment = 0x02          # в режиме приема оплаты
    request_payout = 0x03   # запрошена выдача наличности
    payout = 0x04           # в режиме выдачи сдачи
    request_cancel = 0x05   # запрошена отмена операции
    cancel = 0x06           # в режиме отмены операции приема/выдачи
    service = 0x07          # сервисный режим
    emptying = 0x08         # сброс наличности в бокс
    filling = 0x09          # внесение наличности


@dataclass
class PaymentState:
    mode: PaymentMode = PaymentMode.ready   # текущий режим работы
    requested_payment: int = 0              # запрошенная сумма на прием
    payment: int = 0                        # принятая сумма
    requested_payout: int = 0               # запрошенная сумма на выдачу
    payout: int = 0                         # выданная сумма
    last_banknote_amount: int = 0           # номинал последней банкноты
    last_banknote_time: datetime = 0        # время операции по последней банкноте
    last_note_dispensing: int = 0           # номинал выдаваемой банкноты
    last_note_in_bezel: int = 0             # номинал последней выдаваемой банкноты


class PaymentCallbackEvents(IntEnum, metaclass=MyEnumMeta):
    Init = 0                        # инициализация купюроприемник
    PaymentNote = 1                 # принята банкнота
    PaymentComplete = 2             # сумма принята полностью, сдача выдана (в случае необходимости)
    PayoutError = 3                 # ошибка выдачи сдачи
    PayoutRequest = 4               # запрошена выдача сдачи
    PayoutComplete = 5              # вся запрошенная сумма выдана
    CancelError = 6                 # ошибка отмены операции
    CancelRequest = 7               # запрос отмены операции
    CancelComplete = 8              # операция отмены произведена успешна
    DeviceInService = 9             # устройство в работе
    DeviceOutOfService = 10         # устройство не работает
    EnterFillingMode = 11           # вход устройства в режим внесения наличности (функциональная карта #5)
    FillNote = 12                   # принята банкнота в режим внесения наличности
    ExitFillingMode = 13            # выход устройства из режима внесения наличности
    EnterEmptyingMode = 14          # вход устройства в режим сброса наличности в бокс (функциональная карта #6)
    ExitEmptyingMode = 15           # выход устройства из режима сброса наличности в бокс
    EnterServiceMode = 16           # вход в сервисный режим (функциональная карта #1)
    ExitServiceMode = 17            # выход из сервисного режима (функциональная карта #2)
    UpdatePayoutInfo = 18           # обновление информации по заполнению хоппера
    UpdateCashboxInfo = 19          # обновление информации по заполнению кассеты
    WaitScreen = 20                 # вывести экран ожидания завершения операции
    CurrentScreen = 21              # вывести экран с текущим состоянием
    CashboxRemoved = 22             # кассета извлечена
    CashboxReplaced = 23            # кассета вставлена
    PrintPayStationReport = 24      # печать отчета
    BanknoteLow = 25                # минимальное показания по банкноте
    PayoutAlarm = 26                # хоппер почти заполнен (более 90%)
    PayoutFull = 27                 # хоппер полностью заполнен
    CashboxAlarm = 28               # кассета почти заполнена (более 90%)
    CashboxFull = 29                # кассета полностью заполнена
    PaymentStart = 30               # начат процесс приема банкноты
    PayoutNote = 31                 # выдана банкнота
    RestoreSessionData = 32         # восстановление состояния сессии после выключения питания
    ResetSessionData = 33           # удаление данных предыдущей сессии
    SaveSessionData = 34            # сохранение данных текущей сессии


class PageType(IntEnum, metaclass=MyEnumMeta):
    Filling = 1


class ReportType(IntEnum, metaclass=MyEnumMeta):
    PayoutInfoEnter = 1
    PayoutInfoExit = 2
    CashboxInfoEnter = 3
    CashboxInfoExit = 4
    CashboxRemoved = 5
    CashboxReplaced = 6
    PayStationReport = 7


ReportTypeTitle = {
    1: 'Наполнение - вход',
    2: 'Наполнение - выход',
    3: 'Сброс в кассету - вход',
    4: 'Сброс в кассету - выход',
    5: 'Кассета открыта',
    6: 'Кассета закрыта',
    7: 'Промежуточный отчет'}


class DisplayPageId(IntEnum, metaclass=MyEnumMeta):
    NoChange = 12               # Нет сдачи
    ChangeWait = 13             # Оплата Пожалуйста, заберите вашу сдачу.
    ChangeError = 14            # Оплата Извините, ошибка при выдаче сдачи.
    Filling = 17                # Заполнение накопителя монет
    FillingFinish = 20          # Заполнение накопителя монет. Процесс окончен!
    Emptying = 19               # Опустошение накопителя монет. Пожалуйста, подождите ...
    EmptyingFinish = 22         # Опустошение накопителя монет. Процесс окончен!
    ChangeTake = 54             # Спасибо! Ваша сдача: Пожалуйста, заберите вашу сдачу.
    NoteRejected = 71           # Банкнота не принимается!
    OutOfOrderInfo = 97         # Извините, процесс в настоящее время невозможен.
    OutOfOrder = 99             # Извините, процесс в настоящее время невозможен.
    PayCanceled = 141           # Выплата: Пожалуйста, заберите деньги!
    CashboxRemoved = 207        # Заполнение накопителя монет. Пожалуйста, вставьте загрузочную кассету!


class ChannelPayoutItem:
    """
    Номиналы купюр в хоппере
    """
    def __init__(self, channel_id: int):
        self.count = 0                                              # текущее количество
        self.limit_min = 0                                          # данные из WinOperate (SetPayoutConfig)
        self.limit_max = SSP_MAX_PAYOUT_CAPACITY                    # данные из WinOperate (SetPayoutConfig)
        nominal = SSP_DEFAULT_CHANNEL_VALUES.get(channel_id, 0)
        self.keeping = nominal in SSP_DEFAULT_PAYOUT_LIMIT          # хранение в хоппере


class ChannelCashboxItem:
    """
    Номиналы купюр в кассете
    """
    def __init__(self, channel_id: int):
        self.count = 0
        self.channel_id = channel_id


class SSPChannel:
    def __init__(self, channel_id: int):
        self.id: int = channel_id
        self.currency: str = SSP_DEFAULT_CURRENCY
        self.nominal: int = SSP_DEFAULT_CHANNEL_VALUES.get(channel_id, 0)
        self.enabled: bool = self.nominal > 0
        self.payout: ChannelPayoutItem = ChannelPayoutItem(channel_id)
        self.cashbox: ChannelCashboxItem = ChannelCashboxItem(channel_id)


class DeviceState:
    def __init__(self):
        self.channels = [SSPChannel(i) for i in range(len(SSP_DEFAULT_CHANNEL_VALUES))]
        self.is_change_payout = False
        self.is_change_cashbox = True
        self.is_need_smartfloat = False
        self.alarm_last_time = datetime.now() - timedelta(seconds=SSP_ALARM_TIMEOUT)

    def get_cashbox_info(self) -> dict:
        cashbox_info = {}
        for channel in self.channels:
            if channel.id:
                cashbox_info[channel.id] = channel.cashbox.count
        return cashbox_info

    def get_payout_info(self) -> dict:
        payout_info = {}
        for channel in self.channels:
            if channel.id:
                payout_info[channel.id] = channel.payout.count
        return payout_info

    def get_channels_mask(self) -> int:
        mask = 0x00
        for channel in self.channels:
            if channel.enabled and (channel.nominal > 0):
                mask |= (1 << (channel.id - 1))
        return mask

    def get_payout_mask(self) -> int:
        mask = 0x00
        for channel in self.channels:
            if channel.payout.keeping and (channel.nominal > 0):
                mask |= (1 << (channel.id - 1))
        return mask

    def get_payout_banknotes_count(self) -> int:
        counter = 0
        for channel in self.channels:
            counter += channel.payout.count
        return counter

    def get_cashbox_banknotes_count(self) -> int:
        counter = 0
        for channel in self.channels:
            counter += channel.cashbox.count
        return counter


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