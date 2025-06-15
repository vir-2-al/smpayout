from enum import IntEnum

from smdevice.helpers import MyEnumMeta


# Standard BNV SSP Commands
class GenericCmd(IntEnum):
    custom = 0x00
    reset = 0x01
    setup_request = 0x05
    host_protocol = 0x06
    poll = 0x07
    disable = 0x09
    enable = 0x0A
    program = 0x0B
    get_serial_number = 0x0C
    sync = 0x11
    dispense = 0x12
    program_status = 0x16
    enable_higher_protocol = 0x19
    get_firmware_version = 0x20
    get_dataset_version = 0x21
    get_build_revision = 0x4F
    configure_bezel = 0x54
    poll_ack = 0x56
    event_ack = 0x57
    get_counters = 0x58
    reset_counters = 0x59


class BNVCmd(IntEnum):
    set_channel_inhibits = 0x02
    display_on = 0x03
    display_off = 0x04
    reject_note = 0x08
    unit_data = 0x0D
    channel_values = 0x0E
    channel_security = 0x0F
    channel_reteach = 0x10
    last_reject = 0x17
    hold = 0x18


# PAYOUT and HOPPER COMMANDS
class PayoutCmd(IntEnum):
    host_serial = 0x14
    get_all_levels = 0x22
    set_refill_mode = 0x30
    payout_amount = 0x33
    set_note_amount = 0x34
    get_note_amount = 0x35
    halt_payout = 0x38
    set_route = 0x3B
    get_route = 0x3C
    float_amount = 0x3D
    get_minimum_payout = 0x3E
    empty = 0x3F
    set_coin_inhibit = 0x40
    float_by_denomination = 0x44
    payout_by_denomination = 0x46
    smart_empty = 0x52
    cashbox_payout_op_data = 0x53
    disable = 0x5B
    enable = 0x5C
    get_payout_capacity = 0x6F


class BarcodeCmd(IntEnum):
    get_config = 0x23
    set_config = 0x24
    get_inhibit_status = 0x25
    set_inhibit_status = 0x26
    get_data = 0x27


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
class SSPEvents(IntEnum, metaclass=MyEnumMeta):
    slave_reset = 0xF1
    note_read = 0xEF
    note_credit = 0xEE
    note_rejecting = 0xED
    note_rejected = 0xEC
    note_stacking = 0xCC
    note_stacked = 0xEB
    note_safe_jam = 0xEA
    note_unsafe_jam = 0xE9
    disabled = 0xE8
    fraud_attempt = 0xE6
    stacker_full = 0xE7
    note_cleared_from_front = 0xE1
    note_cleared_to_cashbox = 0xE2
    cashbox_removed = 0xE3
    cashbox_replaced = 0xE4
    barcode_validate = 0xE5
    barcode_ack = 0xD1
    note_path_open = 0xE0
    channel_disable = 0xB5
    initialising = 0xB6
    dispensing = 0xDA
    dispensed = 0xD2
    tickets_replaced = 0xA1
    tickets_low = 0xA0
    jammed = 0xD5
    halted = 0xD6
    floating = 0xD7
    floated = 0xD8
    time_out = 0xD9
    incomplete_payout = 0xDC
    incomplete_float = 0xDD
    cashbox_paid = 0xDE
    coin_credit = 0xDF
    coin_mech_jammed = 0xC4
    coin_mech_return_pressed = 0xC5
    emptying = 0xC2
    emptied = 0xC3
    smart_emptying = 0xB3
    smart_emptied = 0xB4
    coin_mech_error = 0xB7
    note_stored_in_payout = 0xDB
    payout_out_of_service = 0xC6
    jam_recovery = 0xB0
    error_during_payout = 0xB1
    note_transfered_stacker = 0xC9
    note_held_bezel = 0xCE
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
    empty = 0xD4


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
    disconnected = 0x01     # нет связи с устройством
    cashbox_removed = 0x02  # вытащен ящик с деньгами
    note_path_open = 0x03   # открыт отсек с приемом банкнот
    error_page = 0x04       # отображено сообщение об ошибке
    disabled = 0x05         # устройство заблокировано


class DeviceCallbackEvents(IntEnum, metaclass=MyEnumMeta):
    CashboxRemoved = 1              # кассета извлечена
    CashboxReplaced = 2             # кассета вставлена
    ExitEmptyingMode = 3            # выход устройства из режима сброса наличности в бокс
    PayoutFull = 4                  # хоппер полностью заполнен
    PaymentNote = 5                 # принята банкнота  **kwarks: {"value": int = номинал банкноты}
    PayoutAmount = 6                # выдана сумма **kwarks: {"amount": int = сумма}
    PayoutError = 7                 # ошибка выдачи банкноты
    FloatedAmount = 8               # общая сумма перемещенных банкнот в кассету **kwarks: {"amount": int = сумма}
    TransferedNote = 9              # банкнота перемещена в кассету **kwarks: {"value": int = номинал банкноты}
    PowerReset = 10                 # устройство перезагружалось
    CashboxFull = 11                # кассета полностью заполнена
    PayoutNote = 12                 # выдана банкнота **kwarks: {"value": int = номинал банкноты}