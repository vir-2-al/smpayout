# Наименование модуля
PAYOUT_MODULE_NAME = "SMPAYOUT"
# Max protocol version supported by SMART Payout (3/11/11).
SSP_MAX_PROTOCOL_VERSION = 8
SSP_STX = 0x7F
SSP_STEX = 0x7E
SSP_CRC_SEED = 0xFFFF
SSP_CRC_POLY = 0x8005
MAX_PRIME_NUMBER = 0x80000000
SSP_DEFAULT_KEY = 0x0123456701234567
# Каналы устройства и соответсвующие им номиналы банкнот {номер канала: номинал банкноты}
SSP_DEFAULT_CHANNEL_VALUES = {0: 0, 1: 10, 2: 50, 3: 100, 4: 200, 5: 500, 6: 1000, 7: 2000, 8: 5000}
# Разрешенные номиналы банкнот для приема
SSP_DEFAULT_ACCEPT_LIMIT = (50, 100, 500, 1000, 5000)
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
