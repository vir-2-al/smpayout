import inspect
import logging
import time
from platform import system

from setuptools.command.develop import develop

from smpayout.cfg import PAYOUT_MODULE_NAME, SSP_DEFAULT_CURRENCY
from smpayout.device_def import SSPResponse
from smpayout.smartpayout import SmartPayout
from smpayout.smartpayout_def import PaymentCallbackEvents
from smpayout.device import Device


current_platform = system()
if current_platform == 'Windows':
    itl_dev_port = 'COM3'
    itl_codec_id = 'cp1251'
elif current_platform == 'Linux':
    itl_dev_port = '/dev/ttyACM1'
    itl_codec_id = 'utf-8'
elif current_platform == 'Darwin':
    itl_dev_port = '/dev/tty.usbmodem14201'
    itl_codec_id = 'utf-8'
def smartpayout_on_event(*, event, **kwargs):

    logger = logging.getLogger(PAYOUT_MODULE_NAME + __name__ + '.' + inspect.stack()[0][3])
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


# def test_smpayout():
#     logging.basicConfig(level=logging.DEBUG)
#
#     # create a recycler object
#     payout = SmartPayout(port=itl_dev_port, address=0, event_callback=smartpayout_on_event)
#     payout.start()
#     time.sleep(1)
#     while True:
#         try:
#             print('commands:                                            functional cards:           tests:')
#             print(' r - report              s - serial number            1 - Out of service          8 - test')
#             print(' e - enable              f - firmware version         2 - In service              9 - smart float')
#             print(' d - disable             a - amount request 100       5 - Fill hoppers            0 - report state')
#             print(' p - pay 50              c - cancel request           6 - Empty hoppers')
#             print(' b - build revision      x - exit')
#             print('---------------------------------------------------------------------------------------------------')
#
#             cmd = input('Press enter command: \n')
#             if cmd == 'r':
#                 payout.GetStoredNotes()
#             if cmd == 'e':
#                 payout.sspEnableValidator()
#             if cmd == 'd':
#                 payout.sspDisableValidator()
#             if cmd == 'p':
#                 # payout.sspPayout(400, SSP_DEFAULT_CURRENCY)
#                 payout.PayoutRequest(50)
#             if cmd == 'x':
#                 break
#             if cmd == 's':
#                 res, sn = payout.sspGetSerianNumber()
#                 print(f'Serial number: {sn}')
#             if cmd == 'f':
#                 res, ver = payout.sspGetFirmwareVersion()
#                 print(f'Firmware version: {ver}')
#             if cmd == 'b':
#                 res, dev_type, dev_ver, pay_ver = payout.sspGetBuildRevision()
#                 print(f'Build revision: device: {dev_type}, device version: {dev_ver}, payout version: {pay_ver}')
#
#             if cmd == 'a':
#                 payout.PaymentRequest(100)
#             if cmd == 'c':
#                 payout.CancelRequest()
#
#             if cmd == '1':
#                 payout.EnterServiceMode()
#             if cmd == '2':
#                 payout.ExitServiceMode()
#             if cmd == '5':
#                 payout.FillHopper()
#             if cmd == '6':
#                 payout.EmptyHopper()
#             if cmd == '8':
#                 # test_payout_config = {100: 30, 500: 20}
#                 test_payout_config = [
#                     {'Value': 50, 'ChannelId': 1, 'LimitMin': 6, 'LimitMax': 81, 'StorageKindId': 2},
#                     {'Value': 100, 'ChannelId': 2, 'LimitMin': None, 'LimitMax': None, 'StorageKindId': 3}
#                 ]
#                 payout.SetPayoutConfig(test_payout_config)
#                 # res, amount = payout.sspGetMinimumPayout()
#                 # amount = payout.GetPayoutAmount()
#                 # payout.SetGlobalServiceMode(True)
#                 # payout.GetReportForm(ReportType.CashboxRemoved)
#
#             if cmd == '9':
#                 # payout.sspFloatAmount(100)
#                 # payout.sspFloatByDenomination({50: 0, 100: 5})
#                 payout.SmartFloat()
#
#             if cmd == '0':
#                 # payout.sspPayoutByDenomination({50: 1, 100: 1})
#                 # payout.sspFloatAmount(0)
#                 payout.PrintPayStationReport()
#                 # payout.sspPayout(150, 'RUB')
#
#         except Exception as se:
#             print(f'Error exception: {se}')
#
#     payout.terminate()
#     print('Exit program')

def test_device():
    # Создание объекта устройства
    device = Device(port=itl_dev_port)
    # Подключение к устройству, установление шифрованного канала связи и инициализация
    device.connect()
    # Выдача банкноты
    device.sspPayout(100, SSP_DEFAULT_CURRENCY)

    # Запрос количества 100 рублевых банкнот
    res, counter = device.sspGetNoteAmount(100, SSP_DEFAULT_CURRENCY)

    # Включение приема банкнот
    device.sspEnablePayout()
    device.sspEnableValidator()

    # Мониторинг состояния устройства
    # Переодически запрашиваем состояние устройства device.sspPoll()
    # см. smpayout/smartpayout.py -> poll_device

    # Выключение приема банкнот
    device.sspDisableValidator()
    device.sspDisablePayout()

    # Сброс банкнот в хоппере
    # device.sspEmpty()

    # Отключение устройства
    device.disconnect()

if __name__ == "__main__":
    # test_smpayout()
    test_device()