from enum import IntEnum
from datetime import datetime, timedelta
from dataclasses import dataclass

from smdevice.cfg import (
    SSP_MAX_PAYOUT_CAPACITY,
    SSP_DEFAULT_CHANNEL_VALUES,
    SSP_DEFAULT_PAYOUT_LIMIT,
    SSP_DEFAULT_CURRENCY,
    SSP_ALARM_TIMEOUT
)
from smdevice.helpers import MyEnumMeta

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