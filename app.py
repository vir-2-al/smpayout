import logging
import time
import keyboard
import re
from platform import system
from typing import Union, Optional

from smdevice.cfg import (SSP_DEFAULT_CURRENCY,
                          SSP_DEFAULT_ACCEPT_LIMIT)
from smdevice.device import Device
from smdevice.device_def import SSPResponse, DeviceCallbackEvents

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()

itl_dev_port = None
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

device : Union[Device, None] = None

def device_events_callback(event: DeviceCallbackEvents, *args, **kwargs):
    print(f'Событие: {event.name}, параметры: {args}   {kwargs}')
    if kwargs.get('value', None):
        print(f'Номинал банкноты: {kwargs["value"]} {SSP_DEFAULT_CURRENCY}')
    if kwargs.get('amount', None):
        print(f'Сумма: {kwargs["amount"]} {SSP_DEFAULT_CURRENCY}')


def get_number(string_number: str) -> Optional[int]:
    m = re.search(r'\d+$', string_number)
    return int(m.group(0).strip()) if m else None

def sample():
    global device

    # Создание объекта устройства
    device = Device(event_callback=device_events_callback,  port=itl_dev_port)
    print(f'Используемый порт: {itl_dev_port}')
    print(f'Нажмите "E" для включение приема банкнот')
    print(f'Нажмите "D" для выключения приема банкнот')
    print(f'Нажмите "P" для выдачи суммы')
    print(f'Нажмите "Z" для сброса банкнот свыше установленного количества')
    print(f'Нажмите "R" для отчета о состоянии устройства')
    print(f'Нажмите "X" для сброса всех банкнот в кассету')
    print()
    print(f'Нажмите "Esc" для выхода из программы')

    while not keyboard.is_pressed('esc'):
        try:
            if not device.connected():
                # Подключение к устройству, установление шифрованного канала связи и инициализация
                device.connect()
            else:
                # Включение приема банкнот
                if keyboard.is_pressed('E'):
                    print('Включение приема банкнот')
                    device.sspEnableValidator()

                # Выключение приема банкнот
                if keyboard.is_pressed('D'):
                    print('Выключение приема банкнот')
                    device.sspDisableValidator()

                # Выдача суммы
                if keyboard.is_pressed('P'):
                    amount = get_number(input('Введите сумму для выдачи: '))
                    print(f'Выдача суммы: {amount}')
                    device.sspPayout(amount, SSP_DEFAULT_CURRENCY)

                # Сброс банкноты
                if keyboard.is_pressed('Z'):
                    keyboard.clear_all_hotkeys()
                    amount = get_number(input('Введите номинал банкноты: '))
                    count = get_number(input('Введите количество банкнот для сдачи: '))
                    device.sspFloatByDenomination({amount: count})

                # Отчет о состоянии устройства
                if keyboard.is_pressed('R'):
                    for banknote_nominal in SSP_DEFAULT_ACCEPT_LIMIT:
                        # Запрос количества банкнот для сдачи
                        res, counter = device.sspGetNoteAmount(banknote_nominal, SSP_DEFAULT_CURRENCY)
                        if res == SSPResponse.ok:
                           print(f'Количество банкнот {banknote_nominal} {SSP_DEFAULT_CURRENCY}: {counter}')
                    # Запрос информации о последней операции перемещения банкнот в кассету
                    res, note_info = device.sspGetCashboxPayoutOpData()
                    if res == SSPResponse.ok:
                        for banknote_nominal, banknote_count in note_info.items():
                            print(f'Количество банкнот {banknote_nominal} {SSP_DEFAULT_CURRENCY}: {banknote_count}')

                # Сброс всех банкнот в нижнюю кассету
                if keyboard.is_pressed('X'):
                    device.sspEmpty()

                # Проверка состояния устройства и получение событий
                device.poll()

            time.sleep(0.100)
        except Exception as e:
            logger.error(f'Произошла ошибка: {e}')
            if device:
                device.disconnect()

    # Отключение устройства
    device.disconnect()


if __name__ == "__main__":
    # test_smpayout()
    sample()