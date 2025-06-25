import re
import time
import logging
from platform import system
from threading import Thread
from typing import Union, Optional

from smdevice.cfg import (SSP_DEFAULT_CURRENCY,
                          SSP_DEFAULT_ACCEPT_LIMIT)
from smdevice.device import Device
from smdevice.device_def import SSPResponse, DeviceCallbackEvents

logging.basicConfig(level=logging.CRITICAL)
logger = logging.getLogger()
is_app_exit = False

current_platform = system()
if current_platform == 'Windows':
    itl_codec_id = 'cp1251'
elif current_platform == 'Linux':
    itl_codec_id = 'utf-8'
elif current_platform == 'Darwin':
    itl_codec_id = 'utf-8'


def device_events_callback(event: DeviceCallbackEvents, *args, **kwargs):
    print(f'Событие: {event.name}, параметры: {args}   {kwargs}')
    if kwargs.get('value', None):
        print(f'Номинал банкноты: {kwargs["value"]} {SSP_DEFAULT_CURRENCY}')
    if kwargs.get('amount', None):
        print(f'Сумма: {kwargs["amount"]} {SSP_DEFAULT_CURRENCY}')


def get_number(string_number: str) -> Optional[int]:
    m = re.search(r'\d+$', string_number)
    return int(m.group(0).strip()) if m else None


def worker(dev: Device):
    global is_app_exit
    while not is_app_exit:
        try:
            if not dev.connected():
                # Подключение к устройству, установление шифрованного канала связи и инициализация
                dev.connect()

            else:
                # Проверка состояния устройства и получение событий
                dev.poll()

            time.sleep(0.100)
        except Exception as e:
            logger.error(f'Произошла ошибка: {e}')
            if dev:
                dev.disconnect()
    # Отключение устройства
    dev.disconnect()


def run():
    itl_dev_port = input("Порт: ")
    print(f'Используемый порт: {itl_dev_port}')
    # Создание объекта устройства
    device = Device(event_callback=device_events_callback, port=itl_dev_port)
    global is_app_exit

    thread = Thread(target=worker, args=(device,))
    thread.start()
    while not is_app_exit:
        try:
            print(f'Введите:')
            print(f'"E" для включение приема банкнот')
            print(f'"D" для выключения приема банкнот')
            print(f'"P" для выдачи суммы')
            print(f'"Z" для сброса банкнот свыше установленного количества')
            print(f'"R" для отчета о состоянии устройства')
            print(f'"X" для сброса всех банкнот в кассету')
            print()
            print(f'Введите "~" для выхода из программы')
            print()

            user_command = input("Введите команду: ").strip().upper()

            is_app_exit = user_command == '~'
            if is_app_exit:
                print('Выход из программы...')
                break
            elif user_command == 'E':
                # Включение приема банкнот
                print('Включение приема банкнот')
                device.sspEnableValidator()
            elif user_command == 'D':
                # Выключение приема банкнот
                print('Выключение приема банкнот')
                device.sspDisableValidator()
            elif user_command == 'P':
                # Выдача суммы
                amount = get_number(input('Введите сумму для выдачи: '))
                print(f'Выдача суммы: {amount}')
                device.sspPayout(amount, SSP_DEFAULT_CURRENCY)
            elif user_command == 'Z':
                # Сброс банкноты
                amount = get_number(input('Введите номинал банкноты: '))
                count = get_number(input('Введите количество банкнот для сдачи: '))
                device.sspFloatByDenomination({amount: count})
            elif user_command == 'R':
                # Отчет о состоянии устройства
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
            elif user_command == 'X':
                # Сброс всех банкнот в нижнюю кассету
                device.sspEmpty()

        except Exception as e:
            logger.error(f'Произошла ошибка: {e}')

    thread.join()


if __name__ == "__main__":
    # test_smpayout()
    run()
