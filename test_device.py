import logging
from datetime import datetime
from platform import system
from typing import Union

from smdevice.cfg import SSP_DEFAULT_CURRENCY
from smdevice.device import Device
from smdevice.device_def import SSPResponse, PollEvents, SSPState
from smdevice.helpers import get_int_str, get_only_int_str

logging.basicConfig(level=logging.DEBUG)
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

def poll_device(self) -> bool:

    res, data = device.sspPoll()
    if res != SSPResponse.ok:
        return False

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
            amount, currency, num_bytes = get_int_str(data, idx + 1)
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
            amount, currency, num_bytes = get_int_str(data, idx + 1)
            idx += num_bytes + 1
            logger.info(f'Floating. {amount} {currency}')
            continue

        # floated = 0xD8
        # The device has completed its float command and the final value
        # floated to the cashbox is given in the event data.
        if event_code == PollEvents.floated:
            amount, currency, num_bytes = get_int_str(data, idx + 1)
            idx += num_bytes + 1
            logger.info(f'Floated. {amount} {currency}')
            self._device.is_change_payout = True
            self._device.is_change_cashbox = True
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
            amount, currency, num_bytes = get_only_int_str(data, idx + 1)
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
            amount, currency, num_bytes = get_int_str(data, idx + 1)
            idx += num_bytes + 1
            logger.info(f'Note paid into store at power-up. {amount} {currency}')
            continue

        # note_paid_stacker_powerup = 0xCA
        # Reported when a note has been detected as paid into the payout
        # store as part of the power-up procedure.
        if event_code == PollEvents.note_paid_stacker_powerup:
            amount, currency, num_bytes = get_int_str(data, idx + 1)
            idx += num_bytes + 1
            logger.info(f'Note paid into stacker at power-up. {amount} {currency}')
            continue

        # note_dispensed_powerup = 0xCD
        # Reported when a note has been dispensed as part of the power-up
        # procedure.
        if event_code == PollEvents.note_dispensed_powerup:
            amount, currency, num_bytes = get_int_str(data, idx + 1)
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

    return res


def sample():
    global device

    # Создание объекта устройства
    device = Device(port=itl_dev_port)

    # Подключение к устройству, установление шифрованного канала связи и инициализация
    device.connect()

    #

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

    # Сброс всех банкнот в кассету
    # device.sspEmpty()

    # Отключение устройства
    device.disconnect()

if __name__ == "__main__":
    # test_smpayout()
    sample()