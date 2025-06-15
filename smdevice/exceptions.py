class PayoutNotInitializedError(Exception):
    def __init__(self):
        super().__init__('Payout is not initialized!')


class PayoutCommunicationError(Exception):
    def __init__(self):
        super().__init__('Communication to payout is broken!')