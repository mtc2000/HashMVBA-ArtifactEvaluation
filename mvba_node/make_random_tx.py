import string
import random


def random_tx_generator(size=250, chars=string.ascii_uppercase + string.digits):
    return '<DummyTX:' + ''.join(random.choice(chars) for _ in range(size - 10)) + '>'

def pseudo_random_tx_generator(size=250, seed=0, chars=string.ascii_uppercase + string.digits):
    random.seed(seed)
    return '<DummyTX:' + ''.join(random.choice(chars) for _ in range(size - 10)) + '>'
