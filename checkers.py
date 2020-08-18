import math
import re

HEX_PATTERN = re.compile("[A-Fa-f0-9]+")
BAD_SYMBOLS_LIST = re.compile(r"_\\/")


def shannon_entropy(data):
    slen = len(data)
    freqs = (float(data.count(c)) / slen for c in set(data))

    return -sum((prob * math.log(prob, 2.0) for prob in freqs))


def check_hex(domain, threshold):
    x = re.search(HEX_PATTERN, domain)
    if x is not None:
        if len(x[0]) >= threshold:
            return True
    return False


def check_bad_symbols(domain):
    x = re.search(BAD_SYMBOLS_LIST, domain)
    return bool(x)
