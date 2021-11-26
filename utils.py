from functools import cache

SUPPORTED_ACTIONS = ["ban", "captcha"]
DELETE_LIST_FILE = "./clean_all.csv"

@cache
def with_suffix(string: str, **kwargs):
    keys = sorted(list(kwargs.keys()))
    suffix = " ".join([f"{k}={kwargs[k]}" for k in keys])
    return f"{string} {suffix}"