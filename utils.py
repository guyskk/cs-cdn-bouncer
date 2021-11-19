from functools import cache


@cache
def with_suffix(string: str, **kwargs):
    keys = sorted(list(kwargs.keys()))
    suffix = " ".join([f"{k}={kwargs[k]}" for k in keys])
    return f"{string} {suffix}"
