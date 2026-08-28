from enum import Enum


class Verdict(str, Enum):
    SAFE = "SAFE"
    UNKNOWN = "UNKNOWN"
    COUNTEREXAMPLE = "COUNTEREXAMPLE"
