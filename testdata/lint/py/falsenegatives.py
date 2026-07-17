# falsenegatives.py documents the capability lint's known, accepted limits
# (spec 1.3: lint is heuristic and advisory, not proof of absence). Two
# known false negatives live here: a dynamically imported module named by a
# variable is never followed, and a capability hidden behind eval is never
# scanned, because DetectPython matches literal text line by line and never
# evaluates or interprets the source it reads. One known false positive
# lives here too: a commented out import still matches the same line
# anchored pattern a live import would, because DetectPython does not parse
# comments out; that is an accepted, documented limitation, not a defect,
# the same posture DetectJS documents for a commented out require.

import importlib

CAPABILITY_MODULE = "subprocess"


def load_capability():
    return importlib.import_module(CAPABILITY_MODULE)


def load_hidden(encoded):
    return eval(encoded)


# import requests
