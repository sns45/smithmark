# env.py is a capability lint fixture (task 4.2, extended in task 4.3 for
# name aware env Symbol capture): every line here is a genuine match for the
# env detection class table (spec 9). The first three lines are name aware
# accesses; the fourth is a bare access the detector cannot resolve to a
# literal name. This header deliberately avoids spelling out the matched
# module dotted names themselves, since DetectPython does not parse
# comments out (the documented false positive posture), and doing so would
# self inflate the detection count below.

import os

api_key = os.environ["API_KEY"]
debug = os.getenv("DEBUG")
timeout = os.environ.get("TIMEOUT")
whole_env = os.environ
