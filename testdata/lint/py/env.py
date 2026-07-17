# env.py is a capability lint fixture (task 4.2): every line here is a
# genuine match for the env detection class table (spec 9).

import os

api_key = os.environ["API_KEY"]
debug = os.getenv("DEBUG")
