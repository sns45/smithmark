# filesystem.py is a capability lint fixture (task 4.2): every line here is
# a genuine match for the filesystem detection class table (spec 9).

import pathlib
from pathlib import Path
import shutil
from shutil import copyfile

with open("data.txt") as f:
    contents = f.read()
