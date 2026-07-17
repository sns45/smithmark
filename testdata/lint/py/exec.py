# exec.py is a capability lint fixture (task 4.2): every line here is a
# genuine match for the exec detection class table (spec 9).

import os
import subprocess
from subprocess import run

os.system("ls -la")
os.execvpe("ls", ["ls", "-la"], custom_env)
os.popen("ls -la")
