// exec.ts is a capability lint fixture (task 4.1): every line here is a
// genuine match for the exec detection class table (spec 9).

import { spawn } from "child_process";

const execaModule = require("execa");
Bun.spawn(["ls", "-la"]);
