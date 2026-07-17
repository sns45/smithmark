// filesystem.js is a capability lint fixture (task 4.1): every line here is
// a genuine match for the filesystem detection class table (spec 9).

import { readFile } from "fs";

const fsModule = require("fs");
const fsPromises = require("fs/promises");
