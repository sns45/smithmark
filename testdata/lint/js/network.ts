// network.ts is a capability lint fixture (task 4.1): every line here is a
// genuine match for the network detection class table (spec 9). Comment
// based and eval based limitations are exercised separately in
// falsenegatives.ts, not mixed in here, so this file's detection count stays
// exactly one per table entry.

import httpImport from "http";
import httpsImport from "https";
import netImport from "net";
import axios from "axios";
import { Agent } from "undici";

export async function fetchData() {
	const httpModule = require("http");
	const httpsModule = require("https");
	const netModule = require("net");
	return fetch("https://api.example.com");
}
