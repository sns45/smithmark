#!/usr/bin/env bun
/**
 * dear-claude
 * MCP server that triggers local Claude Code instances from external platforms
 */

import { createCLI } from "./cli.js";

const cli = createCLI();
cli.parse(process.argv);
