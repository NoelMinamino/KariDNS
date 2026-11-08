#!/usr/bin/env node
import { main } from '../lib/cli.js';

process.exit(await main(process.argv.slice(2)));
