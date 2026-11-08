// Logging: to standard error, or to syslog through logger(1) (one long-lived child, the facility from `log = ...`).  Node has no syslog binding and the
// project uses no package for it.  A line never holds control characters (a zone name or a tool's message cannot start a second line).  Key material is
// never passed here: callers log names, numbers and the clipped messages of the tools only.

import { spawn } from 'node:child_process';

const clean = (s) => String(s).replace(/[\0-\x1f\x7f]+/g, ' ');

export function createLogger({ target = 'stderr', name = 'karidns', stream = process.stderr, spawnFn = spawn, loggerPath = '/usr/bin/logger' } = {}) {
  let sink = null;                       // the stdin of logger(1)
  if (target !== 'stderr') {
    try {
      const child = spawnFn(loggerPath, ['-t', name, '-p', `${target}.notice`], { stdio: ['pipe', 'ignore', 'ignore'], shell: false });
      child.on('error', () => { sink = null; });
      child.stdin.on('error', () => { sink = null; });
      sink = child.stdin;
    } catch {
      sink = null;
    }
  }
  const write = (level, msg) => {
    const line = `${level}${level ? ': ' : ''}${clean(msg)}`;
    if (sink) sink.write(`${line}\n`);
    else stream.write(`${new Date().toISOString()} ${name}[${process.pid}]: ${line}\n`);
  };
  return {
    info: (msg) => write('', msg),
    warn: (msg) => write('warning', msg),
    error: (msg) => write('error', msg),
    close: () => { if (sink) { sink.end(); sink = null; } },
  };
}
