// Child processes (planning 3.9): spawn(file, argv) only, never a shell; a fixed environment; a timeout; a cap on the output.  The tools we run
// (dnssec-keygen, dnssec-signzone, karidns-zone, karicheck, karictl) take every value as an argv word, so nothing here quotes or interprets anything.

import { spawn } from 'node:child_process';

export const ENV = Object.freeze({
  PATH: '/usr/bin:/bin:/usr/local/bin',
  LANG: 'C',
  LC_ALL: 'C',
  TZ: 'UTC',
});

// The environment of a child: the fixed one plus HOME (libpq reads ~/.pgpass, the tools their defaults).
export function childEnv(home = process.env.HOME) {
  return home ? { ...ENV, HOME: home } : { ...ENV };
}

// -> Promise<{ code, signal, stdout, stderr, truncated, timedOut, spawnError }>; never rejects.  The output is kept up to maxOutput octets per stream;
// a child that writes more is killed (truncated: true).  After timeoutMs the child gets SIGKILL (timedOut: true).
export function runChild(file, argv, { cwd, timeoutMs = 60000, maxOutput = 1 << 20, spawnFn = spawn, env = childEnv() } = {}) {
  return new Promise((resolve) => {
    const res = { code: null, signal: null, stdout: '', stderr: '', truncated: false, timedOut: false, spawnError: null };
    let child;
    try {
      child = spawnFn(file, argv, { cwd, env, shell: false, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    } catch (e) {
      res.spawnError = e.message;
      resolve(res);
      return;
    }
    const out = [[], []];
    const size = [0, 0];
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      res.stdout = Buffer.concat(out[0]).toString('utf8');
      res.stderr = Buffer.concat(out[1]).toString('utf8');
      resolve(res);
    };
    const timer = setTimeout(() => {
      res.timedOut = true;
      child.kill('SIGKILL');
    }, timeoutMs);
    timer.unref?.();
    const collect = (i) => (chunk) => {
      const room = maxOutput - size[i];
      if (room > 0) {
        const part = chunk.length > room ? chunk.subarray(0, room) : chunk;
        out[i].push(part);
        size[i] += part.length;
      }
      if (chunk.length > room && !res.truncated) {
        res.truncated = true;
        child.kill('SIGKILL');
      }
    };
    child.stdout.on('data', collect(0));
    child.stderr.on('data', collect(1));
    child.on('error', (e) => {
      res.spawnError = e.message;
      finish();
    });
    child.on('close', (code, signal) => {
      res.code = code;
      res.signal = signal;
      finish();
    });
  });
}

// a message of a tool's standard error for the log and the state table: control characters and anything past 1 KB removed (planning 3.9)
export function clip(text, max = 1024) {
  const s = String(text).replace(/[\0-\x08\x0b-\x1f\x7f]/g, '?').trim();
  return s.length > max ? `${s.slice(0, max)}...` : s;
}
