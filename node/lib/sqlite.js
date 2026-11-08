// node:sqlite prints an ExperimentalWarning when it is imported (Node 22 to 24); that is one line of noise in every log, not information.  Shared by
// karidns-signer and karidns-webadmin (A-20).

export async function loadSqlite(importer = () => import('node:sqlite')) {
  const emit = process.emitWarning;
  process.emitWarning = (w, ...rest) => {
    const type = typeof rest[0] === 'string' ? rest[0] : rest[0]?.type;
    if (type === 'ExperimentalWarning' && /SQLite/i.test(String(w))) return;
    return emit.call(process, w, ...rest);
  };
  try {
    return await importer();
  } catch (e) {
    throw new Error(`database = sqlite3 needs node:sqlite (Node 22.13 or newer): ${e.message}`);
  } finally {
    process.emitWarning = emit;
  }
}
