// Errors of the API as RFC 9457 problem documents (planning 4.2).  A handler throws an ApiError; the server turns it into application/problem+json.
// Anything else that is thrown is a bug or a database failure: the body of a 500 carries the request id and nothing else.

const TITLES = {
  400: 'Bad request',
  401: 'Authentication required',
  403: 'Forbidden',
  404: 'Not found',
  405: 'Method not allowed',
  409: 'Conflict',
  413: 'Payload too large',
  415: 'Unsupported media type',
  422: 'Unprocessable content',
  429: 'Too many requests',
  500: 'Internal error',
  503: 'Service unavailable',
};

export class ApiError extends Error {
  // status: the HTTP status; code: the machine readable part of the type (urn:karidns:api:<code>); detail: for humans; errors: [{code, severity, text, pointer}];
  // headers: more response headers (Retry-After, Allow)
  constructor(status, code, detail, { errors, headers } = {}) {
    super(detail ?? code);
    this.status = status;
    this.code = code;
    this.detail = detail;
    this.errors = errors;
    this.headers = headers;
  }
}

export const badRequest = (detail, pointer) => new ApiError(400, 'bad-request', detail, pointer === undefined ? undefined : { errors: [{ code: 'bad-request', severity: 'error', text: detail, pointer }] });
export const forbidden = (detail, code = 'forbidden') => new ApiError(403, code, detail);
export const notFound = (detail = 'no such object') => new ApiError(404, 'not-found', detail);
export const conflict = (detail, code = 'conflict') => new ApiError(409, code, detail);

// the document: a 500 says nothing but the request id
export function problem(err, requestId) {
  const status = err instanceof ApiError ? err.status : 500;
  const doc = { api: 1, type: `urn:karidns:api:${err instanceof ApiError ? err.code : 'internal'}`, title: TITLES[status] ?? 'Error', status };
  if (err instanceof ApiError && status !== 500 && err.detail) doc.detail = err.detail;
  doc.request_id = requestId;
  if (err instanceof ApiError && err.errors?.length) doc.errors = err.errors;
  return doc;
}

// A database error -> an ApiError, or null when it is not one we understand (the caller then logs it and answers 500).  PostgreSQL by SQLSTATE, SQLite by
// the message.  A privilege error (42501) after the API itself allowed the request means row level security disagreed with the API: that is a bug, the
// caller logs it and answers 500 (planning 3.3 step 5), so it is not mapped here.
export function mapDbError(e) {
  const msg = String(e?.message ?? '');
  switch (e?.code) {
    case '23505': return conflict('an object with this name or key exists already', 'exists');
    case '23001': case '23503': return conflict('the object is still used by another object, or refers to one that does not exist', 'in-use');
    case '23514': return new ApiError(422, 'constraint', constraintText(e));
    case '40001': case '40P01': case '55P03': return new ApiError(503, 'busy', 'the database is busy, try again', { headers: { 'Retry-After': '2' } });
    case '57014': return new ApiError(503, 'busy', 'the database took too long, try again', { headers: { 'Retry-After': '5' } });
    default:
  }
  if (/database is locked|database table is locked|SQLITE_BUSY/i.test(msg)) return new ApiError(503, 'busy', 'the database is busy, try again', { headers: { 'Retry-After': '2' } });
  if (/timeout exceeded when trying to connect|Connection terminated|ECONNREFUSED|ENOTFOUND|ECONNRESET|the database system is (starting up|shutting down)/i.test(msg) || ['57P01', '57P02', '57P03', '08006', '08001', '53300'].includes(e?.code)) {
    return new ApiError(503, 'database-unavailable', 'the database cannot be reached, try again', { headers: { 'Retry-After': '5' } });
  }
  if (/UNIQUE constraint failed/i.test(msg)) return conflict('an object with this name or key exists already', 'exists');
  if (/FOREIGN KEY constraint failed/i.test(msg)) return conflict('the object is still used by another object, or refers to one that does not exist', 'in-use');
  if (/CHECK constraint failed/i.test(msg)) return new ApiError(422, 'constraint', constraintText(e));
  if (/karidns_auth\.[a-z_]+: /.test(msg)) return new ApiError(409, 'refused', constraintText(e));
  return null;
}

// the text of a constraint or trigger error without the table names of the schema's internals: our own triggers' messages (karidns_auth.<table>: ...) are meant to be read
function constraintText(e) {
  const m = /karidns_auth\.[a-z_]+: ([^\n]*)/.exec(String(e.message));
  if (m) return m[1].slice(0, 300);
  const c = /constraint "?([a-z_0-9]+)"?/i.exec(String(e.message));
  return c ? `the value violates the constraint ${c[1]}` : 'the value violates a constraint of the database';
}
