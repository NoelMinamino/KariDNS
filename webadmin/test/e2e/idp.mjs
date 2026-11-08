// A fake OpenID Connect provider as a program, for the integration and browser tests (tests/run_webadmin_oidc_test.sh): it listens on 127.0.0.1 and writes
// "issuer <url>" when it is ready.  The tests change who it signs in and how it spoils tokens with POST <issuer>/__control {"sub": ..., "amr": [...], "tamper": ...}.
//
//   IDP_PORT=9200 IDP_ISSUER_HOST=localhost IDP_REDIRECTS=http://127.0.0.1:8053/api/v1/auth/oidc/idp/callback IDP_CLIENT_ID=... IDP_CLIENT_SECRET=... node idp.mjs
//
// It stops on SIGTERM or SIGINT.
import { FakeIdp } from '../fakeidp.js';

const idp = new FakeIdp({ clientId: process.env.IDP_CLIENT_ID, clientSecret: process.env.IDP_CLIENT_SECRET, issuerHost: process.env.IDP_ISSUER_HOST ?? '127.0.0.1' });
idp.controllable = true;
await idp.start(Number(process.env.IDP_PORT ?? 0));
for (const r of (process.env.IDP_REDIRECTS ?? '').split(',').filter(Boolean)) idp.redirectUris.add(r);
console.log(`issuer ${idp.issuer}`);
const stop = async () => { await idp.stop(); process.exit(0); };
process.on('SIGTERM', stop);
process.on('SIGINT', stop);
