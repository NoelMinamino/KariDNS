#ifndef DNS_DB_STREAM_H
#define DNS_DB_STREAM_H

/*
 * dns_db_stream.h - KDB1: the byte stream between karidns-dbloader and the Backend (design: beta design 1.4).
 *
 * Pure functions, no I/O (but the hot list's state file, kdb_hotl_file_*, which only the loader calls).  Shared by the loader (encoder, decoder of Backend messages) and the Backend
 * (decoder of loader messages + state machine).  The Backend treats every byte as hostile.
 *
 *   encoder  kdb_enc_*       growable buffer (malloc), TLV appenders.                     (encoder side only)
 *   framer   kdb_framer_*    incremental: kdb_framer_feed(bytes) then kdb_framer_next() until KDB_MORE.
 *                            Validates the 12-byte header before the body is buffered.  No allocation: the
 *                            caller supplies the body buffer (KDB_MAX_BODY bytes for the full range).
 *   decoder  kdb_decode      one frame -> typed kdb_msg_t (required tags present, each tag once, unknown tag =
 *                            error, exact integer lengths, ASCII strings, canonical absolute DNS names, view
 *                            index < view count).  No allocation.
 *   machine  kdb_sm_accept   Backend side: AWAIT_HELLO -> READY <-> IN_BATCH <-> IN_ZONE, the zone image rules
 *                            (the announced size, the sum of the ZONE_IMAGE messages, the header of the image) and
 *                            the byte / record limit checks.  It does not read the image (zone_image_validate_ex()).
 *
 * Wire format: 12-byte header {"KDB1", u16 type, u16 flags (=0), u32 body length}, big-endian.  Body of every
 * message except ZONE_IMAGE: TLV list {u16 tag, u16 len, value}.  ZONE_IMAGE body: octets of a zone image.
 * (0.7 M3: type 5, ZONE_DATA, the zone as the RRs of an AXFR in DNS messages, is gone: the data of a database zone is a zone image, and a
 * loader that does not send images is not taken.  Type 5 is unknown now.)
 * A TLV length is a u16, so no single value (settings text, nested entry) exceeds 65,535 bytes.
 *
 * Lifetime: kdb_str_t, kdb_frame_t.body and the iterators point into the framer's buffer.  They are valid until
 * the next kdb_framer_next() call; copy what must be kept.  Names are copied into NUL-terminated arrays.
 *
 * Any KDB_E_* result on the Backend is a protocol error: the caller logs reason once and closes the stream.
 * Reasons never contain bytes taken from the stream (no log injection).
 *
 * ---------------------------------------------------------------------------------------------------------
 * Tag tables.  Tags are numbered 1..n per message type (and per nested entry).  R = required, O = optional.
 *   u8/u16/u32/u64/i64: exact length 1/2/4/8, big-endian (i64 two's complement)
 *   str   : printable ASCII 0x20-0x7E, no NUL, length <= max (ne = at least 1 byte)
 *   path  : file path or schema name: valid UTF-8 (RFC 3629, shortest form, no surrogates, <= U+10FFFF) without
 *           control characters (C0, DEL, C1); bytes kept as they are ('%XX' is not decoded); length <= max
 *   text  : like str plus TAB (0x09) and LF (0x0A)
 *   bytes : opaque, length rule given
 *   name  : canonical absolute presentation text as dns_wire.h produces (dns_name_normalize() returns it
 *           unchanged, ends with an unescaped '.'), <= 1024 bytes
 *   view  : u16 index, must be < the number of configured views (when the decoder is told it)
 *   Duplicate, unknown or truncated tags, a wrong length, a missing R tag: protocol error.
 *
 * loader -> Backend
 *   HELLO (1)         1 proto_version u16 R (=1) | 2 loader_version str<=64 R | 3 driver str<=32 R | 4 pid u32 R |
 *                     5 features u32 O (0.7 WP7a: bit0 KDB_FEAT_STORE: the loader speaks the store protocol below; bit1 KDB_FEAT_LOOKUP: it answers FETCH_REQ mode 2; bit2 KDB_FEAT_LOOKUP_BODY: it answers mode 3; absent = 0;
 *                     0.7 M3, bit3 KDB_FEAT_IMAGE: it sends the data of a zone as a zone image (ZONE_BEGIN with the image flag and ZONE_IMAGE messages); needs tag 6) |
 *                     6 image_version u32 O (0.7 M3: the version of the zone image format the loader builds, ZONE_IMAGE_VERSION of dns_zone_image.h; present exactly when
 *                     features has bit3).  The Backend takes only a loader that has bit 3 and its own image version (KDB_E_VERSION, a protocol error with a reason that says so):
 *                     the loader and the Backend are one package, and there is no other way to send a zone.
 *   INVENTORY_REQ (2) no tags (empty body)
 *   BATCH_BEGIN (3)   1 batch_id u64 R | 2 kind u8 R (0 startup,1 full,2 diff,3 zone,4 auto) | 3 change_seq u64 R |
 *                     4 request_id u64 O (B6a: the batch answers that RELOAD_REQ; absent or 0 = not an answer)
 *   ZONE_BEGIN (4)    1 view view R | 2 zone name R | 3 source_id i64 R | 4 zone_kind u8 R (0 primary,1 secondary,
 *                     2 catalog) | 5 serial u32 R | 6 flags u32 R (bit0 presigned, bit1 extended, bit2 tinydns, bit3 summary, bit4 image; others 0) |
 *                     7 rr_count u64 R (primary: the RRs of the zone image, >= 1; secondary and catalog: 0, no data, B7b) | 8 digest bytes R (exactly 32) |
 *                     9 settings text<=65535 O | 10 profile str ne <=255 O |
 *                     D1a (fetch stream only): 11 request_id u64 O (the FETCH_REQ this zone answers; required on the fetch stream, forbidden
 *                     on the batch stream).  flags bit3 = summary: the zone's serial, kind and settings without its data (primary: rr_count 0, no
 *                     no zone image, digest all zero); on the fetch stream, and (milestone 4) in a batch when CONFIG said dir_only.  12 soa_refresh u32 | 13 soa_retry u32 | 14 soa_expire u32 (all
 *                     three or none: the timers of the zone's SOA, which the zone directory keeps without the zone).
 *                     D1a step 6, a summary only, tags 12..14 required, all of 15..20 or none: the apex of the zone, for the answer to an SOA question when the
 *                     zone is not in memory.  15 soa_mname name | 16 soa_rname name | 17 soa_minimum u32 | 18 soa_ttl u32 | 19 ns_ttl u32 (the three
 *                     TTLs <= 2147483647, RFC 2181 8) | 20 ns_names bytes<=2047: 1..8 canonical absolute names of the apex NS RRset, separated by one LF.
 *                     21 glue bytes<=2048 O (with 15..20): the addresses of the NS targets that are inside the zone, which the answer carries in Additional
 *                     (RFC 2181 9).  Records of  index u8 (the position of the name in tag 20) | type u8 (1 A, 28 AAAA) | ttl u32 (<= 2147483647) |
 *                     address (4 or 16 octets, RFC 1035 3.4.1, RFC 3596 2.2); the indexes do not decrease, at most 8 records for one index.
 *                     22 naddrs bytes<=1152 O (with 15..20): the addresses of the NS targets that are NOT inside the zone, which the loader found in the database
 *                     by name (the A and AAAA records of that name in any zone of the same source), for the NOTIFY the Backend sends (RFC 1996 3.2) when
 *                     the zone changes while its data is out of memory.  Records of  index u8 (the position of the name in tag 20) | type u8 (1 A, 28 AAAA) |
 *                     address (4 or 16 octets); the indexes do not decrease, at most 8 records for one index.  The Backend keeps them with the apex block.
 *                     0.7 M3 (a zone image): flags bit4 = image (KDB_ZF_IMAGE): the zone's data is the zone image of dns_zone_image.h, built by the loader, sent as ZONE_IMAGE
 *                     messages.  A primary zone has no other way to carry its data, so the flag is required (a summary and a secondary have no data).  23 image_size u64: the size of the image in octets (tag 23 is there exactly when the flag is; a primary, not a summary; a
 *                     multiple of 8, the size of the header of the image at least, at most 0xFFFFF000, and at most max-zone-bytes, which for a zone image is the
 *                     size of the image).  rr_count is then the number of RRs of the image (n_rrs, >= 1, not the RRs of an AXFR: no second SOA, no Extended AXFR marker or
 *                     definition RRs; the tag and location definitions are in the image) and at most max-zone-records.  The digest is SHA-256 of the image bytes
 *                     followed by the markers of the settings text, the profile and a PRESIGNED zone (dns_pdns_reader.c); the image of one zone is always the same
 *                     bytes (zone_image_freeze() is deterministic), so the same rows give the same digest.
 *   ZONE_IMAGE (20)   0.7 M3: raw, no TLV: the next octets of the image (1 to KDB_MAX_BODY, 1 MiB), in the order of the image.  Only between a ZONE_BEGIN with the image flag
 *                     and its ZONE_END.  The sum of the messages is image_size
 *                     exactly: one more octet than announced is a protocol error as is a ZONE_END before the image is complete.  The first message holds at least the header of the image
 *                     (the zone_image_t struct, in the byte order of the machine: the loader and the Backend run on one host) and its magic, version, total_size (= image_size) and n_rrs
 *                     (= rr_count) are checked at once, before the rest is buffered.  The size is only a cap: a Backend allocates for the octets that came, never for the announced
 *                     size.  What is inside is the business of zone_image_validate_ex() (dns_zone_image.h), run by the Backend on the whole image.
 *   ZONE_END (6)      1 rr_count u64 R
 *   ZONE_ABORT (7)    1 reason str<=255 R
 *   ZONE_FAILED (8)   1 view view R | 2 zone name R | 3 source_id i64 R | 4 reason str<=255 R | 5 request_id u64 O (D1a: fetch stream only, required there)
 *   ZONE_DELETE (9)   1 view view R | 2 zone name R | 3 source_id i64 R
 *   PROFILE (10)      1 name str ne <=255 R | 2 settings text<=65535 R
 *   BATCH_END (11)    1 batch_id u64 R | 2 n_zones u32 R | 3 n_failed u32 R | 4 n_deleted u32 R
 *   AUTO_STATUS (12)  B9; only between batches (state READY), no state change.  1 ENTRY nested, repeatable (<= 1024), one per view
 *                     that has auto reload on: 1 view view R | 2 last_poll u64 R (unix seconds, 0 = never) |
 *                     3 applied_seq u64 R (change log position of the last complete load) | 4 pending u32 R (changes seen, not yet
 *                     applied) | 5 error str<=255 O (the last poll / load error of the view, absent = none) |
 *                     B11 (multi-server reload requests, PostgreSQL), all optional: 6 flags u8 (bit0 the auto reload fields 2..5 are
 *                     real, bit1 the request fields 7..11 are real; absent = 1) | 7 server_id str ne <=64 (the id the loader reports
 *                     under) | 8 req_generation u64 (the last reload request applied; 0 = none) | 9 req_ok u8 (0/1: every zone of
 *                     that reload loaded) | 10 req_error str<=255 (why the last read of the requests or write of the status
 *                     row failed, absent = none) | 11 req_time u64 (unix seconds of the last status row written, 0 = never).
 *                     Item C (the signer), optional: 12 sig_wait u32 (the zones with the metadata X-KARIDNS-SIGNER=1 that changed and are not reloaded until the
 *                     signer asks) | 13 sig_names str<=255 (the first few of their names, "a, b, c, and N more").
 *                     An entry is sent for a view that has auto reload on or whose source has the multi-server tables.
 *   WARM_LIST (13)    D1a step 7 (design 8.4); only between batches (state READY), no state change.  The zones the loader's state file lists, in the
 *                     order the Backend should read them, sent once after the startup load (an empty list when there is none), in parts:
 *                     1 list_id u64 R | 2 part u32 R (0, 1, ... in order) | 3 last u8 R (0/1) | 4 ENTRY nested, repeatable (<= KDB_HOT_PART_MAX):
 *                     1 view str ne <=255 R (the NAME of the view, not an index: the file outlives a reconfiguration) | 2 zone name R |
 *                     6 file_state u8 O (KDB_HF_*: what the loader found in its state file at its start) | 7 file_zones u32 O (the zones the file held).
 *                     Tag 5 is not used by this message.  The Backend treats the entries as untrusted: a name that is not a zone of its directory is ignored.
 *   HOT_ACK (14)      D1a step 7; only between batches, no state change.  The loader's answer to the last part of a HOT_LIST:
 *                     1 list_id u64 R | 2 status u8 R (KDB_HA_*) | 3 zones u32 R (the zones the state file holds now) | 4 error str<=255 O
 *
 *                     0.7 WP7a, the store protocol (store design 5.3 / 5.4; negotiated: HELLO features bit0 from the loader, CONFIG tag 10 from the
 *                     Backend; without it none of the four messages below is sent and the loader works with INVENTORY as before).  The loader keeps no table
 *                     of the zones: it lists the zones of a source to the Backend (MANIFEST, a pass over `domains` in id order) or says which changed
 *                     (CHANGES, pages of the change log), and the Backend asks for the bodies it lacks with FETCH_REQ on the fetch stream (priority 2, by name,
 *                     with the source id in tag 8).  All four are inside a batch (IN_BATCH) and count in BATCH_END: n_zones = manifest entries + upserts of
 *                     CHANGES, n_deleted = deletes of CHANGES + ZONE_DELETE messages.  An entry is a claim of an untrusted loader: the Backend checks it.
 *   MANIFEST_BEGIN (15) A pass over every zone of one view's source starts (first fill, change-log gap, replaced database, `reload -force`, a source without a
 *                     change log).  1 batch_id u64 R | 2 view view R | 3 count u64 R (an estimate of the entries, 0 = unknown) | 4 cursor u64 R (the
 *                     change-log cursor taken BEFORE the first page: the changes that came during the pass are in the CHANGES that follow it) |
 *                     5 cursor_valid u8 R (0: the source has no change log, tag 4 means nothing and the Backend keeps no cursor) | 6 db_ident bytes<=64 O (the
 *                     identity of the database, opaque; stored with the cursor and sent back in CONFIG) | 7 flags u32 R (bit0 KDB_MF_VERIFY reserved,
 *                     bit1 KDB_MF_PLAIN: a plain PowerDNS schema: no stamps, entries carry the serial)
 *   MANIFEST (16)     One page of a pass: 1 batch_id u64 R | 2 view view R | 3 page u32 R (0, 1, ... in order) | 4 ENTRY nested, repeatable (<= KDB_MANIFEST_PAGE_MAX):
 *                     1 source_id i64 R (domains.id) | 2 name name R | 3 kind u8 R (0 primary, 1 secondary, 2 catalog) | 4 stamp_gen u64 R | 5 stamp_time u64 R
 *                     (karidns_zone_state.generation / changed_at) | 6 flags u8 O (bit0 KDB_EF_STAMPED: the stamp is real; absent / 0: the zone has no state row, and the
 *                     Backend compares the serial (tag 7) or wants the body) | 7 serial u32 O (plain schema) | 8 digest bytes<=32 exactly O (a verify pass).
 *                     Only zones the view serves are listed (the view mapping is applied by the loader) and only zones the loader can send (a canonical name, a loadable
 *                     type); the others are counted in MANIFEST_END n_skipped, and the Backend that sweeps a zone that is not listed deletes it.
 *   MANIFEST_END (17) 1 batch_id u64 R | 2 view view R | 3 n_entries u64 R (the sum of the pages) | 4 n_skipped u64 R | 5 cursor u64 R | 6 cursor_valid u8 R |
 *                     7 db_ident bytes<=64 O | 8 complete u8 R (1: every page was sent, the Backend may sweep what the pass did not list; 0: the loader gave up (a database
 *                     error): no sweep).  The mass-delete guard (decision D7) is the Backend's: the loader only reports the counts.
 *   CHANGES (18)      Distinct domains the change log says changed since the cursor: 1 batch_id u64 R | 2 view view R | 3 cursor u64 R (valid only when tag 4 is 1: the
 *                     position the drain has reached; earlier pages carry the cursor the drain started at) | 4 last u8 R (1: the drain is complete up to tag 3,
 *                     which the Backend may make durable once the entries are recorded) | 5 db_ident bytes<=64 O | 6 ENTRY nested, repeatable (<= KDB_MANIFEST_PAGE_MAX):
 *                     1 source_id i64 R | 2 op u8 R (1 upsert: the domain exists and the view serves it; 2 delete: it is gone, or the view no longer serves it, or its type
 *                     cannot be loaded) | 3 name name (an upsert needs it; a delete has it when the loader knows it) | 4 kind u8 (an upsert needs it) | 5 stamp_gen u64 |
 *                     6 stamp_time u64 | 7 flags u8 O (bit0 KDB_EF_STAMPED, bit1 KDB_EF_FORCE: read the body whatever the stamp says: a reload request; bit2 KDB_EF_HOLD (0.7,
 *                     signer-wait): a zone the store has an image of keeps it and the version waits for the signer; one it has not, or the version it has, is answered with a
 *                     ZONE_RESULT that carries the source id) | 8 serial u32 O.
 *                     A domain can be in two pages of a drain; the entries are idempotent.
 *   LOOKUP_RESULT (19) 0.7, fetch stream only (the answer to FETCH_REQ mode 2): 1 request_id u64 R | 2 view view R | 3 found u8 R (0/1) | and, with found = 1: 4 source_id i64 R |
 *                     5 name name R (the zone: canonical, the entry of a MANIFEST) | 6 kind u8 R (KDB_ZK_*) | 7 stamp_gen u64 R | 8 stamp_time u64 R | 9 flags u8 O (bit0 KDB_EF_STAMPED) |
 *                     10 serial u32 O (a plain schema).  With found = 0 none of 4..10.  The Backend records the zone as a MANIFEST entry would (a KNOWN record, its body is read when a
 *                     query asks for it); the entry is a claim of an untrusted loader: its name must enclose the name that was asked for.
 *                     Mode 3 (KDB_FETCH_LOOKUP_FULL): with found = 1 the LOOKUP_RESULT is followed, on the same stream and with the same request id, by that zone's body, ZONE_BEGIN ..
 *                     ZONE_IMAGE .. ZONE_END (or ZONE_FAILED, or ZONE_ABORT), as the answer to a FETCH_REQ mode 0 for the zone would be; with found = 0 nothing follows.  From the Backend's
 *                     side the request becomes a fetch of the zone with the same id: the body must be the zone the result named (the name and the source id), at most one body comes
 *                     for a request, and a body that comes without a result, for another zone, or for a mode 2 request is discarded.
 * Backend -> loader (type | 0x8000)
 *   CONFIG (0x8001)   1 generation u64 R | 2 driver str ne <=32 R | 3 server_id str<=64 O |
 *                     4 VIEW nested, repeatable (<= 1024):
 *                         1 index u16 R | 2 name str ne <=255 R | 3 source path ne<=1023 O (absent = driver default; B4a: the Backend repeats the global source for views that use it) |
 *                         4 conninfo_file path ne<=1023 O | 5 auto_reload u8 R (0/1) | 6 poll_interval u32 R (s) |
 *                         7 coalesce_ms u32 R | 8 max_zone_records u64 R | 9 max_zone_bytes u64 R |
 *                         10 shared_source u8 O (0/1; B6b: the source is the global one, so karidns_domain_views maps zones to this view)
 *                         11 cursor u64 O | 12 cursor_valid u8 O (0/1; 0.7 WP7a: the change-log cursor the Backend keeps for this view, valid only with tag 12 = 1; absent or 0 = none: a first fill) |
 *                         13 db_ident bytes<=64 O (the identity of the database the cursor belongs to, as the loader reported it; a different identity makes the loader list the source again)
 *                     5 default_ttl u32 O (<= 2147483647; B4a) | 6 bulk_threshold u8 O (<= 100) | 7 loader_threads u32 O (<= 16) |
 *                     8 dir_only u8 O (0/1; D1a milestone 4: memory-limit is set, so a zone the Backend does not have in memory is sent as a
 *                         summary (ZONE_BEGIN with the summary flag, settings and SOA timers, no zone image) also in a batch) |
 *                     9 signer_wait u8 O (0/1; 0.6.0 item C: database { signer-wait }; absent = 1) |
 *                     10 store_proto u8 O (0/1; 0.7 WP7a: use the store protocol: no INVENTORY is sent or wanted, the loader answers with MANIFEST / CHANGES; the Backend
 *                         sets it only when HELLO features has KDB_FEAT_STORE; absent = 0)
 *   RELOAD_REQ (0x8002) 1 request_id u64 R | 2 scope u8 R (0 all, 1 one zone) | 3 view view O | 4 zone name O |
 *                     5 force u8 R (0/1); scope 1 needs tags 3 and 4, scope 0 forbids them.
 *                     Store protocol: scope 0 with force = 1 is a MANIFEST pass of every source (`karictl reload -force`); scope 0 without it drains the change log; scope 1
 *                     answers with a CHANGES entry (op 1, flag FORCE) for the zone, or a ZONE_DELETE (source id 0: by name) when the database has no such zone.
 *   INVENTORY (0x8003) 1 ENTRY nested, repeatable: 1 view view R | 2 zone name R | 3 source_id i64 R |
 *                         4 serial u32 R | 5 digest bytes (exactly 32; required unless the zone is not resident) |
 *                         6 resident u8 O (D1a: 0/1, absent = 1; 0 = the Backend has only the directory entry of the zone, no data and
 *                         no digest)
 *                     An inventory may span several INVENTORY messages (the Backend sends a few hundred entries at a time);
 *                     INVENTORY_END ends it and its n_zones is the total of the entries of all of them.
 *   INVENTORY_END (0x8004) 1 last_change_seq u64 R | 2 n_zones u64 R
 *   ZONE_RESULT (0x8005) 1 view view R | 2 zone name R | 3 status u8 R (0 applied,1 unchanged,2 rejected,
 *                     3 shadowed,4 deleted) | 4 reason str<=255 O | 5 source_id i64 O (0.7: the answer to a CHANGES upsert with KDB_EF_HOLD that
 *                     was not held: the zone does not wait for the signer; such a ZONE_RESULT is not a result of the batch)
 *   BATCH_RESULT (0x8006) 1 batch_id u64 R | 2 request_ids bytes O (n * u64, <= 2048 bytes) | 3 n_applied u32 R |
 *                     4 n_unchanged u32 R | 5 n_rejected u32 R | 6 n_deleted u32 R | 7 store_error u32 O (0.7, only to a loader whose HELLO features have
 *                     KDB_FEAT_BATCH_STATUS: the errno for which the store could not make the batch durable; the loader then reads the changes of the batch
 *                     again from where it was before it, so a batch the store did not record is never passed; absent = 0, recorded)
 *   FETCH_REQ (0x8007) D1a, fetch stream only: 1 request_id u64 R (> 0) | 2 view view R | 3 zone name R (mode 2: a query name) |
 *                     4 priority u8 R (0 a query waits for it, 1 warm-up, 2 background) | 5 mode u8 R (0 the zone, 1 its summary, 2 lookup, 3 lookup and body) |
 *                     6 range_lo name O | 7 range_hi name O (D1b: both or none; a loader that does not read ranges answers ZONE_FAILED) |
 *                     8 source_id i64 O (0.7 WP7a: the domains.id the Backend holds for the zone (a KNOWN zone of the store protocol); a loader that finds the name with
 *                         another id answers ZONE_FAILED: the zone was renamed or created again, and CHANGES says so)
 *                     0.7, mode 2 (KDB_FETCH_LOOKUP; only to a loader whose HELLO features have KDB_FEAT_LOOKUP): the first start of a store has not listed every zone yet, and a
 *                     query asks for a name it does not know.  Tag 3 is the query name; the loader finds the zone of the view that encloses it (the name and its parent names, the
 *                     longest one that the view serves and the loader can send; the root is not looked for) and answers LOOKUP_RESULT, or ZONE_FAILED (a database error).  Tags 6, 7
 *                     and 8 are not used with it.
 *                     0.7, mode 3 (KDB_FETCH_LOOKUP_FULL; only to a loader whose HELLO features have KDB_FEAT_LOOKUP_BODY, 0x4): a lookup as mode 2, and when a zone is found the loader sends
 *                     its body after the LOOKUP_RESULT, with the same request id (LOOKUP_RESULT in the answer, then ZONE_BEGIN .. ZONE_END of the zone the result named: one round trip for
 *                     a zone that the Backend did not know).  When the body cannot be read the loader answers ZONE_FAILED with the request id and the name of the zone.  A loader serves it
 *                     ahead of the bodies of the background fill (the priority of the request is 0).  Tags 6, 7 and 8 are not used.
 *   HOT_LIST (0x8008) D1a step 7 (design 8.4), first stream only: the zones most asked for, hottest first, in parts as WARM_LIST (tags 1..4 the same;
 *                     5 limit u32 O: the most entries the loader keeps in its state file, <= KDB_HOT_MAX, absent = KDB_HOT_MAX).  Several parts carry
 *                     one list_id; a part that does not follow the one before (or a new list_id) starts the list again.  The loader merges the list
 *                     with what it has (the zones of the old list that nobody asked for since stay after the new ones), writes the state file when
 *                     the last part has come, and answers with HOT_ACK.  The entries are untrusted input of the loader: counts, names and views are checked.
 *   DEBUG (0x8009)    0.7 M2, first stream only: 1 level u8 R (<= 99): the debug level in force (karictl trace / notrace), sent after the CONFIG of
 *                     every handshake and at every change; the loader logs its messages up to that level (karidns-dbloader --debug at its start)
 *
 * The fetch stream (D1a, design 6.1) is a second KDB1 stream, made by the supervisor with the first.  It carries only what a
 * parked query waits for: FETCH_REQ from the Backend; from the loader, ZONE_BEGIN .. ZONE_IMAGE .. ZONE_END / ZONE_ABORT (PROFILE
 * before ZONE_BEGIN) or ZONE_FAILED for each request, every one with the request id.  No HELLO, no batches, no results: the
 * state machine starts in READY (kdb_sm_init_fetch()) and the Backend discards a zone it did not ask for.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "dns_wire.h" /* DNS_NAME_TEXT_SIZE */

#define KDB_MAGIC "KDB1"
#define KDB_VERSION 1
#define KDB_HEADER_LEN 12
#define KDB_MAX_BODY (1u << 20)      /* every message */
#define KDB_REASON_LEN 128
#define KDB_FEAT_STORE 0x1u          /* HELLO features: the store protocol (MANIFEST / CHANGES) */
#define KDB_FEAT_LOOKUP 0x2u         /* HELLO features: the loader answers FETCH_REQ mode KDB_FETCH_LOOKUP with LOOKUP_RESULT (the zone that encloses a name, 0.7 first start) */
#define KDB_FEAT_LOOKUP_BODY 0x4u    /* HELLO features: the loader answers FETCH_REQ mode KDB_FETCH_LOOKUP_FULL with LOOKUP_RESULT and, when it found a zone, the body of that zone (0.7 first start) */
#define KDB_FEAT_IMAGE 0x8u          /* HELLO features: the loader sends a zone as a zone image (ZONE_BEGIN flag KDB_ZF_IMAGE, ZONE_IMAGE messages), tag 6 says which image version (0.7 M3) */
#define KDB_FEAT_BATCH_STATUS 0x10u  /* HELLO features: the loader reads BATCH_RESULT tag 7 (the batch was not recorded by the store) and does not go past such a batch (0.7) */
#define KDB_MF_VERIFY 0x1u           /* MANIFEST_BEGIN flags: a verify pass (entries carry digests; reserved) */
#define KDB_MF_PLAIN 0x2u            /* ... a plain PowerDNS schema: no stamps, serials */
#define KDB_EF_STAMPED 0x1u          /* MANIFEST / CHANGES entry flags: the stamp (generation, changed_at) is real */
#define KDB_EF_FORCE 0x2u            /* CHANGES entry: read the body whatever the stamp says */
#define KDB_EF_HOLD 0x4u             /* CHANGES upsert (signer-wait, 0.7): a zone the Backend has keeps the version it has; one it does not have is read as it is */
#define KDB_MANIFEST_PAGE_MAX 16384  /* entries of one MANIFEST / CHANGES message */
#define KDB_IDENT_MAX 64             /* database identity, bytes */
#define KDB_FETCH_BUSY_REASON "busy: too many fetch requests are waiting"   /* the loader's ZONE_FAILED reason when its fetch queue is full (the Backend counts these) */
#define KDB_DIGEST_LEN 32
#define KDB_VIEWS_ANY 0xFFFFFFFFu    /* view_count: do not check view indexes */
#define KDB_MAX_CONFIG_VIEWS 1024
#define KDB_MAX_PROFILES 65535u      /* PROFILE messages per batch */
#define KDB_HOT_PART_MAX 16384        /* D1a step 7: entries of one HOT_LIST / WARM_LIST message (a part) */
#define KDB_HOT_MAX 100000            /* ... and of the whole list (database { hot-list-size } is at most this) */
#define KDB_HOT_FILE_MAX (64u << 20)  /* a state file above this many bytes is not read */
/* the state file at the loader's start: none configured, read, not there, ignored (corrupt), cannot be read */
enum { KDB_HF_NONE = 0, KDB_HF_LOADED, KDB_HF_MISSING, KDB_HF_CORRUPT, KDB_HF_UNREADABLE, KDB_HF_N };
/* HOT_ACK: written, same as the file (not written again), could not be written, no state file configured, the list was not valid */
enum { KDB_HA_WRITTEN = 0, KDB_HA_UNCHANGED, KDB_HA_FAILED, KDB_HA_NOFILE, KDB_HA_IGNORED, KDB_HA_N };
#define KDB_DEFAULT_MAX_ZONE_RECORDS 10000000ull
#define KDB_DEFAULT_MAX_ZONE_BYTES (1ull << 30)

enum {
    /* loader -> Backend */
    KDB_T_HELLO = 1, KDB_T_INVENTORY_REQ = 2, KDB_T_BATCH_BEGIN = 3, KDB_T_ZONE_BEGIN = 4,
    KDB_T_ZONE_END = 6, KDB_T_ZONE_ABORT = 7, KDB_T_ZONE_FAILED = 8, KDB_T_ZONE_DELETE = 9, KDB_T_PROFILE = 10,
    KDB_T_BATCH_END = 11, KDB_T_AUTO_STATUS = 12, KDB_T_WARM_LIST = 13, KDB_T_HOT_ACK = 14,
    KDB_T_MANIFEST_BEGIN = 15, KDB_T_MANIFEST = 16, KDB_T_MANIFEST_END = 17, KDB_T_CHANGES = 18,      /* 0.7 WP7a: the store protocol */
    KDB_T_LOOKUP_RESULT = 19,           /* 0.7: the answer to FETCH_REQ mode KDB_FETCH_LOOKUP (fetch stream only) */
    KDB_T_ZONE_IMAGE = 20,              /* 0.7 M3: the next octets of a zone image (raw, up to KDB_MAX_BODY; ZONE_BEGIN with KDB_ZF_IMAGE, .. ZONE_END) */
    /* Backend -> loader: high bit set */
    KDB_T_CONFIG = 0x8001, KDB_T_RELOAD_REQ = 0x8002, KDB_T_INVENTORY = 0x8003, KDB_T_INVENTORY_END = 0x8004,
    KDB_T_ZONE_RESULT = 0x8005, KDB_T_BATCH_RESULT = 0x8006,
    KDB_T_FETCH_REQ = 0x8007,           /* D1a: fetch stream */
    KDB_T_HOT_LIST = 0x8008,            /* D1a step 7: the zones most asked for (first stream) */
    KDB_T_DEBUG = 0x8009                /* 0.7 M2: the debug level in force (first stream) */
};

enum { KDB_FETCH_PRIO_QUERY = 0, KDB_FETCH_PRIO_WARM, KDB_FETCH_PRIO_BACKGROUND, KDB_FETCH_PRIO_N };
enum { KDB_FETCH_FULL = 0, KDB_FETCH_SUMMARY, KDB_FETCH_LOOKUP, KDB_FETCH_LOOKUP_FULL };      /* LOOKUP (0.7): tag 3 is a query name, not a zone: which zone of the view encloses it?  LOOKUP_FULL: the same, and the body of the zone that is found follows the answer */

enum { KDB_BATCH_STARTUP = 0, KDB_BATCH_FULL, KDB_BATCH_DIFF, KDB_BATCH_ZONE, KDB_BATCH_AUTO };
enum { KDB_ZK_PRIMARY = 0, KDB_ZK_SECONDARY, KDB_ZK_CATALOG };
#define KDB_ZF_PRESIGNED 0x1u
#define KDB_ZF_EXTENDED 0x2u    /* the image may carry location / ECS tags, tinydns time stamps and locations, several or restricted SOA RRs (zone_image_validate_ex(): without the flag it has none) */
#define KDB_ZF_TINYDNS 0x4u     /* B8: the zone is a tinydns zone (ZONE_IMAGE_F_TINYDNS: time-dependent TTLs, never cached), also without any time stamp or location */
#define KDB_APEX_NS_MAX 8        /* D1a step 6: NS names of a summary's apex */
#define KDB_APEX_NS_BYTES 2047   /* ... and the bytes of their list (8 names of 253 characters and the separators) */
#define KDB_APEX_GLUE_PER_NS 8   /* addresses of one NS target in the glue list */
#define KDB_APEX_GLUE_BYTES 2048 /* ... and the bytes of the list (8 names, 8 AAAA records of 22 octets each: 1408) */
#define KDB_NOTIFY_ADDR_PER_NS 8 /* D1a step 7: addresses of one NS target in the NOTIFY address list (tag 22) */
#define KDB_NOTIFY_ADDR_BYTES 1152 /* ... and the bytes of the list (8 targets, 8 AAAA records of 18 octets each) */
#define KDB_ZF_IMAGE 0x10u      /* 0.7 M3: the data of the zone is a zone image (ZONE_BEGIN tag 23 = its size, ZONE_IMAGE messages): required for every primary zone with data; rr_count is the n_rrs of the image */
#define KDB_ZF_SUMMARY 0x8u     /* D1a, fetch stream: the zone's summary (serial, kind, settings), no data, rr_count 0, zero digest */
enum { KDB_ST_APPLIED = 0, KDB_ST_UNCHANGED, KDB_ST_REJECTED, KDB_ST_SHADOWED, KDB_ST_DELETED,
       KDB_ST_SEND_BODY,       /* D1a: SEND_BODY, to a summary (or to a zone body that was left out): the zone is in the Backend's memory in another version than the loader says, send it whole */
       KDB_ST_NOT_RESIDENT };  /* D1a: NOT_RESIDENT, to a zone body: the Backend took the version into its directory and left the data out (memory-limit), so it has no data of the zone */

typedef enum {
    KDB_OK = 0,
    KDB_MORE,            /* framer: need more input */
    /* errors (protocol errors for the Backend) */
    KDB_E_MAGIC, KDB_E_TYPE, KDB_E_FLAGS, KDB_E_LENGTH,
    KDB_E_TLV_TRUNC, KDB_E_TLV_DUP, KDB_E_TLV_UNKNOWN, KDB_E_TLV_MISSING, KDB_E_TLV_LEN, KDB_E_TLV_STR,
    KDB_E_TLV_NAME, KDB_E_RANGE,
    KDB_E_STATE, KDB_E_VERSION, KDB_E_COUNT, KDB_E_SEQ,
    KDB_E_LIMIT_BYTES, KDB_E_LIMIT_RECORDS, KDB_E_LIMIT_PROFILES
} kdb_rc_t;

static inline bool kdb_rc_is_error(kdb_rc_t rc) { return rc >= KDB_E_MAGIC; }
const char *kdb_rc_name(kdb_rc_t rc);
const char *kdb_type_name(uint16_t type);   /* "?" for an unknown type */

/* ---------------------------------------------------------------- encoder */
typedef struct {
    uint8_t *buf;
    size_t len, cap;
    size_t msg_start, nest_start;
    uint16_t cur_type;
    bool open, nested, err;     /* err is sticky: out of memory, value too long, message too long */
} kdb_enc_t;

void kdb_enc_init(kdb_enc_t *e);
void kdb_enc_free(kdb_enc_t *e);
void kdb_enc_reset(kdb_enc_t *e);                 /* drop the contents, keep the memory */
int kdb_enc_begin(kdb_enc_t *e, uint16_t type);   /* 0, or -1 (sticky error) */
int kdb_enc_u8(kdb_enc_t *e, uint16_t tag, uint8_t v);
int kdb_enc_u16(kdb_enc_t *e, uint16_t tag, uint16_t v);
int kdb_enc_u32(kdb_enc_t *e, uint16_t tag, uint32_t v);
int kdb_enc_u64(kdb_enc_t *e, uint16_t tag, uint64_t v);
int kdb_enc_i64(kdb_enc_t *e, uint16_t tag, int64_t v);
int kdb_enc_bytes(kdb_enc_t *e, uint16_t tag, const void *p, size_t n);   /* n <= 65535 */
int kdb_enc_str(kdb_enc_t *e, uint16_t tag, const char *s);               /* NUL not sent; also used for text */
int kdb_enc_name(kdb_enc_t *e, uint16_t tag, const char *name);           /* the caller passes the canonical form */
int kdb_enc_nest_begin(kdb_enc_t *e, uint16_t tag);                       /* one level */
int kdb_enc_nest_end(kdb_enc_t *e);
int kdb_enc_end(kdb_enc_t *e);                    /* patches the length; fails if above the type's limit */
int kdb_enc_raw_msg(kdb_enc_t *e, uint16_t type, const void *body, size_t n);   /* ZONE_IMAGE, or crafted bodies */

/* ---------------------------------------------------------------- framer */
typedef enum { KDB_FROM_LOADER = 0, KDB_FROM_BACKEND = 1 } kdb_dir_t;   /* which side wrote the stream */

typedef struct { uint16_t type; const uint8_t *body; uint32_t len; } kdb_frame_t;

typedef struct {
    kdb_dir_t dir;
    uint8_t *buf;                /* body buffer, caller owned, >= KDB_MAX_BODY for the whole range */
    size_t cap;
    const uint8_t *in;
    size_t in_len;
    uint8_t hdr[KDB_HEADER_LEN];
    size_t hdr_have;
    uint32_t body_len, body_have;
    uint16_t type;
    int phase;
    kdb_rc_t fail;               /* sticky */
    char reason[KDB_REASON_LEN];
} kdb_framer_t;

void kdb_framer_init(kdb_framer_t *f, kdb_dir_t dir, uint8_t *buf, size_t cap);
/* Offer input.  The bytes are not copied here: call kdb_framer_next() until KDB_MORE (or an error) before the
 * next feed and before the memory behind p goes away.  Returns KDB_E_STATE if the previous input is not consumed. */
kdb_rc_t kdb_framer_feed(kdb_framer_t *f, const uint8_t *p, size_t n);
/* KDB_OK: *out is one complete, header-validated frame (valid until the next call); KDB_MORE: input used up;
 * KDB_E_*: protocol error (sticky), f->reason says why. */
kdb_rc_t kdb_framer_next(kdb_framer_t *f, kdb_frame_t *out);

/* ---------------------------------------------------------------- decoded messages */
typedef struct { const char *p; uint32_t len; } kdb_str_t;     /* p == NULL: absent */

typedef struct { uint16_t proto; kdb_str_t loader_version, driver; uint32_t pid; uint32_t features; /* tag 5, KDB_FEAT_*; 0 = absent */
                 uint32_t image_version;   /* tag 6 (0.7 M3): the zone image version the loader builds; 0 = absent */ } kdb_hello_t;
typedef struct { uint64_t batch_id; uint8_t kind; uint64_t change_seq; uint64_t request_id; /* 0 = none */
                 uint64_t cfg_generation; /* the CONFIG the loader made the batch with (tag 5; 0 = not sent) */ } kdb_batch_begin_t;
typedef struct {
    uint16_t view; char name[DNS_NAME_TEXT_SIZE]; int64_t source_id; uint8_t zone_kind; uint32_t serial;
    uint32_t flags; uint64_t rr_count; uint8_t digest[KDB_DIGEST_LEN]; kdb_str_t settings, profile;
    uint64_t request_id;        /* D1a: 0 = tag absent */
    bool has_soa_timers;        /* D1a: tags 12..14, the SOA refresh / retry / expire of the zone (a summary carries them for the directory) */
    uint32_t soa_refresh, soa_retry, soa_expire;
    bool has_apex;              /* D1a step 6: tags 15..20 */
    char soa_mname[DNS_NAME_TEXT_SIZE], soa_rname[DNS_NAME_TEXT_SIZE];
    uint32_t soa_minimum, soa_ttl, ns_ttl;
    const char *ns_names;       /* the names separated by LF; points into the frame, valid until the next frame is read */
    uint16_t ns_names_len;
    uint8_t ns_count;
    const uint8_t *glue;        /* tag 21 (validated by the decoder), NULL when there is none; points into the frame like ns_names */
    uint16_t glue_len;
    const uint8_t *naddrs;      /* tag 22 (validated by the decoder), NULL when there is none; points into the frame */
    uint16_t naddrs_len;
    uint64_t image_size;        /* 0.7 M3: tag 23, the size of the zone image; 0 = the flag KDB_ZF_IMAGE is not set (the decoder: the tag is there exactly when the flag is) */
} kdb_zone_begin_t;
typedef struct { const uint8_t *body; uint32_t len; } kdb_zone_image_t;     /* 0.7 M3: the octets of one ZONE_IMAGE message (points into the frame) */
typedef struct { uint64_t rr_count; } kdb_zone_end_t;
typedef struct { kdb_str_t reason; } kdb_zone_abort_t;
typedef struct { uint16_t view; char name[DNS_NAME_TEXT_SIZE]; int64_t source_id; kdb_str_t reason; uint64_t request_id; /* 0 = absent */ } kdb_zone_failed_t;
typedef struct { uint16_t view; char name[DNS_NAME_TEXT_SIZE]; int64_t source_id; } kdb_zone_delete_t;
typedef struct { kdb_str_t name, settings; } kdb_profile_t;
typedef struct { uint64_t batch_id; uint32_t n_zones, n_failed, n_deleted; } kdb_batch_end_t;
typedef struct { uint32_t n_entries; const uint8_t *body; uint32_t body_len; } kdb_auto_status_t;     /* entries: kdb_auto_status_entries() */

typedef struct {
    uint64_t generation; kdb_str_t driver, server_id;
    uint32_t default_ttl;       /* 0 = tag absent */
    int bulk_threshold;         /* percent; -1 = tag absent */
    uint32_t loader_threads;    /* 0 = tag absent */
    bool dir_only;              /* tag 8 (D1a milestone 4): memory-limit is set; the loader sends the summary only (no data) for a zone the Backend does not have in memory */
    bool signer_wait;           /* tag 9 (0.6.0 item C): the loader does not reload a zone with the metadata X-KARIDNS-SIGNER=1 because of the change log; absent = true */
    bool store_proto;           /* tag 10 (0.7 WP7a): the store protocol (MANIFEST / CHANGES instead of INVENTORY); absent = false */
    uint32_t n_views;
    const uint8_t *body; uint32_t body_len;       /* for kdb_config_views() */
} kdb_config_t;
typedef struct {
    uint64_t request_id; uint8_t scope, force; bool has_zone; uint16_t view; char zone[DNS_NAME_TEXT_SIZE];
} kdb_reload_req_t;
typedef struct { uint32_t n_entries; const uint8_t *body; uint32_t body_len; } kdb_inventory_t;
typedef struct { uint64_t last_change_seq, n_zones; } kdb_inventory_end_t;
typedef struct { uint16_t view; char name[DNS_NAME_TEXT_SIZE]; uint8_t status; kdb_str_t reason; bool has_source_id; int64_t source_id; } kdb_zone_result_t;   /* source_id: tag 5 (0.7, the answer to a CHANGES upsert with KDB_EF_HOLD) */
typedef struct {
    uint64_t batch_id; const uint8_t *request_ids; uint32_t n_request_ids;   /* big-endian u64 each */
    uint32_t n_applied, n_unchanged, n_rejected, n_deleted;
    uint32_t store_error;                               /* tag 7 (0.7, only to a loader with KDB_FEAT_BATCH_STATUS): the errno for which the Backend's store could not record the batch; 0 = recorded */
} kdb_batch_result_t;
typedef struct {
    uint64_t list_id; uint32_t part; bool last; uint32_t n_entries;
    uint32_t limit;             /* HOT_LIST tag 5, 0 = absent */
    int file_state;             /* WARM_LIST tag 6 (KDB_HF_*), -1 = absent */
    uint32_t file_zones;        /* WARM_LIST tag 7 */
    const uint8_t *body; uint32_t body_len;       /* for kdb_hot_entries() */
} kdb_hot_list_t;
typedef struct { uint64_t list_id; uint8_t status; uint32_t zones; kdb_str_t error; } kdb_hot_ack_t;
typedef struct { uint8_t level; } kdb_debug_t;
typedef struct {
    uint64_t request_id; uint16_t view; char name[DNS_NAME_TEXT_SIZE]; uint8_t priority, mode;
    bool has_range; char range_lo[DNS_NAME_TEXT_SIZE], range_hi[DNS_NAME_TEXT_SIZE];
    int64_t source_id;          /* tag 8; 0 = absent */
} kdb_fetch_req_t;

/* 0.7: LOOKUP_RESULT (the entry is a claim of an untrusted loader, as a MANIFEST entry: the Backend checks it) */
typedef struct {
    uint64_t request_id; uint16_t view; bool found;
    int64_t source_id; char name[DNS_NAME_TEXT_SIZE]; uint8_t kind; bool stamped; uint64_t stamp_gen, stamp_time; bool has_serial; uint32_t serial;     /* (found only) */
} kdb_lookup_result_t;

/* 0.7 WP7a: the store protocol */
typedef struct {
    uint64_t batch_id; uint16_t view; uint64_t count; uint64_t cursor; bool cursor_valid;
    uint8_t ident[KDB_IDENT_MAX]; uint8_t ident_len; uint32_t flags;
} kdb_manifest_begin_t;
typedef struct { uint64_t batch_id; uint16_t view; uint32_t page; uint32_t n_entries; const uint8_t *body; uint32_t body_len; } kdb_manifest_t;
typedef struct {
    uint64_t batch_id; uint16_t view; uint64_t n_entries, n_skipped; uint64_t cursor; bool cursor_valid;
    uint8_t ident[KDB_IDENT_MAX]; uint8_t ident_len; bool complete;
} kdb_manifest_end_t;
typedef struct {
    uint64_t batch_id; uint16_t view; uint64_t cursor; bool last;
    uint8_t ident[KDB_IDENT_MAX]; uint8_t ident_len;
    uint32_t n_entries; const uint8_t *body; uint32_t body_len;       /* for kdb_changes_entries() */
} kdb_changes_t;

typedef struct {
    uint16_t type;
    uint32_t view_count;       /* as given to kdb_decode() */
    union {
        kdb_hello_t hello; kdb_batch_begin_t batch_begin; kdb_zone_begin_t zone_begin;
        kdb_zone_end_t zone_end; kdb_zone_abort_t zone_abort; kdb_zone_failed_t zone_failed;
        kdb_zone_delete_t zone_delete; kdb_profile_t profile; kdb_batch_end_t batch_end; kdb_auto_status_t auto_status;
        kdb_config_t config; kdb_reload_req_t reload_req; kdb_inventory_t inventory;
        kdb_inventory_end_t inventory_end; kdb_zone_result_t zone_result; kdb_batch_result_t batch_result;
        kdb_fetch_req_t fetch_req; kdb_hot_list_t hot_list; kdb_hot_ack_t hot_ack; kdb_debug_t debug;
        kdb_manifest_begin_t manifest_begin; kdb_manifest_t manifest; kdb_manifest_end_t manifest_end; kdb_changes_t changes;
        kdb_lookup_result_t lookup_result; kdb_zone_image_t zone_image;
    } u;
} kdb_msg_t;

/* Decode one frame of either direction (the type says which).  view_count: number of configured views, or
 * KDB_VIEWS_ANY.  why (>= KDB_REASON_LEN bytes) receives the reason on error. */
kdb_rc_t kdb_decode(const kdb_frame_t *fr, uint32_t view_count, kdb_msg_t *msg, char *why, size_t whylen);
/* D1a step 6: is p a glue list as tag 21 of ZONE_BEGIN describes it, for an apex with ns_count NS names? */
bool kdb_apex_glue_valid(const uint8_t *p, size_t len, unsigned ns_count);
/* D1a step 7: is p a NOTIFY address list as tag 22 of ZONE_BEGIN describes it, for an apex with ns_count NS names? */
bool kdb_notify_addrs_valid(const uint8_t *p, size_t len, unsigned ns_count);

/* Repeated nested entries of CONFIG and INVENTORY.  The entries were validated by kdb_decode(); the iterator
 * checks again and simply ends on anything unexpected. */
typedef struct { const uint8_t *p; size_t left; uint32_t view_count; } kdb_iter_t;
typedef struct {
    uint16_t index; kdb_str_t name, source, conninfo_file; uint8_t auto_reload; uint32_t poll_interval, coalesce_ms;
    uint64_t max_zone_records, max_zone_bytes;
    uint8_t shared_source;      /* tag 10; 0 = absent */
    bool has_cursor;            /* tags 11 / 12: the Backend's change-log cursor for the view (WP7a) */
    uint64_t cursor;
    uint8_t ident[KDB_IDENT_MAX]; uint8_t ident_len;      /* tag 13 */
} kdb_config_view_t;
typedef struct {
    uint16_t view; char name[DNS_NAME_TEXT_SIZE]; int64_t source_id; uint32_t serial; uint8_t digest[KDB_DIGEST_LEN];
    bool resident;              /* D1a: false = the Backend has no data of the zone, and `digest` is all zero */
} kdb_inventory_entry_t;
#define KDB_AS_AUTO 1u      /* AUTO_STATUS entry flags: the auto reload fields are real */
#define KDB_AS_REQ 2u       /* the reload request fields are real (B11) */
typedef struct {
    uint16_t view; uint64_t last_poll, applied_seq; uint32_t pending; kdb_str_t error;
    uint8_t flags; kdb_str_t server_id; uint64_t req_generation; bool req_ok; kdb_str_t req_error; uint64_t req_time;   /* B11 */
    uint32_t sig_wait; kdb_str_t sig_names;      /* item C: the zones that wait for the signer (tags 12, 13); 0 / empty = absent */
} kdb_auto_status_entry_t;
void kdb_auto_status_entries(const kdb_msg_t *m, kdb_iter_t *it);
bool kdb_auto_status_entries_next(kdb_iter_t *it, kdb_auto_status_entry_t *out);
void kdb_config_views(const kdb_msg_t *m, kdb_iter_t *it);
bool kdb_config_views_next(kdb_iter_t *it, kdb_config_view_t *out);
void kdb_inventory_entries(const kdb_msg_t *m, kdb_iter_t *it);
bool kdb_inventory_entries_next(kdb_iter_t *it, kdb_inventory_entry_t *out);
/* 0.7 WP7a: the entries of MANIFEST and CHANGES */
typedef struct {
    int64_t source_id; char name[DNS_NAME_TEXT_SIZE]; uint8_t kind; uint64_t stamp_gen, stamp_time;
    bool stamped; bool has_serial; uint32_t serial; bool has_digest; uint8_t digest[KDB_DIGEST_LEN];
} kdb_manifest_entry_t;
typedef struct {
    int64_t source_id; uint8_t op;          /* 1 upsert, 2 delete (KDB_CH_*) */
    bool has_name; char name[DNS_NAME_TEXT_SIZE]; uint8_t kind; uint64_t stamp_gen, stamp_time; bool stamped, force, hold; bool has_serial; uint32_t serial;
} kdb_changes_entry_t;
enum { KDB_CH_UPSERT = 1, KDB_CH_DELETE = 2 };
void kdb_manifest_entries(const kdb_msg_t *m, kdb_iter_t *it);
bool kdb_manifest_entries_next(kdb_iter_t *it, kdb_manifest_entry_t *out);
void kdb_changes_entries(const kdb_msg_t *m, kdb_iter_t *it);
bool kdb_changes_entries_next(kdb_iter_t *it, kdb_changes_entry_t *out);

/* ---------------------------------------------------------------- hot list (D1a step 7, design 8.4) */
/* The zones most asked for, hottest first: (view name, zone name) pairs in a malloc'd buffer, "view\0zone\0" each.  Used by the Backend (HOT_LIST out, WARM_LIST in),
 * the loader (the state file, the merge) and the state file's reader.  Every pair is validated when it is added: the view is 1..255 printable ASCII bytes, the
 * zone a canonical absolute name, the list at most KDB_HOT_MAX pairs. */
typedef struct { char *buf; size_t len, cap; uint32_t n; } kdb_hotl_t;
void kdb_hotl_init(kdb_hotl_t *l);
void kdb_hotl_free(kdb_hotl_t *l);
void kdb_hotl_clear(kdb_hotl_t *l);
bool kdb_hotl_add(kdb_hotl_t *l, const char *view, const char *zone);     /* false: not valid, the list is full, or out of memory (the list is unchanged) */
bool kdb_hotl_next(const kdb_hotl_t *l, size_t *pos, const char **view, const char **zone);   /* *pos starts at 0 */
bool kdb_hotl_equal(const kdb_hotl_t *a, const kdb_hotl_t *b);
/* out = the entries of fresh, then those of old that fresh does not have, at most limit (a pair twice in fresh counts once).  false: out of memory. */
bool kdb_hotl_merge(const kdb_hotl_t *fresh, const kdb_hotl_t *old, uint32_t limit, kdb_hotl_t *out);
/* Encode l as messages of type (KDB_T_HOT_LIST or KDB_T_WARM_LIST) into e, one part at a time: emit(ud) is called with each finished message in e (it sends it and
 * resets e).  limit 0 = no tag 5; file_state < 0 = no tags 6 and 7.  0, or -1 (an emit failed, or the encoder is out of memory). */
int kdb_hot_encode(const kdb_hotl_t *l, kdb_enc_t *e, uint16_t type, uint64_t list_id, uint32_t limit, int file_state, uint32_t file_zones,
                   int (*emit)(void *ud), void *ud);
void kdb_hot_entries(const kdb_msg_t *m, kdb_iter_t *it);
bool kdb_hot_entries_next(kdb_iter_t *it, char view[256], char zone[DNS_NAME_TEXT_SIZE]);

/* The state file (design 8.4, decision 10).  Text: a first line "KARIDNS-HOT-LIST 1", one line "view TAB zone" per entry, hottest first, and a last line
 * "END <count> <checksum>" (FNV-1a of the entry lines, 8 hex digits); anything else (a truncated file, a bad line, a wrong count or checksum, bytes after END,
 * an empty file) is refused.  The reader never trusts the file: it may be damaged or written by somebody else. */
bool kdb_hotl_parse(const char *buf, size_t len, kdb_hotl_t *out, char *why, size_t whylen);   /* why: a reason without bytes of the file */
char *kdb_hotl_serialize(const kdb_hotl_t *l, size_t *len);                                    /* malloc'd, NULL: out of memory */
/* Read: KDB_HF_LOADED (out holds the list), KDB_HF_MISSING, KDB_HF_CORRUPT (ignored; why says what) or KDB_HF_UNREADABLE (why = strerror) */
int kdb_hotl_file_read(const char *path, kdb_hotl_t *out, char *why, size_t whylen);
/* Write l to path atomically: path.tmp (new, mode 0600, never follows a link), fsync, rename.  0, or -1 with err set. */
int kdb_hotl_file_write(const char *path, const kdb_hotl_t *l, char *err, size_t errlen);

/* ---------------------------------------------------------------- Backend state machine */
typedef struct {
    uint64_t max_zone_records;   /* default KDB_DEFAULT_MAX_ZONE_RECORDS */
    uint64_t max_zone_bytes;     /* the size of the image of one zone (0.7 M3: what the ZONE_DATA bodies added up to before); default KDB_DEFAULT_MAX_ZONE_BYTES */
    uint32_t view_count;         /* configured views, or KDB_VIEWS_ANY */
} kdb_limits_t;

typedef enum { KDB_S_AWAIT_HELLO = 0, KDB_S_READY, KDB_S_IN_BATCH, KDB_S_IN_ZONE, KDB_S_ERROR } kdb_state_t;

typedef struct {
    kdb_limits_t lim;
    kdb_state_t state;
    bool inventory_req_seen, batch_seen;
    uint64_t batch_id;
    uint64_t n_zones, n_failed, n_deleted;     /* of the current batch (zones = completed by ZONE_END) */
    uint32_t n_profiles;                       /* of the current batch */
    bool man_open;                             /* 0.7 WP7a: inside a MANIFEST pass (MANIFEST_BEGIN seen, MANIFEST_END not yet) */
    bool man_deferred;                         /* 0.7 M2: the pages of a pass are handed to the reconcile thread (kdb_sm_legal_frame() only, no decode here) and checked there (kdb_man_t): the sum of MANIFEST_END is not checked here */
    uint16_t man_view;
    uint32_t man_page;                         /* the next page number */
    uint64_t man_entries;                      /* entries seen in this pass */
    /* current zone, valid in IN_ZONE */
    uint64_t zone_rr_declared;                 /* ZONE_BEGIN rr_count */
    bool zone_image;                           /* the zone being received is an image (ZONE_BEGIN flag KDB_ZF_IMAGE) */
    uint64_t zone_image_size;                  /* ... its announced size (ZONE_BEGIN tag 23) */
    uint64_t zone_image_have;                  /* ... the octets of ZONE_IMAGE messages so far; at most zone_image_size, equal to it at ZONE_END */
    bool fetch;                                /* D1a: the fetch stream (kdb_sm_init_fetch()) */
    uint64_t zone_req_id;                      /* fetch stream: the request id of the zone being received (ZONE_BEGIN tag 11) */
    kdb_rc_t fail;
    char reason[KDB_REASON_LEN];
} kdb_sm_t;

void kdb_sm_init(kdb_sm_t *sm, const kdb_limits_t *lim);   /* lim == NULL: defaults, KDB_VIEWS_ANY */
/* The state machine of the fetch stream (D1a): starts in READY, accepts PROFILE / ZONE_BEGIN / ZONE_FAILED there and ZONE_IMAGE /
 * ZONE_END / ZONE_ABORT in a zone; every ZONE_BEGIN and ZONE_FAILED carries a request id; summaries are allowed.  After ZONE_END,
 * ZONE_ABORT and ZONE_FAILED the machine is READY again and the profile count starts again. */
void kdb_sm_init_fetch(kdb_sm_t *sm, const kdb_limits_t *lim);
/* Validate one frame from the loader against the current state, decode it, apply the semantic checks.  KDB_OK:
 * *msg is valid and the state advanced.  KDB_E_*: protocol error; the state is KDB_S_ERROR (sticky) and
 * sm->reason says why.  An error leaves any partial zone to be discarded by the caller. */
kdb_rc_t kdb_sm_accept(kdb_sm_t *sm, const kdb_frame_t *fr, kdb_msg_t *msg);
/* 0.7 M2: the first half of kdb_sm_accept(): is a frame of this type allowed in the state (nothing of the frame is decoded).  KDB_OK, or KDB_E_STATE with the state set to KDB_S_ERROR and the reason, as
 * kdb_sm_accept() does for the same frame; the state is not advanced.  The stream thread of the Backend uses it for the pages of a pass (MANIFEST), which it copies to the reconcile thread undecoded. */
kdb_rc_t kdb_sm_legal_frame(kdb_sm_t *sm, uint16_t type);
/* from now on the pages of a pass are not offered to kdb_sm_accept() (see man_deferred); BATCH_END's zone count is then the caller's to add (sm->n_zones) */
void kdb_sm_defer_manifest(kdb_sm_t *sm);
/* What the reconcile thread does with the pages the stream thread copied: decode and check them against the pass's MANIFEST_BEGIN, in the order they came (the rules of kdb_sm_accept()), and the sum at
 * MANIFEST_END.  A KDB_E_* is a protocol error of the loader as any other (why says the rule, never bytes of the stream). */
typedef struct { uint64_t batch_id; uint16_t view; uint32_t page; uint64_t entries; uint32_t view_count; } kdb_man_t;
void kdb_man_begin(kdb_man_t *a, uint64_t batch_id, uint16_t view, uint32_t view_count);
kdb_rc_t kdb_man_page(kdb_man_t *a, const kdb_frame_t *fr, kdb_msg_t *m, char *why, size_t whylen);
kdb_rc_t kdb_man_end(const kdb_man_t *a, const kdb_manifest_end_t *e, char *why, size_t whylen);

#endif
