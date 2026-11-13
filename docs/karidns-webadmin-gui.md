# KARIDNS WEBADMIN WEB INTERFACE — user manual

## NAME

**The KariDNS web interface** — the screens of `karidns-webadmin`, for the people who look after zones: how to sign in, find a zone, change records safely, bring the servers up to date, go back to an earlier version, and (for global masters) look after users and permissions.

## OVERVIEW

The web interface is a page in your browser that talks to the API of [`karidns-webadmin`](karidns-webadmin.md). It shows what the API answers and sends what you ask for; it keeps no data of its own. Open the address your administrator gave you (for example `https://dns-admin.example.test/`).

- **Languages.** English and Japanese. The page follows the language of your browser; change it under *Your account*, *Language*. Names, record data and codes are never translated.
- **Browsers.** Firefox ESR, Chrome and Edge (the current and the previous version), Safari 17 or newer. Nothing needs to be installed. The page needs JavaScript and shows nothing without it.
- **The menu** (top of every page): Home, Zones, Templates, Servers, Administration (global masters only), Audit log (global and domain masters), Account, About. *Skip to the content* is the first thing the Tab key reaches.
- **What you see depends on your role.** Hiding a button is only a hint; the service decides every time, and a refusal is shown in words (see MESSAGES AND WHAT TO DO).

| Role | What the screens give you |
|---|---|
| **Global master** | everything: all zones, new zones and deleting zones, zone settings and metadata, templates (write), users, groups, record policies and grants, the whole audit log, reset of another user's two-step verification, the update of a whole dataset |
| **Domain master** (one or more zones) | the records of its zones within its record policy, preview and commit, import and export, versions and rollback, applying a template, the update button, DNSSEC (view and key requests), the grants on its zones, the audit log of its zones |
| **Subdomain master** (a suffix of a zone) | the names under its suffix (and the apex SOA and NS, read only), editing within its policy, the versions (its part of each change), the update button; no import, export, DNSSEC, audit log or grants |
| **Everyone** | your account: password, two-step verification, API tokens, language, signing out |

A person can hold several grants (on several zones, or through groups). The zone list shows the role on each zone; the start page lists every grant with its record policy.

## SIGNING IN

**Sign in** asks for the user name and the password. When your account uses two-step verification the page asks for the 6-digit code of your authenticator app (or press *I have a code* first). The service gives **one answer for every refusal** — wrong name, wrong password, wrong code, a disabled or locked account — so the page cannot tell you which it was. If the service says *Too many requests*, the button counts down and works again by itself. A password is never kept by the page, and nothing is filled in from the address.

*Sign in with ...* buttons below the form (one for each identity provider your administrator set up) leave the page, let the provider check you, and bring you back to the page you were on. If it did not work you see one message ("The sign-in with the identity provider was not accepted..."): an identity must be linked to your user by a global master first, and the reason is in the service's log, not on the screen. Someone whose account has two-step verification is asked for the code on a page of its own after a provider (unless the provider vouches for two factors itself).

**Set up two-step verification.** If your account must use it (the first sign-in of a global master, by default) you can do nothing else until it is on. Scan the QR code with an authenticator app, or press *Show the key as text* and type the key in; then type the 6-digit code the app shows now and press *Confirm*. The key is shown **once**: the page removes it as soon as you confirm. Do not share your screen while it is shown. The same page is under *Your account* when you want to turn it on yourself.

**Your session.** The page never asks the service anything on its own, so the idle time means what it says. Two minutes before the end a window counts down; *Stay signed in* is one request that moves the end. At the absolute time limit of a session there is no *Stay signed in*: finish and sign in again. When the session is over (the idle time, a sign-out in another tab, an administrator) the sign-in opens **over** what you were doing. If you are the same person the page goes on, and your unsaved changes (see CHANGING RECORDS) are still there; a different person starts at the start page, and the changes are dropped. A sign-out in one tab signs out all tabs of the browser.

## THE START PAGE

*Home* greets you and lists what you may do: one row for each grant with your role, the zones it covers (*All zones*, a zone, or a suffix of a zone), your record policy (the types, the TTL range, wildcards, delegations, DNAME, the apex, the most records) and the group the grant comes through. With no row you have no access yet: ask a global master.

## ZONES

**Zones** lists the zones you may see: the name, your role, the kind, the serial and notes (*kept signed by the signer*, *signed elsewhere*, *catalog ...*). Search by a part of the name or its start (letters, digits, dots, hyphens, underscores), by kind and by signed or not. When the service has more than one dataset there is a dataset selector. The list is paged: *Next page* and *First page*; the page never shows totals. A global master also sees **New zone** and **Update every zone of this dataset** (PostgreSQL).

**A zone** has a header (kind, serial, generation, when it last changed, the signer's state, the last reload request, your role and record policy) and sections: *Records*, *Versions*, *Import*, *Template*, *Settings*, *DNSSEC*, *Grants*, and a link *Export (zone file)*. The sections you may not use are not shown.

**The records** are shown a page at a time, as *record sets* (all the records with the same name and type). Names are relative to the zone (`www`, `@` for the zone itself); hover for the absolute name. Search by a part of the owner name (*Name contains*), from a name (*Start at name*), by type, and choose how many record sets a page (25 to 500). Each record is shown in the **text form a change takes**: names inside the data are absolute (they end with a dot), MX and SRV start with their numbers, for example:

```records
www 300 A 192.0.2.10
@ 3600 MX 10 mail.example.test.
_sip._tcp 300 SRV 10 60 5060 sip.example.test.
```

**Text and bytes.** Zone data is shown as text and never as anything else. A byte that is not printable ASCII is written the way a zone file writes it, as a backslash and three decimal digits: the letter é (the two bytes C3 A9 in UTF-8) in a TXT record is shown and kept as `\195\169`, and in a quoted string the letter itself and `959` are two ways to write the same two bytes (RFC 1035 section 5.1: `DDD` is the octet with that decimal value). A control character in a name or a comment is shown the same way (`\007`); an invisible character that reorders or hides text (a right-to-left override, a zero-width space) is shown as a marker such as `<U+202E>` in a distinct style, so that a record cannot make the page lie. Nothing in a record, a name or a comment is ever a link, and the page runs none of it.

A record set you may not edit says why, in its State column: the zone is not a primary zone; the zone is signed elsewhere; the signer makes the DNSSEC records; it has location or ECS tags (change those with `karidns-zone`); a record has no text form or is switched off; the type is not in your policy; the name is outside your part of the zone or at the apex; your policy does not allow the change. The **SOA** is shown and is edited only by a global master, in a form of its own (the service writes the next serial whatever you type).

## CHANGING RECORDS

Changes are collected in a **draft** (a *change set* in the making), looked at, and only then saved.

1. **Edit**, **Add a record set** or **Delete** puts an entry into *Your changes*. Each entry has *Undo* and *Edit*. The draft lives in the memory of the page only: nothing is stored in the browser, closing the tab loses it, and the page asks before it is left while a draft exists.
2. In the editor (press *Add to the changes* when you are done), *Name* is relative to the zone (`www`), `@` for the zone itself, or a full name with a final dot. *Records* are one record a line, in zone file syntax. *TTL* is in seconds; your policy's range is shown.
3. **Preview** is a dry run: nothing is saved. It shows the diff (per record set, what it was and what it would be, with `+` and `-` as well as colour), the messages of the zone checks with their codes (a message about a record is shown at that record), and the version and serial the change would get. A diff of more than 200 record sets is shown in pages of 200. Preview again after any change: the **Commit** button waits for a preview of exactly this draft.
4. **Commit** saves the change with a precondition: the records as you loaded them. It is one version of the zone, with your *Comment* (optional, kept in the history). The box *Update the servers after saving* is ticked as the administrator configured it.

**Conflicts.** If somebody changed a record set after you loaded it, Commit or Preview answers *The records were changed by someone else after you loaded them* and the page shows, for each record set, **what you loaded**, **what is there now** and **your change**. *Take theirs* drops your entry and reads the zone again; *Keep mine* keeps your change and makes the present state the new precondition (preview again). A refusal because the zone kept changing (*The zone was changed by someone else while this was done*) just means: look at it again.

**Refusals are told where they belong.** A message of the zone checks stands at its record; a field the service names (a name that is not a host name, a TTL outside your policy) is marked with the reason; *You are not allowed to do this* names the record set that no grant allows; *This would give you more records than your policy allows* is your policy's limit. The buttons wait the number of seconds the service asks for after *Too many requests*.

## THE UPDATE BUTTON AND THE SERVERS

A saved change is **in the database**; the servers serve it after a reload, which is explicit. *Update the servers now* (section *Records*) asks every server that reads the database to load the zone again. For a zone the **signer** keeps there is no button: the signer asks for the reload when it has signed the change, and the page says so (*waiting for the signer*). After a request the page looks at the zone and at the servers every 5 seconds for at most two minutes and says how many servers have loaded the change (*3 of 4 servers have loaded the change*); with SQLite3 there is no server status and it asks nothing more. This is the only polling the page does, and it extends your session like any request.

**Servers** shows, for every dataset and server, the generation it has applied, when, whether every zone loaded, and the zones that did not. *Refresh* asks again.

## NEW ZONE, IMPORT, EXPORT, SETTINGS

**New zone** (global masters; *Zones*, *New zone*) is made from *a form* (the SOA values, name servers, more records written as `name [ttl] TYPE data`), *a template* (its values are the defaults of the form) or *a zone file* (typed, pasted or read from a file of your computer). The preview shows the whole new zone; *Create the zone* goes to its page.

```records
www 300 A 192.0.2.10
www 300 AAAA 2001:db8::10
mail 3600 MX 10 mx1.example.test.
```

**Import** (the masters of the whole zone; section *Import*) takes a zone file in BIND format (plain records; no DNSSEC records, no `$INCLUDE` or `$GENERATE`) in one of two modes: *Replace* (the zone becomes the file) or *Merge* (only the record sets in the file are replaced). A file is read as strict UTF-8; a file in another encoding is refused with the hint to save it as UTF-8 and write other bytes as `\DDD`. The size is checked before anything is sent (16 MiB). Preview first; nothing is saved until you commit.

**Export (zone file)** is a plain link: the browser saves the zone as a file. It is not offered to a subdomain master.

**Settings.** The attributes (kind, catalog zone, views, masters) and the **metadata** of the zone are changed by global masters; others read them. *Delete the zone* removes the zone with its records, metadata, keys, history and the grants on it, **for good**, and asks you to type the name of the zone again.

## VERSIONS AND ROLLBACK

Every saved change of a zone is a **version**: number, kind (*created*, *edit*, *template applied*, *import*, *rollback*), time, who made it (a person, or `operator (<database role>)` for a tool such as `karidns-zone import`), the comment, the serial and the number of record sets it changed. A zone keeps its newest 100 versions; the *audit log* is the complete record. A subdomain master sees the part of each change that lies under its suffix.

For the masters of the whole zone the list marks **changes outside the versions**: something wrote to the database without going through `karidns-zone` (a tool such as `psql` or a PowerDNS utility). The marker names the record sets when the audit log knows them.

- **Open a version** to see the change it made, as the same diff the editor shows.
- **Compare**: version A with a later version, or with the zone as it is now (*Against the zone now*). Lines with `-` are the record sets after version A, lines with `+` the other end.
- **Roll back to version N** is a new change that puts every record set that later versions changed back as it was after version N. *Preview the rollback* first (how many record sets would be restored and how many versions undone; the SOA is not restored, because its serial only grows), then *Roll back*. A record set that something outside the versions changed is a **conflict**: the commit stays off and a table lists each one (*As the newest version left it* and *Now*). The way on is the second question *Roll back anyway and overwrite these*, which names how many record sets it overwrites; answering Yes commits once with `force`. A conflict that appears only when you commit (a write between your preview and your commit) is shown the same way, and nothing was saved.
- A rollback of a signed zone is signed again by the signer. `karictl rollback` (the server's memory, for emergencies) and this rollback (the database, durable) are different things: see the [API reference](karidns-api.md).

## TEMPLATES

A **template** is a named set of records copied into a zone, once; nothing links the zone to it afterwards. Everybody reads templates; global masters write them. A template has a name, a description, **SOA defaults** and its records, written one a line as `owner [TTL] TYPE data` (`@` is the zone itself; a name without a final dot is relative to the zone it is copied into; lines that begin with `;` are ignored):

```records
@ 3600 NS ns1.example.test.
@ 3600 NS ns2.example.test.
www 300 A 192.0.2.10
mail 300 AAAA 2001:db8::25
```

*Check* is a dry run of the zone checks (`karicheck`); a refusal is shown with the line of each record. *Check again* re-runs the checks of a saved template as of now. Deleting asks first.

In the section *Template* of a zone (the masters of the whole zone), *Apply a template* replaces the zone's record sets of the same name and type with the template's; the others stay. Preview shows what would be overwritten; to undo it, roll back to the version before.

## DNSSEC

Section *DNSSEC* (domain and global masters) shows how the zone is signed: kept signed by `karidns-signer`, signed elsewhere (served as it is) or not signed; for a zone the signer keeps, when it last signed, the serial, when the next signing is due, **the time left until the first signature expires** (this is the number to watch) and the last error of the signer as text. *Keys* lists the DNSKEY records with their key tags. **DS records for the parent zone** are computed from the keys with the SEP flag (digest type 2 is SHA-256, 4 is SHA-384), each with a *Copy* button: give one to the operator of the parent zone. *Key requests* shows what was asked of the signer and its answer; the form asks for *Start signing this zone* or *Add one more key* (algorithm, key size for RSA, key type, NSEC or NSEC3). The signer makes the keys and signs; this only asks it, one request at a time.

## ADMINISTRATION

*Administration* is for global masters: the menu entry is theirs only, and anybody else who opens its address sees a notice (and the page asks the service nothing).

- **Users** and **Groups**: search by the start of the name, *New user* (with a first password of at least 12 characters, not containing the user name) or *New group*. The page of one user or group has its name, display name, e-mail address and *Disabled* (a disabled user is signed out and loses its tokens). You cannot disable or delete yourself.
- **Signing in** (on the page of a user): whether a password is set, whether two-step verification is on, the failed attempts and the lock. **Unlock the account** clears the attempts and the lock; **Reset two-step verification** is for a user who lost the device: it is switched off and the user's sessions end (where the configuration requires it, the user enrols again at the next sign-in). You cannot reset your own: switch it off from your account, or ask another global master. *New password* sets a password and ends the user's sessions. Each of these asks first.
- **Identity at a provider**: *Link the identity* ties the user to an issuer and a **subject** (the `sub` of the ID token). Nobody is made by a sign-in, and an unlinked identity is refused. When a sign-in is refused because nobody is linked, the subject is in the service's log. Linking another identity, or removing the link, signs the user out.
- **Member of / Members**: a user is in groups; a group has members, added by exact name (groups nest) and removed after a question. Members have the grants of the group.

On the grants page of a zone, a domain master finds the user or group to give a grant to by its exact name, but only among the principals it can see: itself, its groups and their members, and those who already hold a grant on this zone (a holder of another of its zones is not enough). For anybody else the page says "No user or group has this name"; a global master adds the new person to one of the domain master's groups or gives it a grant first.
- **Record policies**: which types, whether wildcards, delegations, DNAME and the apex are allowed, the TTL range and the most records. A policy that is in use cannot be deleted.
- **Grants**: a grant gives a user or group a role (domain master or subdomain master on a zone, with a suffix for the latter; global master) with a record policy. The page lists all grants with a filter by user and by zone; removing a grant asks first.

**Grants of a zone** (section *Grants* of a zone, for its domain masters and global masters) lists who may read or write the zone and has the form to give a grant on it. A domain master may give domain-master and subdomain-master grants on **its** zone with a policy **no wider than its own**: the form offers the policies that look so, and the service decides (*A grant may not give more than you have yourself*).

## AUDIT LOG

*Audit log* (global masters: everything; domain masters: the rows of their zones) shows every change of the data and of the permissions, newest first, 100 a page. Filters: zone, user or group (by name), change set, table, and a time range (`since`, `until`, ISO 8601 such as `2026-11-08T12:00:00Z`). A row shows when, who (a person, or the database role of a tool), the table and what (added, changed, deleted), the zone and the change set. *all rows* lists the rows of the same change; *version* opens the versions of the zone with that version marked. *Row N* opens the details: the source, the database role and the row as it was **before** and **after**, as pretty-printed text (cut at 20,000 characters). What is in them was written by other people, and is shown like any other zone data.

## YOUR ACCOUNT

- **Change password**: the current password and the new one twice (at least 12 characters, not containing your user name). *Sign out my other sessions* is ticked by default. An account that signs in with an identity provider only has no password form.
- **Two-step verification**: turn it on (the QR code page) or off (password and a code). Where the configuration requires it, it cannot be switched off. An account with no password gives the code alone.
- **Identity provider**: the identity your user is linked to, read only (a global master links and unlinks).
- **API tokens**: a program can use the API as you without a password. *Make a token* (a name; valid for 1 to 365 days; *Read only* for tokens that must not change anything). The token is shown **once**, with a *Copy* button and a warning; it leaves the page when you press *I have saved it*. A token can be revoked after a question.
- **Language** (applied at once) and **Session** (when it ends at the latest, the idle time; *Log out*, *Log out everywhere*).

## ABOUT

*About* shows the versions of the web interface, the service, `karidns-zone` and `karicheck`, the datasets and the record types the service takes. If the service was upgraded while your page was open, the page says *The service has been updated. Reload the page to use the new version.* with a button.

## ACCESSIBILITY

The page is built to meet WCAG 2.1 level AA (not certified): real buttons, links, labels and tables, everything by keyboard (the focus is always visible; dialogs trap it and give it back; *Escape* closes a dialog), results and errors announced to screen readers, errors tied to their fields, contrast of at least 4.5:1 for text and 3:1 for the edges of controls, no information by colour alone (a diff has `+` and `-`, a badge has words), the layout works at 200 % zoom and in a window 320 pixels wide, and animation respects *reduce motion*. The checklist, with how each point is checked and the manual check for Chrome, Edge and Safari, is in [karidns-webadmin-gui-checklist.md](karidns-webadmin-gui-checklist.md).

## MESSAGES AND WHAT TO DO

The messages of the service are in the language of the page. The text is the page's own, not the service's, so it is the same for the same cause. What to do:

| Message | What it means, and what to do |
|---|---|
| `The user name, the password or the code is wrong.` | One message for every refusal. Check the name, the password and the code (a code is good once; wait for the next one). A disabled or locked account looks the same: ask a global master. Every code refused although the app shows the right one: the clock of the server is more than about 30 seconds off (a code is accepted one 30-second step either side); the page cannot tell this from a wrong code, so tell the operator (the server clock must be right, `ntpd`). |
| `Too many requests. Wait a moment and try again.` | A rate limit. The button counts down. If it keeps happening, something else is also using your account. |
| `You are not signed in.` | The session ended. The sign-in opens over the page; sign in and go on. |
| `The request was refused as unsafe. Reload the page and try again.` | The page and the session did not match (a session replaced in another tab). Reload. |
| `You are not allowed to do this.` | No grant of yours allows exactly this change. The record set is named at its entry; look at your role and record policy on the zone page. |
| `This would give you more records than your policy allows.` | Your policy has a limit on the number of records in your part of the zone. |
| `A grant may not give more than you have yourself.` | Choose a policy no wider than your own. |
| `There is no such object, or you may not see it.` | The zone or object does not exist for you. It may have been deleted, or you have no grant. |
| `The records were changed by someone else after you loaded them.` | A conflict: choose *Take theirs* or *Keep mine* for each record set, then preview again. |
| `The zone was changed by someone else while this was done. Look at it again.` | Reload the page of the zone and redo the change. |
| `The zone checks refuse this change.` | The checks (`karicheck`) found an error in the result; the messages stand at their records. Fix them and preview again. |
| `This zone cannot be edited here.` | The zone is not a primary zone. Change it where it is made. |
| `This zone is signed elsewhere and cannot be edited here.` | The zone is served as it was signed. Change it at its source and import it. |
| `This record set has location tags and cannot be edited here.` | Change it with `karidns-zone` or the zone file. |
| `The signer keeps this zone; the server is updated when the signer has signed the change.` | No button is needed. The servers load the zone after the signer has signed. |
| `The change was saved, but the servers could not be told to reload.` | The data is saved; use *Update the servers now* again, or ask the operator. |
| `Some record sets were changed after the versions you undo.` | A rollback conflict: look at the table and decide (see VERSIONS AND ROLLBACK). |
| `A version in this range was too big to keep its record sets.` | The history cannot show or follow this range. Use the audit log. |
| `An object with this name exists already.` | Choose another name. |
| `The object is still in use.` | A policy or a template is used elsewhere; remove the use first. |
| `You cannot do this to yourself.` | You cannot disable, delete or reset the two-step verification of your own account here. |
| `The password must have at least 12 characters and must not contain your user name.` | Choose a longer password. |
| `Two-step verification is required for your account and cannot be switched off.` | By the configuration of the service. |
| `The service cannot be reached. Check the connection and try again.` | The network, a proxy or the service is down. |
| `The service did not answer in time. Try again.` | A busy service or database. Wait and try again. |
| `The service is busy. Try again in a moment.` | The service is protecting itself; the button waits. |
| `The database cannot be reached. Try again in a moment.` | Tell the operator if it lasts. |
| `The service had an internal error.` | A bug or a fault. Give the number shown with it (*Give this number to the operator*) to the operator: it finds the line in the log. |
| `The sign-in with the identity provider was not accepted. Try again, sign in with your password if you have one, or ask an administrator.` | Your identity is not linked to a user, the account is disabled, or the provider refused. The reason is in the service's log. |
| `The identity provider cannot be reached right now. Try again in a moment.` | The provider or the network between the service and the provider. |
| `The browser blocked something on this page ({directive}). A proxy or an extension may be changing the page; the web interface will not work correctly.` | A proxy or a browser extension adds a script or a style to the page. Switch it off for this site; the operator must not let a proxy inject content. |

## MEASUREMENTS

Measured on 2026-11-09 with `tests/run_webadmin_gui_measure.sh` on the FreeBSD 15.1 build host (a jail with 4 vCPU on a shared machine; Firefox 160.0 headless through geckodriver; Node 24.22.1; the service on SQLite3 and the browser on the same host, so there is **no network time** in these numbers; one browser, the memory watchdog on). A zone of 100,000 records (`BIG=100000`). The driver polls every 100 ms, so a time is good to about 0.1 s; where a number has "median" it is the median of 3 runs (5 for reloads).

| What | Time |
|---|---|
| Size of the interface | 48 files, 391 KiB (no compression; the files are served from memory with strong entity tags) |
| First load to the sign-in form (nothing cached) | 0.3 to 0.4 s |
| A reload to the sign-in form (every file asked about again) | 0.12 to 0.13 s (median of 5) |
| Sign-in: click to the start page | 70 ms |
| Records of the zone of 100,000 records: address to 100 rows (the default page) | 110 ms |
| ...to 500 rows (the largest page) | 110 ms; the page holds 5,631 elements |
| Next page of 500 | 126 to 128 ms |
| A search by a part of the name (the whole zone is scanned) | 106 ms |
| **Preview** of one record set in that zone (a dry run: the zone is checked) | 1.0 s |
| **Commit** of one record set (checks, permissions, the write) | 1.1 s |
| Peak resident size of Firefox, geckodriver and the driver together | 2.2 GiB |

Almost all of the 1.0 s of a preview is the service, not the page: the same dry run asked of the API without a browser takes 0.46 s, and 0.92 s with the precondition (`expect`) that the page always sends, because `karidns-zone` reads the whole zone once for the check and once more for the precondition. The time therefore grows with the size of the zone, not with the size of the change (the service manual, [MEASUREMENTS](karidns-webadmin.md), has the API alone at 15 records, 1,000 and 100,000). Reading a page does not grow with the depth: a page of a big zone costs about the same at any place. On PostgreSQL reading costs more (190 ms for 500 record sets against 40 ms on SQLite3; the service manual has the numbers). Not measured: a slow network (the page is 391 KiB), a browser other than Firefox, a phone.

## GLOSSARY

English and Japanese terms as the two languages of the interface use them.

| English | 日本語 | Meaning |
|---|---|---|
| zone | ゾーン | a part of the name space served as one unit; for example `example.test` |
| record set (RRset) | レコードセット | all records with the same name and type; the unit of an edit |
| record | レコード | one resource record: a TTL and its data |
| dataset | データセット | one set of zones in the service (a database schema or a file) |
| change set | チェンジセット | the edits saved together as one version; the draft before it is saved is "your changes" |
| preview | プレビュー | a dry run: shows what a change would do and saves nothing |
| commit | 確定 | save the previewed change |
| changed outside the versions | バージョンを経由せずに変更 | a record set that something other than a change set changed: `psql`, a PowerDNS tool; a rollback would overwrite it |
| version | バージョン | one saved change of a zone, in its history |
| rollback | ロールバック | a new change that puts the zone back as it was after an earlier version |
| template | テンプレート | a named set of records copied into a zone |
| serial | シリアル | the SOA serial number of the zone |
| generation | 世代 | a counter of changes of the zone in the database; what a server reports as applied |
| servers | サーバー | the DNS servers that read the database; "update the servers" asks them to load again |
| signer | signer | `karidns-signer`, which keeps a zone signed |
| key tag | キータグ | the number that names a DNSSEC key in DS and RRSIG records |
| DS record | DS レコード | the record the parent zone holds for a signed child zone |
| global master | グローバルマスター | may do everything, in every zone and in the administration |
| domain master | ドメインマスター | looks after the whole of one or more zones |
| subdomain master | サブドメインマスター | looks after the names under a suffix of a zone |
| grant | 権限 | gives a user or group a role on a zone, or everywhere, with a record policy |
| record policy | レコードポリシー | what a grant may write: types, TTL range, wildcards, delegations, DNAME, the apex, the most records |
| user | ユーザー | a person or a service account that signs in |
| group | グループ | users and groups that share their grants |
| audit log | 監査ログ | the record of every change of the data and the permissions |
| two-step verification | 2 段階認証 | the 6-digit code of an authenticator app after the password |
| API token | API トークン | a secret that lets a program use the API as you |
| identity provider | ID プロバイダー | an OpenID Connect provider that signs people in |

## SEE ALSO

[Service manual](karidns-webadmin.md) (installing, the configuration, TLS and the reverse proxy, identity providers, security, measurements of the API), [API reference](karidns-api.md) (every endpoint, error and setting), [accessibility and browser checklist](karidns-webadmin-gui-checklist.md), [`karidns-zone(8)`](karidns-zone.md), [`karicheck(8)`](karicheck.md), [`karidns-signer(8)`](karidns-signer.md).
