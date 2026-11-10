# KARIDNS WEBADMIN WEB INTERFACE — accessibility and browser checklist

## NAME

**Accessibility and browser checklist** of the web interface of `karidns-webadmin` ([user manual](karidns-webadmin-gui.md)): the WCAG 2.1 level AA checklist with how each point is met and checked, and the manual check for Chrome, Edge and Safari that the maintainer runs before a release. Only Firefox is automated.

## WHAT IS CLAIMED

The interface is built to meet **WCAG 2.1 level AA**. It is not certified: no audit by a third party, no test with people who use assistive technology, no test with a screen reader by the project (part 4 below says how to do one). The browsers are Firefox ESR (the two current ESR lines), Chrome and Edge (current and previous), Safari 17 or newer; Firefox is run by the tests, the others by part 3.

## 1. THE WCAG 2.1 AA CHECKLIST

"Script" means a check that runs in the tests: **U** = `webadmin/test/ui_review.test.js` or another unit test (Node, fake DOM, `tests/run_webadmin_unit_test.sh`); **B** = the browser tests (`webadmin/test/e2e/a11y.mjs`, run in every screen the scenarios open, and the scenarios themselves: `tests/run_webadmin_gui_test.sh`, `tests/run_webadmin_gui_pg_test.sh`). "Manual" is part 2 or 3.

| SC | Name | Status | How it is met, and how it is checked |
|---|---|---|---|
| 1.1.1 | Non-text content | Met | The only image is the QR code (an `svg` with `role="img"` and a label; the key is also available as text). B: every image has a name. |
| 1.2.1 to 1.2.5 | Time-based media | Not applicable | No audio, no video. |
| 1.3.1 | Info and relationships | Met | Real `button`, `a`, `table` with `th scope`, `label for`, `fieldset` / `legend`, lists, landmarks (`header`, `nav` with a name, `main`, `footer`), one `h1` per screen and headings that do not skip a level. B: labels, names, `th scope`, one `h1`, no skipped level. |
| 1.3.2 | Meaningful sequence | Met | The order of the document is the order on the screen. Manual (2.1, 2.2). |
| 1.3.3 | Sensory characteristics | Met | No instruction depends on shape, colour or place alone. Manual (2.7). |
| 1.3.4 | Orientation | Met | No orientation is locked. |
| 1.3.5 | Identify input purpose | Met | `autocomplete` is `username`, `current-password`, `new-password`, `one-time-code`. B: every password field has one. |
| 1.4.1 | Use of colour | Met | Links are underlined; a diff has `+` and `-`; a badge has words; an invalid field has a message as well as a border; a conflict says so. Manual (2.5). |
| 1.4.2 | Audio control | Not applicable | No audio. |
| 1.4.3 | Contrast (minimum) | Met | 4.5:1 for every pair of text and background in the light and the dark scheme. U: the colours are read from `app.css` and the ratio of 16 pairs in each scheme is computed. |
| 1.4.4 | Resize text | Met | Sizes are in `rem`; nothing has a fixed height. U: no font size in pixels. Manual (2.4). |
| 1.4.5 | Images of text | Met | No text is drawn as an image. |
| 1.4.10 | Reflow | Met | The page is laid out in 320 CSS pixels with nothing but a data table or a block of code reaching past the right edge (they scroll). B: the sign-in, the start page, the account, the zone list, a zone, the versions, the users and the audit log are measured in 320 px (the root element is given that width; Firefox will not make a window narrower than about 490 px). |
| 1.4.11 | Non-text contrast | Met | 3:1 for the border of a field and a button, the focus ring, the frame of a secret, the selected tab. U: 12 pairs in each scheme. |
| 1.4.12 | Text spacing | Met | No fixed heights or widths on text; long words wrap (`overflow-wrap: anywhere`). Manual (2.4). |
| 1.4.13 | Content on hover or focus | Met | Nothing appears on hover or focus except the tooltips that the browser itself makes from `title` (the ISO time of a time, the absolute name of a name): the information is also in the text. |
| 2.1.1 | Keyboard | Met | Everything is a real control. B: the scenarios "the keyboard alone signs in and signs out" and "a record set is added and previewed without the mouse". |
| 2.1.2 | No keyboard trap | Met | A dialog is modal (`showModal`): the focus stays in it and returns where it was when it closes; Escape closes it. U: Escape closes the sign-in dialog (`ui_views.test.js`). Manual (2.2). |
| 2.1.4 | Character key shortcuts | Not applicable | There are none. |
| 2.2.1 | Timing adjustable | Met | The idle timeout warns two minutes before the end and *Stay signed in* extends it. The absolute limit of a session cannot be extended (a security rule); the window says so and tells when. B: the idle warning scenario. |
| 2.2.2 | Pause, stop, hide | Met | Nothing moves. The countdown in the session warning and the status line after *Update the servers* (5 s, at most two minutes) are updates the person started or needs, and stop by themselves. |
| 2.3.1 | Three flashes | Met | Nothing flashes. |
| 2.4.1 | Bypass blocks | Met | *Skip to the content* is the first stop of the Tab key; the landmarks. B: the keyboard scenario. |
| 2.4.2 | Page titled | Met | The title is the screen's name and the product (zone names are shown as text). B: every screen has a title. |
| 2.4.3 | Focus order | Met | The order of the document; after a change of screen the focus moves to the content; a dialog takes it and gives it back; the language choice keeps it on the control (`ui_views.test.js`). Manual (2.2). |
| 2.4.4 | Link purpose | Met | A link's text says where it goes; where the text is short (*all rows*, *Edit*, *Undo*) the accessible name adds the object. U: the name contains the visible text. |
| 2.4.5 | Multiple ways | Met | The menu, the search of every list, and links between related screens (a version to its audit rows and back). |
| 2.4.6 | Headings and labels | Met | A heading or label says what the screen or field is. B: one `h1`, no skipped level. |
| 2.4.7 | Focus visible | Met | A 3 px ring in a colour that has 3:1 against the page (`:focus-visible`); nothing removes the outline but `main` (focused by the script only). U: the rule is there. Manual (2.3). |
| 2.5.1 | Pointer gestures | Met | Click and keys only. |
| 2.5.2 | Pointer cancellation | Met | Actions run on `click`, after the button is released. |
| 2.5.3 | Label in name | Met | U: the accessible name of each control with a longer label contains its visible text, in both languages. B: the same on every screen the scenarios open. |
| 2.5.4 | Motion actuation | Not applicable | No function is triggered by moving the device. |
| 3.1.1 | Language of page | Met | `lang` of the page follows the chosen language. B: it is `en` or `ja`. |
| 3.1.2 | Language of parts | Met | The names of the languages in the language list are in their language (`lang`). Record data, names and codes are technical text and are not translated. Every error code has a message in both languages (`ui_scan.test.js`), so no English text of the service shows in Japanese. |
| 3.2.1 | On focus | Met | Nothing happens when a control gets the focus. |
| 3.2.2 | On input | Met | The language list changes the page at once; the hint under it says so. Nothing else changes the screen by input alone. |
| 3.2.3 | Consistent navigation | Met | One menu, one order. |
| 3.2.4 | Consistent identification | Met | One catalog of messages: the same thing has the same words (Preview, Commit, Undo). |
| 3.3.1 | Error identification | Met | A field with a mistake has `aria-invalid`, a message tied with `aria-describedby`, and gets the focus; the message is in a live region. B: the refusals told at the field. |
| 3.3.2 | Labels or instructions | Met | Every field has a label; hints state the rules (password length, name characters, time format). |
| 3.3.3 | Error suggestion | Met | A message says what to do; see MESSAGES AND WHAT TO DO in the manual. |
| 3.3.4 | Error prevention (legal, financial, data) | Met | A change is previewed before it is saved; deleting a zone asks for its name; deleting anything else, resetting two-step verification, unlocking, removing a grant and revoking a token ask first; a rollback over a change made outside the versions needs a second question. |
| 4.1.1 | Parsing | Met | The page is built with the DOM, not parsed from strings. B: no duplicate `id`, and every `aria-describedby`, `aria-labelledby` and `aria-controls` names an element that exists. |
| 4.1.2 | Name, role, value | Met | B: every button, link, field, open dialog and `nav` has a name; state is `aria-expanded`, `aria-current`, `aria-invalid`, `disabled`, `hidden`. |
| 4.1.3 | Status messages | Met | A polite and an assertive live region exist on every screen; results, counts, errors and timers use `role="status"` / `role="alert"`. B: both regions are present. |

## 2. MANUAL CHECK OF ONE BROWSER

Do this once in Firefox and once in each of Chrome, Edge and Safari before a release, on the version that is current. Use a test service with the sample data of the browser tests (a global master, a domain master, a zone `example.test`). Tick what works; write down what does not and the browser and version.

### 2.1 Pages and screens

1. Open the address. The sign-in form shows, in the language of the browser. No red banner at the bottom ("The browser blocked something on this page"). The console shows no error and no violation of the content security policy.
2. Sign in as a global master (enrol two-step verification if asked: the QR code is drawn, the key is hidden until asked for). The menu shows Home, Zones, Templates, Servers, Administration, Audit log, Your account, About.
3. Open each menu entry and one zone with each of its sections. Each screen has one heading, a title in the tab, and no horizontal scroll bar at the window widths of 2.4.
4. Sign in as a domain master and as a subdomain master: only their zones, their sections, and no Administration.
5. Reading order: with a screen reader or with the focus order (Tab), the order on a zone page is the header, the sections, the search, the records, the draft.

### 2.2 Keyboard

1. From the address bar press Tab: *Skip to the content* appears and works (the focus moves to the content).
2. Sign in, find a zone, open *Edit* on a record set, change it, *Add to the changes*, *Preview*, *Commit* — with the keyboard only. The focus is always visible, never lost to the top of the page, and returns to a sensible place after a dialog closes.
3. Open the session warning (wait for the idle time, or set `session-idle` low): the dialog has the focus, Tab stays inside, Escape closes it.
4. Choose the language with the arrow keys in the list: the page changes language and the focus stays on the list.
5. In a form with a text field, press Enter: it submits that form only. In a Japanese input method, confirming a conversion with Enter must **not** submit the form (check this in Safari in particular).

### 2.3 Focus and colour

1. The focus ring is visible on every kind of control: link, button, field, list, checkbox, the *details* arrow, a row button.
2. Switch the system to the dark scheme and back: the page follows; text is readable; the ring and the borders of fields are visible.
3. Windows *forced colors* / high contrast (Edge, Chrome, Firefox): borders and the focus ring stay visible.

### 2.4 Size and spacing

1. Browser zoom 200 %: nothing is cut off, no overlap, no horizontal scroll bar on the sign-in, the start page, a zone page, the versions or an edit dialog. At 400 % (a 320 px wide page) the same, but a table of records may scroll sideways.
2. Text spacing (the bookmarklet of the W3C "Text Spacing" or an extension: line height 1.5, paragraph 2, letter 0.12, word 0.16 of the font size): no text is clipped.
3. Set the minimum or default font size of the browser larger: the page follows it.

### 2.5 Colour is not the only signal

1. Switch the display to grey scale (or use the browser's emulation of colour blindness): a diff can still be read by its `+` and `-`, a conflict by its words, an invalid field by its message, the current menu entry by its weight and underline.

### 2.6 Things that differ between browsers

1. **Copy buttons** (the API token, a DS record): the text is copied. On a page that is not a secure context (`http` on a name other than `localhost`) the copy button reports that the browser did not allow it, and the text can be selected by hand.
2. **Import** with a file chosen from the computer: the file is read into the box; a file in another encoding than UTF-8 is refused with the hint.
3. **Export (zone file)** is saved as a file with the name the service gives; the session cookie went with it (a login is not asked).
4. **Two tabs**: *Log out* in one tab signs out the other (BroadcastChannel); *Log out everywhere* the same.
5. **Sign in with an identity provider** (needs a provider): the way back from the provider is a cross-site navigation, and the page then knows it is signed in at once, with no second sign-in (the cookie of the session is `SameSite=Strict`; plan assumption 10). Check it in Safari and in a Chrome with third-party cookie blocking on.
6. **Writes** work: every request that changes something sends the `Origin` header (assumption 1). A save that answers `The request was refused as unsafe` in one browser only is a sign that it does not.
7. **Trusted Types**: in Chrome and Edge the console shows no "This document requires 'TrustedHTML'" error; Firefox and Safari ignore the directive.
8. **Date and time** are in the language and the time zone of the browser; the ISO time is the tooltip.

### 2.7 Wording

1. Read each screen in both languages for instructions that point by position or look ("the button on the right", "the red field").

### 2.8 Record of a run

| Date | Browser and version | System | Person | Not working (numbers of the steps) |
|---|---|---|---|---|
| | | | | |

## 3. CHROME, EDGE AND SAFARI: THE SHORT LIST

If there is little time, these are the points that have a reason to differ from Firefox: 2.2 step 5 (Enter in an input method), 2.2 step 4 (the focus stays on the language list), 2.6 steps 1, 4, 5 and 6, and 2.4 step 1. Safari 17 is the oldest supported: `dialog`, `:focus-visible`, `BroadcastChannel` and `Intl.DateTimeFormat` are there; nothing is polyfilled.

## 4. WITH A SCREEN READER (NOT DONE BY THE PROJECT)

The tests cannot say whether a screen reader reads the page sensibly. The useful pairs are NVDA with Firefox, VoiceOver with Safari, and Narrator or JAWS with Edge. Go through: sign in; the start page; the zone list (the table is announced with its caption and headers); a zone page; the editor (the dialog is announced with its name, the fields with their labels and hints); a preview (the result is announced politely, a conflict assertively); the session warning (announced at once); a delete asking for the name. Report what is not read, read twice, or read in the wrong order.

## 5. KNOWN LIMITS

- The reflow test gives the root element the width of 320 pixels; a real 320 pixel window also changes the size of a dialog, which is checked by hand (2.4).
- The script cannot judge whether a text makes sense or whether the order is right; those are 2.1 and 2.2.
- The contrast is computed from the colours of the style sheet; text on a colour that the browser makes (selection, autofill, forced colours) is not.
- Record data, names and comments are shown as they are, in whatever language they are in, without a `lang`.

## SEE ALSO

[User manual](karidns-webadmin-gui.md), [service manual](karidns-webadmin.md) (browsers, the page's policy), `tests/TEST_MATRIX.md` (rows 303, 311, 312, 313).
