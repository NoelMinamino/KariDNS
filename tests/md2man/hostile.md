# HOSTILE(1) — text that roff would take for its own

## NAME

**hostile** — every line here would be a request or an escape without the converter

## DESCRIPTION

.TH FAKE 1 a line that starts with a dot
'br a line that starts with an apostrophe
.\" a roff comment
text with \fBa font escape\fR, \(em, \e, \\ and a backslash at the end \
and "double quotes", tabs	inside, and characters outside ASCII: é — ✓ 日本

- .SH an item that starts with a dot
- 'item with an apostrophe

```
.SH inside a code block
'apostrophe in code
\fB backslash in code
-  --options-in-code

	a tab-indented line
```

## .SH "A HEADING" WITH A DOT AND "QUOTES"

| .cell | _ |
|---|---|
| = | T{ |
| \| | `.x` |

| Key | Text that is wrapped in a text block of tbl |
|---|---|
| a | T} T} T} T} T} T} T} T} T} T} T} T} T} T} T} T} T} T} T} T} T} T} T} T} T} T} T} T} T} T} T} T} T} T} T} T} T} T} T} T} T} T} T} T} T} T} T} T} T} T} |

term with .dot
: .SH a definition that starts with a dot
