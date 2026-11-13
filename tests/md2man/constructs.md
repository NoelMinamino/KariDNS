# EXAMPLE-TOOL(8) — KariDNS Reference Manual

```text
EXAMPLE-TOOL(8)                 KariDNS Manual                 EXAMPLE-TOOL(8)
```

---

## NAME

**example-tool** — a tool that shows every construct of the manuals

---

## SYNOPSIS

```sh
example-tool [-c config] [--check] <zone>
```

## DESCRIPTION

A paragraph with `code`, **bold**, *italic*, ***both***, **bold with `code` inside**, a [link to a manual](karictl.md),
a [link to a site](https://www.example.org/docs) and <https://www.example.net/> on two lines, `-c` and --check, a
file db/*.sql that stays as it is, an escaped \* star and a \| pipe.

### A subsection

1. the first step
2. the second step, with a nested list:
   - a bullet
   - another bullet
3. the third step

- an item
  with a lazy continuation

  and a second paragraph

  ```sh
  example-tool --check
  ```
- a last item

> [!WARNING]
> A callout of two
> lines.

> A plain quote.

## OPTIONS

`-c` *file*
: The configuration file.

  A second paragraph of the option.

`--check`
: Check and exit.

## TABLES

| Name | Value |
|---|---:|
| a | 1 |
| `b-c` | 22 |

| Column one | Column two | Column three |
|---|---|---|
| short | a cell with a long text that has to be wrapped inside the table because the table would be too wide otherwise | x |
| another | more words | y |

| Option | Default | Description |
|---|---|---|
| `user "<name>";` | none | A cell so long that the table cannot stay a table in an eighty column terminal: it says the same thing again and again, it says the same thing again and again, it says the same thing again and again, it says the same thing again and again, it says the same thing again and again, it says the same thing again and again, it says the same thing again and again, it says the same thing again and again. |
| `port <n>;` | 53 | The port. |

## SEE ALSO

- [`karictl(8)`](karictl.md) — the control utility

```text
KariDNS                         September 2026                 EXAMPLE-TOOL(8)
```
