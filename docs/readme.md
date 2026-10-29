# NeoZen Documentation (Zensical)

This directory holds the NeoZen documentation, built with [Zensical](https://github.com/zensical/zensical).

## Directory Structure

```
docs/
├── src/            # Documentation source files (Markdown), and their assets
│   ├── pdf/        # The home page deck (generated from slides/, committed)
│   └── assets/og/  # The card a shared link shows (generated, committed)
├── slides/         # Source of the home page deck (Marp Markdown)
├── overrides/      # Theme template overrides
├── site/           # Generated output (not committed)
├── zensical.toml   # Site configuration and navigation
└── Makefile        # Build commands
```

## Building

```bash
make build    # Build the site into site/
make serve    # Start a local server, with live reload
make clean    # Remove the generated site
```

A new page must also be listed in `nav` in `zensical.toml`.

## The deck

The home page shows "NeoZen, in six slides": `src/pdf/neozen.pdf`, displayed a slide at a time by `src/javascripts/deck.js` (pdf.js, loaded from jsDelivr only on that page). Its source is `slides/neozen.md`, a [Marp](https://marp.app/) deck. After editing it, run `make slides` (needs `marp`, from `npm install -g @marp-team/marp-cli`, and Chrome) and commit the new PDF. `make build` then redraws the Open Graph card from its first slide (needs `pdftoppm`, from poppler).
