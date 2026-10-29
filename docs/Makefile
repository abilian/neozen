# NeoZen Documentation - Zensical Build

ZENSICAL := uv run zensical

.PHONY: help build serve slides clean

help:
	@echo "NeoZen Documentation (Zensical)"
	@echo ""
	@echo "Commands:"
	@echo "  make build    - Build the documentation site"
	@echo "  make serve    - Start local development server"
	@echo "  make slides   - Redraw the home page deck from slides/neozen.md"
	@echo "  make clean    - Remove generated files"
	@echo ""

# The home page deck. Committed, and redrawn (marp, which drives a headless
# Chrome) only when its source is newer.
DECK := src/pdf/neozen.pdf

$(DECK): slides/neozen.md
	@mkdir -p $(dir $@)
	marp --no-stdin --html --pdf --allow-local-files $< -o $@

slides: $(DECK)

# The Open Graph card a shared link shows: the deck's first slide. Committed,
# and redrawn (pdftoppm, from poppler) only when the deck is newer.
OG_CARD := src/assets/og/card.jpg

$(OG_CARD): $(DECK)
	@mkdir -p $(dir $@)
	pdftoppm -f 1 -l 1 -singlefile -jpeg -jpegopt quality=85 -scale-to-x 1200 -scale-to-y -1 $< $(basename $@)

build: $(OG_CARD)
	$(ZENSICAL) build --strict

serve:
	$(ZENSICAL) serve --open

clean:
	rm -rf site/
