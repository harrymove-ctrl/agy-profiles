"""Static anti-slop guardrails for Web Console source and built static assets."""

from __future__ import annotations

from pathlib import Path
import re
import unittest

REPO_ROOT = Path(__file__).resolve().parent.parent
WEB_UI_SRC = REPO_ROOT / "web-ui" / "src"
WEB_STATIC = REPO_ROOT / "src" / "agy_profiles" / "web_static"

BANNED_SLOP_RE = re.compile(
    r"\b(?:unleash|seamlessly|revolutionize|next-gen|candlelit|botanical|leverage|delve|empower|streamline)\b",
    re.IGNORECASE,
)
PLURAL_PARENS_RE = re.compile(r"\b(?:lock|link|profile|item)\(s\)", re.IGNORECASE)


STRING_LITERAL_RE = re.compile(r'"([^"\\]*(?:\\.[^"\\]*)*)"|\'([^\'\\]*(?:\\.[^\'\\]*)*)\'|`([^`\\]*(?:\\.[^`\\]*)*)`')
JSX_TEXT_RE = re.compile(r">([^<>`\"'{}]+)<")


def _iter_ui_sources() -> list[Path]:
    paths: list[Path] = []
    for ext in ("*.ts", "*.tsx", "*.css"):
        for path in sorted(WEB_UI_SRC.rglob(ext)):
            rel = path.relative_to(WEB_UI_SRC)
            if path.name == "astryx-themes.ts" or rel.parts[0] == "themes":
                continue
            paths.append(path)
    themes_dir = WEB_UI_SRC.parent / "themes"
    if themes_dir.is_dir():
        for path in sorted(themes_dir.glob("*/*.theme.ts")):
            paths.append(path)
    return paths


class WebUiAntiSlopTests(unittest.TestCase):
    def test_no_dashes_slop_or_parens_plurals_in_ui_source(self) -> None:
        sources = _iter_ui_sources()
        self.assertGreater(len(sources), 0)
        for path in sources:
            text = path.read_text(encoding="utf-8")
            rel = path.relative_to(REPO_ROOT)
            self.assertNotIn("\u2014", text, f"Found em-dash in {rel}")
            self.assertNotIn("\u2013", text, f"Found en-dash in {rel}")
            for match in STRING_LITERAL_RE.finditer(text):
                literal = next(group for group in match.groups() if group is not None)
                self.assertNotIn(
                    " - ",
                    literal,
                    f"Found spaced hyphen inside string literal in {rel}: {literal!r}",
                )
            for match in JSX_TEXT_RE.finditer(text):
                jsx_text = match.group(1)
                self.assertNotIn(
                    " - ",
                    jsx_text,
                    f"Found spaced hyphen inside JSX text in {rel}: {jsx_text!r}",
                )
            self.assertIsNone(
                PLURAL_PARENS_RE.search(text),
                f"Found (s) plural template in {rel}",
            )
            self.assertIsNone(
                BANNED_SLOP_RE.search(text),
                f"Found banned slop word in {rel}",
            )

    def test_no_unsafe_html_or_nested_cards_in_tsx(self) -> None:
        for path in sorted(WEB_UI_SRC.rglob("*.tsx")):
            text = path.read_text(encoding="utf-8")
            rel = path.relative_to(REPO_ROOT)
            self.assertNotIn(
                "dangerouslySetInnerHTML",
                text,
                f"dangerouslySetInnerHTML forbidden in {rel}",
            )
            # Track `<Card` depth line-by-line so card-in-card nesting fails immediately.
            card_depth = 0
            for idx, line in enumerate(text.splitlines(), start=1):
                opens = len(re.findall(r"<Card\b", line))
                closes = len(re.findall(r"</Card>", line))
                if opens > 0 and card_depth > 0:
                    self.fail(f"Nested <Card> detected at {rel}:{idx}")
                card_depth += opens - closes
                self.assertGreaterEqual(card_depth, 0)

    def test_static_css_has_zero_google_fonts(self) -> None:
        css_path = WEB_STATIC / "styles.css"
        self.assertTrue(css_path.is_file(), "Compiled web_static/styles.css missing")
        css_text = css_path.read_text(encoding="utf-8")
        self.assertNotIn("fonts.googleapis.com", css_text)

    def test_default_theme_is_gothic_studio_and_components_are_pure(self) -> None:
        themes_file = WEB_UI_SRC / "astryx-themes.ts"
        themes_text = themes_file.read_text(encoding="utf-8")
        self.assertIn(
            'defaultThemeSlug: keyof typeof themes = "gothic-studio"',
            themes_text,
        )

        components_dir = WEB_UI_SRC / "components"
        raw_markers = ("<div", "<span", "<img", "className=")
        for path in sorted(components_dir.glob("*.tsx")):
            source = path.read_text(encoding="utf-8")
            for marker in raw_markers:
                self.assertNotIn(
                    marker,
                    source,
                    f"Non-Astryx primitive marker {marker!r} found in {path.name}",
                )

        fonts_dir = WEB_STATIC / "fonts"
        font_names = [path.name for path in fonts_dir.glob("*.woff2")]
        self.assertTrue(
            any(name.startswith("fustat-") for name in font_names),
            f"Missing bundled Fustat .woff2 font in {fonts_dir}",
        )
        self.assertTrue(
            any(name.startswith("jetbrains-mono-") for name in font_names),
            f"Missing bundled JetBrains Mono .woff2 font in {fonts_dir}",
        )


if __name__ == "__main__":
    unittest.main()
