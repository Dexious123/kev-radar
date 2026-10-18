"""Making untrusted text inert where it is shown as Markdown or opened in a spreadsheet.

Text in this app comes from uploaded exports, imported exception registers, and public
feeds. Streamlit renders Markdown with raw HTML turned off, but it still renders images
and links, so a value written as ``![x](https://host/y)`` makes the viewer's browser
fetch that address. A CSV cell that starts with ``=``, ``+``, ``-`` or ``@`` becomes a
live formula when the file is opened in a spreadsheet.
"""

from __future__ import annotations

import re

# Characters that start an image, a link, inline HTML, code, LaTeX, a table cell, or
# strikethrough. Dots, dashes, and underscores are left alone so host names stay intact
# for the briefing's fact checker.
_MARKDOWN = re.compile(r"([\\`*\[\]<>!$|~])")
_IMAGE = re.compile(r"!\[")
FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


def md_text(value: object) -> str:
    """One untrusted value, safe to drop into a Markdown sentence: escaped and on one line."""
    text = "" if value is None else str(value)
    return _MARKDOWN.sub(r"\\\1", " ".join(text.split()))


def md_without_images(markdown: str) -> str:
    """A whole Markdown document (a model's draft) with every image turned into plain text."""
    return _IMAGE.sub(r"!\\[", str(markdown or ""))


def spreadsheet_cell(value: object) -> object:
    """Quote a text cell a spreadsheet would read as a formula. Numbers are left as they are."""
    if isinstance(value, str) and value.startswith(FORMULA_START):
        return "'" + value
    return value


def from_spreadsheet_cell(value: object) -> object:
    """Undo ``spreadsheet_cell`` on import, so a register survives a round trip unchanged."""
    if isinstance(value, str) and len(value) > 1 and value[0] == "'" and value[1:].startswith(FORMULA_START):
        return value[1:]
    return value
