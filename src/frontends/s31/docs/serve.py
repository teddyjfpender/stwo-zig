#!/usr/bin/env python3
"""Serve the S31 Markdown guide with local syntax highlighting and MathJax."""

import argparse
import hashlib
import html
import re
import tempfile
import urllib.request
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit

import markdown
import markdown.extensions.codehilite as codehilite
from pygments.formatters import HtmlFormatter
from pygments.lexer import RegexLexer
from pygments.token import Comment, Keyword, Name, Number, Operator, Punctuation, String, Text


S31 = Path(__file__).resolve().parent.parent
DOCS = S31 / "docs"
CHAPTERS = (
    ("README.md", "Start here"),
    ("walkthrough.md", "0a. One proof by hand"),
    ("worked-proofs.md", "0b. Reduction and recurrence"),
    ("source.md", "1. Source language"),
    ("library.md", "2. Standard / math library"),
    ("circuits.md", "3. Circuit gates"),
    ("air.md", "4. AIR and polynomials"),
    ("hashes.md", "5. Hashes and Merkle paths"),
    ("proofs.md", "6. Proofs and audit"),
)
MATHJAX_URL = "https://cdn.jsdelivr.net/npm/mathjax@3.2.2/es5/tex-svg.js"
MATHJAX_SHA256 = "d4295dc33744836935c1399feece5159577b34c5c8ffb9f1c6324cd82e03a882"
MATHJAX_CACHE = Path(tempfile.gettempdir()) / "s31-docs-assets" / "tex-svg.js"

MATHJAX_CONFIG = r"""
window.MathJax = {
  tex: {
    inlineMath: [['\\(', '\\)']],
    displayMath: [['\\[', '\\]']]
  },
  svg: { fontCache: 'global' },
  options: {
    ignoreHtmlClass: '.*',
    processHtmlClass: 'arithmatex',
    skipHtmlTags: ['script', 'noscript', 'style', 'textarea', 'pre', 'code']
  }
};
"""


class S31Lexer(RegexLexer):
    """Highlight the implemented S31 text subset, not a hypothetical syntax."""

    name = "S31"
    aliases = ["s31"]
    filenames = ["*.s31"]
    tokens = {
        "root": [
            (r"\s+", Text),
            (r"//[^\n]*", Comment.Single),
            (r'"(?:[^"\\]|\\.)*"', String),
            (r"\b(?:use|fn|circuit|public|private|let|assert_eq)\b", Keyword),
            (r"\b(?:m31|u16|bit|Digest|Poseidon2|Blake2sReduced)\b", Keyword.Type),
            (r"\b(?:std::[A-Za-z_][A-Za-z0-9_:]*|iterate|splat|select|m31_from_u16|poseidon2_leaf|poseidon2_pair|blake2s_leaf|blake2s_pair|merkle_path_poseidon2|merkle_path_blake2s)(?=\s*[<(])", Name.Builtin),
            (r"\b\d+(?:_m31)?\b", Number.Integer),
            (r"->|\.\*|::|[+*=<>@-]", Operator),
            (r"[{}\[\]();,:]", Punctuation),
            (r"[A-Za-z_][A-Za-z0-9_]*", Name),
            (r".", Text),
        ]
    }


_original_get_lexer = codehilite.get_lexer_by_name


def _get_lexer(name: str, **options):
    if name == "s31":
        return S31Lexer(**options)
    return _original_get_lexer(name, **options)


codehilite.get_lexer_by_name = _get_lexer


def ensure_mathjax() -> None:
    if MATHJAX_CACHE.is_file():
        if hashlib.sha256(MATHJAX_CACHE.read_bytes()).hexdigest() == MATHJAX_SHA256:
            return
        MATHJAX_CACHE.unlink()
    MATHJAX_CACHE.parent.mkdir(parents=True, exist_ok=True)
    try:
        with urllib.request.urlopen(MATHJAX_URL, timeout=30) as response:
            data = response.read()
    except OSError as error:
        raise RuntimeError(f"could not fetch the pinned MathJax bundle: {error}") from error
    if hashlib.sha256(data).hexdigest() != MATHJAX_SHA256:
        raise RuntimeError("downloaded MathJax bundle did not match its pinned SHA-256")
    temporary = MATHJAX_CACHE.with_suffix(".tmp")
    temporary.write_bytes(data)
    temporary.replace(MATHJAX_CACHE)


def render_markdown(raw: str) -> str:
    return markdown.markdown(
        raw,
        extensions=["tables", "fenced_code", "codehilite", "toc", "pymdownx.arithmatex"],
        extension_configs={
            "codehilite": {"guess_lang": False, "linenums": False},
            "pymdownx.arithmatex": {"generic": True},
        },
    )


class Handler(SimpleHTTPRequestHandler):
    extensions_map = {
        **SimpleHTTPRequestHandler.extensions_map,
        ".s31": "text/plain; charset=utf-8",
        ".zig": "text/plain; charset=utf-8",
        ".py": "text/plain; charset=utf-8",
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(S31), **kwargs)

    def do_GET(self):
        path = unquote(urlsplit(self.path).path)
        if path == "/":
            self.send_response(302)
            self.send_header("Location", "/docs/")
            self.end_headers()
            return
        if path == "/assets/tex-svg.js":
            return self._send_bytes(MATHJAX_CACHE.read_bytes(), "text/javascript; charset=utf-8")
        if path == "/docs/":
            path = "/docs/README.md"
        if not path.endswith(".md"):
            return super().do_GET()
        source = (S31 / path.lstrip("/")).resolve()
        if not source.is_relative_to(S31) or not source.is_file():
            self.send_error(404, "Markdown file not found")
            return
        raw = source.read_text(encoding="utf-8")
        title_match = re.search(r"^#\s+(.+)$", raw, re.MULTILINE)
        title = title_match.group(1) if title_match else source.stem
        body = render_markdown(raw)
        active = source.name if source.parent == DOCS else ""
        nav = "".join(
            f'<a class="{"active" if name == active else ""}" href="/docs/{name}">{html.escape(label)}</a>'
            for name, label in CHAPTERS
        )
        css = (DOCS / "site.css").read_text(encoding="utf-8")
        light = HtmlFormatter(style="friendly").get_style_defs(".codehilite")
        dark = HtmlFormatter(style="github-dark").get_style_defs(".codehilite")
        page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)} · S31 Docs</title>
<style>{css}\n{light}\n@media(prefers-color-scheme:dark){{{dark}}}</style>
<script>{MATHJAX_CONFIG}</script><script defer src="/assets/tex-svg.js"></script>
</head><body><div class="layout">
<aside><a class="brand" href="/docs/">S31 Docs</a>
<div class="sub">Computation → circuit → AIR → proof</div><nav>{nav}</nav></aside>
<main><article>{body}
<div class="footer">Live preview of {html.escape(str(source.relative_to(S31)))} · Refresh to see edits</div>
</article></main></div></body></html>"""
        return self._send_bytes(page.encode("utf-8"), "text/html; charset=utf-8")

    def _send_bytes(self, data: bytes, content_type: str):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    ensure_mathjax()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"S31 docs: http://127.0.0.1:{args.port}/docs/", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
