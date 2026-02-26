import html
import json
import re
from typing import Any

from markupsafe import Markup


def generate_highlighted_json(data: dict[str, Any]) -> Markup:
    """Transforms a Python dictionary into syntax-highlighted HTML.

    Relies on Bulma typography classes to avoid frontend JS highlighting libraries.
    """
    safe_str = html.escape(json.dumps(data, indent=2))

    def replacer(match: re.Match) -> str:
        token = match.group(0)
        # Identify Keys (Ends with a colon)
        if token.endswith(":"):
            key = token[:-1].rstrip()
            return f'<span class="has-text-info-light">{key}</span>:'
        # Identify String Values
        elif token.startswith("&quot;"):
            return f'<span class="has-text-success-light">{token}</span>'
        # Identify Null
        elif token == "null":
            return f'<span class="has-text-danger-light">{token}</span>'
        # Identify Numbers & Booleans
        else:
            return f'<span class="has-text-warning">{token}</span>'

    # Regex matches: Keys (with colon) | Strings | Primitives (true, false, null, numbers)
    pattern = re.compile(
        r"&quot;(?:\\&quot;|.)*?&quot;\s*:|&quot;(?:\\&quot;|.)*?&quot;|\b(?:true|false|null|\d+(?:\.\d+)?)\b"
    )
    highlighted = pattern.sub(replacer, safe_str)

    return Markup(highlighted)
