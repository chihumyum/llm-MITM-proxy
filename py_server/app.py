import copy
import json
import threading
from typing import Dict, List, Optional, Tuple

from flask import Flask, jsonify, request

from llm_client import LLMClient


# -----------------------
# Shared configuration
# -----------------------

class ConfigState:
    """
    Stores current focus text, model choice, and on/off switch.
    Thread-safe so the HTTP handler and any worker threads can read/write.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.focus: Optional[str] = None
        self.enabled: bool = True
        self.model: str = "4o-mini"

    def to_dict(self) -> Dict:
        with self._lock:
            return {
                "focus": self.focus,
                "enabled": self.enabled,
                "model": self.model,
            }

    def update(self, *, focus: Optional[str] = None, enabled: Optional[bool] = None, model: Optional[str] = None) -> None:
        with self._lock:
            if focus is not None:
                self.focus = focus.strip() or None
            if enabled is not None:
                self.enabled = bool(enabled)
            if model is not None:
                self.model = model


config_state = ConfigState()
client = LLMClient()
app = Flask(__name__)


@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    response.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
    return response


# -----------------------
# Helpers: YouTube parsing
# -----------------------

def _has_video_renderer(node) -> bool:
    """
    Recursively checks if a node (dict or list) contains a 'videoRenderer' key.

    Args:
        node: The JSON structure to search (dict, list, or other type)

    Returns:
        True if a videoRenderer is found anywhere in the structure, False otherwise.
    """
    if isinstance(node, dict):
        if "videoRenderer" in node:
            return True
        return any(_has_video_renderer(v) for v in node.values())
    if isinstance(node, list):
        return any(_has_video_renderer(item) for item in node)
    return False


def _find_video_renderer(node) -> Optional[Dict]:
    """
    Recursively searches for and returns the first videoRenderer dict found in the given node.

    Args:
        node: The JSON structure to search (can be a dict, list, or other type).

    Returns:
        The videoRenderer dict if found, None otherwise.
    """
    if isinstance(node, dict):
        if "videoRenderer" in node:
            return node["videoRenderer"]
        for v in node.values():
            found = _find_video_renderer(v)
            if found:
                return found
    elif isinstance(node, list):
        for item in node:
            found = _find_video_renderer(item)
            if found:
                return found
    return None


def _collect_video_items(node, acc: List[Dict]) -> None:
    """
    Traverse the JSON and collect one entry for every list item that contains a videoRenderer.
    The order here is reused by the filtering pass, so LLM decisions line up.
    """
    if isinstance(node, list):
        for item in node:
            if _has_video_renderer(item):
                renderer = _find_video_renderer(item)
                if renderer:
                    acc.append(renderer)
            else:
                _collect_video_items(item, acc)
    elif isinstance(node, dict):
        for v in node.values():
            _collect_video_items(v, acc)


def _extract_title(renderer: Dict) -> str:
    """
    Extracts the title text from a videoRenderer dict.

    Args:
        renderer: The videoRenderer dict containing title information.

    Returns:
        The video title string if found, otherwise the videoId, or "unknown" as a fallback.
    """
    title = renderer.get("title") or {}
    if isinstance(title, dict):
        if "simpleText" in title:
            return str(title["simpleText"])
        runs = title.get("runs")
        if isinstance(runs, list):
            parts = [r.get("text", "") for r in runs if isinstance(r, dict)]
            text = " ".join([p for p in parts if p])
            if text:
                return text
    return renderer.get("videoId") or "unknown"


# -----------------------
# Helpers: LLM + filtering
# -----------------------

def _parse_keep_flags(raw: str, expected: int) -> List[int]:
    """
    Try to parse a list of 0/1 decisions from the LLM response.
    """
    flags: List[int] = []
    try:
        # First try JSON parsing
        data = json.loads(raw)
        if isinstance(data, list):
            for item in data:
                if item in (0, 1, "0", "1"):
                    flags.append(int(item))
                if len(flags) == expected:
                    break
        if len(flags) == expected:
            return flags
    except Exception:
        pass

    # Fallback: regex digits
    import re

    for ch in re.findall(r"[01]", raw):
        flags.append(int(ch))
        if len(flags) == expected:
            break

    # Pad with 1 (keep) on failure to avoid over-filtering
    while len(flags) < expected:
        flags.append(1)
    return flags


def _filter_structure(node, decisions_iter) -> Tuple[object, int, int]:
    """
    Walk through the structure, drop list items that contain a videoRenderer if the corresponding decision is 0.
    Returns (new_node, kept, dropped).
    """
    if isinstance(node, list):
        new_list = []
        kept = dropped = 0
        for item in node:
            if _has_video_renderer(item):
                decision = next(decisions_iter)
                if decision:
                    new_list.append(item)
                    kept += 1
                else:
                    dropped += 1
            else:
                filtered_child, k, d = _filter_structure(item, decisions_iter)
                new_list.append(filtered_child)
                kept += k
                dropped += d
        return new_list, kept, dropped
    elif isinstance(node, dict):
        kept = dropped = 0
        new_dict = {}
        for k, v in node.items():
            filtered_child, child_kept, child_dropped = _filter_structure(v, decisions_iter)
            new_dict[k] = filtered_child
            kept += child_kept
            dropped += child_dropped
        return new_dict, kept, dropped
    else:
        return node, 0, 0


def run_llm_filter(videos: List[Dict], focus: str, model: str) -> List[int]:
    titles = [_extract_title(v) for v in videos]
    numbered = "\n".join(f"{i+1}. {t}" for i, t in enumerate(titles))
    system = (
        "You filter YouTube videos. Given the user's focus, return a JSON array of 0/1 of the same length "
        "as the list. 1 = keep (helps the user stay on focus), 0 = drop. Return only the JSON array."
    )
    query = f"User focus: {focus}\nVideos:\n{numbered}\nReturn JSON array like [1,0,1]"

    res = client.generate(
        model=model,
        system=system,
        query=query,
        temperature=0.0,
        lastk=0,
        rag_usage=False,
    )
    raw = res.get("result") if isinstance(res, dict) else None
    if not raw:
        # If server used a different key, fall back to str()
        raw = json.dumps(res)
    return _parse_keep_flags(raw, expected=len(titles))


# -----------------------
# HTTP endpoints
# -----------------------

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "config": config_state.to_dict()})


@app.route("/", methods=["GET"])
def home():
    """
    Minimal local UI for setting focus and enabling/disabling the filter.
    Kept intentionally barebones to avoid extra assets.
    """
    return """
    <html>
      <head><title>YouTube Focus Filter</title></head>
      <body style="font-family: sans-serif; max-width: 640px;">
        <h2>YouTube Focus Filter</h2>
        <form id="cfg">
          <label>Focus: <input type="text" id="focus" style="width: 400px;" /></label><br/><br/>
          <label><input type="checkbox" id="enabled" checked/> Enabled</label><br/><br/>
          <label>Model: <input type="text" id="model" value="4o-mini" /></label><br/><br/>
          <button type="submit">Save</button>
        </form>
        <pre id="status"></pre>
        <script>
          async function refresh() {
            const res = await fetch('/config');
            const data = await res.json();
            document.getElementById('focus').value = data.focus || '';
            document.getElementById('enabled').checked = data.enabled;
            document.getElementById('model').value = data.model || '';
            document.getElementById('status').innerText = JSON.stringify(data, null, 2);
          }
          document.getElementById('cfg').addEventListener('submit', async (e) => {
            e.preventDefault();
            const payload = {
              focus: document.getElementById('focus').value,
              enabled: document.getElementById('enabled').checked,
              model: document.getElementById('model').value,
            };
            const res = await fetch('/config', {
              method: 'POST',
              headers: {'Content-Type': 'application/json'},
              body: JSON.stringify(payload),
            });
            document.getElementById('status').innerText = JSON.stringify(await res.json(), null, 2);
          });
          refresh();
        </script>
      </body>
    </html>
    """


@app.route("/config", methods=["GET", "POST"])
def config():
    if request.method == "GET":
        return jsonify(config_state.to_dict())

    payload = request.get_json(silent=True) or {}
    config_state.update(
        focus=payload.get("focus"),
        enabled=payload.get("enabled"),
        model=payload.get("model"),
    )
    return jsonify(config_state.to_dict())


@app.route("/config", methods=["OPTIONS"])
@app.route("/filter", methods=["OPTIONS"])
def _options():
    return ("", 204)


@app.route("/filter", methods=["POST"])
def filter_handler():
    payload = request.get_json(force=True, silent=True)
    if not payload:
        return jsonify({"error": "Missing JSON body"}), 400
    if "response" not in payload:
        return jsonify({"error": "Missing required 'response' field in JSON body"}), 400

    enabled = payload.get("enabled")
    focus_override = payload.get("focus")

    state = config_state.to_dict()
    focus = focus_override or state["focus"]
    is_enabled = state["enabled"] if enabled is None else bool(enabled)
    model = state["model"]

    if not is_enabled:
        return jsonify({"filtered": False, "reason": "filter disabled", "response": payload["response"]})
    if not focus:
        return jsonify({"filtered": False, "reason": "focus not set", "response": payload["response"]})

    yt_response = payload["response"]
    videos: List[Dict] = []
    _collect_video_items(yt_response, videos)

    if not videos:
        return jsonify({"filtered": False, "reason": "no videos found", "response": yt_response})

    decisions = run_llm_filter(videos, focus, model)
    decisions_iter = iter(decisions)
    filtered_copy = copy.deepcopy(yt_response)
    filtered_response, kept, dropped = _filter_structure(filtered_copy, decisions_iter)

    return jsonify(
        {
            "filtered": True,
            "kept": kept,
            "dropped": dropped,
            "response": filtered_response,
            "decisions": decisions,
        }
    )


if __name__ == "__main__":
    # Expose on 0.0.0.0 so Docker can map the port
    app.run(host="0.0.0.0", port=5000)
