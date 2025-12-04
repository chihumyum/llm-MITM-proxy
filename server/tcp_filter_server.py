"""
TCP Filter Server for YouTube Focus Filter

Protocol (Length-Prefix):
- Receive: 4-byte length (big-endian) + raw response body
- Send: 4-byte length (big-endian) + filtered response body

The server maintains a persistent connection with the C proxy.
Also provides an HTTP API for configuration on port 5001.
"""

import copy
import gzip
import hashlib
import json
import os
import re
import socket
import struct
import sys
import threading
import time
import zlib
from dataclasses import dataclass, field
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from llm_client import LLMClient


# -----------------------
# Unified Configuration
# -----------------------

@dataclass
class ServerConfig:
    """Centralized configuration with environment variable support."""
    host: str = field(default_factory=lambda: os.getenv("SERVER_HOST", "0.0.0.0"))
    tcp_port: int = field(default_factory=lambda: int(os.getenv("TCP_PORT", "5000")))
    http_port: int = field(default_factory=lambda: int(os.getenv("HTTP_PORT", "5001")))
    llm_timeout: float = field(default_factory=lambda: float(os.getenv("LLM_TIMEOUT", "30.0")))
    cache_size: int = field(default_factory=lambda: int(os.getenv("CACHE_SIZE", "1000")))
    cache_ttl: int = field(default_factory=lambda: int(os.getenv("CACHE_TTL", "3600")))  # 1 hour


SERVER_CONFIG = ServerConfig()
TEMPLATES_DIR = Path(__file__).parent / "templates"


# -----------------------
# Shared configuration & Statistics
# -----------------------

class FilterStats:
    """Thread-safe statistics for filtering operations."""
    
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.requests_total: int = 0
        self.videos_processed: int = 0
        self.videos_kept: int = 0
        self.videos_dropped: int = 0
        self.cache_hits: int = 0
        self.cache_misses: int = 0
        self.errors: int = 0
        self.last_request_time: Optional[float] = None
        self.avg_latency_ms: float = 0.0
        self._latency_samples: List[float] = []
    
    def record_request(self, kept: int, dropped: int, latency_ms: float) -> None:
        with self._lock:
            self.requests_total += 1
            self.videos_processed += kept + dropped
            self.videos_kept += kept
            self.videos_dropped += dropped
            self.last_request_time = time.time()
            self._latency_samples.append(latency_ms)
            # Keep only last 100 samples for average
            if len(self._latency_samples) > 100:
                self._latency_samples.pop(0)
            self.avg_latency_ms = sum(self._latency_samples) / len(self._latency_samples)
    
    def record_cache_hit(self) -> None:
        with self._lock:
            self.cache_hits += 1
    
    def record_cache_miss(self) -> None:
        with self._lock:
            self.cache_misses += 1
    
    def record_error(self) -> None:
        with self._lock:
            self.errors += 1
    
    def to_dict(self) -> Dict:
        with self._lock:
            return {
                "requests_total": self.requests_total,
                "videos_processed": self.videos_processed,
                "videos_kept": self.videos_kept,
                "videos_dropped": self.videos_dropped,
                "cache_hits": self.cache_hits,
                "cache_misses": self.cache_misses,
                "cache_hit_rate": round(self.cache_hits / max(1, self.cache_hits + self.cache_misses) * 100, 1),
                "errors": self.errors,
                "avg_latency_ms": round(self.avg_latency_ms, 1),
                "last_request_time": self.last_request_time,
            }


filter_stats = FilterStats()


class ConfigState:
    """
    Stores current focus text, model choice, and on/off switch.
    Thread-safe so the handler and any worker threads can read/write.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.focus: Optional[str] = os.getenv("FOCUS", "educational content, programming, learning")
        self.enabled: bool = False
        self.model: str = os.getenv("LLM_MODEL", "gpt-4o-mini")

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


try:
    import brotli  # type: ignore
    _has_brotli = True
except Exception:
    brotli = None
    _has_brotli = False


# -----------------------
# Compression helpers
# -----------------------

def decompress_if_needed(data: bytes) -> Tuple[bytes, Optional[str]]:
    """
    Best-effort decompress. Returns (decoded_bytes, encoding_used or None).
    Only decompresses when magic bytes look like a known encoding.
    """
    # gzip magic
    if data.startswith(b"\x1f\x8b"):
        try:
            return gzip.decompress(data), "gzip"
        except Exception:
            pass

    # zlib/deflate magic (0x78 0x01/0x5e/0x9c/0xda)
    if len(data) > 2 and data[0] == 0x78 and data[1] in (0x01, 0x5E, 0x9C, 0xDA):
        try:
            return zlib.decompress(data), "deflate"
        except Exception:
            pass

    # brotli has no fixed magic, try last
    if _has_brotli:
        try:
            return brotli.decompress(data), "br"
        except Exception:
            pass

    return data, None


def recompress(data: bytes, encoding: Optional[str]) -> bytes:
    if encoding == "gzip":
        return gzip.compress(data)
    if encoding == "deflate":
        return zlib.compress(data)
    if encoding == "br" and _has_brotli:
        return brotli.compress(data)
    return data


# -----------------------
# LLM Response Cache
# -----------------------

class LLMCache:
    """Thread-safe LRU cache for LLM decisions with TTL support."""
    
    def __init__(self, max_size: int = 1000, ttl_seconds: int = 3600) -> None:
        self._lock = threading.Lock()
        self._cache: Dict[str, Tuple[int, float]] = {}  # key -> (decision, timestamp)
        self._max_size = max_size
        self._ttl = ttl_seconds
    
    def _make_key(self, title: str, focus: str) -> str:
        """Create a cache key from title and focus."""
        # Normalize and hash for consistent keys
        normalized = f"{title.lower().strip()}|{focus.lower().strip()}"
        return hashlib.md5(normalized.encode()).hexdigest()
    
    def get(self, title: str, focus: str) -> Optional[int]:
        """Get cached decision for a title. Returns None if not cached or expired."""
        key = self._make_key(title, focus)
        with self._lock:
            if key in self._cache:
                decision, timestamp = self._cache[key]
                if time.time() - timestamp < self._ttl:
                    filter_stats.record_cache_hit()
                    return decision
                else:
                    # Expired, remove it
                    del self._cache[key]
            filter_stats.record_cache_miss()
            return None
    
    def put(self, title: str, focus: str, decision: int) -> None:
        """Cache a decision for a title."""
        key = self._make_key(title, focus)
        with self._lock:
            # Evict oldest entries if at capacity
            if len(self._cache) >= self._max_size:
                # Remove oldest 10%
                sorted_items = sorted(self._cache.items(), key=lambda x: x[1][1])
                to_remove = len(self._cache) // 10 or 1
                for k, _ in sorted_items[:to_remove]:
                    del self._cache[k]
            
            self._cache[key] = (decision, time.time())
    
    def clear(self) -> None:
        """Clear all cached entries."""
        with self._lock:
            self._cache.clear()
    
    def stats(self) -> Dict:
        """Get cache statistics."""
        with self._lock:
            return {
                "size": len(self._cache),
                "max_size": self._max_size,
                "ttl_seconds": self._ttl,
            }


llm_cache = LLMCache(
    max_size=SERVER_CONFIG.cache_size,
    ttl_seconds=SERVER_CONFIG.cache_ttl
)


# -----------------------
# YouTube JSON parsing
# -----------------------

# All known video renderer types in YouTube API responses
VIDEO_RENDERER_KEYS = [
    "videoRenderer",           # Search results, browse pages
    "compactVideoRenderer",    # Sidebar recommendations on watch page
    "gridVideoRenderer",       # Grid layout videos
    "playlistVideoRenderer",   # Videos in playlists
    "endScreenVideoRenderer",  # End screen recommendations
    "reelItemRenderer",        # YouTube Shorts
    "shortsLockupViewModel",   # Shorts in different contexts
    "richItemRenderer",        # Rich items (often wraps videoRenderer)
    "lockupViewModel",         # Next API recommendations (watch page sidebar)
]


def _get_video_renderer_key(node: Dict) -> Optional[str]:
    """Return the renderer key if node contains a video renderer, else None."""
    for key in VIDEO_RENDERER_KEYS:
        if key in node:
            return key
    return None


def _has_video_renderer(node) -> bool:
    if isinstance(node, dict):
        if _get_video_renderer_key(node):
            return True
        return any(_has_video_renderer(v) for v in node.values())
    if isinstance(node, list):
        return any(_has_video_renderer(item) for item in node)
    return False


def _find_video_renderer(node) -> Tuple[Optional[Dict], Optional[str]]:
    """Find and return (renderer_dict, renderer_key) or (None, None)."""
    if isinstance(node, dict):
        key = _get_video_renderer_key(node)
        if key:
            return node[key], key
        for v in node.values():
            found, found_key = _find_video_renderer(v)
            if found:
                return found, found_key
    elif isinstance(node, list):
        for item in node:
            found, found_key = _find_video_renderer(item)
            if found:
                return found, found_key
    return None, None


def _collect_video_items(node, acc: List[Tuple[Dict, str]]) -> None:
    """Collect all video items as (renderer, renderer_key) tuples."""
    if isinstance(node, list):
        for item in node:
            if isinstance(item, dict):
                key = _get_video_renderer_key(item)
                if key:
                    acc.append((item[key], key))
                else:
                    _collect_video_items(item, acc)
    elif isinstance(node, dict):
        key = _get_video_renderer_key(node)
        if key:
            acc.append((node[key], key))
        else:
            for v in node.values():
                _collect_video_items(v, acc)


def _extract_title(renderer: Dict) -> str:
    """Extract title from various video renderer types."""
    
    # 1. Try lockupMetadataViewModel (used in lockupViewModel for next API, richItemRenderer for browse)
    #    Path for lockupViewModel: metadata.lockupMetadataViewModel.title.content
    #    Path for richItemRenderer: content.lockupViewModel.metadata.lockupMetadataViewModel.title.content
    def try_lockup_metadata(node: Dict) -> Optional[str]:
        # Direct path: metadata.lockupMetadataViewModel.title.content (lockupViewModel in next API)
        metadata = node.get("metadata", {})
        lockup_meta = metadata.get("lockupMetadataViewModel", {})
        title_obj = lockup_meta.get("title", {})
        content = title_obj.get("content")
        if content and isinstance(content, str):
            return content
        
        # Nested in content.lockupViewModel (richItemRenderer in browse API)
        content_node = node.get("content", {})
        lockup_vm = content_node.get("lockupViewModel", {})
        if lockup_vm:
            metadata = lockup_vm.get("metadata", {})
            lockup_meta = metadata.get("lockupMetadataViewModel", {})
            title_obj = lockup_meta.get("title", {})
            content = title_obj.get("content")
            if content and isinstance(content, str):
                return content
        
        return None
    
    lockup_title = try_lockup_metadata(renderer)
    if lockup_title:
        return lockup_title
    
    # 2. Try different title field locations (classic structure)
    title = renderer.get("title") or renderer.get("headline") or {}
    
    if isinstance(title, dict):
        if "simpleText" in title:
            return str(title["simpleText"])
        # Check for content field (newer API format)
        if "content" in title and isinstance(title["content"], str):
            return title["content"]
        runs = title.get("runs")
        if isinstance(runs, list):
            parts = [r.get("text", "") for r in runs if isinstance(r, dict)]
            text = "".join([p for p in parts if p])
            if text:
                return text
        # For accessibility labels
        if "accessibility" in title:
            acc = title.get("accessibility", {}).get("accessibilityData", {})
            label = acc.get("label", "")
            if label:
                return label
    elif isinstance(title, str):
        return title
    
    # 3. Fallback: try to get from accessibility
    acc_text = renderer.get("accessibility", {}).get("accessibilityData", {}).get("label", "")
    if acc_text:
        return acc_text
    
    # 4. Try accessibilityText in various locations
    acc_text2 = renderer.get("accessibilityText")
    if acc_text2 and isinstance(acc_text2, str):
        return acc_text2
    
    # 5. Last resort: video ID
    return renderer.get("videoId") or "unknown"


# -----------------------
# LLM filtering
# -----------------------

def _parse_keep_flags(raw: str, expected: int) -> List[int]:
    flags: List[int] = []
    try:
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

    for ch in re.findall(r"[01]", raw):
        flags.append(int(ch))
        if len(flags) == expected:
            break

    while len(flags) < expected:
        flags.append(1)
    return flags


def _create_placeholder_renderer(renderer_key: str, original_title: str) -> Dict:
    """
    Create a placeholder video renderer that won't cause YouTube frontend issues.
    The placeholder looks like a real video but indicates it was filtered.
    """
    placeholder_video_id = "dQw4w9WgXcQ"  # A valid video ID as fallback
    filtered_title = f"[Filtered] {original_title[:50]}..." if len(original_title) > 50 else f"[Filtered] {original_title}"
    placeholder_thumbnail_url = "https://i.ytimg.com/vi/dQw4w9WgXcQ/hqdefault.jpg"
    
    # For lockupViewModel (used in /next API)
    if renderer_key == "lockupViewModel":
        return {
            "contentImage": {
                "thumbnailViewModel": {
                    "image": {
                        "sources": [
                            {
                                "url": placeholder_thumbnail_url,
                                "width": 168,
                                "height": 94
                            }
                        ]
                    },
                    "overlays": []
                }
            },
            "metadata": {
                "lockupMetadataViewModel": {
                    "title": {
                        "content": filtered_title
                    },
                    "metadata": {
                        "contentMetadataViewModel": {
                            "metadataRows": [
                                {
                                    "metadataParts": [
                                        {
                                            "text": {
                                                "content": "Filtered Content"
                                            }
                                        }
                                    ]
                                },
                                {
                                    "metadataParts": [
                                        {
                                            "text": {
                                                "content": "Filtered"
                                            }
                                        }
                                    ]
                                }
                            ],
                            "delimiter": " • "
                        }
                    }
                }
            },
            "rendererContext": {
                "commandContext": {
                    "onTap": {
                        "innertubeCommand": {
                            "watchEndpoint": {
                                "videoId": placeholder_video_id
                            }
                        }
                    }
                }
            }
        }
    
    # For richItemRenderer (used in /browse API) - wraps lockupViewModel
    if renderer_key == "richItemRenderer":
        return {
            "content": {
                "lockupViewModel": {
                    "contentImage": {
                        "thumbnailViewModel": {
                            "image": {
                                "sources": [
                                    {
                                        "url": placeholder_thumbnail_url,
                                        "width": 360,
                                        "height": 202
                                    }
                                ]
                            },
                            "overlays": []
                        }
                    },
                    "metadata": {
                        "lockupMetadataViewModel": {
                            "title": {
                                "content": filtered_title
                            },
                            "metadata": {
                                "contentMetadataViewModel": {
                                    "metadataRows": [
                                        {
                                            "metadataParts": [
                                                {
                                                    "text": {
                                                        "content": "Filtered Content"
                                                    }
                                                }
                                            ]
                                        },
                                        {
                                            "metadataParts": [
                                                {
                                                    "text": {
                                                        "content": "Filtered"
                                                    }
                                                }
                                            ]
                                        }
                                    ],
                                    "delimiter": " • "
                                }
                            }
                        }
                    },
                    "rendererContext": {
                        "commandContext": {
                            "onTap": {
                                "innertubeCommand": {
                                    "watchEndpoint": {
                                        "videoId": placeholder_video_id
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "trackingParams": ""
        }
    
    # Default: Base placeholder structure for videoRenderer, compactVideoRenderer, etc.
    placeholder = {
        "videoId": placeholder_video_id,
        "title": {
            "runs": [{"text": filtered_title}]
        },
        "descriptionSnippet": {
            "runs": [{"text": "This video was filtered by YouTube Focus Filter."}]
        },
        "lengthText": {
            "simpleText": "0:00"
        },
        "viewCountText": {
            "simpleText": "Filtered"
        },
        "navigationEndpoint": {
            "watchEndpoint": {
                "videoId": placeholder_video_id
            }
        },
        "thumbnail": {
            "thumbnails": [
                {
                    "url": placeholder_thumbnail_url,
                    "width": 120,
                    "height": 90
                }
            ]
        },
        "shortBylineText": {
            "runs": [{"text": "Filtered Content"}]
        },
        "ownerText": {
            "runs": [{"text": "Filtered Content"}]
        },
        "publishedTimeText": {
            "simpleText": ""
        }
    }
    
    return placeholder


def _filter_structure(node, decisions_iter, titles_iter=None) -> Tuple[object, int, int]:
    """
    Filter the JSON structure, replacing filtered videos with placeholders.
    """
    if isinstance(node, list):
        new_list = []
        kept = dropped = 0
        for item in node:
            if isinstance(item, dict):
                renderer_key = _get_video_renderer_key(item)
                if renderer_key:
                    decision = next(decisions_iter)
                    title = next(titles_iter) if titles_iter else "Video"
                    if decision:
                        new_list.append(item)
                        kept += 1
                    else:
                        # Replace with placeholder instead of removing
                        placeholder = {renderer_key: _create_placeholder_renderer(renderer_key, title)}
                        new_list.append(placeholder)
                        dropped += 1
                else:
                    filtered_child, k, d = _filter_structure(item, decisions_iter, titles_iter)
                    new_list.append(filtered_child)
                    kept += k
                    dropped += d
            else:
                filtered_child, k, d = _filter_structure(item, decisions_iter, titles_iter)
                new_list.append(filtered_child)
                kept += k
                dropped += d
        return new_list, kept, dropped
    elif isinstance(node, dict):
        renderer_key = _get_video_renderer_key(node)
        if renderer_key:
            # This shouldn't normally happen at dict level, but handle it
            decision = next(decisions_iter)
            title = next(titles_iter) if titles_iter else "Video"
            if decision:
                return node, 1, 0
            else:
                return {renderer_key: _create_placeholder_renderer(renderer_key, title)}, 0, 1
        
        kept = dropped = 0
        new_dict = {}
        for k, v in node.items():
            filtered_child, child_kept, child_dropped = _filter_structure(v, decisions_iter, titles_iter)
            new_dict[k] = filtered_child
            kept += child_kept
            dropped += child_dropped
        return new_dict, kept, dropped
    else:
        return node, 0, 0


def run_llm_filter(videos: List[Tuple[Dict, str]], focus: str, model: str, client: LLMClient) -> Tuple[List[int], List[str]]:
    """
    Run LLM filter on videos with caching. Returns (decisions, titles).
    videos is a list of (renderer_dict, renderer_key) tuples.
    """
    titles = [_extract_title(v[0]) for v in videos]
    decisions = []
    uncached_indices = []
    uncached_titles = []
    
    # Check cache first
    for i, title in enumerate(titles):
        cached = llm_cache.get(title, focus)
        if cached is not None:
            decisions.append(cached)
        else:
            decisions.append(-1)  # Placeholder
            uncached_indices.append(i)
            uncached_titles.append(title)
    
    # If all cached, return immediately
    if not uncached_titles:
        print(f"[LLM] All {len(titles)} videos found in cache", file=sys.stderr)
        return decisions, titles
    
    print(f"[LLM] Cache: {len(titles) - len(uncached_titles)} hits, {len(uncached_titles)} misses", file=sys.stderr)
    
    # Query LLM for uncached titles
    numbered = "\n".join(f"{i+1}. {t}" for i, t in enumerate(uncached_titles))
    system = (
        "You are a YouTube video filter. The user wants to focus on specific topics. "
        "For each video title, decide if it matches the user's focus area. "
        "Return a JSON array of 0 or 1 for each video: 1 = keep (matches focus), 0 = filter out (does not match). "
        "Return ONLY the JSON array, nothing else."
    )
    query = f"User's focus topic: {focus}\n\nVideo titles to evaluate:\n{numbered}\n\nReturn a JSON array with {len(uncached_titles)} elements, one for each video."

    print(f"[LLM] Sending {len(uncached_titles)} videos to filter", file=sys.stderr)
    print(f"[LLM] Focus: {focus}", file=sys.stderr)

    res = client.generate(
        model=model,
        system=system,
        query=query,
        temperature=0.0,
    )
    
    raw = res.get("result") if isinstance(res, dict) else None
    print(f"[LLM] Raw response: {raw[:500] if raw else 'None'}...", file=sys.stderr)
    
    if not raw:
        raw = json.dumps(res)
    
    uncached_decisions = _parse_keep_flags(raw, expected=len(uncached_titles))
    
    # Update cache and fill in decisions
    for i, idx in enumerate(uncached_indices):
        decision = uncached_decisions[i]
        decisions[idx] = decision
        llm_cache.put(titles[idx], focus, decision)
    
    return decisions, titles


# -----------------------
# JSON extraction from response
# -----------------------

def extract_json_from_body(body: bytes) -> Optional[Dict]:
    """
    Try to extract JSON from the response body.
    YouTube API responses contain JSON data.
    """
    try:
        # First, try to decode as UTF-8
        text = body.decode('utf-8', errors='ignore')
        
        # Look for JSON object patterns
        # YouTube often has JSON embedded in responses
        
        # Try parsing the whole thing as JSON first
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
        
        # Look for ytInitialData or similar patterns
        patterns = [
            r'var ytInitialData\s*=\s*(\{.+?\});',
            r'window\["ytInitialData"\]\s*=\s*(\{.+?\});',
            r'"contents"\s*:\s*(\{.+\})',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group(1))
                except json.JSONDecodeError:
                    continue
        
        # Try to find any large JSON object
        start = text.find('{')
        if start != -1:
            # Find matching closing brace
            depth = 0
            for i, c in enumerate(text[start:], start):
                if c == '{':
                    depth += 1
                elif c == '}':
                    depth -= 1
                    if depth == 0:
                        try:
                            return json.loads(text[start:i+1])
                        except json.JSONDecodeError:
                            break
        
        return None
        
    except Exception as e:
        print(f"Error extracting JSON: {e}", file=sys.stderr)
        return None


def replace_json_in_body(original_body: bytes, original_json: Dict, filtered_json: Dict) -> bytes:
    """
    Replace the JSON in the original body with the filtered JSON.
    """
    try:
        text = original_body.decode('utf-8', errors='ignore')
        original_str = json.dumps(original_json, separators=(',', ':'))
        filtered_str = json.dumps(filtered_json, separators=(',', ':'))
        
        # Try direct replacement
        if original_str in text:
            new_text = text.replace(original_str, filtered_str, 1)
            return new_text.encode('utf-8')
        
        # If the JSON was found via pattern, we need to be smarter
        # For now, just return the filtered JSON directly if it's an API response
        return filtered_str.encode('utf-8')
        
    except Exception as e:
        print(f"Error replacing JSON: {e}", file=sys.stderr)
        return original_body


# -----------------------
# Main filter logic
# -----------------------

def filter_response(body: bytes, client: Optional[LLMClient]) -> bytes:
    """
    Filter YouTube response body.
    Returns the filtered body (raw bytes, no chunked encoding).
    """
    start_time = time.time()
    
    if client is None or not client.available():
        print("LLM client unavailable, passing through", file=sys.stderr)
        return body

    state = config_state.to_dict()
    focus = state["focus"]
    is_enabled = state["enabled"]
    model = state["model"]
    
    if not is_enabled:
        print("Filter disabled, passing through", file=sys.stderr)
        return body
    
    if not focus:
        print("Focus not set, passing through", file=sys.stderr)
        return body
    
    # Decompress if needed so we can parse JSON
    decompressed_body, encoding_used = decompress_if_needed(body)
    if encoding_used:
        print(f"Detected compressed body ({encoding_used}), decompressing", file=sys.stderr)
    
    print(f"Body size: {len(decompressed_body)} bytes", file=sys.stderr)
    
    # Try to extract JSON
    json_data = extract_json_from_body(decompressed_body)
    
    if not json_data:
        print("No JSON found in response, passing through", file=sys.stderr)
        return body
    
    # Collect videos as (renderer, renderer_key) tuples
    videos: List[Tuple[Dict, str]] = []
    _collect_video_items(json_data, videos)
    
    if not videos:
        print("No videos found in response, passing through", file=sys.stderr)
        return body
    
    print(f"Found {len(videos)} videos to filter", file=sys.stderr)
    
    # Get LLM decisions
    try:
        decisions, titles = run_llm_filter(videos, focus, model, client)
        print(f"LLM decisions: {decisions}", file=sys.stderr)
    except Exception as e:
        print(f"LLM filter error: {e}, passing through", file=sys.stderr)
        filter_stats.record_error()
        import traceback
        traceback.print_exc()
        return body
    
    # Apply filter with placeholder replacement
    decisions_iter = iter(decisions)
    titles_iter = iter(titles)
    filtered_json = copy.deepcopy(json_data)
    filtered_json, kept, dropped = _filter_structure(filtered_json, decisions_iter, titles_iter)
    
    # Record statistics
    latency_ms = (time.time() - start_time) * 1000
    filter_stats.record_request(kept, dropped, latency_ms)
    
    print(f"Filtered: kept={kept}, replaced with placeholder={dropped}, latency={latency_ms:.1f}ms", file=sys.stderr)
    
    # Replace JSON in body
    filtered_body = replace_json_in_body(decompressed_body, json_data, filtered_json)
    
    # Recompress to match original encoding if we decompressed
    filtered_body = recompress(filtered_body, encoding_used)
    
    return filtered_body


# -----------------------
# TCP Server with length-prefix protocol
# -----------------------

def recv_exact(conn: socket.socket, n: int) -> bytes:
    """Receive exactly n bytes from the socket."""
    data = bytearray()
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Connection closed while receiving data")
        data.extend(chunk)
    return bytes(data)


def recv_message(conn: socket.socket) -> bytes:
    """
    Receive a message with 4-byte length prefix (big-endian).
    """
    length_bytes = recv_exact(conn, 4)
    length = struct.unpack('>I', length_bytes)[0]
    print(f"Receiving message of {length} bytes", file=sys.stderr)
    return recv_exact(conn, length)


def send_message(conn: socket.socket, data: bytes) -> None:
    """
    Send a message with 4-byte length prefix (big-endian).
    """
    length = len(data)
    print(f"Sending message of {length} bytes", file=sys.stderr)
    conn.sendall(struct.pack('>I', length))
    conn.sendall(data)


def handle_connection(conn: socket.socket, client: LLMClient) -> None:
    """
    Handle connection using length-prefix protocol.
    Receive: 4-byte length + raw body
    Send: 4-byte length + filtered body
    """
    try:
        # Receive message with length prefix
        body = recv_message(conn)
        
        print(f"Received {len(body)} bytes from C proxy", file=sys.stderr)
        
        # Filter the response
        filtered = filter_response(body, client)
        
        print(f"Sending {len(filtered)} bytes back to C proxy", file=sys.stderr)
        
        # Send back filtered response with length prefix
        send_message(conn, filtered)
        
    except ConnectionError as e:
        print(f"Connection error: {e}", file=sys.stderr)
        raise


# -----------------------
# HTTP API Server
# -----------------------

class ConfigHTTPHandler(SimpleHTTPRequestHandler):
    """HTTP handler for configuration API and serving the web UI."""
    
    def __init__(self, *args, **kwargs):
        # Set directory for static files
        super().__init__(*args, directory=str(TEMPLATES_DIR), **kwargs)
    
    def log_message(self, format, *args):
        print(f"[HTTP] {args[0]}", file=sys.stderr)
    
    def send_json(self, data: dict, status: int = 200):
        body = json.dumps(data).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(body))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
        self.wfile.write(body)
    
    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
    
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        
        if path == '/config':
            self.send_json(config_state.to_dict())
        elif path == '/stats':
            self.send_json(filter_stats.to_dict())
        elif path == '/cache':
            self.send_json(llm_cache.stats())
        elif path == '/health':
            self.send_json({
                'status': 'ok',
                'config': config_state.to_dict(),
                'stats': filter_stats.to_dict(),
                'cache': llm_cache.stats(),
            })
        elif path == '/' or path == '/index.html':
            # Serve the HTML file
            try:
                html_path = TEMPLATES_DIR / 'index.html'
                with open(html_path, 'rb') as f:
                    content = f.read()
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.send_header('Content-Length', len(content))
                self.end_headers()
                self.wfile.write(content)
            except FileNotFoundError:
                self.send_error(404, 'index.html not found')
        else:
            # Serve static files
            super().do_GET()
    
    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        
        if path == '/config':
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)
            
            try:
                payload = json.loads(body.decode('utf-8'))
                config_state.update(
                    focus=payload.get('focus'),
                    enabled=payload.get('enabled'),
                    model=payload.get('model'),
                )
                # Clear cache when focus changes
                if 'focus' in payload:
                    llm_cache.clear()
                    print("[Config] Focus changed, cache cleared", file=sys.stderr)
                self.send_json(config_state.to_dict())
            except json.JSONDecodeError:
                self.send_json({'error': 'Invalid JSON'}, 400)
        elif path == '/cache/clear':
            llm_cache.clear()
            self.send_json({'status': 'ok', 'message': 'Cache cleared'})
        else:
            self.send_json({'error': 'Not found'}, 404)


def run_http_server():
    """Run the HTTP API server in a separate thread."""
    server = HTTPServer((SERVER_CONFIG.host, SERVER_CONFIG.http_port), ConfigHTTPHandler)
    print(f"HTTP API server running on http://{SERVER_CONFIG.host}:{SERVER_CONFIG.http_port}", file=sys.stderr)
    server.serve_forever()


def main():
    print(f"Initializing LLM client...", file=sys.stderr)
    client = LLMClient()
    
    # Start HTTP server in a background thread
    http_thread = threading.Thread(target=run_http_server, daemon=True)
    http_thread.start()
    
    print(f"Starting TCP Filter Server on {SERVER_CONFIG.host}:{SERVER_CONFIG.tcp_port}", file=sys.stderr)
    print(f"Focus: {config_state.focus}", file=sys.stderr)
    print(f"Model: {config_state.model}", file=sys.stderr)
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((SERVER_CONFIG.host, SERVER_CONFIG.tcp_port))
        server_socket.listen(1)
        
        print(f"TCP server listening on {SERVER_CONFIG.host}:{SERVER_CONFIG.tcp_port}", file=sys.stderr)
        print(f"Web UI available at http://localhost:{SERVER_CONFIG.http_port}", file=sys.stderr)
        
        while True:
            print("Waiting for C proxy connection...", file=sys.stderr)
            conn, addr = server_socket.accept()
            
            with conn:
                print(f"Connected by {addr}", file=sys.stderr)
                
                # Keep connection alive for multiple requests
                try:
                    while True:
                        handle_connection(conn, client)
                except ConnectionError as e:
                    print(f"Connection closed: {e}", file=sys.stderr)
                except Exception as e:
                    print(f"Error handling connection: {e}", file=sys.stderr)
                    import traceback
                    traceback.print_exc()


if __name__ == "__main__":
    main()
