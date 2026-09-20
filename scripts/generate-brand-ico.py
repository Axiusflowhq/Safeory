#!/usr/bin/env python3
"""Generate Safeory's multi-resolution favicon from the main product logo."""

from __future__ import annotations

import os
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "apps" / "web" / "public" / "branding-assets" / "safeory-logo.svg"
OUTPUT = ROOT / "apps" / "web" / "app" / "favicon.ico"
SIZES = (16, 32, 48, 64, 128, 256)


def find_browser() -> str:
    """Find a Chromium browser capable of faithfully rasterizing the SVG."""
    commands = ("msedge", "microsoft-edge", "google-chrome", "chromium", "chromium-browser")
    for command in commands:
        executable = shutil.which(command)
        if executable:
            return executable

    candidates = (
        Path(os.environ.get("PROGRAMFILES(X86)", "")) / "Microsoft/Edge/Application/msedge.exe",
        Path(os.environ.get("PROGRAMFILES", "")) / "Microsoft/Edge/Application/msedge.exe",
        Path(os.environ.get("PROGRAMFILES", "")) / "Google/Chrome/Application/chrome.exe",
        Path(os.environ.get("PROGRAMFILES(X86)", "")) / "Google/Chrome/Application/chrome.exe",
        Path("/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"),
        Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
    )
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    raise RuntimeError("A Chromium browser (Edge, Chrome, or Chromium) is required to render the main logo")


def png_dimensions(png: bytes) -> tuple[int, int]:
    if png[:8] != b"\x89PNG\r\n\x1a\n" or png[12:16] != b"IHDR":
        raise ValueError("Browser did not produce a valid PNG")
    return struct.unpack(">II", png[16:24])


def render_frames(browser: str, svg: str) -> list[tuple[int, bytes]]:
    frames: list[tuple[int, bytes]] = []
    with tempfile.TemporaryDirectory(prefix="safeory-favicon-") as temp_dir:
        temp = Path(temp_dir)
        html = temp / "logo.html"
        for size in SIZES:
            png_path = temp / f"logo-{size}.png"
            html.write_text(
                "<!doctype html><style>html,body{margin:0;overflow:hidden;background:transparent}"
                f"svg{{display:block;width:{size}px;height:{size}px}}</style>" + svg,
                encoding="utf-8",
            )
            command = (
                browser,
                "--headless",
                "--disable-gpu",
                "--hide-scrollbars",
                "--default-background-color=00000000",
                "--force-device-scale-factor=1",
                f"--window-size={size},{size}",
                f"--screenshot={png_path}",
                html.as_uri(),
            )
            for _ in range(3):
                result = subprocess.run(command, capture_output=True, text=True, timeout=30)
                if png_path.is_file() and png_path.stat().st_size > max(500, size * 5):
                    break
            if result.returncode != 0 or not png_path.is_file():
                detail = result.stderr.strip() or result.stdout.strip() or "unknown browser error"
                raise RuntimeError(f"Could not render {size}px favicon frame: {detail}")
            png = png_path.read_bytes()
            if len(png) <= max(500, size * 5):
                raise RuntimeError(f"Browser produced an empty {size}px favicon frame after 3 attempts")
            if png_dimensions(png) != (size, size):
                raise ValueError(f"Expected a {size}x{size} PNG frame, got {png_dimensions(png)}")
            frames.append((size, png))
    return frames


def write_ico(frames: list[tuple[int, bytes]], output: Path) -> None:
    header = struct.pack("<HHH", 0, 1, len(frames))
    directory = bytearray()
    payload = bytearray()
    offset = 6 + 16 * len(frames)
    for size, png in frames:
        dimension = 0 if size == 256 else size
        directory.extend(struct.pack("<BBBBHHII", dimension, dimension, 0, 0, 1, 32, len(png), offset))
        payload.extend(png)
        offset += len(png)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(header + directory + payload)


def main() -> None:
    frames = render_frames(find_browser(), SOURCE.read_text(encoding="utf-8"))
    write_ico(frames, OUTPUT)
    sizes = ", ".join(f"{size}px" for size, _ in frames)
    print(f"Generated {OUTPUT.relative_to(ROOT)} from {SOURCE.relative_to(ROOT)} ({sizes})")


if __name__ == "__main__":
    main()
