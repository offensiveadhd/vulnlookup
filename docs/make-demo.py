#!/usr/bin/env python3
"""Record the README demo: runs a scripted terminal session through the real CLI and writes
docs/demo.svg (an animated SVG that GitHub renders inline) plus docs/demo.html (the same
session as a self-contained HTML player) and docs/demo-frames/*.txt (the frames, for an MP4
or GIF via Playwright + ffmpeg, see docs/make-demo-video.mjs).

    python docs/make-demo.py            # needs the network or a warm cache

No dependency: the SVG is written by hand, one <text> block per frame, revealed by CSS
keyframes. Deterministic: the same session gives the same file.
"""

from __future__ import annotations

import html
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
CLI = ROOT / "skills" / "vulnlookup" / "scripts" / "vulnlookup.py"
OUT_SVG = ROOT / "docs" / "demo.svg"
OUT_HTML = ROOT / "docs" / "demo.html"
FRAMES = ROOT / "docs" / "demo-frames"

# (what is typed, how long the result stays on screen in seconds, max lines to show)
SESSION = [
    ("vulnlookup cve CVE-2021-44228 --format brief --style terse", 3.0, 40),
    ('vulnlookup product "apache httpd 2.4.49" --kev --poc --style terse', 4.5, 40),
    ('vulnlookup product "apache httpd 2.4.49" --kev --style executive --format brief', 5.5, 40),
    ('vulnlookup resolve "log4j 2.14.1"', 3.0, 40),
    ('vulnlookup product "log4j 2.99" --format brief', 3.5, 40),
    ("VULNLOOKUP_NO_ALIAS=1 vulnlookup resolve gitlab", 5.0, 11),
    ('vulnlookup product "openssl 1.1.1" --severity CRITICAL --recommend --format md --limit 2', 7.0, 40),
    ("vulnlookup key status", 2.5, 40),
]

COLS, ROWS = 124, 34
CHAR_W, LINE_H = 7.8, 18
PAD = 16
W = int(COLS * CHAR_W + 2 * PAD)
H = int(ROWS * LINE_H + 2 * PAD + 30)
TYPE_S = 0.035  # seconds per typed character


def run(cmd: str) -> str:
    import os
    import shlex

    env = dict(os.environ)
    words = shlex.split(cmd)
    while "=" in words[0]:  # a leading VAR=value goes into the environment, like a shell
        k, _, v = words.pop(0).partition("=")
        env[k] = v
    argv = [sys.executable, str(CLI)] + words[1:]
    r = subprocess.run(argv, capture_output=True, text=True, env=env, encoding="utf-8")  # noqa: S603
    out = r.stdout
    if r.returncode == 3:
        out = r.stderr + out
    elif r.stderr and not out.strip():
        out = r.stderr
    return out.rstrip("\n") + (f"\n[exit {r.returncode}]" if r.returncode else "")


def clip(text: str, max_lines: int) -> list[str]:
    lines = [ln[:COLS] for ln in text.splitlines()]
    if len(lines) > max_lines:
        lines = lines[: max_lines - 1] + [f"… {len(lines) - max_lines + 1} more line(s)"]
    return lines


def colour(line: str) -> str:
    if line.startswith("$ "):
        return "#D8DEE6"
    if "CRIT" in line or "KEV" in line or line.startswith("ambiguous"):
        return "#FF8A4A"
    if line.startswith("[exit") or line.startswith("Not counted") or line.startswith("note:"):
        return "#8A94A2"
    if "EXACT" in line or "RANGE" in line or "exact dictionary" in line:
        return "#B8FF3C"
    return "#C8D0DA"


def main() -> None:
    FRAMES.mkdir(exist_ok=True)
    frames: list[tuple[str, list[str], float]] = []
    for i, (cmd, hold, max_lines) in enumerate(SESSION):
        out = run(cmd)
        lines = clip(out, max_lines)
        (FRAMES / f"{i + 1:02d}.txt").write_text("$ " + cmd + "\n" + "\n".join(lines) + "\n", encoding="utf-8")
        frames.append((cmd, lines, hold))

    # timeline
    t = 0.6
    timeline = []
    for cmd, _lines, hold in frames:
        type_t = len(cmd) * TYPE_S
        timeline.append((t, type_t, hold))
        t += type_t + 0.4 + hold + 0.3
    total = t

    svg = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" font-family="\'IBM Plex Mono\',\'JetBrains Mono\',\'Cascadia Code\',Consolas,monospace" font-size="13">',
        "<style>",
        "@keyframes cycle { 0% { opacity: 0 } 100% { opacity: 0 } }",
        f".f {{ opacity: 0; animation-duration: {total:.2f}s; animation-iteration-count: infinite; animation-timing-function: steps(1, end); }}",
    ]
    # one keyframe set per frame: visible from its start to its end
    for i, (start, type_t, hold) in enumerate(timeline):
        end = start + type_t + 0.4 + hold
        a, b = start / total * 100, end / total * 100
        svg.append(
            f"@keyframes f{i} {{ 0% {{ opacity: 0 }} {a:.3f}% {{ opacity: 1 }} {b:.3f}% {{ opacity: 1 }} {min(b + 0.001, 100):.3f}% {{ opacity: 0 }} 100% {{ opacity: 0 }} }}"
        )
        svg.append(f".f{i} {{ animation-name: f{i}; }}")
        # typing: the output appears after the command is typed
        oa = (start + type_t + 0.4) / total * 100
        svg.append(
            f"@keyframes o{i} {{ 0% {{ opacity: 0 }} {oa:.3f}% {{ opacity: 1 }} {b:.3f}% {{ opacity: 1 }} {min(b + 0.001, 100):.3f}% {{ opacity: 0 }} 100% {{ opacity: 0 }} }}"
        )
        svg.append(f".o{i} {{ animation-name: o{i}; }}")
    svg.append("</style>")
    svg.append(f'<rect width="{W}" height="{H}" rx="12" fill="#0B0D10"/>')
    svg.append(f'<rect x="0" y="0" width="{W}" height="30" rx="12" fill="#14181D"/>')
    svg.append(
        '<circle cx="18" cy="15" r="5" fill="#E5484D"/><circle cx="36" cy="15" r="5" fill="#FF6B1A"/><circle cx="54" cy="15" r="5" fill="#B8FF3C"/>'
    )
    svg.append(
        f'<text x="{W / 2:.0f}" y="20" text-anchor="middle" fill="#8A94A2" font-size="12">vulnlookup — passive CVE / CPE / EPSS / KEV lookup</text>'
    )
    y0 = 30 + PAD + 14
    for i, (cmd, lines, _hold) in enumerate(frames):
        svg.append(f'<g class="f f{i}">')
        svg.append(f'<text x="{PAD}" y="{y0}" fill="#B8FF3C">$ <tspan fill="#D8DEE6">{html.escape(cmd)}</tspan></text>')
        svg.append(f'<g class="f o{i}">')
        for j, line in enumerate(lines[: ROWS - 1]):
            svg.append(
                f'<text x="{PAD}" y="{y0 + (j + 1) * LINE_H}" fill="{colour(line)}" xml:space="preserve">{html.escape(line)}</text>'
            )
        svg.append("</g></g>")
    svg.append("</svg>")
    OUT_SVG.write_text("\n".join(svg) + "\n", encoding="utf-8")

    # the HTML player: same frames, a tiny script, no dependency
    OUT_HTML.write_text(
        "<!doctype html><meta charset=utf-8><title>vulnlookup demo</title>"
        "<style>body{margin:0;background:#0B0D10;display:grid;place-items:center;min-height:100vh}"
        f"pre{{width:{W}px;height:{H}px;box-sizing:border-box;padding:{PAD + 30}px {PAD}px {PAD}px;margin:0;border-radius:12px;"
        "background:#0B0D10;color:#C8D0DA;font:13px/18px 'IBM Plex Mono','JetBrains Mono','Cascadia Code',Consolas,monospace;overflow:hidden;white-space:pre}"
        ".p{color:#B8FF3C}.c{color:#D8DEE6}.h{color:#FF8A4A}.g{color:#8A94A2}.ok{color:#B8FF3C}</style>"
        "<pre id=t></pre><script>const F="
        + __import__("json").dumps([{"cmd": c, "lines": ln, "hold": h} for c, ln, h in frames])
        + ";const t=document.getElementById('t');const esc=s=>s.replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));"
        "const cls=l=>/CRIT|KEV|^ambiguous/.test(l)?'h':/^\\[exit|^Not counted|^note:/.test(l)?'g':/EXACT|RANGE|exact dictionary/.test(l)?'ok':'';"
        "async function sleep(ms){return new Promise(r=>setTimeout(r,ms))}"
        "async function play(){for(;;){for(const f of F){let typed='';t.innerHTML='<span class=p>$ </span>';"
        "for(const ch of f.cmd){typed+=ch;t.innerHTML='<span class=p>$ </span><span class=c>'+esc(typed)+'</span>▌';await sleep(35)}"
        "await sleep(400);t.innerHTML='<span class=p>$ </span><span class=c>'+esc(f.cmd)+'</span>\\n'+f.lines.map(l=>'<span class=\"'+cls(l)+'\">'+esc(l)+'</span>').join('\\n');"
        "await sleep(f.hold*1000)}}}play();</script>\n",
        encoding="utf-8",
    )
    print(f"wrote {OUT_SVG} ({OUT_SVG.stat().st_size // 1024} KB, {total:.0f}s loop) and {OUT_HTML}")


if __name__ == "__main__":
    main()
