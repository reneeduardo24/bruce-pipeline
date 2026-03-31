from __future__ import annotations

import html
from pathlib import Path
from typing import Any

from .configuration import AppConfig
from .models import ProcessedCapture
from .utils import atomic_write_json, atomic_write_text, copy_to_latest, utc_timestamp


def ensure_placeholder_dashboard(config: AppConfig) -> None:
    if config.paths.latest_html.exists():
        return
    atomic_write_text(
        config.paths.latest_html,
        """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Bruce Pipeline</title>
  <style>
    :root { color-scheme: light; --bg: #f5efe6; --card: #fffaf3; --ink: #1f2933; --accent: #c26d28; }
    body { margin: 0; font-family: Georgia, serif; background: radial-gradient(circle at top, #fff8ed 0%, #f1e6d6 52%, #e4d2bc 100%); color: var(--ink); }
    main { max-width: 880px; margin: 48px auto; padding: 24px; }
    section { background: rgba(255, 250, 243, 0.92); border: 1px solid rgba(69, 46, 25, 0.12); border-radius: 18px; padding: 24px; box-shadow: 0 22px 42px rgba(94, 65, 34, 0.08); }
    h1 { margin-top: 0; letter-spacing: 0.04em; text-transform: uppercase; font-size: 1.2rem; }
    p { line-height: 1.6; }
    code { background: rgba(194, 109, 40, 0.12); padding: 2px 6px; border-radius: 6px; }
  </style>
</head>
<body>
  <main>
    <section>
      <h1>Bruce Pipeline</h1>
      <p>The dashboard will appear here after the first valid capture is processed.</p>
      <p>Drop a <code>.pcap</code> or <code>.pcapng</code> file into the inbox and wait for the analyzer to publish the latest HTML report.</p>
    </section>
  </main>
</body>
</html>
""",
    )


def _metric_row(label: str, raw_value: Any, normalized_value: float) -> str:
    width = max(4.0, normalized_value * 100.0)
    return (
        "<tr>"
        f"<th>{html.escape(label)}</th>"
        f"<td>{html.escape(str(raw_value))}</td>"
        f"<td><div class=\"meter\"><span style=\"width:{width:.1f}%\"></span></div>{normalized_value:.2f}</td>"
        "</tr>"
    )


def _render_top_list(items: list[dict[str, Any]], title: str) -> str:
    if not items:
        return f"<section class=\"panel\"><h3>{html.escape(title)}</h3><p>No data.</p></section>"
    rows = "".join(
        f"<tr><td>{html.escape(str(item['value']))}</td><td>{item['count']}</td></tr>"
        for item in items
    )
    return (
        f"<section class=\"panel\"><h3>{html.escape(title)}</h3>"
        f"<table><tbody>{rows}</tbody></table></section>"
    )


def build_summary(
    capture: ProcessedCapture,
    config: AppConfig,
) -> dict[str, Any]:
    return {
        "app_name": config.app_name,
        "generated_at": utc_timestamp(),
        "profile": config.profile.to_dict(),
        "capture": capture.to_dict(),
    }


def write_summary_files(
    *,
    capture: ProcessedCapture,
    config: AppConfig,
    summary_path: Path,
    html_path: Path,
) -> dict[str, Any]:
    summary = build_summary(capture, config)
    atomic_write_json(summary_path, summary)
    atomic_write_text(html_path, render_html(summary))
    copy_to_latest(summary_path, config.paths.latest_summary)
    copy_to_latest(Path(capture.detail_csv_path), config.paths.latest_csv)
    copy_to_latest(html_path, config.paths.latest_html)
    return summary


def write_state_files(summary: dict[str, Any], config: AppConfig) -> None:
    atomic_write_json(config.paths.current_state, summary["capture"])
    atomic_write_json(
        config.paths.active_profile,
        {
            "loaded_at": utc_timestamp(),
            "profile_path": str(config.profile_path),
            "profile": config.profile.to_dict(),
        },
    )


def render_html(summary: dict[str, Any]) -> str:
    capture = summary["capture"]
    metrics = capture["metrics"]
    assessment = capture["assessment"]
    classification = assessment["classification"]
    palette = {
        "NORMAL": ("#2c6e49", "#edf8ef"),
        "CONGESTIONADO": ("#9a6700", "#fff8e6"),
        "CRITICO": ("#b42318", "#fff0ed"),
    }
    accent, surface = palette.get(classification, ("#1f2933", "#ffffff"))
    metric_labels = {
        "NF": "Frames",
        "NB": "BSSIDs",
        "NK": "Clients",
        "NP": "Probe activity",
        "ND": "Disruptive events",
    }
    raw_map = {
        "NF": metrics["frames"],
        "NB": metrics["unique_bssids"],
        "NK": metrics["unique_clients"],
        "NP": metrics["probe_activity"],
        "ND": metrics["disruptive_events"],
    }
    metric_rows = "".join(
        _metric_row(metric_labels[key], raw_map[key], float(value))
        for key, value in assessment["normalized_metrics"].items()
    )
    previous = capture["previous_classification"] or "NONE"
    changed = "YES" if capture["state_changed"] else "NO"
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Bruce Pipeline Dashboard</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f4ece1;
      --paper: rgba(255, 251, 245, 0.95);
      --ink: #1f2933;
      --muted: #52606d;
      --accent: {accent};
      --surface: {surface};
      --line: rgba(31, 41, 51, 0.08);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: Georgia, serif;
      color: var(--ink);
      background:
        radial-gradient(circle at top left, rgba(194, 109, 40, 0.18), transparent 28%),
        radial-gradient(circle at top right, rgba(44, 110, 73, 0.12), transparent 24%),
        linear-gradient(180deg, #fbf6ef 0%, var(--bg) 100%);
    }}
    main {{ max-width: 1120px; margin: 0 auto; padding: 24px; }}
    header {{ display: grid; gap: 12px; padding: 32px 0 18px; }}
    h1 {{ margin: 0; font-size: clamp(2rem, 5vw, 3.8rem); letter-spacing: 0.04em; text-transform: uppercase; }}
    p {{ margin: 0; color: var(--muted); line-height: 1.6; }}
    .badge {{ display: inline-flex; width: fit-content; padding: 10px 16px; border-radius: 999px; background: var(--surface); color: var(--accent); border: 1px solid color-mix(in srgb, var(--accent) 32%, white); font-weight: 700; letter-spacing: 0.05em; text-transform: uppercase; }}
    .hero {{ display: grid; gap: 18px; background: var(--paper); border: 1px solid var(--line); border-radius: 24px; padding: 24px; box-shadow: 0 24px 60px rgba(41, 48, 56, 0.08); }}
    .score {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 14px; }}
    .card, .panel {{ background: rgba(255, 255, 255, 0.74); border: 1px solid var(--line); border-radius: 18px; padding: 18px; }}
    .label {{ color: var(--muted); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.08em; }}
    .value {{ font-size: 2.2rem; margin-top: 10px; font-weight: 700; }}
    .grid {{ display: grid; gap: 18px; grid-template-columns: 2fr 1fr; margin-top: 18px; }}
    .panels {{ display: grid; gap: 18px; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); margin-top: 18px; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ text-align: left; padding: 12px 0; border-bottom: 1px solid var(--line); vertical-align: top; }}
    th {{ width: 30%; font-weight: 700; }}
    .meter {{ margin-bottom: 8px; height: 10px; width: 100%; background: rgba(31, 41, 51, 0.08); border-radius: 999px; overflow: hidden; }}
    .meter span {{ display: block; height: 100%; background: linear-gradient(90deg, color-mix(in srgb, var(--accent) 74%, white), var(--accent)); border-radius: 999px; }}
    footer {{ padding: 18px 0 36px; color: var(--muted); font-size: 0.92rem; }}
    @media (max-width: 860px) {{ .grid {{ grid-template-columns: 1fr; }} }}
  </style>
</head>
<body>
  <main>
    <header>
      <span class="badge">{html.escape(classification)}</span>
      <h1>Bruce Pipeline</h1>
      <p>Latest Wi-Fi environment classification generated from a Bruce RAW Sniffer capture.</p>
    </header>

    <section class="hero">
      <div class="score">
        <article class="card"><div class="label">IACO</div><div class="value">{assessment['score']:.2f}</div></article>
        <article class="card"><div class="label">Frames</div><div class="value">{metrics['frames']}</div></article>
        <article class="card"><div class="label">Unique BSSIDs</div><div class="value">{metrics['unique_bssids']}</div></article>
        <article class="card"><div class="label">Duration</div><div class="value">{metrics['duration_seconds']:.3f}s</div></article>
      </div>
      <p>{html.escape(assessment['band_description'])}</p>
    </section>

    <section class="grid">
      <article class="panel">
        <h2>Metric Breakdown</h2>
        <table>
          <tbody>{metric_rows}</tbody>
        </table>
      </article>
      <article class="panel">
        <h2>Capture</h2>
        <table>
          <tbody>
            <tr><th>Source</th><td>{html.escape(capture['source_name'])}</td></tr>
            <tr><th>Stored path</th><td>{html.escape(capture['stored_path'])}</td></tr>
            <tr><th>SHA256</th><td>{html.escape(capture['sha256'])}</td></tr>
            <tr><th>Processed at</th><td>{html.escape(capture['processed_at'])}</td></tr>
            <tr><th>Format</th><td>{html.escape(capture['capture_format'])}</td></tr>
            <tr><th>Previous class</th><td>{html.escape(previous)}</td></tr>
            <tr><th>State changed</th><td>{changed}</td></tr>
          </tbody>
        </table>
      </article>
    </section>

    <section class="panels">
      {_render_top_list(metrics['top_bssids'], 'Top BSSIDs')}
      {_render_top_list(metrics['top_ssids'], 'Top SSIDs')}
    </section>

    <footer>
      Generated at {html.escape(summary['generated_at'])}. JSON and CSV companions are stored alongside this report.
    </footer>
  </main>
</body>
</html>
"""
