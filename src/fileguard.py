import os
import hashlib
import json
import logging
import argparse
import time
from datetime import datetime
from fnmatch import fnmatch
from collections import Counter

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


BASELINE_FILE = "data/baseline.json"
LOG_FILE = "logs/alerts.log"
EVENTS_FILE = "logs/events.jsonl"
REPORT_FILE = "reports/report.html"

# Janela anti-duplicados (segundos). Se quiseres desligar: mete 0.
DEDUP_WINDOW_SECONDS = 1.0


def setup_logging():
    os.makedirs("logs", exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
        handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()],
    )


def load_config(config_path: str):
    if not config_path:
        return {"include": [], "exclude": []}

    config_path = os.path.abspath(os.path.expanduser(config_path))
    if not os.path.exists(config_path):
        logging.warning("Config não encontrada em %s (a usar regras vazias)", config_path)
        return {"include": [], "exclude": []}

    with open(config_path, "r", encoding="utf-8") as f:
        cfg = json.load(f)

    cfg.setdefault("include", [])
    cfg.setdefault("exclude", [])
    return cfg


def matches_any(path: str, patterns: list[str]) -> bool:
    for p in patterns:
        if fnmatch(path, p):
            return True
    return False


def should_monitor(path: str, cfg) -> bool:
    path = os.path.abspath(path)

    includes = cfg.get("include", [])
    if includes and not matches_any(path, includes):
        return False

    excludes = cfg.get("exclude", [])
    if excludes and matches_any(path, excludes):
        return False

    return True


def hash_file(path: str) -> str:
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(4096), b""):
            sha256.update(block)
    return sha256.hexdigest()


def log_event(event_type: str, path: str, details: dict | None = None):
    os.makedirs("logs", exist_ok=True)
    entry = {
        "ts": datetime.now().isoformat(timespec="seconds"),
        "type": event_type,
        "path": os.path.abspath(path),
    }
    if details:
        entry["details"] = details

    with open(EVENTS_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def create_baseline(directory: str, cfg):
    directory = os.path.abspath(directory)
    baseline = {}

    for root, _, files in os.walk(directory):
        for name in files:
            filepath = os.path.abspath(os.path.join(root, name))
            if not should_monitor(filepath, cfg):
                continue
            try:
                baseline[filepath] = {
                    "sha256": hash_file(filepath),
                    "size": os.path.getsize(filepath),
                    "mtime": os.path.getmtime(filepath),
                }
            except Exception as e:
                logging.error("Erro ao criar baseline para %s: %s", filepath, e)

    os.makedirs("data", exist_ok=True)
    with open(BASELINE_FILE, "w", encoding="utf-8") as f:
        json.dump(
            {
                "created_at": datetime.now().isoformat(timespec="seconds"),
                "root": directory,
                "files": baseline,
            },
            f,
            indent=4,
            ensure_ascii=False,
        )

    logging.info("Baseline criada: %d ficheiros guardados em %s", len(baseline), BASELINE_FILE)


def load_baseline():
    if not os.path.exists(BASELINE_FILE):
        logging.error("Baseline não encontrada em %s", BASELINE_FILE)
        return None
    with open(BASELINE_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def scan_current_state(root: str, cfg):
    current = {}
    for root_dir, _, files in os.walk(root):
        for name in files:
            filepath = os.path.abspath(os.path.join(root_dir, name))
            if not should_monitor(filepath, cfg):
                continue
            try:
                current[filepath] = {
                    "sha256": hash_file(filepath),
                    "size": os.path.getsize(filepath),
                    "mtime": os.path.getmtime(filepath),
                }
            except Exception as e:
                logging.error("Erro ao ler %s: %s", filepath, e)
    return current


def compare_states(baseline, current):
    baseline_files = baseline["files"]

    logging.info("A verificar integridade em: %s", baseline["root"])
    logging.info("Ficheiros na baseline: %d | Ficheiros atuais: %d", len(baseline_files), len(current))

    apagados = novos = modificados = 0

    # apagados
    for path in baseline_files:
        if path not in current:
            apagados += 1
            logging.warning("FICHEIRO APAGADO: %s", path)
            log_event("deleted", path)

    # novos e modificados
    for path, info in current.items():
        if path not in baseline_files:
            novos += 1
            logging.warning("FICHEIRO NOVO: %s", path)
            log_event("new", path)
        else:
            if info["sha256"] != baseline_files[path]["sha256"]:
                modificados += 1
                logging.warning("FICHEIRO MODIFICADO: %s", path)
                log_event("modified", path)

    logging.info("Resumo: %d modificados | %d novos | %d apagados", modificados, novos, apagados)


class GuardHandler(FileSystemEventHandler):
    def __init__(self, baseline_files: dict, cfg):
        self.baseline_files = baseline_files
        self.cfg = cfg

        # anti-duplicados simples
        self._last_seen: dict[tuple[str, str], float] = {}

    def _dedup_ok(self, event_type: str, path: str) -> bool:
        if DEDUP_WINDOW_SECONDS <= 0:
            return True
        key = (event_type, os.path.abspath(path))
        now = time.time()
        last = self._last_seen.get(key, 0.0)
        if now - last < DEDUP_WINDOW_SECONDS:
            return False
        self._last_seen[key] = now
        return True

    def _check_file(self, path: str):
        path = os.path.abspath(path)
        if not os.path.exists(path):
            return
        if not should_monitor(path, self.cfg):
            return

        try:
            current_hash = hash_file(path)
        except Exception as e:
            logging.error("Erro a fazer hash de %s: %s", path, e)
            return

        if path not in self.baseline_files:
            if self._dedup_ok("new", path):
                logging.warning("FICHEIRO NOVO: %s", path)
                log_event("new", path)
        else:
            if current_hash != self.baseline_files[path]["sha256"]:
                if self._dedup_ok("modified", path):
                    logging.warning("FICHEIRO MODIFICADO: %s", path)
                    log_event("modified", path)

    def on_created(self, event):
        if event.is_directory:
            return
        self._check_file(event.src_path)

    def on_modified(self, event):
        if event.is_directory:
            return
        self._check_file(event.src_path)

    def on_deleted(self, event):
        if event.is_directory:
            return
        path = os.path.abspath(event.src_path)
        if not should_monitor(path, self.cfg):
            return

        if path in self.baseline_files:
            if self._dedup_ok("deleted", path):
                logging.warning("FICHEIRO APAGADO: %s", path)
                log_event("deleted", path)
        else:
            logging.info("Ficheiro apagado (não estava na baseline): %s", path)

    def on_moved(self, event):
        if event.is_directory:
            return
        old = os.path.abspath(event.src_path)
        new = os.path.abspath(event.dest_path)

        if should_monitor(old, self.cfg) or should_monitor(new, self.cfg):
            if self._dedup_ok("moved", old):
                logging.warning("FICHEIRO MOVIDO/RENOMEADO: %s -> %s", old, new)
                log_event("moved", old, {"to": new})

        # verificar o novo destino
        self._check_file(new)


def watch_mode(root: str, baseline_files: dict, cfg):
    logging.info("Modo tempo real ativo em: %s (CTRL+C para parar)", root)
    handler = GuardHandler(baseline_files, cfg)
    observer = Observer()
    observer.schedule(handler, root, recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("A parar (CTRL+C)...")
        observer.stop()

    observer.join()


def read_events():
    if not os.path.exists(EVENTS_FILE):
        return []
    events = []
    with open(EVENTS_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def generate_report_html(events: list[dict], output_path: str):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    total = len(events)
    counts = Counter(e.get("type", "unknown") for e in events)
    last_events = events[-25:]  # últimos 25

    now = datetime.now().isoformat(timespec="seconds")

    html = []
    html.append("<!doctype html>")
    html.append("<html lang='pt-PT'><head><meta charset='utf-8'>")
    html.append("<meta name='viewport' content='width=device-width, initial-scale=1'>")
    html.append("<title>FileGuard - Relatório</title>")
    html.append("""
    <style>
      body{font-family:Arial, sans-serif; margin:24px; color:#111;}
      h1{margin-bottom:4px;}
      .meta{color:#555; margin-bottom:18px;}
      .cards{display:flex; gap:12px; flex-wrap:wrap; margin:16px 0;}
      .card{border:1px solid #ddd; border-radius:10px; padding:12px 14px; min-width:160px;}
      .num{font-size:28px; font-weight:700;}
      table{border-collapse:collapse; width:100%; margin-top:12px;}
      th,td{border:1px solid #ddd; padding:8px; text-align:left; font-size:14px;}
      th{background:#f6f6f6;}
      .tag{display:inline-block; padding:2px 8px; border-radius:999px; border:1px solid #ddd; font-size:12px;}
      code{white-space:pre-wrap;}
    </style>
    """)
    html.append("</head><body>")

    html.append("<h1>FileGuard — Relatório de Eventos</h1>")
    html.append(f"<div class='meta'>Gerado em: <b>{now}</b> | Fonte: <code>{EVENTS_FILE}</code></div>")

    html.append("<div class='cards'>")
    html.append(f"<div class='card'><div class='num'>{total}</div><div>Total de eventos</div></div>")
    for k in ["modified", "new", "deleted", "moved"]:
        html.append(f"<div class='card'><div class='num'>{counts.get(k,0)}</div><div>{k}</div></div>")
    html.append("</div>")

    html.append("<h2>Resumo por tipo</h2>")
    html.append("<table><thead><tr><th>Tipo</th><th>Quantidade</th></tr></thead><tbody>")
    for t, n in counts.most_common():
        html.append(f"<tr><td><span class='tag'>{t}</span></td><td>{n}</td></tr>")
    html.append("</tbody></table>")

    html.append("<h2>Últimos 25 eventos</h2>")
    html.append("<table><thead><tr><th>Timestamp</th><th>Tipo</th><th>Path</th><th>Detalhes</th></tr></thead><tbody>")
    for e in reversed(last_events):
        ts = e.get("ts", "")
        t = e.get("type", "")
        path = e.get("path", "")
        details = e.get("details", "")
        if isinstance(details, dict):
            details = json.dumps(details, ensure_ascii=False)
        html.append(
            f"<tr><td>{ts}</td>"
            f"<td><span class='tag'>{t}</span></td>"
            f"<td><code>{path}</code></td>"
            f"<td><code>{details}</code></td></tr>"
        )
    html.append("</tbody></table>")

    html.append("</body></html>")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(html))

    logging.info("Relatório gerado: %s", output_path)


def parse_args():
    p = argparse.ArgumentParser(description="FileGuard - Monitor de Integridade de Ficheiros (HIDS simplificado)")
    p.add_argument("--baseline", action="store_true", help="Criar/recriar a baseline")
    p.add_argument("--watch", action="store_true", help="Monitorização em tempo real (watchdog)")
    p.add_argument("--report", action="store_true", help="Gerar relatório HTML a partir do events.jsonl")
    p.add_argument(
        "--path",
        default=os.path.expanduser("~/fileguard_lab/criticos"),
        help="Pasta a monitorizar (usada na criação da baseline)",
    )
    p.add_argument(
        "--config",
        default=os.path.expanduser("~/fileguard/config.json"),
        help="Ficheiro de configuração JSON (include/exclude)",
    )
    return p.parse_args()


def main():
    setup_logging()
    args = parse_args()
    cfg = load_config(args.config)

    # Gera relatório mesmo que não exista baseline
    if args.report:
        events = read_events()
        generate_report_html(events, REPORT_FILE)
        return

    if args.baseline:
        create_baseline(os.path.abspath(os.path.expanduser(args.path)), cfg)
        return

    baseline = load_baseline()
    if not baseline:
        logging.info("Dica: cria uma baseline com: python src/fileguard.py --baseline --path <pasta>")
        return

    root = baseline["root"]

    if args.watch:
        watch_mode(root, baseline["files"], cfg)
        return

    current = scan_current_state(root, cfg)
    compare_states(baseline, current)


if __name__ == "__main__":
    main()
