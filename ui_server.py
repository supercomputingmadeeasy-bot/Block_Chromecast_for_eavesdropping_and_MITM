#!/usr/bin/env python3
"""
Chromecast Blocker — Web UI Server

Provides a browser-based control panel with:
  • Real-time terminal output via WebSocket (xterm.js)
  • Parallel task execution (each command runs in its own thread)
  • REST API (can be called from terminal/scripts too)
  • Config editor, log viewer, iptables viewer

Usage:
    python3 ui_server.py [--host 0.0.0.0] [--port 8080] [--debug]

Then open http://<pi-ip>:8080 in a browser.
"""

import os
import sys
import uuid
import subprocess
import threading
import json
import logging
import signal
from pathlib import Path
from datetime import datetime
from typing import Dict, Optional

import yaml
import psutil
from flask import Flask, render_template, request, jsonify, abort, Response
from flask_socketio import SocketIO, emit

# ─── Paths ───────────────────────────────────────────────────────────────────

BASE_DIR = Path(__file__).parent.resolve()
CONFIG_FILE = BASE_DIR / 'config.yaml'
LOG_DIR = BASE_DIR / 'logs'
LOG_DIR.mkdir(exist_ok=True)
BLOCKER_LOG = LOG_DIR / 'blocker.log'
UI_LOG = LOG_DIR / 'ui_server.log'

# ─── Logging ─────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(UI_LOG),
    ],
)
logger = logging.getLogger(__name__)

# ─── Flask / SocketIO ────────────────────────────────────────────────────────

app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['SECRET_KEY'] = os.urandom(32)
socketio = SocketIO(
    app,
    cors_allowed_origins='*',
    async_mode='threading',
    logger=False,
    engineio_logger=False,
)

# ─── Task registry ───────────────────────────────────────────────────────────
# task_id → {name, cmd, started, pid}
active_tasks: Dict[str, dict] = {}
task_lock = threading.Lock()


# ─── Subprocess streaming ────────────────────────────────────────────────────

def _pipe_reader(stream, task_id: str, fd: str):
    """Read lines from a stream and emit them as WebSocket events."""
    try:
        for line in iter(stream.readline, ''):
            if line:
                socketio.emit('terminal_output', {
                    'task_id': task_id,
                    'fd': fd,
                    'line': line,
                    'ts': datetime.now().strftime('%H:%M:%S'),
                })
    except Exception:
        pass
    finally:
        stream.close()


def _stream_process(proc: subprocess.Popen, task_id: str):
    """Attach reader threads to stdout/stderr and a waiter thread."""
    t_out = threading.Thread(
        target=_pipe_reader, args=(proc.stdout, task_id, 'stdout'), daemon=True
    )
    t_err = threading.Thread(
        target=_pipe_reader, args=(proc.stderr, task_id, 'stderr'), daemon=True
    )
    t_out.start()
    t_err.start()

    def _waiter():
        t_out.join()
        t_err.join()
        proc.wait()
        with task_lock:
            active_tasks.pop(task_id, None)
        socketio.emit('task_done', {
            'task_id': task_id,
            'exit_code': proc.returncode,
            'ts': datetime.now().strftime('%H:%M:%S'),
        })
        logger.info(f'Task {task_id} finished (exit={proc.returncode})')

    threading.Thread(target=_waiter, daemon=True).start()


def run_task(name: str, cmd: list, env: Optional[dict] = None) -> str:
    """
    Launch *cmd* as a background subprocess. Returns a unique task_id.
    Output is streamed live to all connected WebSocket clients.
    Can be called from any thread → parallel execution is supported.
    """
    task_id = uuid.uuid4().hex[:8]
    full_env = {**os.environ, **(env or {})}

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            cwd=str(BASE_DIR),
            env=full_env,
        )
    except Exception as exc:
        raise RuntimeError(f'Could not start process: {exc}') from exc

    with task_lock:
        active_tasks[task_id] = {
            'name': name,
            'cmd': ' '.join(str(c) for c in cmd),
            'started': datetime.now().isoformat(),
            'pid': proc.pid,
        }

    _stream_process(proc, task_id)

    socketio.emit('task_started', {
        'task_id': task_id,
        'name': name,
        'cmd': ' '.join(str(c) for c in cmd),
        'ts': datetime.now().strftime('%H:%M:%S'),
    })
    logger.info(f'Task {task_id} started: {" ".join(str(c) for c in cmd)}')
    return task_id


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _load_config() -> dict:
    try:
        with open(CONFIG_FILE) as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}


def _iptables_rules() -> str:
    try:
        r = subprocess.run(
            ['sudo', 'iptables-save'],
            capture_output=True, text=True, timeout=8
        )
        return r.stdout
    except Exception as exc:
        return f'# Error reading iptables: {exc}\n'


def _rule_count() -> int:
    try:
        r = subprocess.run(
            ['sudo', 'iptables', '-L', '-n', '--line-numbers'],
            capture_output=True, text=True, timeout=8
        )
        return sum(
            1 for line in r.stdout.splitlines()
            if line and not line.startswith('Chain') and not line.startswith('target')
            and not line.startswith('num')
        )
    except Exception:
        return -1


def _device_protected(ip: str, rules: str) -> bool:
    return ip in rules


# ─── REST API ────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/status')
def api_status():
    config = _load_config()
    rules = _iptables_rules()
    rule_count = _rule_count()
    devices = config.get('chromecast_devices', [])

    device_statuses = []
    for dev in devices:
        ip = dev.get('ip', '')
        device_statuses.append({
            'ip': ip,
            'name': dev.get('name', ip),
            'enabled': dev.get('enabled', True),
            'protected': _device_protected(ip, rules),
        })

    with task_lock:
        tasks = list(active_tasks.items())

    return jsonify({
        'rule_count': rule_count,
        'devices': device_statuses,
        'active_tasks': [
            {'task_id': tid, **info} for tid, info in tasks
        ],
        'server_time': datetime.now().isoformat(),
    })


@app.route('/api/tasks')
def api_tasks():
    with task_lock:
        return jsonify([{'task_id': tid, **info} for tid, info in active_tasks.items()])


@app.route('/api/task/<task_id>', methods=['DELETE'])
def api_kill_task(task_id: str):
    """Kill a running task and all its child processes."""
    with task_lock:
        task = active_tasks.get(task_id)
    if not task:
        abort(404)
    try:
        parent = psutil.Process(task['pid'])
        for child in parent.children(recursive=True):
            child.kill()
        parent.kill()
    except psutil.NoSuchProcess:
        pass
    except Exception as exc:
        return jsonify({'error': str(exc)}), 500
    return jsonify({'ok': True, 'task_id': task_id})


@app.route('/api/command', methods=['POST'])
def api_command():
    """
    Trigger a blocker action.

    Body (JSON):
        action  : one of the ACTIONS keys below
        ip      : Chromecast IP (required for per-device actions)
        args    : optional extra args list

    Returns immediately with {'task_id': '...'}.
    Output is streamed via WebSocket.
    Multiple calls can run in parallel.
    """
    data = request.get_json(force=True, silent=True) or {}
    action = data.get('action', '').strip()
    ip = data.get('ip', '').strip()
    extra_args = data.get('args', [])

    # Map UI action names → CLI commands
    ACTIONS = {
        # advanced_blocker.py actions
        'protect_all':    ['python3', str(BASE_DIR / 'advanced_blocker.py'),    'protect-all'],
        'monitor':        ['python3', str(BASE_DIR / 'advanced_blocker.py'),    'monitor'],
        'summary':        ['python3', str(BASE_DIR / 'advanced_blocker.py'),    'summary'],
        'export_rules':   ['python3', str(BASE_DIR / 'advanced_blocker.py'),    'export', '--output', str(LOG_DIR / 'rules_backup.txt')],
        'rotate_logs':    ['python3', str(BASE_DIR / 'advanced_blocker.py'),    'rotate-logs'],
        # chromecast_blocker.py actions
        'discover':       ['python3', str(BASE_DIR / 'chromecast_blocker.py'),  'discover'],
        'flush':          ['python3', str(BASE_DIR / 'chromecast_blocker.py'),  'flush'],
        # status_monitor.py
        'status_monitor': ['python3', str(BASE_DIR / 'status_monitor.py')],
    }

    # Per-device actions need --ip
    IP_ACTIONS = {
        'block':         ['python3', str(BASE_DIR / 'chromecast_blocker.py'), 'block',        '--ip'],
        'full_protect':  ['python3', str(BASE_DIR / 'chromecast_blocker.py'), 'full-protect', '--ip'],
        'status':        ['python3', str(BASE_DIR / 'chromecast_blocker.py'), 'status',       '--ip'],
        'monitor_ip':    ['python3', str(BASE_DIR / 'chromecast_blocker.py'), 'monitor',      '--ip'],
    }

    if action in IP_ACTIONS:
        if not ip:
            return jsonify({'error': 'ip is required for this action'}), 400
        cmd = IP_ACTIONS[action] + [ip] + extra_args
        task_id = run_task(f'{action} {ip}', cmd)
        return jsonify({'task_id': task_id})

    if action in ACTIONS:
        cmd = ACTIONS[action] + extra_args
        task_id = run_task(action, cmd)
        return jsonify({'task_id': task_id})

    # Allow raw shell-like command for advanced terminal use
    if action == 'raw' and data.get('cmd'):
        import shlex
        try:
            cmd = shlex.split(data['cmd'])
        except ValueError as exc:
            return jsonify({'error': str(exc)}), 400
        task_id = run_task('raw', cmd)
        return jsonify({'task_id': task_id})

    return jsonify({'error': f'Unknown action: {action!r}'}), 400


@app.route('/api/config', methods=['GET', 'POST'])
def api_config():
    if request.method == 'GET':
        try:
            return jsonify({'config': CONFIG_FILE.read_text()})
        except Exception as exc:
            return jsonify({'error': str(exc)}), 500

    # POST – save new config
    data = request.get_json(force=True, silent=True) or {}
    raw = data.get('config', '')
    try:
        yaml.safe_load(raw)           # validate YAML before saving
    except yaml.YAMLError as exc:
        return jsonify({'error': f'Invalid YAML: {exc}'}), 400

    try:
        CONFIG_FILE.write_text(raw)
        return jsonify({'ok': True})
    except Exception as exc:
        return jsonify({'error': str(exc)}), 500


@app.route('/api/logs')
def api_logs():
    """Return last N lines from the main log file."""
    n = min(int(request.args.get('n', 300)), 2000)
    candidates = [
        BLOCKER_LOG,
        BASE_DIR / 'chromecast_blocker.log',
        LOG_DIR / 'advanced_blocker.log',
    ]
    lines: list = []
    for log_file in candidates:
        if log_file.exists():
            try:
                with open(log_file) as f:
                    lines = f.readlines()[-n:]
                break
            except Exception:
                pass
    return jsonify({'lines': lines, 'n': n})


@app.route('/api/iptables')
def api_iptables():
    return jsonify({'rules': _iptables_rules()})


@app.route('/api/log_files')
def api_log_files():
    files = []
    for p in sorted(LOG_DIR.glob('*.log*')):
        files.append({'name': p.name, 'size': p.stat().st_size})
    return jsonify({'files': files})


# ─── SocketIO events ─────────────────────────────────────────────────────────

@socketio.on('connect')
def on_connect():
    logger.info(f'WebSocket client connected: {request.sid}')


@socketio.on('disconnect')
def on_disconnect():
    logger.info(f'WebSocket client disconnected: {request.sid}')


@socketio.on('ping_server')
def on_ping(data):
    emit('pong_server', {'ts': datetime.now().isoformat()})


# ─── Entry point ─────────────────────────────────────────────────────────────

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description='Chromecast Blocker Web UI',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument('--host', default='0.0.0.0', help='Bind address')
    parser.add_argument('--port', type=int, default=8080, help='HTTP port')
    parser.add_argument('--debug', action='store_true', help='Enable Flask debug mode')
    args = parser.parse_args()

    banner = f"""
╔══════════════════════════════════════════════════════════╗
║        Chromecast Blocker — Web UI Server                ║
╠══════════════════════════════════════════════════════════╣
║  Open in browser: http://{args.host}:{args.port:<5}               ║
║  Ctrl-C to stop                                          ║
╚══════════════════════════════════════════════════════════╝
"""
    print(banner)
    socketio.run(
        app,
        host=args.host,
        port=args.port,
        debug=args.debug,
        allow_unsafe_werkzeug=True,
        use_reloader=False,
    )


if __name__ == '__main__':
    main()
