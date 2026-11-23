"""
Borehole ML System
------------------
Role-based borehole maintenance management:
  * District Officer - assigns work, reviews reports, manages users, monitors risk
  * Expert           - carries out inspections and recommends repairs
  * Trainee          - carries out repairs and installations

Folder layout:
    app.py
    templates/index.html      <- your landing page (unchanged)
"""

import os
import re
import secrets
import sqlite3
import time
from datetime import date, datetime, timedelta
from functools import wraps


from flask import (
    Flask,
    abort,
    flash,
    g,
    redirect,
    render_template,
    render_template_string,
    request,
    send_from_directory,
    session,
    url_for,
)
from markupsafe import Markup, escape
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "borehole_users.db")


def load_secret_key():
    """Use SECRET_KEY from the environment, otherwise create and keep a local one."""
    env_key = os.environ.get("SECRET_KEY")
    if env_key:
        return env_key

    path = os.path.join(BASE_DIR, ".secret_key")
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read().strip()

    key = secrets.token_hex(32)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(key)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return key


app = Flask(__name__)
app.secret_key = load_secret_key()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    # Set HTTPS_ONLY=1 once the site is served over HTTPS.
    SESSION_COOKIE_SECURE=os.environ.get("HTTPS_ONLY", "0") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
)

# Set BEHIND_PROXY=1 when hosted behind a reverse proxy (most hosting services).
if os.environ.get("BEHIND_PROXY", "0") == "1":
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

ROLES = ("Trainee", "Expert", "District Officer")
TASK_TYPES = ("Inspection", "Repair", "Installation")
ROLE_TASK_TYPES = {
    "Expert": ("Inspection",),
    "Trainee": ("Repair", "Installation"),
}
PRIORITIES = ("Low", "Medium", "High", "Critical")
STATUSES = (
    "Pending",
    "In Progress",
    "Submitted for Review",
    "Needs Correction",
    "Completed",
)

HIGH_RISK = 60.0
MEDIUM_RISK = 40.0
MIN_PASSWORD_LENGTH = 8
TEXT_LIMIT = 2000
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,30}$")

# Basic brute-force protection for the login form.
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_SECONDS = 300
FAILED_LOGINS = {}

PRIORITY_RANK_SQL = (
    "CASE t.priority WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 "
    "WHEN 'Medium' THEN 3 ELSE 4 END"
)


# --------------------------------------------------
# DATABASE
# --------------------------------------------------

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()

    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL
                CHECK (role IN ('Trainee', 'Expert', 'District Officer')),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS boreholes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT NOT NULL UNIQUE,
            village TEXT NOT NULL,
            district TEXT NOT NULL,
            risk_score REAL NOT NULL DEFAULT 0
                CHECK (risk_score >= 0 AND risk_score <= 100),
            risk_updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            borehole_id INTEGER NOT NULL REFERENCES boreholes(id),
            task_type TEXT NOT NULL
                CHECK (task_type IN ('Inspection', 'Repair', 'Installation')),
            description TEXT NOT NULL,
            priority TEXT NOT NULL DEFAULT 'Medium'
                CHECK (priority IN ('Low', 'Medium', 'High', 'Critical')),
            deadline TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Pending'
                CHECK (status IN ('Pending', 'In Progress',
                                  'Submitted for Review',
                                  'Needs Correction', 'Completed')),
            assigned_to INTEGER NOT NULL REFERENCES users(id),
            created_by INTEGER NOT NULL REFERENCES users(id),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            closed_at TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS task_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
            author_id INTEGER NOT NULL REFERENCES users(id),
            report_type TEXT NOT NULL,
            findings TEXT,
            faults TEXT,
            recommendation TEXT,
            work_performed TEXT,
            materials_used TEXT,
            remaining_issues TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token_hash TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            used_at TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS task_feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
            sender_id INTEGER NOT NULL REFERENCES users(id),
            kind TEXT NOT NULL DEFAULT 'Message',
            message TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            message TEXT NOT NULL,
            link TEXT,
            is_read INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_tasks_assignee ON tasks(assigned_to, status);
        CREATE INDEX IF NOT EXISTS idx_notifications_user
            ON notifications(user_id, is_read);
        """
    )

    # Demo data. Set SEED_DEMO=0 in the environment to switch this off.
    if os.environ.get("SEED_DEMO", "1") == "1":
        demo_users = [
            ("Demo Trainee", "trainee", "trainee123", "Trainee"),
            ("Demo Expert", "expert", "expert123", "Expert"),
            ("District Officer", "officer", "officer123", "District Officer"),
        ]
        for full_name, username, password, role in demo_users:
            db.execute(
                """
                INSERT OR IGNORE INTO users
                    (full_name, username, password_hash, role)
                VALUES (?, ?, ?, ?)
                """,
                (full_name, username, generate_password_hash(password), role),
            )

        # Sample boreholes with PLACEHOLDER risk scores. Replace these with
        # scores produced by the machine-learning model.
        if db.execute("SELECT COUNT(*) FROM boreholes").fetchone()[0] == 0:
            samples = [
                ("BH-001", "Chikanda", "Zomba", 78.0),
                ("BH-002", "Mpunga", "Zomba", 52.5),
                ("BH-003", "Domasi", "Zomba", 21.0),
                ("BH-004", "Thondwe", "Zomba", 85.5),
                ("BH-005", "Songani", "Zomba", 34.0),
                ("BH-006", "Likangala", "Zomba", 64.0),
            ]
            db.executemany(
                "INSERT INTO boreholes (code, village, district, risk_score) "
                "VALUES (?, ?, ?, ?)",
                samples,
            )

    db.commit()


# --------------------------------------------------
# GENERAL HELPERS
# --------------------------------------------------

def today_iso():
    return date.today().isoformat()


def is_officer():
    return session.get("role") == "District Officer"


def risk_level(score):
    score = score or 0
    if score >= HIGH_RISK:
        return "High"
    if score >= MEDIUM_RISK:
        return "Medium"
    return "Low"


def parse_date(value):
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except (TypeError, ValueError):
        return None


def form_text(name):
    return request.form.get(name, "").strip()


def notify(db, user_id, message, link=None):
    db.execute(
        "INSERT INTO notifications (user_id, message, link) VALUES (?, ?, ?)",
        (user_id, message, link),
    )


def notify_officers(db, message, link=None, exclude=None):
    for row in db.execute(
        "SELECT id FROM users WHERE role = 'District Officer'"
    ).fetchall():
        if row["id"] != exclude:
            notify(db, row["id"], message, link)


def recalculate_risk_from_report(db, task, role, values):
    """Transparent interim rules; this is not a trained ML prediction."""
    borehole = db.execute(
        "SELECT id, code, risk_score FROM boreholes WHERE id = ?",
        (task["borehole_id"],),
    ).fetchone()
    if borehole is None:
        return None

    old_score = float(borehole["risk_score"] or 0)
    new_score = old_score

    if role == "Expert":
        faults = (values.get("faults") or "").strip().lower()
        no_fault_terms = ("none", "no fault", "no faults", "no issue", "no issues", "not observed")
        if faults and not any(term in faults for term in no_fault_terms):
            new_score += 15
        elif faults:
            new_score -= 8

        findings = (values.get("findings") or "").lower()
        severe_terms = ("leak", "broken", "crack", "damaged", "contaminat", "dry", "not working", "failure")
        if any(term in findings for term in severe_terms):
            new_score += 10

    elif role == "Trainee":
        work = (values.get("work_performed") or "").strip()
        remaining = (values.get("remaining_issues") or "").strip().lower()
        no_issue_terms = ("none", "no issue", "no issues", "resolved", "fully repaired", "not applicable", "n/a")
        if work:
            new_score -= 15
        if remaining and not any(term in remaining for term in no_issue_terms):
            new_score += 15
        materials = (values.get("materials_used") or "").lower()
        equipment_terms = ("new pump", "pump", "valve", "pipe", "handle", "rod", "seal", "bearing", "equipment", "device", "installed", "replaced")
        if task["task_type"] == "Installation" or any(term in materials for term in equipment_terms):
            new_score -= 5

    new_score = round(max(0.0, min(100.0, new_score)), 1)
    db.execute(
        "UPDATE boreholes SET risk_score = ?, risk_updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        (new_score, borehole["id"]),
    )
    if new_score > HIGH_RISK:
        notify_officers(
            db,
            f"HIGH-RISK ALERT: {borehole['code']} now has a risk score of {new_score:.1f}% "
            f"after a {('Expert inspection' if role == 'Expert' else 'Trainee work report')}.",
            url_for("boreholes"),
        )
    return new_score


def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(16)
    return session["_csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def protect_against_csrf():
    if request.method == "POST":
        sent = request.form.get("_csrf", "")
        expected = session.get("_csrf", "")
        if not sent or not expected or not secrets.compare_digest(sent, expected):
            abort(400)


# --------------------------------------------------
# TEMPLATE FILTERS
# --------------------------------------------------

STATUS_CLASSES = {
    "Pending": "grey",
    "In Progress": "blue",
    "Submitted for Review": "purple",
    "Needs Correction": "amber",
    "Completed": "green",
}
PRIORITY_CLASSES = {
    "Low": "grey",
    "Medium": "blue",
    "High": "amber",
    "Critical": "red",
}
RISK_CLASSES = {"High": "red", "Medium": "amber", "Low": "green"}


@app.template_filter("status_badge")
def status_badge(value):
    css = STATUS_CLASSES.get(value, "grey")
    return Markup('<span class="badge {}">{}</span>').format(css, value)


@app.template_filter("priority_badge")
def priority_badge(value):
    css = PRIORITY_CLASSES.get(value, "grey")
    return Markup('<span class="badge {}">{}</span>').format(css, value)


@app.template_filter("risk_badge")
def risk_badge(score):
    level = risk_level(score)
    return Markup('<span class="badge {}">{} &middot; {}%</span>').format(
        RISK_CLASSES[level], level, "{:.0f}".format(score or 0)
    )


@app.template_filter("fmt_dt")
def fmt_dt(value):
    """Convert a UTC database timestamp to Malawi time (CAT, UTC+2)."""
    if not value:
        return ""
    try:
        parsed = datetime.strptime(str(value)[:19], "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return str(value)
    return (parsed + timedelta(hours=2)).strftime("%d %b %Y, %H:%M")


@app.template_filter("fmt_date")
def fmt_date(value):
    parsed = parse_date(value)
    return parsed.strftime("%d %b %Y") if parsed else (value or "")


# --------------------------------------------------
# SHARED LAYOUT
# --------------------------------------------------

BASE_STYLE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }} | Borehole ML System</title>
    <meta name="theme-color" content="#075985">
    <link rel="manifest" href="{{ url_for('manifest') }}">
    <link rel="icon" href="{{ url_for('static', filename='icons/icon-192.png') }}">
    <link rel="apple-touch-icon" href="{{ url_for('static', filename='icons/icon-192.png') }}">
    <style>
        :root {
            --blue: #075985; --blue-dark: #082f49; --blue-mid: #0284c7;
            --green: #15803d; --red: #dc2626; --amber: #b45309;
            --text: #1e293b; --muted: #64748b; --border: #e2e8f0;
            --bg: #f1f5f9;
        }
        * { box-sizing: border-box; }
        body { margin: 0; font-family: Arial, Helvetica, sans-serif;
               background: var(--bg); color: var(--text); line-height: 1.5; }
        a { color: var(--blue-mid); }
        header.site { background: var(--blue); color: white; padding: 16px 20px; }
        header.site h1 { margin: 0; font-size: 22px; }
        header.site p { margin: 4px 0 0; font-size: 13px; opacity: .9; }
        nav { background: var(--blue-dark); padding: 0 20px; display: flex;
              flex-wrap: wrap; align-items: center; gap: 4px; }
        nav a, nav button.link { color: white; text-decoration: none;
              font-weight: bold; font-size: 14px; padding: 13px 12px;
              background: none; border: none; cursor: pointer; margin: 0; }
        nav a:hover, nav button.link:hover { background: rgba(255,255,255,.12); }
        nav .spacer { flex: 1; }
        nav .who { color: #bae6fd; font-size: 13px; padding: 0 10px; }
        nav form { margin: 0; display: inline; }
        .count { background: var(--red); color: white; border-radius: 10px;
                 padding: 1px 7px; font-size: 11px; margin-left: 4px; }
        .container { width: 94%; max-width: 1200px; margin: 24px auto; }
        .card { background: white; padding: 24px; margin-bottom: 20px;
                border-radius: 10px; box-shadow: 0 1px 6px rgba(0,0,0,.08); }
        .card h2 { margin-top: 0; color: var(--blue-dark); }
        .card h3 { color: var(--blue-dark); margin-bottom: 6px; }
        .page-head { display: flex; justify-content: space-between;
                     align-items: center; flex-wrap: wrap; gap: 10px;
                     margin-bottom: 18px; }
        .page-head h2 { margin: 0; color: var(--blue-dark); }
        .stat-grid { display: grid; gap: 14px; margin-bottom: 20px;
                     grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); }
        .stat { display: block; background: white; border-radius: 10px;
                padding: 16px; text-decoration: none; color: var(--text);
                border-left: 5px solid var(--blue-mid);
                box-shadow: 0 1px 6px rgba(0,0,0,.08); }
        .stat:hover { transform: translateY(-2px); }
        .stat.green { border-color: #16a34a; } .stat.amber { border-color: #f59e0b; }
        .stat.red { border-color: #dc2626; } .stat.purple { border-color: #7c3aed; }
        .stat.grey { border-color: #94a3b8; }
        .stat-value { display: block; font-size: 30px; font-weight: bold;
                      color: var(--blue-dark); }
        .stat-label { font-size: 13px; color: var(--muted); }
        .role-grid { display: grid; gap: 15px; margin: 20px 0;
                     grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); }
        .role-card { padding: 18px; border: 1px solid #dbe5ec;
                     border-radius: 8px; background: #f8fbfd; }
        label { display: block; margin: 14px 0 6px; font-weight: bold; font-size: 14px; }
        input, select, textarea { width: 100%; padding: 10px; font-size: 15px;
              border: 1px solid #cbd5e1; border-radius: 6px; font-family: inherit; }
        textarea { min-height: 90px; resize: vertical; }
        input:focus, select:focus, textarea:focus { outline: 2px solid #7dd3fc; }
        .form-grid { display: grid; gap: 0 18px;
                     grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); }
        button, .button { display: inline-block; border: none; border-radius: 6px;
              padding: 10px 16px; margin-top: 14px; background: var(--blue-mid);
              color: white; cursor: pointer; text-decoration: none; font-size: 14px; }
        button:hover, .button:hover { background: #0369a1; }
        .success { background: #16a34a; } .success:hover { background: #15803d; }
        .danger { background: var(--red); } .danger:hover { background: #b91c1c; }
        .secondary { background: #64748b; } .secondary:hover { background: #475569; }
        .small { padding: 6px 11px; font-size: 13px; margin-top: 0; }
        .message, .error { padding: 12px 14px; margin-bottom: 14px; border-radius: 6px; }
        .message { background: #dcfce7; color: #166534; }
        .error { background: #fee2e2; color: #991b1b; }
        .table-wrap { overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; background: white; }
        th, td { text-align: left; padding: 11px 12px;
                 border-bottom: 1px solid var(--border); font-size: 14px; }
        th { background: #eaf2f8; color: var(--blue-dark); white-space: nowrap; }
        tr:hover td { background: #fafcfe; }
        .actions { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }
        .actions form { display: inline; margin: 0; }
        .actions button, .actions .button { margin-top: 0; }
        .inline-form { display: flex; gap: 6px; align-items: center; }
        .inline-form input { width: 90px; padding: 6px; }
        .inline-form button { margin-top: 0; }
        .badge { display: inline-block; padding: 3px 10px; border-radius: 12px;
                 font-size: 12px; font-weight: bold; white-space: nowrap; }
        .badge.grey { background: #e2e8f0; color: #475569; }
        .badge.blue { background: #dbeafe; color: #1d4ed8; }
        .badge.green { background: #dcfce7; color: #166534; }
        .badge.amber { background: #fef3c7; color: #92400e; }
        .badge.red { background: #fee2e2; color: #991b1b; }
        .badge.purple { background: #ede9fe; color: #5b21b6; }
        .overdue { color: var(--red); font-weight: bold; }
        .muted { color: var(--muted); }
        .filters { display: flex; flex-wrap: wrap; gap: 12px; align-items: flex-end; }
        .filters div { flex: 1; min-width: 140px; }
        .filters label { margin-top: 0; }
        .filters button, .filters .button { margin-top: 0; }
        .detail-grid { display: grid; gap: 14px;
                       grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); }
        .detail-grid dt { font-size: 12px; text-transform: uppercase;
                          letter-spacing: .5px; color: var(--muted); }
        .detail-grid dd { margin: 2px 0 12px; font-weight: bold; }
        .thread-item { border: 1px solid var(--border); border-radius: 8px;
                       padding: 12px 14px; margin-bottom: 10px; background: #f8fbfd; }
        .thread-item.mine { background: #eff6ff; border-color: #bfdbfe; }
        .thread-meta { font-size: 12px; color: var(--muted); margin-bottom: 6px; }
        .thread-body { white-space: pre-wrap; }
        .report-field { margin: 8px 0; }
        .report-field strong { display: block; font-size: 12px;
              text-transform: uppercase; color: var(--muted); }
        .notice-item { display: block; padding: 12px 14px; border-radius: 8px;
              border: 1px solid var(--border); margin-bottom: 8px; color: var(--text);
              text-decoration: none; background: white; }
        .notice-item.unread { background: #eff6ff; border-color: #93c5fd; font-weight: bold; }
        .notice-item small { display: block; color: var(--muted); font-weight: normal; }
        footer.site { text-align: center; padding: 20px; color: var(--muted); font-size: 13px; }
        @media (max-width: 600px) { .card { padding: 16px; } nav .who { display: none; } }
    </style>
</head>
<body>
    <header class="site">
        <h1>Borehole ML System</h1>
        <p>Borehole Failure Prediction and Maintenance Management</p>
    </header>

    {% if session.get('user_id') %}
    <nav>
        <a href="{{ url_for('dashboard') }}">Dashboard</a>
        <a href="{{ url_for('task_list') }}">
            {{ 'All Tasks' if session.get('role') == 'District Officer' else 'My Tasks' }}
        </a>
        {% if session.get('role') == 'District Officer' %}
            <a href="{{ url_for('task_new') }}">Assign Task</a>
            <a href="{{ url_for('boreholes') }}">Boreholes</a>
            <a href="{{ url_for('manage_users') }}">Manage Users</a>
        {% endif %}
        <a href="{{ url_for('notifications') }}">Notifications
            {% if unread %}<span class="count">{{ unread }}</span>{% endif %}
        </a>
        <span class="spacer"></span>
        <span class="who">{{ session.get('full_name') }} &middot; {{ session.get('role') }}</span>
        <form method="POST" action="{{ url_for('logout') }}">
            <input type="hidden" name="_csrf" value="{{ csrf_token() }}">
            <button class="link" type="submit">Logout</button>
        </form>
    </nav>
    {% endif %}

    <main class="container">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% for category, message in messages %}
                <div class="{{ 'error' if category == 'error' else 'message' }}">{{ message }}</div>
            {% endfor %}
        {% endwith %}
        {{ content }}
    </main>

    <footer class="site">Borehole ML System &copy; 2026</footer>
    <script>
        if ('serviceWorker' in navigator) {
            window.addEventListener('load', function () {
                navigator.serviceWorker.register('/sw.js');
            });
        }
    </script>
</body>
</html>
"""

MACROS = """
{% macro csrf() %}<input type="hidden" name="_csrf" value="{{ csrf_token() }}">{% endmacro %}

{% macro stat(label, value, tone='blue', href='#') %}
<a class="stat {{ tone }}" href="{{ href }}">
    <span class="stat-value">{{ value }}</span>
    <span class="stat-label">{{ label }}</span>
</a>
{% endmacro %}

{% macro task_table(tasks, show_assignee=True) %}
<div class="table-wrap">
<table>
    <thead>
        <tr>
            <th>Borehole</th><th>Type</th><th>Priority</th><th>Status</th>
            <th>Deadline</th>
            {% if show_assignee %}<th>Assigned to</th>{% endif %}
            <th></th>
        </tr>
    </thead>
    <tbody>
    {% for t in tasks %}
        <tr>
            <td><strong>{{ t['borehole_code'] }}</strong><br>
                <span class="muted">{{ t['village'] }}</span></td>
            <td>{{ t['task_type'] }}</td>
            <td>{{ t['priority']|priority_badge }}</td>
            <td>{{ t['status']|status_badge }}</td>
            <td>{{ t['deadline']|fmt_date }}
                {% if t['overdue'] %}<br><span class="overdue">Overdue</span>{% endif %}</td>
            {% if show_assignee %}<td>{{ t['assignee_name'] }}</td>{% endif %}
            <td><a class="button small" href="{{ url_for('task_detail', task_id=t['id']) }}">Open</a></td>
        </tr>
    {% else %}
        <tr><td colspan="7" class="muted">No tasks to show.</td></tr>
    {% endfor %}
    </tbody>
</table>
</div>
{% endmacro %}
"""


def render_page(title, content, **context):
    unread = 0
    if session.get("user_id"):
        unread = get_db().execute(
            "SELECT COUNT(*) FROM notifications WHERE user_id = ? AND is_read = 0",
            (session["user_id"],),
        ).fetchone()[0]

    inner = render_template_string(MACROS + content, **context)
    return render_template_string(
        BASE_STYLE, title=title, content=Markup(inner), unread=unread
    )


# --------------------------------------------------
# ACCESS CONTROL
# --------------------------------------------------

def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in first.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped_view


def role_required(*allowed_roles):
    def decorator(view):
        @wraps(view)
        def wrapped_view(*args, **kwargs):
            if not session.get("user_id"):
                flash("Please log in first.", "error")
                return redirect(url_for("login"))
            if session.get("role") not in allowed_roles:
                abort(403)
            return view(*args, **kwargs)

        return wrapped_view

    return decorator


# --------------------------------------------------
# ANDROID / INSTALLABLE APP SUPPORT (PWA)
# --------------------------------------------------

@app.route("/manifest.webmanifest")
def manifest():
    return send_from_directory(
        app.static_folder, "manifest.webmanifest",
        mimetype="application/manifest+json",
    )


@app.route("/sw.js")
def service_worker():
    response = send_from_directory(
        app.static_folder, "sw.js", mimetype="application/javascript"
    )
    response.headers["Service-Worker-Allowed"] = "/"
    response.headers["Cache-Control"] = "no-cache"
    return response


@app.route("/offline")
def offline():
    return render_template_string(
        """<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Offline | Borehole ML System</title>
        <style>body{font-family:Arial,sans-serif;background:#f1f5f9;color:#1e293b;
        display:grid;place-items:center;min-height:100vh;margin:0;text-align:center}
        .box{background:#fff;padding:32px;border-radius:12px;max-width:340px;
        box-shadow:0 1px 6px rgba(0,0,0,.1)}h1{color:#075985;font-size:22px}
        button{background:#0284c7;color:#fff;border:0;border-radius:6px;
        padding:10px 18px;font-size:15px}</style></head><body><div class="box">
        <h1>You are offline</h1>
        <p>The Borehole ML System needs an internet connection. Check your
        network or mobile data, then try again.</p>
        <button onclick="location.reload()">Try again</button></div></body></html>"""
    )


@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    return response


# --------------------------------------------------
# LANDING PAGE AND AUTHENTICATION
# --------------------------------------------------

@app.route("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return render_template("index.html")


def login_locked(key):
    record = FAILED_LOGINS.get(key)
    if not record:
        return False
    attempts, first_time = record
    if time.time() - first_time > LOCKOUT_SECONDS:
        FAILED_LOGINS.pop(key, None)
        return False
    return attempts >= MAX_LOGIN_ATTEMPTS


def register_failed_login(key):
    attempts, first_time = FAILED_LOGINS.get(key, (0, time.time()))
    FAILED_LOGINS[key] = (attempts + 1, first_time)


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = form_text("username")
        password = request.form.get("password", "")
        key = (request.remote_addr, username.lower())

        if login_locked(key):
            flash("Too many failed attempts. Please wait a few minutes.", "error")
            return redirect(url_for("login"))

        user = get_db().execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            FAILED_LOGINS.pop(key, None)
            session.clear()
            session.permanent = True
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["full_name"] = user["full_name"]
            session["role"] = user["role"]
            flash("Login successful.", "message")
            return redirect(url_for("dashboard"))

        register_failed_login(key)
        flash("Incorrect username or password.", "error")

    content = """
    <div class="card">
        <h2>Welcome</h2>
        <p>Log in to access the Borehole ML System.</p>

        <div class="role-grid">
            <div class="role-card"><h3>Trainee</h3>
                <p>Carry out assigned repairs and equipment installation.</p></div>
            <div class="role-card"><h3>Expert</h3>
                <p>Inspect boreholes and give technical recommendations.</p></div>
            <div class="role-card"><h3>District Officer</h3>
                <p>Assign work, review reports and manage user accounts.</p></div>
        </div>

        <form method="POST" action="{{ url_for('login') }}">
            {{ csrf() }}
            <label for="username">Username</label>
            <input type="text" id="username" name="username" required autocomplete="username">
            <label for="password">Password</label>
            <input type="password" id="password" name="password" required autocomplete="current-password">
            <button type="submit">Log In</button>
        </form>
        <p><a href="{{ url_for('reset_password') }}">I have a password reset code</a></p>
    </div>
    """
    return render_page("Login", content)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have logged out successfully.", "message")
    return redirect(url_for("login"))


# --------------------------------------------------
# DASHBOARD
# --------------------------------------------------

def task_stats(db, user_id=None):
    where = "WHERE assigned_to = :uid" if user_id else ""
    row = db.execute(
        f"""
        SELECT
            COALESCE(SUM(status = 'Pending'), 0) AS pending,
            COALESCE(SUM(status = 'In Progress'), 0) AS in_progress,
            COALESCE(SUM(status = 'Submitted for Review'), 0) AS submitted,
            COALESCE(SUM(status = 'Needs Correction'), 0) AS correction,
            COALESCE(SUM(status = 'Completed'), 0) AS completed,
            COALESCE(SUM(deadline < :today AND status != 'Completed'), 0) AS overdue,
            COALESCE(SUM(task_type = 'Inspection'), 0) AS inspections,
            COALESCE(SUM(task_type = 'Inspection' AND status = 'Completed'), 0)
                AS inspections_done,
            COALESCE(SUM(task_type != 'Inspection' AND status = 'Completed'), 0)
                AS repairs_done
        FROM tasks {where}
        """,
        {"today": today_iso(), "uid": user_id},
    ).fetchone()
    return dict(row)


TASK_SELECT = """
    SELECT t.*,
           b.code AS borehole_code, b.village, b.district, b.risk_score,
           a.full_name AS assignee_name, a.role AS assignee_role,
           c.full_name AS creator_name,
           CASE WHEN t.deadline < :today AND t.status != 'Completed'
                THEN 1 ELSE 0 END AS overdue
    FROM tasks t
    JOIN boreholes b ON b.id = t.borehole_id
    JOIN users a ON a.id = t.assigned_to
    JOIN users c ON c.id = t.created_by
"""


@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    uid = session["user_id"]
    params = {"today": today_iso(), "uid": uid}

    if is_officer():
        stats = task_stats(db)
        high_risk_count = db.execute(
            "SELECT COUNT(*) FROM boreholes WHERE risk_score >= ?", (HIGH_RISK,)
        ).fetchone()[0]

        awaiting = db.execute(
            TASK_SELECT
            + f" WHERE t.status = 'Submitted for Review' ORDER BY t.updated_at LIMIT 5",
            params,
        ).fetchall()
        overdue = db.execute(
            TASK_SELECT
            + " WHERE t.deadline < :today AND t.status != 'Completed' "
              "ORDER BY t.deadline LIMIT 5",
            params,
        ).fetchall()
        risky = db.execute(
            "SELECT * FROM boreholes ORDER BY risk_score DESC LIMIT 5"
        ).fetchall()

        content = """
        <div class="page-head"><h2>Welcome, {{ session['full_name'] }}</h2>
            <a class="button" href="{{ url_for('task_new') }}">+ Assign Task</a></div>

        <div class="stat-grid">
            {{ stat('Pending tasks', s.pending, 'grey', url_for('task_list', status='Pending')) }}
            {{ stat('In progress', s.in_progress, 'blue', url_for('task_list', status='In Progress')) }}
            {{ stat('Awaiting your review', s.submitted, 'purple', url_for('task_list', status='Submitted for Review')) }}
            {{ stat('Needs correction', s.correction, 'amber', url_for('task_list', status='Needs Correction')) }}
            {{ stat('Overdue', s.overdue, 'red', url_for('task_list', status='Overdue')) }}
            {{ stat('Completed repairs', s.repairs_done, 'green', url_for('task_list', status='Completed')) }}
            {{ stat('Inspections done', s.inspections_done ~ ' / ' ~ s.inspections, 'green', url_for('task_list', task_type='Inspection')) }}
            {{ stat('High-risk boreholes', high_risk_count, 'red', url_for('boreholes')) }}
        </div>

        <div class="card"><h2>Reports awaiting review</h2>
            {{ task_table(awaiting) }}</div>

        <div class="card"><h2>Overdue work</h2>
            {{ task_table(overdue) }}</div>

        <div class="card"><h2>Highest-risk boreholes</h2>
            <div class="table-wrap"><table>
                <thead><tr><th>Code</th><th>Village</th><th>District</th><th>Risk</th><th></th></tr></thead>
                <tbody>
                {% for b in risky %}
                    <tr><td><strong>{{ b['code'] }}</strong></td><td>{{ b['village'] }}</td>
                        <td>{{ b['district'] }}</td><td>{{ b['risk_score']|risk_badge }}</td>
                        <td><a class="button small" href="{{ url_for('task_new', borehole_id=b['id']) }}">Assign task</a></td></tr>
                {% endfor %}
                </tbody></table></div>
            <p class="muted">Risk scores are placeholders until the machine-learning model is connected.</p>
        </div>
        """
        return render_page(
            "Dashboard", content, s=stats, high_risk_count=high_risk_count,
            awaiting=awaiting, overdue=overdue, risky=risky,
        )

    stats = task_stats(db, uid)
    active = db.execute(
        TASK_SELECT
        + f" WHERE t.assigned_to = :uid AND t.status != 'Completed' "
          f"ORDER BY {PRIORITY_RANK_SQL}, t.deadline LIMIT 10",
        params,
    ).fetchall()
    unread = db.execute(
        "SELECT * FROM notifications WHERE user_id = ? AND is_read = 0 "
        "ORDER BY id DESC LIMIT 5",
        (uid,),
    ).fetchall()

    if session["role"] == "Expert":
        intro = "Your inspections and technical findings are shown below."
        done_label = "Inspections completed"
    else:
        intro = "Your repairs and installations are shown below."
        done_label = "Repairs completed"

    content = """
    <div class="page-head"><h2>Welcome, {{ session['full_name'] }}</h2></div>
    <p class="muted">{{ intro }}</p>

    <div class="stat-grid">
        {{ stat('Pending', s.pending, 'grey', url_for('task_list', status='Pending')) }}
        {{ stat('In progress', s.in_progress, 'blue', url_for('task_list', status='In Progress')) }}
        {{ stat('Submitted for review', s.submitted, 'purple', url_for('task_list', status='Submitted for Review')) }}
        {{ stat('Needs correction', s.correction, 'amber', url_for('task_list', status='Needs Correction')) }}
        {{ stat('Overdue', s.overdue, 'red', url_for('task_list', status='Overdue')) }}
        {{ stat(done_label, s.completed, 'green', url_for('task_list', status='Completed')) }}
    </div>

    {% if unread %}
    <div class="card"><h2>New notifications</h2>
        {% for n in unread %}
            <a class="notice-item unread" href="{{ url_for('open_notification', notification_id=n['id']) }}">
                {{ n['message'] }}<small>{{ n['created_at']|fmt_dt }}</small></a>
        {% endfor %}
    </div>
    {% endif %}

    <div class="card"><h2>My active tasks</h2>
        {{ task_table(active, False) }}</div>
    """
    return render_page(
        "Dashboard", content, s=stats, active=active, unread=unread,
        intro=intro, done_label=done_label,
    )


# --------------------------------------------------
# BOREHOLES (District Officer)
# --------------------------------------------------

@app.route("/boreholes", methods=["GET", "POST"])
@role_required("District Officer")
def boreholes():
    db = get_db()

    if request.method == "POST":
        code = form_text("code").upper()
        village = form_text("village")
        district = form_text("district")
        score = request.form.get("risk_score", type=float)

        if not code or not village or not district or score is None:
            flash("Please complete all borehole fields.", "error")
        elif not 0 <= score <= 100:
            flash("Risk score must be between 0 and 100.", "error")
        else:
            try:
                db.execute(
                    "INSERT INTO boreholes (code, village, district, risk_score) "
                    "VALUES (?, ?, ?, ?)",
                    (code, village, district, score),
                )
                db.commit()
                flash("Borehole added.", "message")
            except sqlite3.IntegrityError:
                flash("A borehole with that code already exists.", "error")
        return redirect(url_for("boreholes"))

    rows = db.execute(
        """
        SELECT b.*,
               (SELECT COUNT(*) FROM tasks t
                WHERE t.borehole_id = b.id AND t.status != 'Completed') AS open_tasks
        FROM boreholes b ORDER BY b.risk_score DESC
        """
    ).fetchall()

    content = """
    <div class="card"><h2>Borehole Risk Monitoring</h2>
        <p class="muted">Scores above {{ high }}% trigger a District Officer alert. Report submissions update scores using transparent interim rules. These are not trained ML predictions.</p>
        <div class="table-wrap"><table>
            <thead><tr><th>Code</th><th>Village</th><th>District</th><th>Risk</th>
                <th>Open tasks</th><th>Update score</th><th></th></tr></thead>
            <tbody>
            {% for b in rows %}
                <tr><td><strong>{{ b['code'] }}</strong></td><td>{{ b['village'] }}</td>
                    <td>{{ b['district'] }}</td><td>{{ b['risk_score']|risk_badge }}</td>
                    <td>{{ b['open_tasks'] }}</td>
                    <td><form class="inline-form" method="POST"
                              action="{{ url_for('update_risk', borehole_id=b['id']) }}">
                        {{ csrf() }}
                        <input type="number" name="risk_score" min="0" max="100" step="0.1"
                               value="{{ b['risk_score'] }}" required>
                        <button class="small" type="submit">Save</button></form></td>
                    <td><a class="button small" href="{{ url_for('task_new', borehole_id=b['id']) }}">Assign task</a></td></tr>
            {% else %}
                <tr><td colspan="7" class="muted">No boreholes yet.</td></tr>
            {% endfor %}
            </tbody></table></div>
    </div>

    <div class="card"><h2>Add a Borehole</h2>
        <form method="POST" action="{{ url_for('boreholes') }}">
            {{ csrf() }}
            <div class="form-grid">
                <div><label for="code">Code</label>
                    <input id="code" name="code" placeholder="BH-007" required maxlength="20"></div>
                <div><label for="village">Village</label>
                    <input id="village" name="village" required maxlength="80"></div>
                <div><label for="district">District</label>
                    <input id="district" name="district" required maxlength="80"></div>
                <div><label for="risk_score">Risk score (0-100)</label>
                    <input id="risk_score" name="risk_score" type="number" min="0" max="100"
                           step="0.1" value="0" required></div>
            </div>
            <button type="submit">Add Borehole</button>
        </form>
    </div>
    """
    return render_page(
        "Boreholes", content, rows=rows, high=int(HIGH_RISK), medium=int(MEDIUM_RISK)
    )


@app.route("/boreholes/<int:borehole_id>/risk", methods=["POST"])
@role_required("District Officer")
def update_risk(borehole_id):
    score = request.form.get("risk_score", type=float)
    if score is None or not 0 <= score <= 100:
        flash("Risk score must be a number between 0 and 100.", "error")
        return redirect(url_for("boreholes"))

    db = get_db()
    cursor = db.execute(
        "UPDATE boreholes SET risk_score = ?, risk_updated_at = CURRENT_TIMESTAMP "
        "WHERE id = ?",
        (score, borehole_id),
    )
    db.commit()
    if cursor.rowcount == 0:
        abort(404)
    flash("Risk score updated.", "message")
    return redirect(url_for("boreholes"))


# --------------------------------------------------
# TASKS: LIST, CREATE, DETAIL
# --------------------------------------------------

@app.route("/tasks")
@login_required
def task_list():
    db = get_db()
    params = {"today": today_iso()}
    where = []

    if not is_officer():
        where.append("t.assigned_to = :uid")
        params["uid"] = session["user_id"]

    status = request.args.get("status", "")
    task_type = request.args.get("task_type", "")
    priority = request.args.get("priority", "")
    assignee = request.args.get("assignee", type=int) if is_officer() else None

    if status == "Overdue":
        where.append("t.deadline < :today AND t.status != 'Completed'")
    elif status in STATUSES:
        where.append("t.status = :status")
        params["status"] = status
    else:
        status = ""

    if task_type in TASK_TYPES:
        where.append("t.task_type = :task_type")
        params["task_type"] = task_type
    else:
        task_type = ""

    if priority in PRIORITIES:
        where.append("t.priority = :priority")
        params["priority"] = priority
    else:
        priority = ""

    if assignee:
        where.append("t.assigned_to = :assignee")
        params["assignee"] = assignee

    sql = TASK_SELECT
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += (
        " ORDER BY CASE t.status WHEN 'Completed' THEN 1 ELSE 0 END, "
        f"{PRIORITY_RANK_SQL}, t.deadline"
    )
    tasks = db.execute(sql, params).fetchall()

    staff = []
    if is_officer():
        staff = db.execute(
            "SELECT id, full_name, role FROM users "
            "WHERE role IN ('Trainee', 'Expert') ORDER BY role, full_name"
        ).fetchall()

    content = """
    <div class="page-head">
        <h2>{{ 'All Tasks' if officer else 'My Tasks' }}</h2>
        {% if officer %}<a class="button" href="{{ url_for('task_new') }}">+ Assign Task</a>{% endif %}
    </div>

    <div class="card">
        <form method="GET" class="filters">
            <div><label for="status">Status</label>
                <select id="status" name="status"><option value="">All</option>
                    {% for s in statuses + ('Overdue',) %}
                    <option value="{{ s }}" {{ 'selected' if s == status }}>{{ s }}</option>{% endfor %}
                </select></div>
            <div><label for="task_type">Type</label>
                <select id="task_type" name="task_type"><option value="">All</option>
                    {% for s in task_types %}
                    <option value="{{ s }}" {{ 'selected' if s == task_type }}>{{ s }}</option>{% endfor %}
                </select></div>
            <div><label for="priority">Priority</label>
                <select id="priority" name="priority"><option value="">All</option>
                    {% for s in priorities %}
                    <option value="{{ s }}" {{ 'selected' if s == priority }}>{{ s }}</option>{% endfor %}
                </select></div>
            {% if officer %}
            <div><label for="assignee">Assigned to</label>
                <select id="assignee" name="assignee"><option value="">Everyone</option>
                    {% for u in staff %}
                    <option value="{{ u['id'] }}" {{ 'selected' if u['id'] == assignee }}>
                        {{ u['full_name'] }} ({{ u['role'] }})</option>{% endfor %}
                </select></div>
            {% endif %}
            <div><button type="submit">Filter</button>
                <a class="button secondary" href="{{ url_for('task_list') }}">Reset</a></div>
        </form>
    </div>

    <div class="card">{{ task_table(tasks, officer) }}</div>
    """
    return render_page(
        "Tasks", content, tasks=tasks, officer=is_officer(), staff=staff,
        statuses=STATUSES, task_types=TASK_TYPES, priorities=PRIORITIES,
        status=status, task_type=task_type, priority=priority, assignee=assignee,
    )


@app.route("/tasks/new", methods=["GET", "POST"])
@role_required("District Officer")
def task_new():
    db = get_db()

    if request.method == "POST":
        borehole_id = request.form.get("borehole_id", type=int)
        assigned_to = request.form.get("assigned_to", type=int)
        task_type = form_text("task_type")
        priority = form_text("priority")
        description = form_text("description")
        deadline_text = form_text("deadline")
        deadline = parse_date(deadline_text)

        borehole = db.execute(
            "SELECT * FROM boreholes WHERE id = ?", (borehole_id,)
        ).fetchone()
        assignee = db.execute(
            "SELECT * FROM users WHERE id = ?", (assigned_to,)
        ).fetchone()

        error = None
        if borehole is None:
            error = "Choose a valid borehole."
        elif task_type not in TASK_TYPES:
            error = "Choose a valid task type."
        elif assignee is None or assignee["role"] not in ROLE_TASK_TYPES:
            error = "Choose a valid Expert or Trainee."
        elif task_type not in ROLE_TASK_TYPES[assignee["role"]]:
            error = (
                "Inspections go to Experts; repairs and installations go to Trainees."
            )
        elif priority not in PRIORITIES:
            error = "Choose a valid priority."
        elif not description or len(description) > TEXT_LIMIT:
            error = f"Enter a description (up to {TEXT_LIMIT} characters)."
        elif deadline is None or deadline < date.today():
            error = "Choose a deadline of today or later."

        if error:
            flash(error, "error")
            return redirect(url_for("task_new", borehole_id=borehole_id or ""))

        cursor = db.execute(
            """
            INSERT INTO tasks
                (borehole_id, task_type, description, priority, deadline,
                 assigned_to, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                borehole_id, task_type, description, priority,
                deadline.isoformat(), assigned_to, session["user_id"],
            ),
        )
        task_id = cursor.lastrowid
        notify(
            db, assigned_to,
            f"New {task_type.lower()} assigned: {borehole['code']} "
            f"({priority} priority, due {deadline.strftime('%d %b %Y')}).",
            url_for("task_detail", task_id=task_id),
        )
        db.commit()
        flash("Task assigned successfully.", "message")
        return redirect(url_for("task_detail", task_id=task_id))

    boreholes_list = db.execute(
        "SELECT * FROM boreholes ORDER BY risk_score DESC"
    ).fetchall()
    staff = db.execute(
        "SELECT id, full_name, role FROM users "
        "WHERE role IN ('Trainee', 'Expert') ORDER BY role, full_name"
    ).fetchall()
    selected = request.args.get("borehole_id", type=int)

    content = """
    <div class="card"><h2>Assign a Task</h2>
        <p class="muted">Inspections are assigned to Experts. Repairs and
           installations are assigned to Trainees.</p>
        <form method="POST" action="{{ url_for('task_new') }}">
            {{ csrf() }}
            <div class="form-grid">
                <div><label for="borehole_id">Borehole</label>
                    <select id="borehole_id" name="borehole_id" required>
                        <option value="">Choose a borehole</option>
                        {% for b in boreholes_list %}
                        <option value="{{ b['id'] }}" {{ 'selected' if b['id'] == selected }}>
                            {{ b['code'] }} - {{ b['village'] }} (risk {{ '%.0f'|format(b['risk_score']) }}%)</option>
                        {% endfor %}
                    </select></div>
                <div><label for="task_type">Task type</label>
                    <select id="task_type" name="task_type" required>
                        <option value="">Choose a type</option>
                        {% for t in task_types %}<option>{{ t }}</option>{% endfor %}
                    </select></div>
                <div><label for="assigned_to">Assign to</label>
                    <select id="assigned_to" name="assigned_to" required>
                        <option value="">Choose a person</option>
                        {% for u in staff %}
                        <option value="{{ u['id'] }}" data-role="{{ u['role'] }}">
                            {{ u['full_name'] }} ({{ u['role'] }})</option>
                        {% endfor %}
                    </select></div>
                <div><label for="priority">Priority</label>
                    <select id="priority" name="priority" required>
                        {% for p in priorities %}
                        <option {{ 'selected' if p == 'Medium' }}>{{ p }}</option>{% endfor %}
                    </select></div>
                <div><label for="deadline">Deadline</label>
                    <input type="date" id="deadline" name="deadline" min="{{ today }}" required></div>
            </div>
            <label for="description">Description / instructions</label>
            <textarea id="description" name="description" maxlength="2000" required></textarea>
            <button type="submit">Assign Task</button>
            <a class="button secondary" href="{{ url_for('task_list') }}">Cancel</a>
        </form>
    </div>

    <script>
        var typeSelect = document.getElementById('task_type');
        var assignee = document.getElementById('assigned_to');
        var needs = { Inspection: 'Expert', Repair: 'Trainee', Installation: 'Trainee' };
        function filterAssignees() {
            var need = needs[typeSelect.value];
            Array.prototype.forEach.call(assignee.options, function (option) {
                if (!option.value) { return; }
                var ok = !need || option.dataset.role === need;
                option.hidden = !ok;
                option.disabled = !ok;
            });
            if (assignee.options[assignee.selectedIndex].disabled) { assignee.value = ''; }
        }
        typeSelect.addEventListener('change', filterAssignees);
        filterAssignees();
    </script>
    """
    return render_page(
        "Assign Task", content, boreholes_list=boreholes_list, staff=staff,
        selected=selected, task_types=TASK_TYPES, priorities=PRIORITIES,
        today=today_iso(),
    )


def load_task(db, task_id):
    """Fetch a task, enforcing that staff can only see their own work."""
    task = db.execute(
        TASK_SELECT + " WHERE t.id = :task_id",
        {"today": today_iso(), "task_id": task_id},
    ).fetchone()
    if task is None:
        abort(404)
    if not is_officer() and task["assigned_to"] != session["user_id"]:
        abort(403)
    return task


@app.route("/tasks/<int:task_id>")
@login_required
def task_detail(task_id):
    db = get_db()
    task = load_task(db, task_id)

    # Opening a task clears its notifications.
    db.execute(
        "UPDATE notifications SET is_read = 1 WHERE user_id = ? AND link = ?",
        (session["user_id"], request.path),
    )
    db.commit()

    reports = db.execute(
        """
        SELECT r.*, u.full_name AS author_name
        FROM task_reports r JOIN users u ON u.id = r.author_id
        WHERE r.task_id = ? ORDER BY r.id DESC
        """,
        (task_id,),
    ).fetchall()
    thread = db.execute(
        """
        SELECT f.*, u.full_name AS sender_name, u.role AS sender_role
        FROM task_feedback f JOIN users u ON u.id = f.sender_id
        WHERE f.task_id = ? ORDER BY f.id
        """,
        (task_id,),
    ).fetchall()

    officer = is_officer()
    is_assignee = task["assigned_to"] == session["user_id"]
    status = task["status"]

    if officer:
        message_kinds = ("Feedback", "Instruction")
    elif session["role"] == "Trainee":
        message_kinds = ("Message", "Assistance Request")
    else:
        message_kinds = ("Message",)

    content = """
    <div class="page-head">
        <h2>{{ task['task_type'] }}: {{ task['borehole_code'] }} - {{ task['village'] }}</h2>
        <a class="button secondary" href="{{ url_for('task_list') }}">&larr; Back to tasks</a>
    </div>

    <div class="card">
        <dl class="detail-grid">
            <div><dt>Status</dt><dd>{{ task['status']|status_badge }}</dd></div>
            <div><dt>Priority</dt><dd>{{ task['priority']|priority_badge }}</dd></div>
            <div><dt>Deadline</dt><dd>{{ task['deadline']|fmt_date }}
                {% if task['overdue'] %}<span class="overdue">(Overdue)</span>{% endif %}</dd></div>
            <div><dt>Borehole risk</dt><dd>{{ task['risk_score']|risk_badge }}</dd></div>
            <div><dt>Assigned to</dt><dd>{{ task['assignee_name'] }} ({{ task['assignee_role'] }})</dd></div>
            <div><dt>Assigned by</dt><dd>{{ task['creator_name'] }}</dd></div>
            <div><dt>Created</dt><dd>{{ task['created_at']|fmt_dt }}</dd></div>
            <div><dt>Last updated</dt><dd>{{ task['updated_at']|fmt_dt }}</dd></div>
        </dl>
        <h3>Instructions</h3>
        <p class="thread-body">{{ task['description'] }}</p>
    </div>

    {# ---------- Assignee actions ---------- #}
    {% if is_assignee and status in ('Pending', 'Needs Correction') %}
    <div class="card"><h2>Start work</h2>
        <p>{{ 'Update the task to In Progress when you begin.' if status == 'Pending'
              else 'The Officer requested corrections. Resume work to continue.' }}</p>
        <form method="POST" action="{{ url_for('task_start', task_id=task['id']) }}">
            {{ csrf() }}<button class="success" type="submit">Mark as In Progress</button></form>
    </div>
    {% endif %}

    {% if is_assignee and status == 'In Progress' %}
    <div class="card">
        <h2>{{ 'Submit inspection report' if role == 'Expert' else 'Submit completion report' }}</h2>
        <p class="muted">Submitting sends your report to the District Officer for review.</p>
        <form method="POST" action="{{ url_for('task_submit', task_id=task['id']) }}">
            {{ csrf() }}
            {% if role == 'Expert' %}
                <label for="findings">Inspection findings</label>
                <textarea id="findings" name="findings" maxlength="2000" required></textarea>
                <label for="faults">Faults identified</label>
                <textarea id="faults" name="faults" maxlength="2000" required placeholder="Write 'None found' if there are no faults"></textarea>
                <label for="recommendation">Recommended repairs</label>
                <textarea id="recommendation" name="recommendation" maxlength="2000" required></textarea>
            {% else %}
                <label for="work_performed">Work performed</label>
                <textarea id="work_performed" name="work_performed" maxlength="2000" required></textarea>
                <label for="materials_used">Materials used</label>
                <textarea id="materials_used" name="materials_used" maxlength="2000" required placeholder="Write 'None' if no materials were used"></textarea>
                <label for="remaining_issues">Remaining problems</label>
                <textarea id="remaining_issues" name="remaining_issues" maxlength="2000" required placeholder="Write 'None' if the work is fully done"></textarea>
            {% endif %}
            <button class="success" type="submit">Submit for Review</button>
        </form>
    </div>
    {% endif %}

    {# ---------- Officer review ---------- #}
    {% if officer and status == 'Submitted for Review' %}
    <div class="card"><h2>Review submitted work</h2>
        <form method="POST" action="{{ url_for('task_review', task_id=task['id']) }}">
            {{ csrf() }}
            <label for="decision">Decision</label>
            <select id="decision" name="decision" required>
                <option value="approve">Confirm completion and close task</option>
                <option value="correct">Request corrections</option>
            </select>
            <label for="comment">Comment (required when requesting corrections)</label>
            <textarea id="comment" name="comment" maxlength="2000"></textarea>
            <button type="submit">Submit Decision</button>
        </form>
    </div>
    {% endif %}

    {# ---------- Reports ---------- #}
    <div class="card"><h2>Reports</h2>
        {% for r in reports %}
        <div class="thread-item">
            <div class="thread-meta">{{ r['report_type'] }} by {{ r['author_name'] }} &middot; {{ r['created_at']|fmt_dt }}</div>
            {% for label, key in [('Findings','findings'), ('Faults','faults'),
                    ('Recommendation','recommendation'), ('Work performed','work_performed'),
                    ('Materials used','materials_used'), ('Remaining problems','remaining_issues')] %}
                {% if r[key] %}<div class="report-field"><strong>{{ label }}</strong>
                    <span class="thread-body">{{ r[key] }}</span></div>{% endif %}
            {% endfor %}
        </div>
        {% else %}<p class="muted">No reports submitted yet.</p>{% endfor %}
    </div>

    {# ---------- Feedback thread ---------- #}
    <div class="card"><h2>Feedback and messages</h2>
        {% for f in thread %}
        <div class="thread-item {{ 'mine' if f['sender_id'] == session['user_id'] }}">
            <div class="thread-meta">{{ f['sender_name'] }} ({{ f['sender_role'] }}) &middot;
                <span class="badge {{ 'amber' if f['kind'] in ('Correction Request', 'Assistance Request') else 'blue' }}">{{ f['kind'] }}</span>
                &middot; {{ f['created_at']|fmt_dt }}</div>
            <div class="thread-body">{{ f['message'] }}</div>
        </div>
        {% else %}<p class="muted">No messages yet.</p>{% endfor %}

        {% if status != 'Completed' %}
        <form method="POST" action="{{ url_for('task_feedback', task_id=task['id']) }}">
            {{ csrf() }}
            <div class="form-grid">
                <div><label for="kind">Message type</label>
                    <select id="kind" name="kind">
                        {% for k in message_kinds %}<option>{{ k }}</option>{% endfor %}
                    </select></div>
            </div>
            <label for="message">Message</label>
            <textarea id="message" name="message" maxlength="2000" required></textarea>
            <button type="submit">Send</button>
        </form>
        {% else %}<p class="muted">This task is closed.</p>{% endif %}
    </div>
    """
    return render_page(
        f"Task {task_id}", content, task=task, reports=reports, thread=thread,
        officer=officer, is_assignee=is_assignee, status=status,
        role=session["role"], message_kinds=message_kinds,
    )


# --------------------------------------------------
# TASK ACTIONS
# --------------------------------------------------

def change_status(db, task_id, new_status, allowed_from):
    """Atomically change status only if the task is still in an allowed state."""
    placeholders = ",".join("?" for _ in allowed_from)
    closed = "CURRENT_TIMESTAMP" if new_status == "Completed" else "NULL"
    cursor = db.execute(
        f"UPDATE tasks SET status = ?, updated_at = CURRENT_TIMESTAMP, "
        f"closed_at = {closed} WHERE id = ? AND status IN ({placeholders})",
        (new_status, task_id, *allowed_from),
    )
    return cursor.rowcount == 1


@app.route("/tasks/<int:task_id>/start", methods=["POST"])
@login_required
def task_start(task_id):
    db = get_db()
    task = load_task(db, task_id)
    if is_officer() or task["assigned_to"] != session["user_id"]:
        abort(403)

    if change_status(db, task_id, "In Progress", ("Pending", "Needs Correction")):
        notify_officers(
            db,
            f"{session['full_name']} started work on {task['borehole_code']} "
            f"({task['task_type'].lower()}).",
            url_for("task_detail", task_id=task_id),
        )
        db.commit()
        flash("Task marked as In Progress.", "message")
    else:
        flash("This task cannot be started from its current status.", "error")
    return redirect(url_for("task_detail", task_id=task_id))


@app.route("/tasks/<int:task_id>/submit", methods=["POST"])
@login_required
def task_submit(task_id):
    db = get_db()
    task = load_task(db, task_id)
    role = session["role"]
    if role not in ROLE_TASK_TYPES or task["assigned_to"] != session["user_id"]:
        abort(403)
    if task["status"] != "In Progress":
        flash("Only tasks that are In Progress can be submitted.", "error")
        return redirect(url_for("task_detail", task_id=task_id))

    if role == "Expert":
        report_type = "Inspection Report"
        fields = ("findings", "faults", "recommendation")
    else:
        report_type = "Completion Report"
        fields = ("work_performed", "materials_used", "remaining_issues")

    values = {name: form_text(name) for name in fields}
    if any(not v or len(v) > TEXT_LIMIT for v in values.values()):
        flash(
            f"Complete every report field (up to {TEXT_LIMIT} characters each).",
            "error",
        )
        return redirect(url_for("task_detail", task_id=task_id))

    if not change_status(db, task_id, "Submitted for Review", ("In Progress",)):
        flash("This task has already been updated.", "error")
        return redirect(url_for("task_detail", task_id=task_id))

    columns = ", ".join(fields)
    marks = ", ".join("?" for _ in fields)
    db.execute(
        f"INSERT INTO task_reports (task_id, author_id, report_type, {columns}) "
        f"VALUES (?, ?, ?, {marks})",
        (task_id, session["user_id"], report_type, *values.values()),
    )
    updated_score = recalculate_risk_from_report(db, task, role, values)
    notify_officers(
        db,
        f"{session['full_name']} submitted a {report_type.lower()} for "
        f"{task['borehole_code']}. Review required.",
        url_for("task_detail", task_id=task_id),
    )
    db.commit()
    flash("Report submitted for review.", "message")
    return redirect(url_for("task_detail", task_id=task_id))


@app.route("/tasks/<int:task_id>/feedback", methods=["POST"])
@login_required
def task_feedback(task_id):
    db = get_db()
    task = load_task(db, task_id)

    if is_officer():
        allowed = ("Feedback", "Instruction")
    elif session["role"] == "Trainee":
        allowed = ("Message", "Assistance Request")
    else:
        allowed = ("Message",)

    kind = form_text("kind")
    message = form_text("message")
    if task["status"] == "Completed":
        flash("This task is closed.", "error")
    elif kind not in allowed:
        flash("Invalid message type.", "error")
    elif not message or len(message) > TEXT_LIMIT:
        flash(f"Enter a message (up to {TEXT_LIMIT} characters).", "error")
    else:
        db.execute(
            "INSERT INTO task_feedback (task_id, sender_id, kind, message) "
            "VALUES (?, ?, ?, ?)",
            (task_id, session["user_id"], kind, message),
        )
        link = url_for("task_detail", task_id=task_id)
        if is_officer():
            notify(db, task["assigned_to"],
                   f"New {kind.lower()} from the Officer on {task['borehole_code']}.",
                   link)
        else:
            notify_officers(
                db,
                f"{session['full_name']} sent a {kind.lower()} on "
                f"{task['borehole_code']}.",
                link,
            )
        db.commit()
        flash("Message sent.", "message")
    return redirect(url_for("task_detail", task_id=task_id))


@app.route("/tasks/<int:task_id>/review", methods=["POST"])
@role_required("District Officer")
def task_review(task_id):
    db = get_db()
    task = load_task(db, task_id)
    decision = form_text("decision")
    comment = form_text("comment")
    link = url_for("task_detail", task_id=task_id)

    if len(comment) > TEXT_LIMIT:
        flash(f"Comments are limited to {TEXT_LIMIT} characters.", "error")
        return redirect(link)

    if decision == "approve":
        if not change_status(db, task_id, "Completed", ("Submitted for Review",)):
            flash("This task is not awaiting review.", "error")
            return redirect(link)
        if comment:
            db.execute(
                "INSERT INTO task_feedback (task_id, sender_id, kind, message) "
                "VALUES (?, ?, 'Approval', ?)",
                (task_id, session["user_id"], comment),
            )
        notify(db, task["assigned_to"],
               f"Your work on {task['borehole_code']} was approved and closed.", link)
        flash("Task confirmed as completed and closed.", "message")

    elif decision == "correct":
        if not comment:
            flash("Explain what needs to be corrected.", "error")
            return redirect(link)
        if not change_status(db, task_id, "Needs Correction", ("Submitted for Review",)):
            flash("This task is not awaiting review.", "error")
            return redirect(link)
        db.execute(
            "INSERT INTO task_feedback (task_id, sender_id, kind, message) "
            "VALUES (?, ?, 'Correction Request', ?)",
            (task_id, session["user_id"], comment),
        )
        notify(db, task["assigned_to"],
               f"Corrections requested on {task['borehole_code']}.", link)
        flash("Correction request sent.", "message")
    else:
        flash("Choose a decision.", "error")
        return redirect(link)

    db.commit()
    return redirect(link)


# --------------------------------------------------
# NOTIFICATIONS
# --------------------------------------------------

@app.route("/notifications")
@login_required
def notifications():
    items = get_db().execute(
        "SELECT * FROM notifications WHERE user_id = ? ORDER BY id DESC LIMIT 100",
        (session["user_id"],),
    ).fetchall()

    content = """
    <div class="page-head"><h2>Notifications</h2>
        <form method="POST" action="{{ url_for('notifications_read_all') }}">
            {{ csrf() }}<button class="secondary small" type="submit">Mark all as read</button></form>
    </div>
    <div class="card">
        {% for n in items %}
            <a class="notice-item {{ 'unread' if not n['is_read'] }}"
               href="{{ url_for('open_notification', notification_id=n['id']) }}">
                {{ n['message'] }}<small>{{ n['created_at']|fmt_dt }}</small></a>
        {% else %}<p class="muted">You have no notifications.</p>{% endfor %}
    </div>
    """
    return render_page("Notifications", content, items=items)


@app.route("/notifications/<int:notification_id>/open")
@login_required
def open_notification(notification_id):
    db = get_db()
    row = db.execute(
        "SELECT * FROM notifications WHERE id = ? AND user_id = ?",
        (notification_id, session["user_id"]),
    ).fetchone()
    if row is None:
        abort(404)
    db.execute("UPDATE notifications SET is_read = 1 WHERE id = ?", (notification_id,))
    db.commit()
    link = row["link"]
    if link and link.startswith("/") and not link.startswith("//"):
        return redirect(link)
    return redirect(url_for("notifications"))


@app.route("/notifications/read-all", methods=["POST"])
@login_required
def notifications_read_all():
    db = get_db()
    db.execute(
        "UPDATE notifications SET is_read = 1 WHERE user_id = ?", (session["user_id"],)
    )
    db.commit()
    return redirect(url_for("notifications"))


# --------------------------------------------------
# USER MANAGEMENT (District Officer)
# --------------------------------------------------

def validate_user_fields(full_name, username, role):
    if not full_name or len(full_name) > 80:
        return "Enter a full name (up to 80 characters)."
    if not USERNAME_PATTERN.match(username):
        return "Usernames need 3-30 letters, numbers, dots, dashes or underscores."
    if role not in ("Trainee", "Expert"):
        return "You can only use the Trainee or Expert roles."
    return None


@app.route("/manage-users", methods=["GET", "POST"])
@role_required("District Officer")
def manage_users():
    db = get_db()

    if request.method == "POST":
        full_name = form_text("full_name")
        username = form_text("username")
        password = request.form.get("password", "")
        role = form_text("role")

        error = validate_user_fields(full_name, username, role)
        if not error and len(password) < MIN_PASSWORD_LENGTH:
            error = f"The password must contain at least {MIN_PASSWORD_LENGTH} characters."

        if error:
            flash(error, "error")
        else:
            try:
                db.execute(
                    "INSERT INTO users (full_name, username, password_hash, role) "
                    "VALUES (?, ?, ?, ?)",
                    (full_name, username, generate_password_hash(password), role),
                )
                db.commit()
                flash("User created successfully.", "message")
            except sqlite3.IntegrityError:
                flash("That username already exists. Choose another.", "error")
        return redirect(url_for("manage_users"))

    users = db.execute(
        """
        SELECT u.id, u.full_name, u.username, u.role, u.created_at,
               (SELECT COUNT(*) FROM tasks t WHERE t.assigned_to = u.id
                AND t.status != 'Completed') AS open_tasks
        FROM users u ORDER BY u.id DESC
        """
    ).fetchall()

    content = """
    <div class="card"><h2>Create a User</h2>
        <p class="muted">Create accounts for Trainees and Experts.</p>
        <form method="POST" action="{{ url_for('manage_users') }}">
            {{ csrf() }}
            <div class="form-grid">
                <div><label for="full_name">Full Name</label>
                    <input id="full_name" name="full_name" required maxlength="80"></div>
                <div><label for="username">Username</label>
                    <input id="username" name="username" required pattern="[A-Za-z0-9_.\\-]{3,30}"
                           title="3-30 letters, numbers, dots, dashes or underscores"></div>
                <div><label for="password">Temporary Password</label>
                    <input type="password" id="password" name="password" minlength="{{ min_len }}"
                           required autocomplete="new-password"></div>
                <div><label for="role">Role</label>
                    <select id="role" name="role" required>
                        <option value="">Choose a role</option>
                        <option>Trainee</option><option>Expert</option></select></div>
            </div>
            <button type="submit">Create User</button>
        </form>
    </div>

    <div class="card"><h2>All Users</h2>
        <div class="table-wrap"><table>
            <thead><tr><th>ID</th><th>Full Name</th><th>Username</th><th>Role</th>
                <th>Open tasks</th><th>Created</th><th>Actions</th></tr></thead>
            <tbody>
            {% for user in users %}
                <tr><td>{{ user['id'] }}</td><td>{{ user['full_name'] }}</td>
                    <td>{{ user['username'] }}</td><td>{{ user['role'] }}</td>
                    <td>{{ user['open_tasks'] }}</td>
                    <td>{{ user['created_at']|fmt_dt }}</td>
                    <td>
                    {% if user['role'] != 'District Officer' %}
                        <div class="actions">
                            <a class="button small" href="{{ url_for('edit_user', user_id=user['id']) }}">Edit</a>
                            <a class="button small secondary" href="{{ url_for('issue_password_reset', user_id=user['id']) }}">Reset password</a>
                            <form method="POST" action="{{ url_for('delete_user', user_id=user['id']) }}"
                                  onsubmit="return confirm('Are you sure you want to delete this user?');">
                                {{ csrf() }}<button class="danger small" type="submit">Delete</button></form>
                        </div>
                    {% else %}<span class="muted">Protected account</span>{% endif %}
                    </td></tr>
            {% else %}
                <tr><td colspan="7">No users found.</td></tr>
            {% endfor %}
            </tbody></table></div>
    </div>
    """
    return render_page("Manage Users", content, users=users, min_len=MIN_PASSWORD_LENGTH)


@app.route("/manage-users/<int:user_id>/edit", methods=["GET", "POST"])
@role_required("District Officer")
def edit_user(user_id):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

    if user is None:
        flash("User not found.", "error")
        return redirect(url_for("manage_users"))
    if user["role"] == "District Officer":
        flash("District Officer accounts are protected.", "error")
        return redirect(url_for("manage_users"))

    has_tasks = db.execute(
        "SELECT COUNT(*) FROM tasks WHERE assigned_to = ?", (user_id,)
    ).fetchone()[0] > 0

    if request.method == "POST":
        full_name = form_text("full_name")
        username = form_text("username")
        role = form_text("role")
        new_password = request.form.get("password", "")

        error = validate_user_fields(full_name, username, role)
        if not error and role != user["role"] and has_tasks:
            error = "This user has tasks, so their role cannot be changed."
        if not error and new_password and len(new_password) < MIN_PASSWORD_LENGTH:
            error = f"The new password must contain at least {MIN_PASSWORD_LENGTH} characters."

        if error:
            flash(error, "error")
            return redirect(url_for("edit_user", user_id=user_id))

        try:
            if new_password:
                db.execute(
                    "UPDATE users SET full_name = ?, username = ?, role = ?, "
                    "password_hash = ? WHERE id = ?",
                    (full_name, username, role,
                     generate_password_hash(new_password), user_id),
                )
            else:
                db.execute(
                    "UPDATE users SET full_name = ?, username = ?, role = ? WHERE id = ?",
                    (full_name, username, role, user_id),
                )
            db.commit()
            flash("User updated successfully.", "message")
            return redirect(url_for("manage_users"))
        except sqlite3.IntegrityError:
            flash("That username is already in use.", "error")
            return redirect(url_for("edit_user", user_id=user_id))

    content = """
    <div class="card"><h2>Edit User</h2>
        <p class="muted">Change the user's details or role.
           {% if has_tasks %}The role is locked because this user has task history.{% endif %}</p>
        <form method="POST">
            {{ csrf() }}
            <label for="full_name">Full Name</label>
            <input id="full_name" name="full_name" value="{{ user['full_name'] }}" required maxlength="80">
            <label for="username">Username</label>
            <input id="username" name="username" value="{{ user['username'] }}" required>
            <label for="role">Role</label>
            <select id="role" name="role" required>
                {% for r in ('Trainee', 'Expert') %}
                <option {{ 'selected' if user['role'] == r }}
                        {{ 'disabled' if has_tasks and user['role'] != r }}>{{ r }}</option>{% endfor %}
            </select>
            <label for="password">New Password (optional)</label>
            <input type="password" id="password" name="password" minlength="{{ min_len }}"
                   autocomplete="new-password" placeholder="Leave blank to keep the current password">
            <button type="submit">Save Changes</button>
            <a class="button secondary" href="{{ url_for('manage_users') }}">Cancel</a>
        </form>
    </div>
    """
    return render_page(
        "Edit User", content, user=user, has_tasks=has_tasks, min_len=MIN_PASSWORD_LENGTH
    )


@app.route("/manage-users/<int:user_id>/delete", methods=["POST"])
@role_required("District Officer")
def delete_user(user_id):
    if session.get("user_id") == user_id:
        flash("You cannot delete the account you are currently using.", "error")
        return redirect(url_for("manage_users"))

    db = get_db()
    user = db.execute(
        "SELECT id, role FROM users WHERE id = ?", (user_id,)
    ).fetchone()

    if user is None:
        flash("User not found.", "error")
    elif user["role"] == "District Officer":
        flash("District Officer accounts are protected.", "error")
    elif db.execute(
        "SELECT COUNT(*) FROM tasks WHERE assigned_to = ?", (user_id,)
    ).fetchone()[0]:
        flash(
            "This user has task records and cannot be deleted. "
            "Keeping them preserves the work history.",
            "error",
        )
    else:
        db.execute("DELETE FROM users WHERE id = ?", (user_id,))
        db.commit()
        flash("User deleted successfully.", "message")
    return redirect(url_for("manage_users"))


# --------------------------------------------------
# SECURE PASSWORD RECOVERY
# --------------------------------------------------

@app.route("/manage-users/<int:user_id>/password-reset", methods=["GET", "POST"])
@role_required("District Officer")
def issue_password_reset(user_id):
    db = get_db()
    user = db.execute("SELECT id, full_name, username, role FROM users WHERE id = ?", (user_id,)).fetchone()
    if user is None:
        abort(404)
    if user["role"] == "District Officer":
        flash("Officer accounts use the separate system-owner recovery procedure.", "error")
        return redirect(url_for("manage_users"))

    token = None
    if request.method == "POST":
        token = secrets.token_urlsafe(32)
        token_hash = __import__("hashlib").sha256(token.encode("utf-8")).hexdigest()
        expires = (datetime.utcnow() + timedelta(minutes=20)).isoformat(timespec="seconds")
        db.execute("UPDATE password_reset_tokens SET used_at = CURRENT_TIMESTAMP WHERE user_id = ? AND used_at IS NULL", (user_id,))
        db.execute(
            "INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)",
            (user_id, token_hash, expires),
        )
        db.commit()

    content = """
    <div class="card"><h2>Password recovery: {{ user['full_name'] }}</h2>
      <p>A one-time reset code is valid for 20 minutes. Give it directly to the account owner.
      You cannot view or set the user's password.</p>
      {% if token %}<div class="message"><strong>One-time reset code</strong><br><code>{{ token }}</code>
        <p>Copy this code and give it securely to the account owner. It will not be shown again.</p></div>
        <p>Reset page: <code>{{ reset_url }}</code></p>
      {% else %}<form method="POST">{{ csrf() }}<button type="submit">Generate one-time reset code</button></form>{% endif %}
      <a class="button secondary" href="{{ url_for('manage_users') }}">Back to users</a>
    </div>"""
    return render_page("Issue Password Reset", content, user=user, token=token,
                       reset_url=request.url_root.rstrip("/") + url_for("reset_password"))


@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    if request.method == "POST":
        token = request.form.get("token", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        token_hash = __import__("hashlib").sha256(token.encode("utf-8")).hexdigest()
        db = get_db()
        record = db.execute(
            "SELECT * FROM password_reset_tokens WHERE token_hash = ? AND used_at IS NULL",
            (token_hash,),
        ).fetchone()
        if not record or datetime.fromisoformat(record["expires_at"]) < datetime.utcnow():
            flash("The reset code is invalid or has expired. Ask the District Officer for a new one.", "error")
        elif len(password) < MIN_PASSWORD_LENGTH:
            flash(f"Password must contain at least {MIN_PASSWORD_LENGTH} characters.", "error")
        elif password != confirm:
            flash("The passwords do not match.", "error")
        else:
            db.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                       (generate_password_hash(password), record["user_id"]))
            db.execute("UPDATE password_reset_tokens SET used_at = CURRENT_TIMESTAMP WHERE id = ?", (record["id"],))
            db.commit()
            flash("Password changed successfully. You can now log in.", "message")
            return redirect(url_for("login"))

    content = """
    <div class="card"><h2>Choose a new password</h2>
      <p>Enter the one-time code provided by the District Officer.</p>
      <form method="POST">{{ csrf() }}
        <label for="token">One-time reset code</label><input id="token" name="token" required autocomplete="off">
        <label for="password">New password</label><input id="password" type="password" name="password" minlength="{{ min_len }}" required autocomplete="new-password">
        <label for="confirm_password">Confirm new password</label><input id="confirm_password" type="password" name="confirm_password" minlength="{{ min_len }}" required autocomplete="new-password">
        <button type="submit">Save new password</button>
      </form></div>"""
    return render_page("Reset Password", content, min_len=MIN_PASSWORD_LENGTH)


@app.cli.command("reset-officer-password")
@__import__("click").argument("username")
def reset_officer_password(username):
    """Emergency recovery for a District Officer; requires trusted local terminal access."""
    import getpass
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    user = db.execute("SELECT id, role FROM users WHERE username = ?", (username,)).fetchone()
    if not user or user["role"] != "District Officer":
        print("No District Officer account found with that username.")
        db.close()
        return
    new_password = getpass.getpass("New password (minimum 8 characters): ")
    if len(new_password) < MIN_PASSWORD_LENGTH:
        print("Password is too short; no change made.")
    else:
        db.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                   (generate_password_hash(new_password), user["id"]))
        db.commit()
        print("District Officer password reset. The password was not displayed or stored in plain text.")
    db.close()


# --------------------------------------------------
# ERROR HANDLING
# --------------------------------------------------

def error_page(title, message, code):
    content = """
    <div class="card"><h2>{{ heading }}</h2><p>{{ message }}</p>
        <a class="button" href="{{ url_for('dashboard') }}">Return to Dashboard</a></div>
    """
    return render_page(title, content, heading=title, message=message), code


@app.errorhandler(400)
def bad_request(_error):
    return error_page(
        "Request Rejected",
        "Your session may have expired. Please go back, refresh the page and try again.",
        400,
    )


@app.errorhandler(403)
def forbidden(_error):
    return error_page("Access Denied", "You do not have permission to access this page.", 403)


@app.errorhandler(404)
def page_not_found(_error):
    return error_page("Page Not Found", "The page you requested does not exist.", 404)


# --------------------------------------------------
# START APPLICATION
# --------------------------------------------------

with app.app_context():
    init_db()

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=os.environ.get("FLASK_DEBUG", "1") == "1",
    )