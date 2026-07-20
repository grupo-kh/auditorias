# -*- coding: utf-8 -*-
"""Auditorías KH — panel de auditorías internas (migración PHP -> Flask).

Arranque: python app.py
Configuración vía variables de entorno (.env en la raíz del repo).
"""

import os
import socket
import sqlite3
from datetime import date
from functools import wraps

from dotenv import load_dotenv
from flask import (
    Flask,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

# ---------------------------------------------------------------------------
# Configuración desde .env
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))

SECRET_KEY = os.environ.get("SECRET_KEY", "")
DB_PATH = os.environ.get("DB_PATH", "data/audit.db")
if not os.path.isabs(DB_PATH):
    DB_PATH = os.path.join(BASE_DIR, DB_PATH)
APP_HOST = os.environ.get("APP_HOST", "0.0.0.0")
APP_PORT = int(os.environ.get("APP_PORT", "8000"))
SERVER_IP = os.environ.get("SERVER_IP", "").strip()

# Prefijo de URL bajo el que se sirve la app (ej. "/auditorias" detrás de un
# proxy inverso). Vacío = la app cuelga de la raíz.
APP_URL_PREFIX = os.environ.get("APP_URL_PREFIX", "").strip().rstrip("/")
if APP_URL_PREFIX and not APP_URL_PREFIX.startswith("/"):
    APP_URL_PREFIX = "/" + APP_URL_PREFIX

# URL pública base (ej. "http://mi-servidor") para componer la URL móvil
# cuando la app está detrás de un proxy; vacío = usar SERVER_IP:APP_PORT.
PUBLIC_URL = os.environ.get("PUBLIC_URL", "").strip().rstrip("/")


def _parse_admin_users(raw):
    """Parsea ADMIN_USERS con formato 'usuario:contraseña,usuario2:contraseña2'."""
    admins = {}
    for par in (raw or "").split(","):
        par = par.strip()
        if not par or ":" not in par:
            continue
        usuario, _, contrasena = par.partition(":")
        usuario = usuario.strip()
        if usuario:
            admins[usuario] = contrasena
    return admins


ADMIN_USERS = _parse_admin_users(os.environ.get("ADMIN_USERS", ""))

app = Flask(__name__)
app.secret_key = SECRET_KEY or os.urandom(32)  # sin SECRET_KEY se genera una efímera

if APP_URL_PREFIX:
    # Monta toda la app bajo el prefijo: las rutas pasan a ser
    # {prefijo}/login, {prefijo}/api, ... y url_for/redirect lo incluyen solo.
    from werkzeug.exceptions import NotFound
    from werkzeug.middleware.dispatcher import DispatcherMiddleware

    app.wsgi_app = DispatcherMiddleware(NotFound(), {APP_URL_PREFIX: app.wsgi_app})


# ---------------------------------------------------------------------------
# Base de datos (sqlite3, filas como dict)
# ---------------------------------------------------------------------------
def get_db():
    """Devuelve una conexión sqlite3 por petición con row_factory dict."""
    if "db" not in g:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def rows_to_dicts(rows):
    return [dict(r) for r in rows]


def get_auditores():
    """Lista de auditores distintos para los formularios de login."""
    cur = get_db().execute("SELECT DISTINCT auditor FROM preguntas ORDER BY auditor")
    return [r["auditor"] for r in cur.fetchall()]


# ---------------------------------------------------------------------------
# Helpers de sesión
# ---------------------------------------------------------------------------
def login_required(view):
    """Página protegida: sin sesión -> redirect a /login."""

    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def _do_login(destino):
    """Procesa el POST de login (compartido por /login y /m_login).

    Devuelve (respuesta_redirect | None, mensaje_error).
    """
    auditor_select = request.form.get("auditor_select", "")
    admin_user = request.form.get("admin_user")
    admin_pass = request.form.get("admin_pass")

    if auditor_select:
        session["user"] = auditor_select
        session["role"] = "auditor"
        return redirect(url_for(destino)), ""
    if admin_user is not None and admin_pass is not None:
        if admin_user in ADMIN_USERS and ADMIN_USERS[admin_user] == admin_pass:
            session["user"] = admin_user
            session["role"] = "admin"
            return redirect(url_for(destino)), ""
        return None, "Credenciales incorrectas"
    return None, "Credenciales incorrectas"


# ---------------------------------------------------------------------------
# Rutas de autenticación
# ---------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    """Login de escritorio (réplica de login.php)."""
    if "user" in session:
        return redirect(url_for("index"))

    error = ""
    if request.method == "POST":
        respuesta, error = _do_login("index")
        if respuesta is not None:
            return respuesta

    return render_template("login.html", auditores=get_auditores(), error=error)


@app.route("/m_login", methods=["GET", "POST"])
def m_login():
    """Login móvil (réplica de m_login.php)."""
    if "user" in session:
        return redirect(url_for("mobile"))

    error = ""
    if request.method == "POST":
        respuesta, error = _do_login("mobile")
        if respuesta is not None:
            return respuesta

    return render_template("m_login.html", auditores=get_auditores(), error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Rutas de páginas
# ---------------------------------------------------------------------------
@app.route("/")
@app.route("/index")
@login_required
def index():
    """Panel principal de escritorio (réplica de index.php)."""
    is_admin = session.get("role") == "admin"
    return render_template("index.html", user=session["user"], is_admin=is_admin)


@app.route("/mobile")
def mobile():
    """Panel móvil (réplica de mobile.php): sin sesión -> /m_login."""
    if "user" not in session:
        return redirect(url_for("m_login"))
    is_admin = session.get("role") == "admin"
    return render_template("mobile.html", user=session["user"], is_admin=is_admin)


@app.route("/reports")
def reports():
    """Informes (solo admin, réplica de reports.php)."""
    if session.get("role") != "admin":
        return "Acceso denegado.", 403
    return render_template("reports.html", user=session.get("user"))


@app.route("/admin_preguntas")
def admin_preguntas():
    """Gestión de preguntas (solo admin, réplica de admin_preguntas.php)."""
    if session.get("role") != "admin":
        return "Acceso denegado. Solo administradores.", 403
    cur = get_db().execute("SELECT * FROM preguntas ORDER BY id DESC")
    preguntas = rows_to_dicts(cur.fetchall())
    return render_template("admin_preguntas.html", preguntas=preguntas)


@app.route("/manual")
def manual():
    """Manual de uso (accesible sin login, réplica de manual.php)."""
    return render_template("manual.html")


@app.route("/m_url")
@login_required
def m_url():
    """Muestra la URL para acceder desde el móvil (réplica de m_url.php)."""
    ruta_mobile = url_for("mobile")  # incluye APP_URL_PREFIX si lo hay
    if PUBLIC_URL:
        url = PUBLIC_URL + ruta_mobile
    else:
        ip = SERVER_IP or _detect_local_ip()
        port_part = "" if APP_PORT in (80, 443) else f":{APP_PORT}"
        url = f"http://{ip}{port_part}{ruta_mobile}"
    return render_template("m_url.html", url=url)


def _detect_local_ip():
    """Autodetecta la IP local del servidor con socket (sin tráfico real).

    Usa la IP pública de Google DNS (8.8.8.8) solo para que el SO elija la
    interfaz de salida; no se envía ningún paquete (UDP connect no transmite).
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return "127.0.0.1"


# ---------------------------------------------------------------------------
# API JSON (mismo contrato que api.php)
# ---------------------------------------------------------------------------
@app.route("/api", methods=["GET", "POST"])
def api():
    if "user" not in session:
        return jsonify({"error": "No autorizado. Inicie sesión."}), 401

    db = get_db()
    action = request.args.get("action", "")
    role = session.get("role")

    # ---------------- get_questions ----------------
    if action == "get_questions":
        auditor = request.args.get("auditor", "")
        if role == "auditor":
            auditor = session["user"]  # auto-filtro para rol auditor
        auditado = request.args.get("auditado", "")
        periodicidad = request.args.get("periodicidad", "")
        search = request.args.get("search", "")

        query = "SELECT id FROM preguntas WHERE 1=1"
        params = []
        if auditor:
            query += " AND auditor = ?"
            params.append(auditor)
        if auditado:
            query += " AND auditado = ?"
            params.append(auditado)
        if periodicidad:
            query += " AND periodicidad = ?"
            params.append(periodicidad)
        if search:
            query += (
                " AND (pregunta LIKE ? OR que_esperamos LIKE ?"
                " OR proceso LIKE ? OR grupo LIKE ?)"
            )
            like = f"%{search}%"
            params.extend([like, like, like, like])

        cur = db.execute(query, params)
        return jsonify([r["id"] for r in cur.fetchall()])

    # ---------------- get_question_details ----------------
    if action == "get_question_details":
        qid = request.args.get("id", 0)
        cur = db.execute("SELECT * FROM preguntas WHERE id = ?", (qid,))
        row = cur.fetchone()
        return jsonify(dict(row) if row else None)

    # ---------------- get_history ----------------
    if action == "get_history":
        qid = request.args.get("id", 0)
        cur = db.execute(
            "SELECT * FROM auditorias WHERE pregunta_id = ? ORDER BY fecha DESC",
            (qid,),
        )
        return jsonify(rows_to_dicts(cur.fetchall()))

    # ---------------- save_audit ----------------
    if action == "save_audit":
        if request.method == "POST":
            data = request.get_json(silent=True) or {}
            cur = db.execute(
                "INSERT INTO auditorias (pregunta_id, fecha, ok_nok, comentario,"
                " numero_operario) VALUES (?, ?, ?, ?, ?)",
                (
                    data.get("pregunta_id", 0),
                    data.get("fecha") or date.today().isoformat(),
                    data.get("ok_nok", ""),
                    data.get("comentario", ""),
                    data.get("numero_operario", ""),
                ),
            )
            db.commit()
            return jsonify({"status": "success", "id": cur.lastrowid})
        return ("", 200)

    # ---------------- update_audit ----------------
    if action == "update_audit":
        if role != "admin":
            return jsonify({"error": "Unauthorized"})
        if request.method == "POST":
            data = request.get_json(silent=True) or {}
            aid = data.get("id", 0)
            if aid:
                db.execute(
                    "UPDATE auditorias SET ok_nok=?, comentario=?, fecha=?,"
                    " numero_operario=? WHERE id=?",
                    (
                        data.get("ok_nok", ""),
                        data.get("comentario", ""),
                        data.get("fecha", ""),
                        data.get("numero_operario", ""),
                        aid,
                    ),
                )
                db.commit()
                return jsonify({"status": "success"})
        return ("", 200)

    # ---------------- delete_audit ----------------
    if action == "delete_audit":
        if role != "admin":
            return jsonify({"error": "Unauthorized"})
        aid = request.args.get("id", 0)
        if aid:
            db.execute("DELETE FROM auditorias WHERE id = ?", (aid,))
            db.commit()
            return jsonify({"status": "success"})
        return ("", 200)

    # ---------------- save_question ----------------
    if action == "save_question":
        if role != "admin":
            return jsonify({"error": "Unauthorized"})
        if request.method == "POST":
            data = request.get_json(silent=True) or {}
            valores = (
                data.get("proceso", ""),
                data.get("auditor", ""),
                data.get("auditado", ""),
                data.get("grupo", ""),
                data.get("punto", 0),
                data.get("pregunta", ""),
                data.get("que_esperamos", ""),
                data.get("periodicidad", ""),
            )
            qid = data.get("id", 0)
            if qid:
                db.execute(
                    "UPDATE preguntas SET proceso=?, auditor=?, auditado=?,"
                    " grupo=?, punto=?, pregunta=?, que_esperamos=?,"
                    " periodicidad=? WHERE id=?",
                    valores + (qid,),
                )
            else:
                db.execute(
                    "INSERT INTO preguntas (proceso, auditor, auditado, grupo,"
                    " punto, pregunta, que_esperamos, periodicidad)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    valores,
                )
            db.commit()
            return jsonify({"status": "success"})
        return ("", 200)

    # ---------------- get_stats ----------------
    if action == "get_stats":
        if role != "admin":
            return jsonify({"error": "Unauthorized"})
        nok_per_week = rows_to_dicts(
            db.execute(
                "SELECT strftime('%W', fecha) as week, COUNT(*) as count"
                " FROM auditorias WHERE ok_nok = 'NOK' GROUP BY week ORDER BY week"
            ).fetchall()
        )
        by_auditor = rows_to_dicts(
            db.execute(
                "SELECT p.auditor, a.ok_nok, COUNT(*) as count FROM auditorias a"
                " JOIN preguntas p ON a.pregunta_id = p.id"
                " GROUP BY p.auditor, a.ok_nok"
            ).fetchall()
        )
        nok_by_audited = rows_to_dicts(
            db.execute(
                "SELECT p.auditado, p.auditor, COUNT(*) as count FROM auditorias a"
                " JOIN preguntas p ON a.pregunta_id = p.id"
                " WHERE a.ok_nok = 'NOK' GROUP BY p.auditado, p.auditor"
            ).fetchall()
        )
        return jsonify(
            {
                "nok_per_week": nok_per_week,
                "by_auditor": by_auditor,
                "nok_by_audited": nok_by_audited,
            }
        )

    # ---------------- get_filter_values ----------------
    if action == "get_filter_values":
        auditor = request.args.get("auditor", "")
        if role == "auditor":
            auditor = session["user"]

        where = " WHERE 1=1"
        params = []
        if auditor:
            where += " AND auditor = ?"
            params.append(auditor)

        auditados = [
            r["auditado"]
            for r in db.execute(
                f"SELECT DISTINCT auditado FROM preguntas{where} ORDER BY auditado",
                params,
            ).fetchall()
        ]
        periodicidades = [
            r["periodicidad"]
            for r in db.execute(
                f"SELECT DISTINCT periodicidad FROM preguntas{where}"
                " ORDER BY periodicidad",
                params,
            ).fetchall()
        ]
        return jsonify({"auditados": auditados, "periodicidades": periodicidades})

    # ---------------- delete_question ----------------
    if action == "delete_question":
        if role != "admin":
            return jsonify({"error": "Unauthorized"})
        qid = request.args.get("id", 0)
        if qid:
            db.execute("DELETE FROM auditorias WHERE pregunta_id = ?", (qid,))
            db.execute("DELETE FROM preguntas WHERE id = ?", (qid,))
            db.commit()
            return jsonify({"status": "success"})
        return ("", 200)

    return jsonify({"error": "Invalid action"})


# ---------------------------------------------------------------------------
# Arranque directo
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host=APP_HOST, port=APP_PORT)
