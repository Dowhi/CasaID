"""
CasaID — Gestor familiar de documentos de identidad
=====================================================
Autor: Antigravity / Senior Full-Stack Dev
Stack : Python · Streamlit · SQLite · Fernet (cryptography) · bcrypt
"""

import os
import uuid
import sqlite3
import hashlib
import base64
import io
import time
from datetime import datetime
from pathlib import Path

import bcrypt
import streamlit as st
from cryptography.fernet import Fernet

# ─────────────────────────────────────────────────────────────────────────────
# PATHS & CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────
BASE_DIR    = Path(__file__).parent
DATA_DIR    = BASE_DIR / "data"
UPLOADS_DIR = DATA_DIR / "uploads"
DB_PATH     = DATA_DIR / "casaid.db"
KEY_PATH    = DATA_DIR / ".fernet.key"

ALLOWED_MIME = {"application/pdf", "image/jpeg", "image/png", "image/webp"}
ALLOWED_EXT  = {".pdf", ".jpg", ".jpeg", ".png", ".webp"}
MAX_FILE_MB  = 20

# ─────────────────────────────────────────────────────────────────────────────
# BOOTSTRAP  — dirs, key, DB
# ─────────────────────────────────────────────────────────────────────────────
def _bootstrap():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    UPLOADS_DIR.mkdir(parents=True, exist_ok=True)

    # Fernet key — generated once, persisted on disk
    if not KEY_PATH.exists():
        KEY_PATH.write_bytes(Fernet.generate_key())
        KEY_PATH.chmod(0o600)

    # SQLite schema
    con = _db()
    con.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id          TEXT PRIMARY KEY,
            username    TEXT UNIQUE NOT NULL,
            full_name   TEXT NOT NULL,
            pw_hash     BLOB NOT NULL,
            created_at  TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS documents (
            id          TEXT PRIMARY KEY,
            user_id     TEXT NOT NULL REFERENCES users(id),
            orig_name   TEXT NOT NULL,
            stored_name TEXT NOT NULL,
            mime_type   TEXT NOT NULL,
            size_bytes  INTEGER NOT NULL,
            uploaded_at TEXT NOT NULL
        );
    """)
    con.commit()
    con.close()


def _db() -> sqlite3.Connection:
    con = sqlite3.connect(DB_PATH, check_same_thread=False)
    con.row_factory = sqlite3.Row
    return con


def _fernet() -> Fernet:
    return Fernet(KEY_PATH.read_bytes())


# ─────────────────────────────────────────────────────────────────────────────
# AUTH HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def register_user(username: str, full_name: str, password: str) -> tuple[bool, str]:
    username = username.strip().lower()
    if len(username) < 3:
        return False, "El usuario debe tener al menos 3 caracteres."
    if len(password) < 6:
        return False, "La contraseña debe tener al menos 6 caracteres."

    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    uid     = str(uuid.uuid4())
    now     = datetime.utcnow().isoformat()

    try:
        con = _db()
        con.execute(
            "INSERT INTO users (id, username, full_name, pw_hash, created_at) VALUES (?,?,?,?,?)",
            (uid, username, full_name.strip(), pw_hash, now),
        )
        con.commit()
        con.close()
        return True, uid
    except sqlite3.IntegrityError:
        return False, "Ese nombre de usuario ya existe."


def login_user(username: str, password: str) -> tuple[bool, dict | str]:
    username = username.strip().lower()
    con = _db()
    row = con.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    con.close()

    if row is None:
        return False, "Usuario o contraseña incorrectos."
    if not bcrypt.checkpw(password.encode(), row["pw_hash"]):
        return False, "Usuario o contraseña incorrectos."

    return True, dict(row)


# ─────────────────────────────────────────────────────────────────────────────
# DOCUMENT HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def save_document(user_id: str, uploaded_file) -> tuple[bool, str]:
    ext = Path(uploaded_file.name).suffix.lower()
    if ext not in ALLOWED_EXT:
        return False, f"Formato no permitido: {ext}"

    raw_bytes = uploaded_file.read()
    if len(raw_bytes) > MAX_FILE_MB * 1024 * 1024:
        return False, f"El archivo supera los {MAX_FILE_MB} MB permitidos."

    # Encrypt
    encrypted = _fernet().encrypt(raw_bytes)

    # Unique stored name: uuid + original extension  (no guessable path)
    stored_name  = f"{uuid.uuid4().hex}{ext}.enc"
    dest_path    = UPLOADS_DIR / stored_name
    dest_path.write_bytes(encrypted)

    doc_id = str(uuid.uuid4())
    now    = datetime.utcnow().isoformat()
    mime   = uploaded_file.type or "application/octet-stream"

    con = _db()
    con.execute(
        "INSERT INTO documents (id, user_id, orig_name, stored_name, mime_type, size_bytes, uploaded_at) "
        "VALUES (?,?,?,?,?,?,?)",
        (doc_id, user_id, uploaded_file.name, stored_name, mime, len(raw_bytes), now),
    )
    con.commit()
    con.close()
    return True, doc_id


def list_documents(user_id: str) -> list[dict]:
    con = _db()
    rows = con.execute(
        "SELECT * FROM documents WHERE user_id=? ORDER BY uploaded_at DESC", (user_id,)
    ).fetchall()
    con.close()
    return [dict(r) for r in rows]


def load_document_bytes(stored_name: str) -> bytes:
    enc = (UPLOADS_DIR / stored_name).read_bytes()
    return _fernet().decrypt(enc)


def delete_document(doc_id: str, user_id: str) -> bool:
    con = _db()
    row = con.execute(
        "SELECT stored_name FROM documents WHERE id=? AND user_id=?", (doc_id, user_id)
    ).fetchone()
    if row is None:
        con.close()
        return False
    stored = row["stored_name"]
    con.execute("DELETE FROM documents WHERE id=?", (doc_id,))
    con.commit()
    con.close()
    path = UPLOADS_DIR / stored
    if path.exists():
        path.unlink()
    return True


# ─────────────────────────────────────────────────────────────────────────────
# SESSION HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def _session_set(user: dict):
    st.session_state["user"] = user
    st.session_state["session_token"] = hashlib.sha256(
        (user["id"] + user["username"] + str(time.time())).encode()
    ).hexdigest()


def _session_clear():
    for k in ["user", "session_token", "preview_doc"]:
        st.session_state.pop(k, None)


def current_user() -> dict | None:
    return st.session_state.get("user")


def is_authenticated() -> bool:
    return "user" in st.session_state and "session_token" in st.session_state


# ─────────────────────────────────────────────────────────────────────────────
# UI — SIDEBAR  (Auth panel)
# ─────────────────────────────────────────────────────────────────────────────
def render_sidebar():
    st.sidebar.image("https://img.icons8.com/fluency/96/identification-documents.png", width=72)
    st.sidebar.title("CasaID 🏠")
    st.sidebar.caption("Gestor familiar de documentos")

    if is_authenticated():
        user = current_user()
        st.sidebar.success(f"✅ {user['full_name']}")
        st.sidebar.caption(f"@{user['username']}")
        st.sidebar.divider()
        if st.sidebar.button("🚪 Cerrar sesión", use_container_width=True):
            _session_clear()
            st.rerun()
        return

    # Auth mode toggle
    if "auth_mode" not in st.session_state:
        st.session_state["auth_mode"] = "login"

    col1, col2 = st.sidebar.columns(2)
    if col1.button("Entrar", use_container_width=True,
                   type="primary" if st.session_state["auth_mode"] == "login" else "secondary"):
        st.session_state["auth_mode"] = "login"
    if col2.button("Registro", use_container_width=True,
                   type="primary" if st.session_state["auth_mode"] == "register" else "secondary"):
        st.session_state["auth_mode"] = "register"

    st.sidebar.divider()

    if st.session_state["auth_mode"] == "login":
        _render_login()
    else:
        _render_register()


def _render_login():
    with st.sidebar.form("form_login", clear_on_submit=False):
        st.subheader("Iniciar sesión")
        username = st.text_input("Usuario", placeholder="tu_usuario")
        password = st.text_input("Contraseña", type="password")
        submitted = st.form_submit_button("Entrar →", use_container_width=True, type="primary")
        if submitted:
            if not username or not password:
                st.error("Completa todos los campos.")
            else:
                ok, result = login_user(username, password)
                if ok:
                    _session_set(result)
                    st.rerun()
                else:
                    st.error(result)


def _render_register():
    with st.sidebar.form("form_register", clear_on_submit=True):
        st.subheader("Crear cuenta")
        full_name = st.text_input("Nombre completo", placeholder="María García")
        username  = st.text_input("Usuario", placeholder="maria_garcia")
        password  = st.text_input("Contraseña", type="password")
        password2 = st.text_input("Repetir contraseña", type="password")
        submitted = st.form_submit_button("Registrarse →", use_container_width=True, type="primary")
        if submitted:
            if not all([full_name, username, password, password2]):
                st.error("Completa todos los campos.")
            elif password != password2:
                st.error("Las contraseñas no coinciden.")
            else:
                ok, result = register_user(username, full_name, password)
                if ok:
                    st.success("✅ Cuenta creada. ¡Ya puedes iniciar sesión!")
                else:
                    st.error(result)


# ─────────────────────────────────────────────────────────────────────────────
# UI — HERO  (not authenticated)
# ─────────────────────────────────────────────────────────────────────────────
def render_hero():
    st.markdown(
        """
        <div style="text-align:center;padding:4rem 0 2rem;">
            <img src="https://img.icons8.com/fluency/120/identification-documents.png"/>
            <h1 style="font-size:2.8rem;margin-top:.5rem;">CasaID</h1>
            <p style="font-size:1.2rem;color:#9b9bbb;">
                Tu bóveda familiar de documentos de identidad<br>
                <span style="font-size:.95rem;">Seguro · Cifrado · Privado</span>
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    cols = st.columns(3)
    features = [
        ("🔐", "Cifrado Fernet", "Tus PDFs se cifran antes de guardarse en disco."),
        ("👤", "Privacidad total",  "Cada usuario solo ve sus propios documentos."),
        ("📲", "Comparte fácil",   "Enlace o WhatsApp con un solo clic."),
    ]
    for col, (icon, title, desc) in zip(cols, features):
        col.markdown(
            f"""
            <div style="background:#1A1D26;border-radius:12px;padding:1.2rem;text-align:center;height:140px;">
                <div style="font-size:2rem;">{icon}</div>
                <strong>{title}</strong><br>
                <small style="color:#9b9bbb;">{desc}</small>
            </div>
            """,
            unsafe_allow_html=True,
        )
    st.info("👈 Usa el panel lateral para iniciar sesión o crear tu cuenta gratuita.")


# ─────────────────────────────────────────────────────────────────────────────
# UI — UPLOAD PANEL
# ─────────────────────────────────────────────────────────────────────────────
def render_upload(user_id: str):
    with st.expander("📤 Subir nuevo documento", expanded=False):
        uploaded = st.file_uploader(
            "Selecciona un PDF o imagen de tu DNI",
            type=["pdf", "jpg", "jpeg", "png", "webp"],
            help=f"Máximo {MAX_FILE_MB} MB — Los archivos se cifran automáticamente.",
        )
        if uploaded:
            cols = st.columns([3, 1])
            cols[0].write(f"**{uploaded.name}** — {uploaded.size / 1024:.1f} KB")
            if cols[1].button("⬆️ Subir", type="primary"):
                with st.spinner("Cifrando y guardando…"):
                    ok, result = save_document(user_id, uploaded)
                if ok:
                    st.success("✅ Documento guardado y cifrado correctamente.")
                    time.sleep(0.8)
                    st.rerun()
                else:
                    st.error(result)


# ─────────────────────────────────────────────────────────────────────────────
# UI — DOCUMENT GALLERY
# ─────────────────────────────────────────────────────────────────────────────
def _fmt_size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024**2:
        return f"{n/1024:.1f} KB"
    return f"{n/1024**2:.1f} MB"


def _whatsapp_link(text: str) -> str:
    import urllib.parse
    return f"https://wa.me/?text={urllib.parse.quote(text)}"


def render_gallery(user: dict):
    docs = list_documents(user["id"])

    if not docs:
        st.markdown(
            """
            <div style="text-align:center;padding:3rem;background:#1A1D26;border-radius:16px;">
                <div style="font-size:3rem;">📂</div>
                <h3>Aún no tienes documentos</h3>
                <p style="color:#9b9bbb;">Usa el panel de arriba para subir tu primer DNI.</p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        return

    st.markdown(f"### 📁 Mis documentos ({len(docs)})")

    for doc in docs:
        with st.container():
            st.markdown(
                f"""
                <div style="background:#1A1D26;border-radius:12px;padding:.8rem 1rem .4rem;
                            border-left:4px solid #6C63FF;margin-bottom:.5rem;">
                    <b>{'📄' if doc['mime_type']=='application/pdf' else '🖼️'} {doc['orig_name']}</b>
                    &nbsp;<span style="color:#9b9bbb;font-size:.85rem;">
                    {_fmt_size(doc['size_bytes'])} · {doc['uploaded_at'][:10]}</span>
                </div>
                """,
                unsafe_allow_html=True,
            )

            btn_cols = st.columns([1, 1, 1, 1, 0.5])

            # ── PREVIEW ──
            if btn_cols[0].button("👁️ Ver", key=f"prev_{doc['id']}"):
                st.session_state["preview_doc"] = doc["id"]

            # ── DOWNLOAD ──
            raw = load_document_bytes(doc["stored_name"])
            btn_cols[1].download_button(
                label="⬇️ Descargar",
                data=raw,
                file_name=doc["orig_name"],
                mime=doc["mime_type"],
                key=f"dl_{doc['id']}",
            )

            # ── SHARE / WHATSAPP ──
            share_text = (
                f"Te comparto mi documento '{doc['orig_name']}' desde CasaID.\n"
                "📥 Descárgalo directamente desde la app."
            )
            wa_url = _whatsapp_link(share_text)
            btn_cols[2].markdown(
                f'<a href="{wa_url}" target="_blank">'
                '<button style="background:#25D366;color:white;border:none;border-radius:8px;'
                'padding:.45rem .9rem;cursor:pointer;width:100%;">🟢 WhatsApp</button></a>',
                unsafe_allow_html=True,
            )

            # ── DELETE ──
            if btn_cols[3].button("🗑️ Borrar", key=f"del_{doc['id']}"):
                st.session_state[f"confirm_del_{doc['id']}"] = True

            if st.session_state.get(f"confirm_del_{doc['id']}"):
                st.warning(f"¿Eliminar **{doc['orig_name']}** permanentemente?")
                c1, c2 = st.columns(2)
                if c1.button("✅ Sí, borrar", key=f"yes_{doc['id']}", type="primary"):
                    delete_document(doc["id"], user["id"])
                    st.session_state.pop(f"confirm_del_{doc['id']}", None)
                    st.rerun()
                if c2.button("❌ Cancelar", key=f"no_{doc['id']}"):
                    st.session_state.pop(f"confirm_del_{doc['id']}", None)
                    st.rerun()

            st.markdown("")  # spacing

    # ── INLINE PREVIEW MODAL ──
    preview_id = st.session_state.get("preview_doc")
    if preview_id:
        target = next((d for d in docs if d["id"] == preview_id), None)
        if target:
            st.divider()
            st.markdown(f"#### 🔍 Previsualización: {target['orig_name']}")
            raw = load_document_bytes(target["stored_name"])

            if target["mime_type"] == "application/pdf":
                # Embed PDF via base64 data URI
                b64 = base64.b64encode(raw).decode()
                st.markdown(
                    f'<iframe src="data:application/pdf;base64,{b64}" '
                    f'width="100%" height="700px" style="border-radius:8px;border:none;"></iframe>',
                    unsafe_allow_html=True,
                )
            else:
                from PIL import Image
                img = Image.open(io.BytesIO(raw))
                st.image(img, use_container_width=True)

            if st.button("✖️ Cerrar previsualización"):
                st.session_state.pop("preview_doc", None)
                st.rerun()


# ─────────────────────────────────────────────────────────────────────────────
# UI — MAIN DASHBOARD
# ─────────────────────────────────────────────────────────────────────────────
def render_dashboard():
    if not is_authenticated():
        render_hero()
        return

    user = current_user()
    st.markdown(
        f"""
        <h2 style="margin-bottom:.2rem;">👋 Hola, <span style="color:#6C63FF;">{user['full_name'].split()[0]}</span></h2>
        <p style="color:#9b9bbb;margin-bottom:1.5rem;">Gestiona tus documentos de identidad de forma segura.</p>
        """,
        unsafe_allow_html=True,
    )

    render_upload(user["id"])
    st.divider()
    render_gallery(user)


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────
def main():
    st.set_page_config(
        page_title="CasaID — Documentos familiares",
        page_icon="🏠",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    # Custom global CSS
    st.markdown(
        """
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap');
        html, body, [class*="css"] { font-family: 'Inter', sans-serif; }
        .block-container { padding-top: 2rem; }
        div[data-testid="stSidebar"] { background: #12141c; }
        div[data-testid="stSidebar"] hr { border-color: #2a2d3a; }
        button[kind="primary"] { border-radius: 8px !important; }
        .stDownloadButton button { border-radius: 8px !important; }
        .stAlert { border-radius: 10px !important; }
        iframe { border-radius: 10px; }
        </style>
        """,
        unsafe_allow_html=True,
    )

    _bootstrap()
    render_sidebar()
    render_dashboard()


if __name__ == "__main__":
    main()
