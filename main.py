import sqlite3, os, shutil, base64, secrets, io
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, send_file, g
from flask_cors import CORS
import functools

app = Flask(__name__)
CORS(app, origins="*")

DB_FILE   = "clientes.db"
SALT_FILE = "clientes.salt"
PDF_DIR   = "constancias"
os.makedirs(PDF_DIR, exist_ok=True)

APP_USER     = os.environ.get("APP_USER",     "admin")
APP_PASSWORD = os.environ.get("APP_PASSWORD", "cambiar_esto")
MASTER_KEY   = os.environ.get("MASTER_KEY",   "clave_maestra_cambiar")
TOKENS       = {}

MESES = ["Enero","Febrero","Marzo","Abril","Mayo","Junio",
         "Julio","Agosto","Septiembre","Octubre","Noviembre","Diciembre"]

# ── Encriptación ──────────────────────────────────────────────────────────────
def generar_salt():
    if not os.path.exists(SALT_FILE):
        with open(SALT_FILE,"wb") as f: f.write(os.urandom(16))
    with open(SALT_FILE,"rb") as f: return f.read()

def get_fernet():
    salt = generar_salt()
    kdf  = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=480000)
    return Fernet(base64.urlsafe_b64encode(kdf.derive(MASTER_KEY.encode())))

def enc(t): return get_fernet().encrypt(t.encode()).decode() if t else ""
def dec(t):
    try: return get_fernet().decrypt(t.encode()).decode() if t else ""
    except: return ""

# ── Base de datos ─────────────────────────────────────────────────────────────
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_FILE)
        g.db.row_factory = sqlite3.Row
        g.db.executescript("""
            CREATE TABLE IF NOT EXISTS clientes (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                nombre_completo  TEXT NOT NULL,
                nit              TEXT,
                dpi              TEXT,
                fecha_nacimiento TEXT,
                contrasena_av    TEXT,
                contrasena_fel   TEXT,
                telefono         TEXT,
                honorarios_fijos REAL DEFAULT NULL,
                activo           INTEGER DEFAULT 1,
                fecha_registro   TEXT DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS bitacora (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                cliente_id   INTEGER NOT NULL,
                fecha        TEXT NOT NULL,
                mes          INTEGER NOT NULL,
                anio         INTEGER NOT NULL,
                tipo         TEXT NOT NULL,
                descripcion  TEXT,
                monto        REAL,
                estado_cobro TEXT DEFAULT 'pendiente_cobro',
                pagado       INTEGER DEFAULT 0,
                pdf_path     TEXT,
                FOREIGN KEY (cliente_id) REFERENCES clientes(id)
            );
        """)
        # Migración: agregar columnas si no existen en DB antigua
        try: g.db.execute("ALTER TABLE clientes ADD COLUMN activo INTEGER DEFAULT 1")
        except: pass
        try: g.db.execute("ALTER TABLE bitacora ADD COLUMN estado_cobro TEXT DEFAULT 'pendiente_cobro'")
        except: pass
        g.db.commit()
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop("db",None)
    if db: db.close()

# ── Auth ──────────────────────────────────────────────────────────────────────
def require_auth(f):
    @functools.wraps(f)
    def wrapper(*args,**kwargs):
        token = request.headers.get("Authorization","").replace("Bearer ","")
        if token not in TOKENS or TOKENS[token] < datetime.now():
            return jsonify({"error":"No autorizado"}), 401
        return f(*args,**kwargs)
    return wrapper

@app.route("/api/login", methods=["POST"])
def login():
    d = request.json or {}
    if d.get("usuario")==APP_USER and d.get("password")==APP_PASSWORD:
        token = secrets.token_hex(32)
        TOKENS[token] = datetime.now() + timedelta(hours=12)
        return jsonify({"token": token})
    return jsonify({"error":"Credenciales incorrectas"}), 401

@app.route("/api/logout", methods=["POST"])
@require_auth
def logout():
    token = request.headers.get("Authorization","").replace("Bearer ","")
    TOKENS.pop(token, None)
    return jsonify({"ok": True})

# ── Clientes ──────────────────────────────────────────────────────────────────
@app.route("/api/clientes", methods=["GET"])
@require_auth
def listar_clientes():
    rows = get_db().execute("SELECT * FROM clientes ORDER BY nombre_completo").fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/clientes", methods=["POST"])
@require_auth
def crear_cliente():
    d  = request.json or {}
    db = get_db()
    db.execute("""
        INSERT INTO clientes
          (nombre_completo,nit,dpi,fecha_nacimiento,contrasena_av,contrasena_fel,telefono,honorarios_fijos,activo)
        VALUES (?,?,?,?,?,?,?,?,1)
    """, (d.get("nombre_completo"), d.get("nit"), d.get("dpi"),
          d.get("fecha_nacimiento"),
          enc(d.get("contrasena_av","")), enc(d.get("contrasena_fel","")),
          d.get("telefono"), d.get("honorarios_fijos")))
    db.commit()
    return jsonify({"id": db.execute("SELECT last_insert_rowid()").fetchone()[0]})

@app.route("/api/clientes/<int:cid>", methods=["GET"])
@require_auth
def ver_cliente(cid):
    row = get_db().execute("SELECT * FROM clientes WHERE id=?", (cid,)).fetchone()
    if not row: return jsonify({"error":"No encontrado"}), 404
    d = dict(row)
    d["contrasena_av"]  = dec(d["contrasena_av"])
    d["contrasena_fel"] = dec(d["contrasena_fel"])
    return jsonify(d)

@app.route("/api/clientes/<int:cid>", methods=["PUT"])
@require_auth
def actualizar_cliente(cid):
    d = request.json or {}
    db = get_db()
    campos, vals = [], []
    for k, v in d.items():
        if k in ("nombre_completo","nit","dpi","fecha_nacimiento","telefono","honorarios_fijos","activo"):
            campos.append(f"{k}=?"); vals.append(v)
        elif k == "contrasena_av":
            campos.append("contrasena_av=?"); vals.append(enc(v))
        elif k == "contrasena_fel":
            campos.append("contrasena_fel=?"); vals.append(enc(v))
    if campos:
        vals.append(cid)
        db.execute(f"UPDATE clientes SET {','.join(campos)} WHERE id=?", vals)
        db.commit()
    return jsonify({"ok": True})

@app.route("/api/clientes/<int:cid>", methods=["DELETE"])
@require_auth
def eliminar_cliente(cid):
    db = get_db()
    # Eliminar PDFs asociados
    rows = db.execute("SELECT pdf_path FROM bitacora WHERE cliente_id=?", (cid,)).fetchall()
    for r in rows:
        if r["pdf_path"] and os.path.exists(r["pdf_path"]):
            os.remove(r["pdf_path"])
    db.execute("DELETE FROM bitacora WHERE cliente_id=?", (cid,))
    db.execute("DELETE FROM clientes WHERE id=?", (cid,))
    db.commit()
    return jsonify({"ok": True})

# ── Bitácora ──────────────────────────────────────────────────────────────────
@app.route("/api/bitacora", methods=["GET"])
@require_auth
def listar_bitacora():
    cid  = request.args.get("cliente_id")
    db   = get_db()
    q    = "SELECT * FROM bitacora"
    args = []
    if cid: q += " WHERE cliente_id=?"; args.append(cid)
    q += " ORDER BY anio DESC, mes DESC, fecha DESC"
    return jsonify([dict(r) for r in db.execute(q, args).fetchall()])

@app.route("/api/bitacora", methods=["POST"])
@require_auth
def crear_entrada():
    if request.content_type and "multipart" in request.content_type:
        d = request.form; pdf_f = request.files.get("pdf"); pdf_path = None
        if pdf_f:
            nombre = f"{d.get('cliente_id')}_{d.get('tipo')}_{datetime.now().strftime('%Y%m%d%H%M%S')}.pdf"
            pdf_path = os.path.join(PDF_DIR, nombre); pdf_f.save(pdf_path)
    else:
        d = request.json or {}; pdf_path = None

    estado_cobro = d.get("estado_cobro","pendiente_cobro")
    pagado = 1 if estado_cobro == "pagado_cliente" else 0

    db  = get_db(); hoy = datetime.now()
    db.execute("""
        INSERT INTO bitacora (cliente_id,fecha,mes,anio,tipo,descripcion,monto,estado_cobro,pagado,pdf_path)
        VALUES (?,?,?,?,?,?,?,?,?,?)
    """, (d.get("cliente_id"), d.get("fecha", hoy.strftime("%Y-%m-%d")),
          d.get("mes", hoy.month), d.get("anio", hoy.year),
          d.get("tipo"), d.get("descripcion"),
          d.get("monto") or None, estado_cobro, pagado, pdf_path))
    db.commit()
    return jsonify({"id": db.execute("SELECT last_insert_rowid()").fetchone()[0]})

@app.route("/api/bitacora/<int:bid>/estado", methods=["PUT"])
@require_auth
def cambiar_estado_cobro(bid):
    d = request.json or {}
    estado = d.get("estado_cobro","pendiente_cobro")
    pagado = 1 if estado == "pagado_cliente" else 0
    db = get_db()
    db.execute("UPDATE bitacora SET estado_cobro=?, pagado=? WHERE id=?", (estado, pagado, bid))
    db.commit()
    return jsonify({"ok": True})

@app.route("/api/bitacora/<int:bid>", methods=["DELETE"])
@require_auth
def eliminar_entrada(bid):
    db  = get_db()
    row = db.execute("SELECT pdf_path FROM bitacora WHERE id=?", (bid,)).fetchone()
    if row and row["pdf_path"] and os.path.exists(row["pdf_path"]):
        os.remove(row["pdf_path"])
    db.execute("DELETE FROM bitacora WHERE id=?", (bid,))
    db.commit()
    return jsonify({"ok": True})

@app.route("/api/bitacora/<int:bid>/pdf", methods=["GET"])
@require_auth
def descargar_pdf(bid):
    row = get_db().execute("SELECT pdf_path FROM bitacora WHERE id=?", (bid,)).fetchone()
    if not row or not row["pdf_path"] or not os.path.exists(row["pdf_path"]):
        return jsonify({"error":"Sin PDF"}), 404
    return send_file(row["pdf_path"], mimetype="application/pdf")

# ── Reportes ──────────────────────────────────────────────────────────────────
@app.route("/api/reportes/bitacora/<int:cid>", methods=["GET"])
@require_auth
def reporte_bitacora(cid):
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib import colors
    from reportlab.lib.units import cm

    db     = get_db(); anio = request.args.get("anio")
    cliente= db.execute("SELECT nombre_completo,nit FROM clientes WHERE id=?", (cid,)).fetchone()
    if not cliente: return jsonify({"error":"No encontrado"}), 404
    q = "SELECT fecha,mes,anio,tipo,descripcion,monto,estado_cobro FROM bitacora WHERE cliente_id=?"
    p = [cid]
    if anio: q += " AND anio=?"; p.append(anio)
    q += " ORDER BY anio,mes,fecha"
    rows = db.execute(q, p).fetchall()
    buf  = io.BytesIO()
    doc  = SimpleDocTemplate(buf, pagesize=letter,
                              leftMargin=2*cm, rightMargin=2*cm,
                              topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()
    story  = [Paragraph("BITÁCORA DE CLIENTE", styles["Title"]), Spacer(1,6),
              Paragraph(f"<b>Cliente:</b> {cliente[0]}", styles["Normal"]),
              Paragraph(f"<b>NIT:</b> {cliente[1] or '—'}", styles["Normal"]),
              Paragraph(f"<b>Generado:</b> {datetime.now().strftime('%d/%m/%Y %H:%M')}", styles["Normal"]),
              Spacer(1,14)]

    estado_label = {"pendiente_cobro":"Pendiente cobrar","cobrado":"Cobrado","pagado_cliente":"Pagado cliente"}
    filas = [["Fecha","Mes","Año","Tipo","Descripción","Monto","Estado cobro"]] + [
             [r[0], MESES[r[1]-1], r[2], r[3], (r[4] or "")[:38],
              f"Q{r[5]:,.2f}" if r[5] else "—",
              estado_label.get(r[6] or "pendiente_cobro","—")] for r in rows]
    t = Table(filas, colWidths=[2.2*cm,2.5*cm,1.4*cm,2.8*cm,5.5*cm,2.2*cm,3*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#1a3a5c")),
        ("TEXTCOLOR",(0,0),(-1,0),colors.white),
        ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
        ("FONTSIZE",(0,0),(-1,-1),8),("ALIGN",(0,0),(-1,-1),"CENTER"),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,colors.HexColor("#eef2f7")]),
        ("GRID",(0,0),(-1,-1),0.4,colors.HexColor("#cccccc")),
        ("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4),
    ]))
    story.append(t)
    total = sum(r[5] for r in rows if r[5])
    story += [Spacer(1,10), Paragraph(f"<b>Total registrado: Q{total:,.2f}</b>", styles["Normal"])]
    doc.build(story); buf.seek(0)
    return send_file(buf, mimetype="application/pdf",
                     download_name=f"bitacora_{cliente[0].replace(' ','_')}.pdf")

@app.route("/api/reportes/honorarios", methods=["GET"])
@require_auth
def reporte_honorarios():
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, KeepTogether
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib import colors
    from reportlab.lib.units import cm

    db = get_db(); anio = request.args.get("anio")
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter,
                             leftMargin=2*cm, rightMargin=2*cm,
                             topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()
    story  = [Paragraph("REPORTE DE HONORARIOS", styles["Title"]),
              Paragraph(f"<b>Generado:</b> {datetime.now().strftime('%d/%m/%Y %H:%M')}", styles["Normal"]),
              Spacer(1,14)]

    clientes = db.execute(
        "SELECT id,nombre_completo,nit FROM clientes WHERE activo=1 ORDER BY nombre_completo"
    ).fetchall()
    total_pend_global = 0

    for cl in clientes:
        q = "SELECT mes,anio,monto,estado_cobro,descripcion FROM bitacora WHERE cliente_id=? AND tipo='Honorarios'"
        p = [cl[0]]
        if anio: q += " AND anio=?"; p.append(anio)
        q += " ORDER BY anio,mes"
        hons = db.execute(q,p).fetchall()
        if not hons: continue

        pend_cobrar = [r for r in hons if (r[3] or "pendiente_cobro")=="pendiente_cobro"]
        cobrados    = [r for r in hons if r[3]=="cobrado"]
        pagados     = [r for r in hons if r[3]=="pagado_cliente"]
        total_pend  = sum(r[2] or 0 for r in pend_cobrar)
        total_cob   = sum(r[2] or 0 for r in cobrados)
        total_pag   = sum(r[2] or 0 for r in pagados)
        total_pend_global += total_pend

        story.append(Paragraph(f"<b>{cl[1]}</b> — NIT: {cl[2] or '—'}", styles["Heading3"]))
        estado_map = {"pendiente_cobro":"Pendiente","cobrado":"Cobrado","pagado_cliente":"Pagado cliente"}
        filas = [["Mes","Año","Monto","Estado"]] + [
                 [MESES[r[0]-1], r[1], f"Q{r[2]:,.2f}" if r[2] else "—",
                  estado_map.get(r[3] or "pendiente_cobro","—")] for r in hons]
        filas += [["","","",""],
                  [f"Pend: Q{total_pend:,.2f}", f"Cobrado: Q{total_cob:,.2f}",
                   f"Pagado: Q{total_pag:,.2f}", ""]]
        t = Table(filas, colWidths=[4*cm,2.5*cm,3.5*cm,4*cm])
        t.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#1a3a5c")),
            ("TEXTCOLOR",(0,0),(-1,0),colors.white),
            ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
            ("FONTSIZE",(0,0),(-1,-1),8),("ALIGN",(0,0),(-1,-1),"CENTER"),
            ("ROWBACKGROUNDS",(0,1),(-1,-2),[colors.white,colors.HexColor("#eef2f7")]),
            ("GRID",(0,0),(-1,-2),0.4,colors.HexColor("#cccccc")),
            ("BACKGROUND",(0,-1),(-1,-1),colors.HexColor("#fdf3e3")),
            ("FONTNAME",(0,-1),(-1,-1),"Helvetica-Bold"),
            ("FONTSIZE",(0,-1),(-1,-1),8),
            ("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4),
        ]))
        story.append(KeepTogether([t, Spacer(1,4)]))
        story.append(Spacer(1,14))

    story.append(Paragraph(f"<b>TOTAL GLOBAL PENDIENTE DE COBRAR: Q{total_pend_global:,.2f}</b>", styles["Heading2"]))
    doc.build(story); buf.seek(0)
    return send_file(buf, mimetype="application/pdf", download_name="honorarios.pdf")

@app.route("/")
def index():
    return jsonify({"status":"ok","mensaje":"API Sistema Clientes v2"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT",5000)))
