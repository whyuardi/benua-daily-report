"""Benua Green Energy — Daily Report System.
FastAPI + HTMX + SQLite — deployed on Vercel.
"""
import os
import json
import sqlite3
import aiosqlite
from datetime import datetime
from fastapi import FastAPI, Request, HTTPException, Depends, Form, Query
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.templating import Jinja2Templates
from contextlib import asynccontextmanager
from database import get_db, init_db
from auth import hash_pin, verify_pin, create_token, decode_token
import asyncio

_db_initialized = False

async def ensure_db():
    global _db_initialized
    if not _db_initialized:
        await init_db()
        _db_initialized = True

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield

app = FastAPI(lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def init_db_middleware(request: Request, call_next):
    await ensure_db()
    return await call_next(request)

# ─── Jinja2 Templates ──────────────────────────────────────
templates = Jinja2Templates(directory="templates")

# ─── Static / Auth Helpers ────────────────────────────────

app.mount("/static", StaticFiles(directory="static"), name="static")

AUTH_TOKEN_COOKIE = "bge_token"

def require_auth(level: str = "operator"):
    """Dependency: extracts + validates JWT from cookie.
    level='owner' only for owner; 'operator' for owner+operator.
    """
    async def _check(request: Request):
        token = request.cookies.get(AUTH_TOKEN_COOKIE)
        if not token:
            # Fallback: Authorization header
            auth = request.headers.get("Authorization", "")
            if auth.startswith("Bearer "):
                token = auth[7:]
        if not token:
            raise HTTPException(401, "Unauthorized")
        payload = decode_token(token)
        if not payload:
            raise HTTPException(401, "Token invalid/expired")
        if level == "owner" and payload.get("role") != "owner":
            raise HTTPException(403, "Forbidden: owner only")
        return payload
    return _check


# ─── Login / Auth Pages ───────────────────────────────────

@app.get("/")
async def index(request: Request):
    """Serve login page"""
    return templates.TemplateResponse(request, "login.html")


@app.post("/api/login")
async def login(request: Request):
    data = await request.form()
    phone = data.get("phone", "").strip()
    pin = data.get("pin", "").strip()
    
    db = await get_db()
    cursor = await db.execute("SELECT id, name, phone, pin, role, division_id FROM users WHERE phone = ?", (phone,))
    user = await cursor.fetchone()
    await db.close()
    
    if not user:
        return JSONResponse({"error": "User tidak ditemukan"}, status_code=401)
    
    if not verify_pin(pin, user["pin"]):
        return JSONResponse({"error": "PIN salah"}, status_code=401)
    
    # Check if user has an active (unsaved) report
    db = await get_db()
    cursor = await db.execute(
        "SELECT id FROM reports WHERE user_id = ? AND saved = 0 ORDER BY created_at DESC LIMIT 1",
        (user["id"],)
    )
    active_report = await cursor.fetchone()
    await db.close()
    
    token = create_token(user["id"], user["role"], user["phone"])
    
    response = JSONResponse({
        "token": token,
        "user": {
            "id": user["id"],
            "name": user["name"],
            "phone": user["phone"],
            "role": user["role"],
            "division_id": user["division_id"],
        },
        "has_active_report": active_report is not None,
    })
    response.set_cookie(
        key=AUTH_TOKEN_COOKIE,
        value=token,
        httponly=True,
        max_age=30 * 24 * 3600,
        samesite="lax",
        secure=(os.environ.get("VERCEL_URL") is not None),
    )
    return response


@app.get("/api/me")
async def get_me(request: Request):
    token = request.cookies.get(AUTH_TOKEN_COOKIE)
    if not token:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
    if not token:
        raise HTTPException(401, "Unauthorized")
    
    payload = decode_token(token)
    if not payload:
        raise HTTPException(401, "Token invalid/expired")
    
    db = await get_db()
    cursor = await db.execute(
        "SELECT u.id, u.name, u.phone, u.role, u.division_id, d.name as division_name FROM users u JOIN divisions d ON u.division_id = d.id WHERE u.id = ?",
        (payload["user_id"],)
    )
    user = await cursor.fetchone()
    await db.close()
    
    if not user:
        raise HTTPException(404, "User not found")
    
    return {"user": {
        "id": user["id"],
        "name": user["name"],
        "phone": user["phone"],
        "role": user["role"],
        "division_id": user["division_id"],
        "division_name": user["division_name"],
    }}


# ─── Dashboard ────────────────────────────────────────────

@app.get("/dashboard")
async def dashboard(request: Request):
    return templates.TemplateResponse(request, "dashboard.html")


@app.get("/api/dashboard/init")
async def dashboard_init(request: Request):
    payload = await require_auth()(request)
    
    db = await get_db()
    
    # Get user profile + divisions
    cursor = await db.execute(
        "SELECT u.id, u.name, u.role, u.division_id, d.name as division_name FROM users u JOIN divisions d ON u.division_id = d.id WHERE u.id = ?",
        (payload["user_id"],)
    )
    user = await cursor.fetchone()
    
    cursor = await db.execute("SELECT id, name FROM divisions ORDER BY name")
    divisions = await cursor.fetchall()
    
    # Get pending & latest reports
    cursor = await db.execute(
        "SELECT id, report_date, created_at, updated_at FROM reports WHERE user_id = ? AND saved = 0 ORDER BY created_at DESC LIMIT 1",
        (payload["user_id"],)
    )
    pending_report = await cursor.fetchone()
    
    cursor = await db.execute(
        "SELECT id, report_date, created_at, updated_at FROM reports WHERE user_id = ? AND saved = 1 ORDER BY created_at DESC LIMIT 5",
        (payload["user_id"],)
    )
    recent_reports = await cursor.fetchall()
    
    # Get all users if admin/owner
    all_users = []
    if user["role"] in ("admin", "owner"):
        cur2 = await db.execute("SELECT id, name FROM users ORDER BY name")
        all_users = await cur2.fetchall()
    
    await db.close()
    
    return {
        "user": dict(user),
        "divisions": [dict(d) for d in divisions],
        "pending_report": dict(pending_report) if pending_report else None,
        "recent_reports": [dict(r) for r in recent_reports],
        "all_users": [dict(u) for u in all_users],
    }


@app.get("/api/dashboard/today")
async def dashboard_today(request: Request, date: str = "", division_id: int = None):
    """Returns dashboard stats + reports for a given date and optional division filter."""
    payload = await require_auth()(request)
    db = await get_db()

    # Default to today if no date
    if not date:
        date = datetime.now().strftime("%Y-%m-%d")

    # Total active users
    if division_id:
        count_query = "SELECT COUNT(*) FROM users WHERE is_active = 1 AND division_id = ?"
        cur = await db.execute(count_query, (division_id,))
        total_users = (await cur.fetchone())[0]
    else:
        cur = await db.execute("SELECT COUNT(*) FROM users WHERE is_active = 1")
        total_users = (await cur.fetchone())[0]

    # Reports with saved=1 for this date
    if division_id:
        reports_query = """
            SELECT r.id, r.user_id, r.report_date, u.name as user_name, d.name as division_name
            FROM reports r
            JOIN users u ON r.user_id = u.id
            JOIN divisions d ON u.division_id = d.id
            WHERE r.report_date = ? AND r.saved = 1 AND u.division_id = ?
            ORDER BY u.name
        """
        cur = await db.execute(reports_query, (date, division_id))
    else:
        reports_query = """
            SELECT r.id, r.user_id, r.report_date, u.name as user_name, d.name as division_name
            FROM reports r
            JOIN users u ON r.user_id = u.id
            JOIN divisions d ON u.division_id = d.id
            WHERE r.report_date = ? AND r.saved = 1
            ORDER BY u.name
        """
        cur = await db.execute(reports_query, (date,))

    report_rows = await cur.fetchall()
    submitted = len(report_rows)

    # Build reports with items
    reports = []
    for row in report_rows:
        r = dict(row)
        items_cur = await db.execute(
            "SELECT id, category, content, sort_order FROM report_items WHERE report_id = ? ORDER BY sort_order",
            (r["id"],)
        )
        items = await items_cur.fetchall()
        grouped = {"completed": [], "in_progress": [], "next_action": []}
        for item in items:
            grouped[item["category"]].append({"id": item["id"], "content": item["content"]})
        r["items"] = grouped
        reports.append(r)

    await db.close()

    return {
        "total_users": total_users,
        "submitted": submitted,
        "missing_count": total_users - submitted,
        "reports": reports,
    }


# ─── Daily Report API ─────────────────────────────────────

@app.get("/api/report/items/{report_id}")
async def get_report_items(report_id: int, request: Request):
    """Returns saved report items for editing."""
    payload = await require_auth()(request)
    db = await get_db()
    
    cursor = await db.execute(
        "SELECT user_id FROM reports WHERE id = ?", (report_id,)
    )
    report = await cursor.fetchone()
    if not report:
        await db.close()
        raise HTTPException(404, "Report not found")
    
    # Owner can see any report; others only their own
    if payload["role"] not in ("admin", "owner") and report["user_id"] != payload["user_id"]:
        await db.close()
        raise HTTPException(403, "Forbidden")
    
    cursor = await db.execute(
        "SELECT id, category, content, sort_order FROM report_items WHERE report_id = ? ORDER BY sort_order",
        (report_id,)
    )
    items = await cursor.fetchall()
    await db.close()
    
    result = {"completed": [], "in_progress": [], "next_action": []}
    for item in items:
        cat = item["category"]
        if cat in result:
            result[cat].append({"id": item["id"], "content": item["content"], "sort_order": item["sort_order"]})
    
    return result


@app.post("/api/report/add-item")
async def add_report_item(request: Request):
    """Add item to active report. HTMX-friendly."""
    payload = await require_auth()(request)
    
    data = await request.form()
    category = data.get("category", "completed")
    content = data.get("content", "").strip()
    
    if not content:
        return JSONResponse({"error": "Konten tidak boleh kosong"}, status_code=400)
    if category not in ("completed", "in_progress", "next_action"):
        return JSONResponse({"error": "Kategori tidak valid"}, status_code=400)
    
    db = await get_db()
    
    # Find or create active report
    cursor = await db.execute(
        "SELECT id FROM reports WHERE user_id = ? AND saved = 0 ORDER BY created_at DESC LIMIT 1",
        (payload["user_id"],)
    )
    report = await cursor.fetchone()
    
    if not report:
        today = datetime.utcnow().strftime("%Y-%m-%d")
        cursor = await db.execute(
            "INSERT INTO reports (user_id, report_date) VALUES (?, ?)",
            (payload["user_id"], today)
        )
        await db.commit()
        report_id = cursor.lastrowid
    else:
        report_id = report["id"]
    
    # Get max sort_order
    cursor = await db.execute(
        "SELECT COALESCE(MAX(sort_order), 0) + 1 FROM report_items WHERE report_id = ? AND category = ?",
        (report_id, category)
    )
    max_order = await cursor.fetchone()
    sort_order = max_order[0] if max_order else 1
    
    cursor = await db.execute(
        "INSERT INTO report_items (report_id, category, content, sort_order) VALUES (?, ?, ?, ?)",
        (report_id, category, content, sort_order)
    )
    await db.commit()
    item_id = cursor.lastrowid
    
    await db.close()
    
    return JSONResponse({"id": item_id, "category": category, "content": content, "sort_order": sort_order}, status_code=201)


@app.post("/api/report/save")
async def save_report(request: Request):
    """Save/update report with items from form."""
    payload = await require_auth()(request)
    
    # We support JSON and form data
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        data = await request.json()
    else:
        data = await request.form()
    
    db = await get_db()
    
    # Find or create active report
    cursor = await db.execute(
        "SELECT id FROM reports WHERE user_id = ? AND saved = 0 ORDER BY created_at DESC LIMIT 1",
        (payload["user_id"],)
    )
    report = await cursor.fetchone()
    
    if not report:
        today = datetime.utcnow().strftime("%Y-%m-%d")
        cursor = await db.execute(
            "INSERT INTO reports (user_id, report_date) VALUES (?, ?)",
            (payload["user_id"], today)
        )
        await db.commit()
        report_id = cursor.lastrowid
    else:
        report_id = report["id"]
        # Clear existing items
        await db.execute("DELETE FROM report_items WHERE report_id = ?", (report_id,))
    
    # Insert items per category
    for category in ("completed", "in_progress", "next_action"):
        items = data.getlist(category) if hasattr(data, 'getlist') else data.get(category, [])
        if isinstance(items, str):
            items = [items]
        for i, content in enumerate(items):
            content = content.strip()
            if content:
                await db.execute(
                    "INSERT INTO report_items (report_id, category, content, sort_order) VALUES (?, ?, ?, ?)",
                    (report_id, category, content, i + 1)
                )
    
    # Mark as saved
    await db.execute("UPDATE reports SET saved = 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?", (report_id,))
    await db.commit()
    await db.close()
    
    return JSONResponse({"report_id": report_id})


# ─── WhatsApp Export ──────────────────────────────────────

@app.get("/api/report/{report_id}/whatsapp")
async def get_report_whatsapp(report_id: int, request: Request):
    """Generate WhatsApp-formatted daily report text."""
    payload = await require_auth()(request)
    db = await get_db()
    
    cursor = await db.execute(
        """SELECT r.id, r.report_date, r.updated_at, u.id as user_id, u.name as user_name,
                  d.name as division_name, r.saved
           FROM reports r
           JOIN users u ON r.user_id = u.id
           JOIN divisions d ON u.division_id = d.id
           WHERE r.id = ?""",
        (report_id,)
    )
    report = await cursor.fetchone()
    
    if not report:
        await db.close()
        raise HTTPException(404, "Laporan tidak ditemukan")
    
    # Authorization: owner/admin can view all; others only their own
    if payload["role"] not in ("admin", "owner") and report["user_id"] != payload["user_id"]:
        await db.close()
        raise HTTPException(403, "Forbidden")
    
    # Get items
    cursor = await db.execute(
        "SELECT category, content FROM report_items WHERE report_id = ? ORDER BY sort_order",
        (report_id,)
    )
    items = await cursor.fetchall()
    await db.close()
    
    # Build categorized items
    categorized = {"completed": [], "in_progress": [], "next_action": []}
    for item in items:
        cat = item["category"]
        if cat in categorized:
            categorized[cat].append(item["content"])
    
    # Format date
    try:
        d = datetime.strptime(report["report_date"], "%Y-%m-%d")
        date_str = d.strftime("%d/%m/%Y")
    except (ValueError, TypeError):
        date_str = report["report_date"]
    
    # Check if owner override — if owner is viewing a report NOT theirs, include user name
    owner_override = payload["role"] == "owner" and report["user_id"] != payload["user_id"]
    
    # Build WA text
    wa_text = f"📋 *Daily Report — {report['user_name']}*\n"
    wa_text += f"📅 {date_str} | {report['division_name']}\n\n"
    
    if categorized["completed"]:
        wa_text += "*✅ Completed:*\n"
        for i, item in enumerate(categorized["completed"], 1):
            wa_text += f"{i}. {item}\n"
        wa_text += "\n"
    
    if categorized["in_progress"]:
        wa_text += "*🔄 In Progress:*\n"
        for i, item in enumerate(categorized["in_progress"], 1):
            wa_text += f"{i}. {item}\n"
        wa_text += "\n"
    
    if categorized["next_action"]:
        wa_text += "*📌 Next Action:*\n"
        for i, item in enumerate(categorized["next_action"], 1):
            wa_text += f"{i}. {item}\n"
        wa_text += "\n"
    
    if owner_override:
        wa_text += f"_Laporan oleh: {report['user_name']}_"
    
    return {"text": wa_text.strip()}


# ─── My Reports ───────────────────────────────────────────

@app.get("/my-reports")
async def my_reports_page(request: Request):
    return templates.TemplateResponse(request, "my-reports.html")


@app.get("/api/my-reports")
async def get_my_reports(request: Request, view: str = "list"):
    """Returns user's reports list or a single report detail."""
    payload = await require_auth()(request)
    db = await get_db()
    
    if view != "list" and view.isdigit():
        # Single report detail
        report_id = int(view)
        cursor = await db.execute(
            """SELECT r.id, r.report_date, r.created_at, r.updated_at, u.name as user_name
               FROM reports r JOIN users u ON r.user_id = u.id WHERE r.id = ?""",
            (report_id,)
        )
        report = await cursor.fetchone()
        if not report:
            await db.close()
            raise HTTPException(404, "Report not found")
        
        # Check access
        if payload["role"] not in ("admin", "owner") and payload["user_id"] != report["user_id"]:
            await db.close()
            raise HTTPException(403, "Forbidden")
        
        cursor = await db.execute(
            "SELECT id, category, content FROM report_items WHERE report_id = ? ORDER BY sort_order",
            (report_id,)
        )
        items = await cursor.fetchall()
        await db.close()
        
        categorized = {"completed": [], "in_progress": [], "next_action": []}
        for item in items:
            cat = item["category"]
            if cat in categorized:
                categorized[cat].append({"id": item["id"], "content": item["content"]})
        
        return {
            "report": dict(report),
            "items": categorized,
        }
    else:
        # List reports — filter by user
        if payload["role"] in ("admin", "owner"):
            cursor = await db.execute(
                """SELECT r.id, r.report_date, r.created_at, r.saved, u.name as user_name
                   FROM reports r JOIN users u ON r.user_id = u.id
                   WHERE r.saved = 1
                   ORDER BY r.created_at DESC LIMIT 50"""
            )
        else:
            cursor = await db.execute(
                """SELECT r.id, r.report_date, r.created_at, r.saved, u.name as user_name
                   FROM reports r JOIN users u ON r.user_id = u.id
                   WHERE r.user_id = ? AND r.saved = 1
                   ORDER BY r.created_at DESC LIMIT 50""",
                (payload["user_id"],)
            )
        reports = await cursor.fetchall()
        await db.close()
        return {"reports": [dict(r) for r in reports]}


# ─── HTMX Partials ────────────────────────────────────────

@app.get("/partials/report-items")
async def get_report_items_partial(request: Request):
    """Returns the report items form (HTMX fragment)."""
    payload = await require_auth()(request)
    db = await get_db()
    
    cursor = await db.execute(
        "SELECT id FROM reports WHERE user_id = ? AND saved = 0 ORDER BY created_at DESC LIMIT 1",
        (payload["user_id"],)
    )
    report = await cursor.fetchone()
    items = {"completed": [], "in_progress": [], "next_action": []}
    
    if report:
        cursor = await db.execute(
            "SELECT id, category, content FROM report_items WHERE report_id = ? ORDER BY sort_order",
            (report["id"],)
        )
        for row in await cursor.fetchall():
            cat = row["category"]
            if cat in items:
                items[cat].append({"id": row["id"], "content": row["content"]})
    
    await db.close()
    
    CATEGORY_LABELS = {
        "completed": "✅ Completed",
        "in_progress": "🔄 In Progress",
        "next_action": "📌 Next Action",
    }
    
    html = ""
    for cat_key in ['completed', 'in_progress', 'next_action']:
        html += f'<div class="report-section">'
        html += f'<h3 class="section-title">{CATEGORY_LABELS[cat_key]}</h3>'
        html += f'<div class="item-list" id="items-{cat_key}">'
        for item in items[cat_key]:
            html += f'''
            <div class="report-item" id="item-{item['id']}">
                <span class="item-text">{item['content']}</span>
                <button class="item-del" 
                        hx-post="/partials/delete-item/{item['id']}"
                        hx-target="#item-{item['id']}"
                        hx-swap="delete"
                        hx-confirm="Hapus item ini?"
                        title="Hapus">&#10005;</button>
            </div>'''
        html += '</div>'
        hx_vals = '{{"category":"{}"}}'.format(cat_key)
        html += f'''
        <div class="add-item-line">
            <input type="text" class="input add-item-input" 
                   placeholder="Tambah item..." 
                   name="content" 
                   hx-post="/partials/add-item" hx-vals='{hx_vals}'
                   hx-trigger="keydown[key=='Enter']"
                   hx-target="#items-{cat_key}"
                   hx-swap="beforeend"
                   hx-on::after-request="this.value=''"
                   _="on htmx:afterRequest if event.detail.successful set my value to ''"
            />
            <button class="btn btn-sm btn-secondary" 
                    hx-post="/partials/add-item" hx-vals='{hx_vals}'
                    hx-include="closest .add-item-line find input"
                    hx-target="#items-{cat_key}"
                    hx-swap="beforeend"
                    hx-on::after-request="
                        document.querySelector('#items-{cat_key} .add-item-line input').value=''
                    ">+</button>
        </div>'''
        html += '</div>'
    
    return HTMLResponse(html)


@app.post("/partials/add-item")
async def add_report_item_partial(request: Request):
    """HTMX endpoint -- returns HTML fragment for new item."""
    payload = await require_auth()(request)
    data = await request.form()
    category = data.get("category", "completed")
    content = data.get("content", "").strip()
    
    if not content or category not in ("completed", "in_progress", "next_action"):
        return HTMLResponse("", status_code=400)
    
    db = await get_db()
    
    # Find or create active report
    cursor = await db.execute(
        "SELECT id FROM reports WHERE user_id = ? AND saved = 0 ORDER BY created_at DESC LIMIT 1",
        (payload["user_id"],)
    )
    report = await cursor.fetchone()
    
    if not report:
        today = datetime.utcnow().strftime("%Y-%m-%d")
        cursor = await db.execute(
            "INSERT INTO reports (user_id, report_date) VALUES (?, ?)",
            (payload["user_id"], today)
        )
        await db.commit()
        report_id = cursor.lastrowid
    else:
        report_id = report["id"]
    
    cursor = await db.execute(
        "SELECT COALESCE(MAX(sort_order), 0) + 1 FROM report_items WHERE report_id = ? AND category = ?",
        (report_id, category)
    )
    max_order = await cursor.fetchone()
    sort_order = max_order[0] if max_order else 1
    
    cursor = await db.execute(
        "INSERT INTO report_items (report_id, category, content, sort_order) VALUES (?, ?, ?, ?)",
        (report_id, category, content, sort_order)
    )
    await db.commit()
    item_id = cursor.lastrowid
    
    await db.close()
    
    return HTMLResponse(f'''
        <div class="report-item" id="item-{item_id}">
            <span class="item-text">{content}</span>
            <button class="item-del" 
                    hx-post="/partials/delete-item/{item_id}"
                    hx-target="#item-{item_id}"
                    hx-swap="delete"
                    hx-confirm="Hapus item ini?"
                    title="Hapus">&#10005;</button>
        </div>
    ''')


@app.post("/partials/delete-item/{item_id}")
async def delete_report_item_partial(item_id: int, request: Request):
    """HTMX endpoint -- deletes an item."""
    payload = await require_auth()(request)
    db = await get_db()
    
    # Verify ownership through report chain
    cursor = await db.execute(
        """SELECT r.user_id FROM report_items ri 
           JOIN reports r ON ri.report_id = r.id 
           WHERE ri.id = ?""",
        (item_id,)
    )
    item = await cursor.fetchone()
    
    if not item:
        await db.close()
        return HTMLResponse("", status_code=404)
    
    if payload["role"] not in ("admin", "owner") and item["user_id"] != payload["user_id"]:
        await db.close()
        return HTMLResponse("", status_code=403)
    
    await db.execute("DELETE FROM report_items WHERE id = ?", (item_id,))
    await db.commit()
    await db.close()
    
    return HTMLResponse("")  # hx-swap="delete" removes target


# ─── Admin: Change PIN ────────────────────────────────────

@app.get("/settings")
async def settings_page(request: Request):
    return templates.TemplateResponse(request, "settings.html")


@app.post("/api/change-pin")
async def change_pin(request: Request):
    payload = await require_auth()(request)
    data = await request.form()
    old_pin = data.get("old_pin", "").strip()
    new_pin = data.get("new_pin", "").strip()
    
    if not old_pin or not new_pin:
        return JSONResponse({"error": "PIN lama dan baru harus diisi"}, status_code=400)
    if len(new_pin) < 4:
        return JSONResponse({"error": "PIN baru minimal 4 karakter"}, status_code=400)
    
    db = await get_db()
    cursor = await db.execute("SELECT pin FROM users WHERE id = ?", (payload["user_id"],))
    user = await cursor.fetchone()
    
    if not verify_pin(old_pin, user["pin"]):
        await db.close()
        return JSONResponse({"error": "PIN lama salah"}, status_code=400)
    
    hashed = hash_pin(new_pin)
    await db.execute("UPDATE users SET pin = ? WHERE id = ?", (hashed, payload["user_id"]))
    await db.commit()
    await db.close()
    
    return JSONResponse({"message": "PIN berhasil diubah"})


# ─── Admin: Manage Users ──────────────────────────────────

@app.get("/admin/users")
async def manage_users_page(request: Request):
    return templates.TemplateResponse(request, "admin-users.html")


@app.get("/api/admin/users")
async def get_users(request: Request):
    payload = await require_auth("owner")(request)
    db = await get_db()
    cursor = await db.execute(
        """SELECT u.id, u.name, u.phone, u.role, u.division_id, d.name as division_name
           FROM users u JOIN divisions d ON u.division_id = d.id ORDER BY u.name"""
    )
    users = await cursor.fetchall()
    await db.close()
    return {"users": [dict(u) for u in users]}


@app.post("/api/admin/users")
async def create_user(request: Request):
    payload = await require_auth("owner")(request)
    data = await request.form()
    name = data.get("name", "").strip()
    phone = data.get("phone", "").strip()
    pin = data.get("pin", "1234").strip()
    division_id = data.get("division_id", "").strip()
    role = data.get("role", "operator").strip()
    
    if not name or not phone or not division_id:
        return JSONResponse({"error": "Nama, telepon, dan divisi harus diisi"}, status_code=400)
    if role not in ("operator", "admin", "owner"):
        return JSONResponse({"error": "Role tidak valid"}, status_code=400)
    
    db = await get_db()
    
    # Check duplicate phone
    cursor = await db.execute("SELECT id FROM users WHERE phone = ?", (phone,))
    if await cursor.fetchone():
        await db.close()
        return JSONResponse({"error": "Nomor telepon sudah terdaftar"}, status_code=400)
    
    hashed = hash_pin(pin)
    await db.execute(
        "INSERT INTO users (name, phone, pin, division_id, role) VALUES (?, ?, ?, ?, ?)",
        (name, phone, hashed, int(division_id), role)
    )
    await db.commit()
    await db.close()
    
    return JSONResponse({"message": "User berhasil ditambahkan"})


@app.post("/api/admin/users/{user_id}/reset-pin")
async def reset_user_pin(user_id: int, request: Request):
    payload = await require_auth("owner")(request)
    data = await request.form()
    new_pin = data.get("new_pin", "").strip()
    if not new_pin:
        new_pin = "1234"
    
    db = await get_db()
    hashed = hash_pin(new_pin)
    await db.execute("UPDATE users SET pin = ? WHERE id = ?", (hashed, user_id))
    await db.commit()
    await db.close()
    
    return JSONResponse({"message": f"PIN user berhasil direset ke {new_pin}"})


# ─── Report Admin: View All Reports ───────────────────────

@app.get("/admin/reports")
async def all_reports_page(request: Request):
    return templates.TemplateResponse(request, "admin-reports.html")


@app.get("/api/admin/reports")
async def get_all_reports(request: Request, date: str = ""):
    payload = await require_auth("owner")(request)
    db = await get_db()
    
    if date:
        cursor = await db.execute(
            """SELECT r.id, r.report_date, r.created_at, r.updated_at, u.name as user_name,
                      d.name as division_name
               FROM reports r
               JOIN users u ON r.user_id = u.id
               JOIN divisions d ON u.division_id = d.id
               WHERE r.report_date = ? AND r.saved = 1
               ORDER BY d.name, u.name""",
            (date,)
        )
    else:
        cursor = await db.execute(
            """SELECT r.id, r.report_date, r.created_at, r.updated_at, u.name as user_name,
                      d.name as division_name
               FROM reports r
               JOIN users u ON r.user_id = u.id
               JOIN divisions d ON u.division_id = d.id
               WHERE r.saved = 1
               ORDER BY r.report_date DESC, d.name, u.name
               LIMIT 50"""
        )
    reports = await cursor.fetchall()
    await db.close()
    
    return {"reports": [dict(r) for r in reports]}


# ─── Quick Save ───────────────────────────────────────────

@app.post("/api/quick-save/{report_id}")
async def quick_save_report(report_id: int, request: Request):
    """Quick-save a draft report via HTMX button."""
    payload = await require_auth()(request)
    db = await get_db()
    
    cursor = await db.execute("SELECT user_id, saved FROM reports WHERE id = ?", (report_id,))
    report = await cursor.fetchone()
    
    if not report:
        await db.close()
        raise HTTPException(404, "Report not found")
    
    if payload["role"] not in ("admin", "owner") and report["user_id"] != payload["user_id"]:
        await db.close()
        raise HTTPException(403, "Forbidden")
    
    if report["saved"]:
        await db.close()
        return JSONResponse({"message": "Already saved"})
    
    # Check has items
    cursor = await db.execute("SELECT COUNT(*) FROM report_items WHERE report_id = ?", (report_id,))
    count = await cursor.fetchone()
    if count[0] == 0:
        await db.close()
        return JSONResponse({"error": "Belum ada item"}, status_code=400)
    
    await db.execute("UPDATE reports SET saved = 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?", (report_id,))
    await db.commit()
    await db.close()
    
    return JSONResponse({"message": "Report saved"})


# ─── Dev mode ─────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)
