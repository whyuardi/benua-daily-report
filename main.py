"""
Benua Green Energy — Daily Report Web App
FastAPI + Jinja2 + HTMX
"""
import os
import datetime
import json
from fastapi import FastAPI, Request, Form, HTTPException, Depends, Query
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware

from database import get_db, init_db
from auth import hash_pin, verify_pin, create_token, decode_token

app = FastAPI(title="BGE Daily Report")

# Static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Templates
templates = Jinja2Templates(directory="templates")

# ─── Auth Middleware ──────────────────────────────────────────────

async def get_current_user(request: Request):
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token = auth[7:]
        payload = decode_token(token)
        if payload:
            return payload
    # Also check query param for htmx
    token = request.query_params.get("token")
    if token:
        payload = decode_token(token)
        if payload:
            return payload
    return None

async def require_owner(request: Request):
    user = await get_current_user(request)
    if not user or user.get('role') != 'owner':
        raise HTTPException(status_code=403, detail="Owner only")
    return user

async def require_auth(request: Request):
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return user

# ─── Startup ──────────────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    await init_db()

# ─── API Routes ──────────────────────────────────────────────────

@app.post("/api/login")
async def login(request: Request, phone: str = Form(...), pin: str = Form(...)):
    db = await get_db()
    cursor = await db.execute(
        """SELECT u.id, u.name, u.phone, u.pin, u.role, u.is_active, u.division_id, d.name as division_name
           FROM users u LEFT JOIN divisions d ON u.division_id = d.id
           WHERE u.phone = ?""",
        (phone,)
    )
    user = await cursor.fetchone()
    await db.close()
    
    if not user:
        return JSONResponse(
            status_code=401,
            content={"error": "Nomor HP tidak terdaftar"}
        )
    if not user['is_active']:
        return JSONResponse(
            status_code=401,
            content={"error": "Akun telah dinonaktifkan"}
        )
    if not verify_pin(pin, user['pin']):
        return JSONResponse(
            status_code=401,
            content={"error": "PIN salah"}
        )
    
    token = create_token(user['id'], user['role'], user['phone'])
    return {
        "token": token,
        "user": {
            "id": user['id'],
            "name": user['name'],
            "phone": user['phone'],
            "role": user['role'],
            "division_id": user['division_id'],
            "division_name": user['division_name'],
        }
    }

@app.get("/api/divisions")
async def get_divisions(request: Request):
    user = await require_auth(request)
    db = await get_db()
    cursor = await db.execute("SELECT id, name, created_at FROM divisions ORDER BY name")
    rows = await cursor.fetchall()
    await db.close()
    return [{"id": r['id'], "name": r['name'], "created_at": r['created_at']} for r in rows]

@app.get("/api/users")
async def get_users(request: Request):
    user = await require_owner(request)
    db = await get_db()
    cursor = await db.execute(
        """SELECT u.id, u.name, u.phone, u.role, u.is_active, u.division_id, d.name as division_name, u.created_at
           FROM users u LEFT JOIN divisions d ON u.division_id = d.id
           ORDER BY u.name"""
    )
    rows = await cursor.fetchall()
    await db.close()
    return [{
        "id": r['id'], "name": r['name'], "phone": r['phone'],
        "role": r['role'], "is_active": r['is_active'],
        "division_id": r['division_id'], "division_name": r['division_name'],
        "created_at": r['created_at']
    } for r in rows]

@app.post("/api/users/create")
async def create_user(
    request: Request,
    name: str = Form(...),
    phone: str = Form(...),
    pin: str = Form(...),
    division_id: int = Form(...),
    role: str = Form("karyawan"),
):
    await require_owner(request)
    db = await get_db()
    try:
        hashed = hash_pin(pin)
        cursor = await db.execute(
            "INSERT INTO users (name, phone, pin, division_id, role) VALUES (?, ?, ?, ?, ?)",
            (name, phone, hashed, division_id, role)
        )
        await db.commit()
        user_id = cursor.lastrowid
        await db.close()
        return {"id": user_id, "name": name, "phone": phone, "role": role}
    except Exception as e:
        await db.close()
        raise HTTPException(status_code=400, detail=f"Gagal menambah user: {str(e)}")

@app.post("/api/users/update")
async def update_user(
    request: Request,
    user_id: int = Form(...),
    name: str = Form(...),
    phone: str = Form(...),
    division_id: int = Form(...),
    is_active: int = Form(1),
):
    await require_owner(request)
    db = await get_db()
    try:
        await db.execute(
            "UPDATE users SET name=?, phone=?, division_id=?, is_active=? WHERE id=?",
            (name, phone, division_id, is_active, user_id)
        )
        await db.commit()
        await db.close()
        return {"ok": True}
    except Exception as e:
        await db.close()
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/users/reset-pin")
async def reset_pin(
    request: Request,
    user_id: int = Form(...),
    new_pin: str = Form(...),
):
    await require_owner(request)
    db = await get_db()
    hashed = hash_pin(new_pin)
    await db.execute("UPDATE users SET pin=? WHERE id=?", (hashed, user_id))
    await db.commit()
    await db.close()
    return {"ok": True}

# ─── Division CRUD ───────────────────────────────────────────────

@app.post("/api/divisions/create")
async def create_division(request: Request, name: str = Form(...)):
    await require_owner(request)
    db = await get_db()
    try:
        cursor = await db.execute("INSERT INTO divisions (name) VALUES (?)", (name,))
        await db.commit()
        div_id = cursor.lastrowid
        await db.close()
        return {"id": div_id, "name": name}
    except Exception as e:
        await db.close()
        raise HTTPException(status_code=400, detail=f"Divisi {name} sudah ada")

@app.post("/api/divisions/update")
async def update_division(request: Request, div_id: int = Form(...), name: str = Form(...)):
    await require_owner(request)
    db = await get_db()
    try:
        await db.execute("UPDATE divisions SET name=? WHERE id=?", (name, div_id))
        await db.commit()
        await db.close()
        return {"ok": True}
    except Exception as e:
        await db.close()
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/divisions/delete")
async def delete_division(request: Request, div_id: int = Form(...)):
    await require_owner(request)
    db = await get_db()
    # Check if division has users
    cursor = await db.execute("SELECT COUNT(*) as c FROM users WHERE division_id=?", (div_id,))
    count = await cursor.fetchone()
    if count and count['c'] > 0:
        await db.close()
        raise HTTPException(status_code=400, detail="Tidak bisa hapus divisi yang masih memiliki karyawan")
    
    await db.execute("DELETE FROM divisions WHERE id=?", (div_id,))
    await db.commit()
    await db.close()
    return {"ok": True}

# ─── Report API ──────────────────────────────────────────────────

@app.get("/api/report/today")
async def get_today_report(request: Request):
    user = await require_auth(request)
    today = datetime.date.today().isoformat()
    db = await get_db()
    cursor = await db.execute(
        """SELECT r.id, r.report_date, r.created_at, r.updated_at
           FROM reports r WHERE r.user_id = ? AND r.report_date = ?""",
        (user['user_id'], today)
    )
    report = await cursor.fetchone()
    if not report:
        await db.close()
        return {"report": None}
    
    cur = await db.execute(
        "SELECT id, category, content, sort_order FROM report_items WHERE report_id=? ORDER BY category, sort_order",
        (report['id'],)
    )
    items = await cur.fetchall()
    await db.close()
    
    return {
        "report": {
            "id": report['id'],
            "report_date": report['report_date'],
            "created_at": report['created_at'],
            "updated_at": report['updated_at'],
            "items": [{"id": i['id'], "category": i['category'], "content": i['content'], "sort_order": i['sort_order']} for i in items]
        }
    }

@app.post("/api/report/save")
async def save_report(request: Request):
    user = await require_auth(request)
    today = datetime.date.today().isoformat()
    db = await get_db()
    
    # Upsert report
    cursor = await db.execute(
        "SELECT id FROM reports WHERE user_id=? AND report_date=?",
        (user['user_id'], today)
    )
    report = await cursor.fetchone()
    
    if report:
        report_id = report['id']
        await db.execute(
            "UPDATE reports SET updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (report_id,)
        )
        # Delete existing items — we'll re-insert
        await db.execute("DELETE FROM report_items WHERE report_id=?", (report_id,))
    else:
        cursor = await db.execute(
            "INSERT INTO reports (user_id, report_date) VALUES (?, ?)",
            (user['user_id'], today)
        )
        report_id = cursor.lastrowid
    
    # Parse items from form
    completed = request.query_params.getlist('completed[]')
    in_progress = request.query_params.getlist('in_progress[]')
    next_action = request.query_params.getlist('next_action[]')
    
    # Try form data if query params empty
    if not any([completed, in_progress, next_action]):
        form = await request.form()
        completed = form.getlist('completed[]')
        in_progress = form.getlist('in_progress[]')
        next_action = form.getlist('next_action[]')
    
    all_items = []
    for i, content in enumerate(completed):
        all_items.append(('completed', content, i))
    for i, content in enumerate(in_progress):
        all_items.append(('in_progress', content, i))
    for i, content in enumerate(next_action):
        all_items.append(('next_action', content, i))
    
    for cat, content, order in all_items:
        await db.execute(
            "INSERT INTO report_items (report_id, category, content, sort_order) VALUES (?, ?, ?, ?)",
            (report_id, cat, content.strip(), order)
        )
    
    await db.commit()
    await db.close()
    return {"ok": True, "report_id": report_id}

@app.post("/api/report/add-item")
async def add_report_item(request: Request):
    user = await require_auth(request)
    today = datetime.date.today().isoformat()
    
    form = await request.form()
    category = form.get('category', 'completed')
    content = form.get('content', '').strip()
    
    if not content:
        raise HTTPException(status_code=400, detail="Item tidak boleh kosong")
    
    db = await get_db()
    
    # Get or create today's report
    cursor = await db.execute(
        "SELECT id FROM reports WHERE user_id=? AND report_date=?",
        (user['user_id'], today)
    )
    report = await cursor.fetchone()
    
    if report:
        report_id = report['id']
    else:
        cursor = await db.execute(
            "INSERT INTO reports (user_id, report_date) VALUES (?, ?)",
            (user['user_id'], today)
        )
        report_id = cursor.lastrowid
    
    # Get max sort_order for this category
    cursor = await db.execute(
        "SELECT COALESCE(MAX(sort_order), -1) + 1 as next FROM report_items WHERE report_id=? AND category=?",
        (report_id, category)
    )
    next_order = await cursor.fetchone()
    sort_order = next_order['next'] if next_order else 0
    
    cursor = await db.execute(
        "INSERT INTO report_items (report_id, category, content, sort_order) VALUES (?, ?, ?, ?)",
        (report_id, category, content, sort_order)
    )
    item_id = cursor.lastrowid
    await db.commit()
    await db.close()
    
    return {"id": item_id, "category": category, "content": content, "sort_order": sort_order}

@app.post("/api/report/delete-item/{item_id}")
async def delete_report_item(item_id: int, request: Request):
    user = await require_auth(request)
    db = await get_db()
    
    # Verify item belongs to user's report
    cursor = await db.execute(
        """SELECT ri.id FROM report_items ri
           JOIN reports r ON ri.report_id = r.id
           WHERE ri.id = ? AND r.user_id = ?""",
        (item_id, user['user_id'])
    )
    if not await cursor.fetchone():
        await db.close()
        raise HTTPException(status_code=404, detail="Item not found")
    
    await db.execute("DELETE FROM report_items WHERE id=?", (item_id,))
    await db.commit()
    await db.close()
    return {"ok": True}

@app.get("/api/report/{report_id}/whatsapp")
async def get_whatsapp_format(report_id: int, request: Request):
    user = await require_auth(request)
    db = await get_db()
    
    cursor = await db.execute(
        """SELECT r.id, r.report_date, u.name, d.name as division_name
           FROM reports r
           JOIN users u ON r.user_id = u.id
           LEFT JOIN divisions d ON u.division_id = d.id
           WHERE r.id = ? AND r.user_id = ?""",
        (report_id, user['user_id'])
    )
    report = await cursor.fetchone()
    if not report:
        await db.close()
        raise HTTPException(status_code=404, detail="Report not found")
    
    cursor = await db.execute(
        "SELECT category, content FROM report_items WHERE report_id=? ORDER BY category, sort_order",
        (report_id,)
    )
    items = await cursor.fetchall()
    await db.close()
    
    # Format WhatsApp message
    date_formatted = datetime.datetime.strptime(report['report_date'], '%Y-%m-%d').strftime('%d/%m/%Y')
    lines = [
        f"📋 *Daily Report — {report['name']}*",
        f"📅 {date_formatted} | {report['division_name'] or '-'}",
        ""
    ]
    
    categories = {
        'completed': '✅ Completed',
        'in_progress': '🔄 In Progress',
        'next_action': '📋 Next Action',
    }
    
    for cat, label in categories.items():
        cat_items = [i for i in items if i['category'] == cat]
        if cat_items:
            lines.append(f"*{label}:*")
            for i, item in enumerate(cat_items, 1):
                lines.append(f"  {i}. {item['content']}")
            lines.append("")
    
    lines.append("_" + "─" * 25 + "_")
    
    return {"text": "\n".join(lines).strip()}

# ─── Dashboard API ───────────────────────────────────────────────

@app.get("/api/dashboard/today")
async def get_dashboard_today(
    request: Request,
    division_id: int | None = Query(None),
    date: str | None = Query(None),
):
    await require_owner(request)
    target_date = date or datetime.date.today().isoformat()
    
    db = await get_db()
    
    # All active users grouped by division
    cursor = await db.execute(
        """SELECT u.id, u.name, d.name as division_name, d.id as division_id
           FROM users u LEFT JOIN divisions d ON u.division_id = d.id
           WHERE u.is_active = 1
           ORDER BY d.name, u.name"""
    )
    all_users = await cursor.fetchall()
    
    # Reports for today
    query = """
        SELECT r.id, r.report_date, r.updated_at, u.id as user_id, u.name as user_name,
               d.name as division_name
        FROM reports r
        JOIN users u ON r.user_id = u.id
        LEFT JOIN divisions d ON u.division_id = d.id
        WHERE r.report_date = ?
    """
    params = [target_date]
    if division_id:
        query += " AND u.division_id = ?"
        params.append(division_id)
    query += " ORDER BY d.name, u.name"
    
    cursor = await db.execute(query, params)
    reports_data = await cursor.fetchall()
    
    # Get items for reports
    report_ids = [r['id'] for r in reports_data]
    items_by_report = {}
    if report_ids:
        placeholders = ','.join('?' * len(report_ids))
        cursor = await db.execute(
            f"SELECT report_id, category, content FROM report_items WHERE report_id IN ({placeholders}) ORDER BY sort_order",
            report_ids
        )
        all_items = await cursor.fetchall()
        for item in all_items:
            rid = item['report_id']
            if rid not in items_by_report:
                items_by_report[rid] = {'completed': [], 'in_progress': [], 'next_action': []}
            cat = item['category']
            if cat in items_by_report[rid]:
                items_by_report[rid][cat].append(item['content'])
    
    # Build response
    reports = []
    submitted_user_ids = set()
    for r in reports_data:
        submitted_user_ids.add(r['user_id'])
        report_items = items_by_report.get(r['id'], {})
        reports.append({
            "report_id": r['id'],
            "user_id": r['user_id'],
            "user_name": r['user_name'],
            "division_name": r['division_name'],
            "report_date": r['report_date'],
            "updated_at": r['updated_at'],
            "items": report_items,
        })
    
    # Missing users
    missing = [u for u in all_users if u['id'] not in submitted_user_ids]
    
    # Stats
    total_users = len(all_users)
    submitted_count = len(submitted_user_ids)
    missing_count = total_users - submitted_count
    
    await db.close()
    
    return {
        "date": target_date,
        "total_users": total_users,
        "submitted": submitted_count,
        "missing_count": missing_count,
        "reports": reports,
        "missing_users": [{"id": u['id'], "name": u['name'], "division": u['division_name']} for u in missing],
    }

@app.get("/api/my-reports")
async def get_my_reports(request: Request, limit: int = 50, offset: int = 0):
    user = await require_auth(request)
    db = await get_db()
    cursor = await db.execute(
        """SELECT r.id, r.report_date, r.created_at, r.updated_at,
                  (SELECT COUNT(*) FROM report_items WHERE report_id = r.id) as item_count
           FROM reports r
           WHERE r.user_id = ?
           ORDER BY r.report_date DESC
           LIMIT ? OFFSET ?""",
        (user['user_id'], limit, offset)
    )
    rows = await cursor.fetchall()
    await db.close()
    return [{
        "id": r['id'], "report_date": r['report_date'],
        "created_at": r['created_at'], "updated_at": r['updated_at'],
        "item_count": r['item_count']
    } for r in rows]

@app.get("/api/my-reports/{report_id}")
async def get_my_report_detail(report_id: int, request: Request):
    user = await require_auth(request)
    db = await get_db()
    cursor = await db.execute(
        """SELECT r.id, r.report_date, r.created_at, r.updated_at
           FROM reports r WHERE r.id = ? AND r.user_id = ?""",
        (report_id, user['user_id'])
    )
    report = await cursor.fetchone()
    if not report:
        # Check if owner (owner can see all)
        if user['role'] == 'owner':
            cursor = await db.execute(
                "SELECT r.id, r.report_date, r.created_at, r.updated_at, u.name as user_name FROM reports r JOIN users u ON r.user_id=u.id WHERE r.id=?",
                (report_id,)
            )
            report = await cursor.fetchone()
    if not report:
        await db.close()
        raise HTTPException(status_code=404, detail="Report not found")
    
    cursor = await db.execute(
        "SELECT id, category, content, sort_order FROM report_items WHERE report_id=? ORDER BY category, sort_order",
        (report_id,)
    )
    items = await cursor.fetchall()
    await db.close()
    
    return {
        "id": report['id'],
        "report_date": report['report_date'],
        "created_at": report['created_at'],
        "updated_at": report['updated_at'],
        "user_name": report.get('user_name'),
        "items": [{"id": i['id'], "category": i['category'], "content": i['content'], "sort_order": i['sort_order']} for i in items]
    }

# ─── Page Routes ─────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {"request": request})

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    return templates.TemplateResponse(request, "dashboard.html", {"request": request})

@app.get("/report", response_class=HTMLResponse)
async def report_page(request: Request):
    return templates.TemplateResponse(request, "report.html", {"request": request})

@app.get("/my-reports", response_class=HTMLResponse)
async def my_reports_page(request: Request):
    return templates.TemplateResponse(request, "my_reports.html", {"request": request})

@app.get("/manage-users", response_class=HTMLResponse)
async def manage_users_page(request: Request):
    return templates.TemplateResponse(request, "manage_users.html", {"request": request})

@app.get("/manage-divisions", response_class=HTMLResponse)
async def manage_divisions_page(request: Request):
    return templates.TemplateResponse(request, "manage_divisions.html", {"request": request})

@app.get("/missing-reports", response_class=HTMLResponse)
async def missing_reports_page(request: Request):
    return templates.TemplateResponse(request, "missing_reports.html", {"request": request})

# ─── HTMX Partial Routes ─────────────────────────────────────────

@app.get("/partials/report-items")
async def get_report_items_partial(request: Request):
    user = await require_auth(request)
    today = datetime.date.today().isoformat()
    db = await get_db()
    
    cursor = await db.execute(
        "SELECT id FROM reports WHERE user_id=? AND report_date=?",
        (user['user_id'], today)
    )
    report = await cursor.fetchone()
    items = {'completed': [], 'in_progress': [], 'next_action': []}
    report_id = None
    
    if report:
        report_id = report['id']
        cursor = await db.execute(
            "SELECT id, category, content, sort_order FROM report_items WHERE report_id=? ORDER BY sort_order",
            (report_id,)
        )
        rows = await cursor.fetchall()
        for r in rows:
            items[r['category']].append(r)
    
    await db.close()
    
    html = ""
    categories = [
        ('completed', 'Completed'),
        ('in_progress', 'In Progress'),
        ('next_action', 'Next Action'),
    ]
    dots = {'completed': 'green', 'in_progress': 'yellow', 'next_action': 'dim'}
    
    for cat_key, cat_label in categories:
        dot_cls = dots[cat_key]
        html += f'<div class="report-section" data-category="{cat_key}">'
        html += f'<div class="report-section-title">'
        html += f'<span class="dot {dot_cls}"></span> {cat_label}'
        html += f'</div>'
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
        html += f'''
        <div class="add-item-line">
            <input type="text" class="input add-item-input" 
                   placeholder="Tambah item..." 
                   name="content" 
                   hx-post="/partials/add-item" hx-vars='{{"category":"{cat_key}"}}'
                   hx-trigger="keydown[key=="Enter"]"
                   hx-target="#items-{cat_key}"
                   hx-swap="beforeend"
                   hx-on::after-request="this.value=''"
                   _="on htmx:afterRequest if event.detail.successful set my value to ''"
            />
            <button class="btn btn-sm btn-secondary" 
                    hx-post="/partials/add-item" hx-vars='{{"category":"{cat_key}"}}'
                    hx-include="closest .add-item-row find input"
                    hx-target="#items-{cat_key}"
                    hx-swap="beforeend"
                    hx-on::after-request="
                        document.querySelector('#items-{cat_key} .add-item-row input').value=''
                    ">+</button>
        </div>'''
        html += '</div>'
    
    return HTMLResponse(html)

# ─── HTMX Add Item ───────────────────────────────────────────────

@app.post("/partials/add-item")
async def add_report_item_partial(request: Request):
    """HTMX endpoint -- returns HTML fragment for new item"""
    user = await require_auth(request)
    today = datetime.date.today().isoformat()
    
    form = await request.form()
    category = form.get('category', 'completed')
    content = form.get('content', '').strip()
    
    if not content:
        return HTMLResponse("")
    
    db = await get_db()
    
    cursor = await db.execute(
        "SELECT id FROM reports WHERE user_id=? AND report_date=?",
        (user['user_id'], today)
    )
    report = await cursor.fetchone()
    
    if report:
        report_id = report['id']
    else:
        cursor = await db.execute(
            "INSERT INTO reports (user_id, report_date) VALUES (?, ?)",
            (user['user_id'], today)
        )
        report_id = cursor.lastrowid
    
    cursor = await db.execute(
        "SELECT COALESCE(MAX(sort_order), -1) + 1 as next FROM report_items WHERE report_id=? AND category=?",
        (report_id, category)
    )
    next_order = await cursor.fetchone()
    sort_order = next_order['next'] if next_order else 0
    
    cursor = await db.execute(
        "INSERT INTO report_items (report_id, category, content, sort_order) VALUES (?, ?, ?, ?)",
        (report_id, category, content, sort_order)
    )
    item_id = cursor.lastrowid
    await db.commit()
    await db.close()
    
    escaped = content.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
    
    html = '<div class="report-item" id="item-' + str(item_id) + '">'
    html += '    <span class="item-text">' + escaped + '</span>'
    html += '    <button class="item-del" hx-post="/partials/delete-item/' + str(item_id) + '"'
    html += '            hx-target="#item-' + str(item_id) + '" hx-swap="delete"'
    html += '            hx-confirm="Hapus item ini?" title="Hapus">&#10005;</button>'
    html += '</div>'
    
    return HTMLResponse(html)


@app.post("/partials/delete-item/{item_id}")
async def delete_report_item_partial(item_id: int, request: Request):
    """HTMX endpoint -- deletes item and returns empty (swap=delete)"""
    user = await require_auth(request)
    db = await get_db()
    cursor = await db.execute(
        """SELECT ri.id FROM report_items ri
           JOIN reports r ON ri.report_id = r.id
           WHERE ri.id = ? AND r.user_id = ?""",
        (item_id, user['user_id'])
    )
    if await cursor.fetchone():
        await db.execute("DELETE FROM report_items WHERE id=?", (item_id,))
        await db.commit()
    await db.close()
    return HTMLResponse("")



# ─── Run ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)