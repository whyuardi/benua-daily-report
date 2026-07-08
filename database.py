"""
Benua Green Energy — Daily Report Database
SQLite via aiosqlite with seed data
"""
import aiosqlite
import os
from passlib.hash import bcrypt

DB_PATH = os.path.join(os.path.dirname(__file__), 'database.db')

async def get_db():
    db = await aiosqlite.connect(DB_PATH)
    db.row_factory = aiosqlite.Row
    await db.execute("PRAGMA journal_mode=WAL")
    await db.execute("PRAGMA foreign_keys=ON")
    return db

async def init_db():
    db = await get_db()
    
    # Create tables
    await db.executescript("""
        CREATE TABLE IF NOT EXISTS divisions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            phone TEXT UNIQUE NOT NULL,
            pin TEXT NOT NULL,
            division_id INTEGER,
            role TEXT NOT NULL DEFAULT 'karyawan' CHECK(role IN ('owner', 'karyawan')),
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (division_id) REFERENCES divisions(id)
        );
        
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            report_date DATE NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, report_date),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        
        CREATE TABLE IF NOT EXISTS report_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id INTEGER NOT NULL,
            category TEXT NOT NULL CHECK(category IN ('completed', 'in_progress', 'next_action')),
            content TEXT NOT NULL,
            sort_order INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (report_id) REFERENCES reports(id) ON DELETE CASCADE
        );
    """)
    
    # Seed divisions
    divisions = [
        'Operation & Service',
        'Engineering',
        'Admin & HR',
        'Finance',
        'Marketing',
        'Management',
    ]
    for name in divisions:
        await db.execute(
            "INSERT OR IGNORE INTO divisions (name) VALUES (?)",
            (name,)
        )
    
    # Get management division id
    cursor = await db.execute("SELECT id FROM divisions WHERE name = 'Management'")
    row = await cursor.fetchone()
    mgmt_id = row['id'] if row else 1
    
    # Seed owner
    hashed_pin = bcrypt.hash('1234')
    await db.execute(
        """INSERT OR IGNORE INTO users (name, phone, pin, division_id, role)
           VALUES (?, ?, ?, ?, ?)""",
        ('Admin BGE', '0000', hashed_pin, mgmt_id, 'owner')
    )
    
    # Seed sample karyawan
    sample_users = [
        ('Bowo', '0811', '1234', 'Operation & Service'),
        ('Sari', '0812', '1234', 'Engineering'),
        ('Dewi', '0813', '1234', 'Admin & HR'),
    ]
    for name, phone, pin, div_name in sample_users:
        cur = await db.execute("SELECT id FROM divisions WHERE name = ?", (div_name,))
        div_row = await cur.fetchone()
        if div_row:
            hashed = bcrypt.hash(pin)
            await db.execute(
                """INSERT OR IGNORE INTO users (name, phone, pin, division_id, role)
                   VALUES (?, ?, ?, ?, 'karyawan')""",
                (name, phone, hashed, div_row['id'])
            )
    
    # Seed sample reports for today
    import datetime
    today = datetime.date.today().isoformat()
    
    cursor = await db.execute("SELECT id, name FROM users WHERE role='owner'")
    owner = await cursor.fetchone()
    if owner:
        # Check if report already exists
        cur = await db.execute(
            "SELECT id FROM reports WHERE user_id=? AND report_date=?",
            (owner['id'], today)
        )
        if not await cur.fetchone():
            ins_cur = await db.execute(
                "INSERT INTO reports (user_id, report_date) VALUES (?, ?)",
                (owner['id'], today)
            )
            report_id = ins_cur.lastrowid
            items = [
                ('completed', 'Survei lokasi tanah kantor', 1),
                ('completed', 'Setup Database app Operation and Service', 2),
                ('in_progress', 'Menunggu review HRIS', 1),
                ('next_action', 'Integrasi database dan build app', 1),
            ]
            for cat, content, order in items:
                await db.execute(
                    "INSERT INTO report_items (report_id, category, content, sort_order) VALUES (?, ?, ?, ?)",
                    (report_id, cat, content, order)
                )
    
    # Seed sample karyawan reports
    cur = await db.execute("SELECT id FROM users WHERE role='karyawan' LIMIT 1")
    karyawan = await cur.fetchone()
    if karyawan:
        cur = await db.execute(
            "SELECT id FROM reports WHERE user_id=? AND report_date=?",
            (karyawan['id'], today)
        )
        if not await cur.fetchone():
            ins_cur = await db.execute(
                "INSERT INTO reports (user_id, report_date) VALUES (?, ?)",
                (karyawan['id'], today)
            )
            report_id = ins_cur.lastrowid
            items = [
                ('completed', 'Menyelesaikan wiring panel SDP', 1),
                ('in_progress', 'Persiapan dokumen tender proyek ABC', 1),
                ('next_action', 'Koordinasi dengan tim procurement', 1),
            ]
            for cat, content, order in items:
                await db.execute(
                    "INSERT INTO report_items (report_id, category, content, sort_order) VALUES (?, ?, ?, ?)",
                    (report_id, cat, content, order)
                )
    
    await db.commit()
    await db.close()
    print(f"Database initialized at {DB_PATH}")