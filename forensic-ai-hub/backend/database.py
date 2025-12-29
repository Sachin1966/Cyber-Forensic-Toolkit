import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), 'database.db')

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            total_scans INTEGER DEFAULT 0,
            total_phishing INTEGER DEFAULT 0,
            total_malware INTEGER DEFAULT 0,
            total_network_attacks INTEGER DEFAULT 0,
            total_email_spam INTEGER DEFAULT 0
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS scan_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_type TEXT NOT NULL,
            input_summary TEXT,
            prediction TEXT,
            confidence REAL,
            is_threat BOOLEAN,
            details TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            name TEXT,
            picture TEXT,
            google_id TEXT UNIQUE,
            password_hash TEXT,
            alert_preferences TEXT,
            theme_preference TEXT DEFAULT 'system',
            show_badges BOOLEAN DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Migration: Add password_hash column if it doesn't exist
    try:
        c.execute('ALTER TABLE users ADD COLUMN password_hash TEXT')
    except sqlite3.OperationalError:
        pass # Column likely already exists

    # Migration: Add alert_preferences column if it doesn't exist
    try:
        c.execute('ALTER TABLE users ADD COLUMN alert_preferences TEXT')
    except sqlite3.OperationalError:
        pass

    # Migration: Add theme_preference column if it doesn't exist
    try:
        c.execute("ALTER TABLE users ADD COLUMN theme_preference TEXT DEFAULT 'system'")
    except sqlite3.OperationalError:
        pass

    # Migration: Add show_badges column if it doesn't exist
    try:
        c.execute('ALTER TABLE users ADD COLUMN show_badges BOOLEAN DEFAULT 1')
    except sqlite3.OperationalError:
        pass

    # Migration: Add details column if it doesn't exist (for existing DBs)
    try:
        c.execute('ALTER TABLE scan_logs ADD COLUMN details TEXT')
    except sqlite3.OperationalError:
        pass # Column likely already exists
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_email TEXT,
            title TEXT,
            message TEXT,
            report_id INTEGER,
            is_read BOOLEAN DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (report_id) REFERENCES scan_logs(id)
        )
    ''')

    # Migration: Add notifications table (handled by CREATE TABLE IF NOT EXISTS)

    # Initialize with 0 if empty
    c.execute('SELECT count(*) FROM stats')
    if c.fetchone()[0] == 0:
        c.execute('INSERT INTO stats (total_scans, total_phishing, total_malware, total_network_attacks, total_email_spam) VALUES (0, 0, 0, 0, 0)')
    
    conn.commit()
    conn.close()

def log_notification(user_email, title, message, report_id=None):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        INSERT INTO notifications (user_email, title, message, report_id)
        VALUES (?, ?, ?, ?)
    ''', (user_email, title, message, report_id))
    conn.commit()
    conn.close()

def get_unread_notifications(user_email=None, limit=20):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    if user_email:
        c.execute('''
            SELECT * FROM notifications 
            WHERE user_email = ? AND is_read = 0 
            ORDER BY created_at DESC LIMIT ?
        ''', (user_email, limit))
    else:
         # Fallback or admin view (optional)
        c.execute('SELECT * FROM notifications WHERE is_read = 0 ORDER BY created_at DESC LIMIT ?', (limit,))
        
    rows = c.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def mark_notification_read(notification_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('UPDATE notifications SET is_read = 1 WHERE id = ?', (notification_id,))
    conn.commit()
    conn.close()

def get_stats():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    # Get totals
    c.execute('SELECT * FROM stats ORDER BY id DESC LIMIT 1')
    row = c.fetchone()
    stats = dict(row) if row else {
        'total_scans': 0,
        'total_phishing': 0,
        'total_malware': 0,
        'total_network_attacks': 0,
        'total_email_spam': 0
    }
    
    # Get trend data (last 7 days)
    c.execute('''
        SELECT 
            date(timestamp) as date, 
            SUM(CASE WHEN is_threat = 1 THEN 1 ELSE 0 END) as threat_count,
            SUM(CASE WHEN is_threat = 0 THEN 1 ELSE 0 END) as safe_count
        FROM scan_logs 
        GROUP BY date(timestamp) 
        ORDER BY date(timestamp) DESC 
        LIMIT 7
    ''')
    trends = c.fetchall()
    stats['threat_trend'] = [dict(t) for t in trends]
    
    conn.close()
    return stats

def update_stats(scan_type, is_threat=False):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Always increment total scans
    c.execute('UPDATE stats SET total_scans = total_scans + 1')
    
    if is_threat:
        if scan_type == 'phishing' or scan_type == 'url':
            c.execute('UPDATE stats SET total_phishing = total_phishing + 1')
        elif scan_type == 'malware' or scan_type == 'file':
            c.execute('UPDATE stats SET total_malware = total_malware + 1')
        elif scan_type == 'network' or scan_type == 'pcap':
            c.execute('UPDATE stats SET total_network_attacks = total_network_attacks + 1')
        elif scan_type == 'email':
            c.execute('UPDATE stats SET total_email_spam = total_email_spam + 1')
            
    conn.commit()
    conn.close()

def log_scan(scan_type, input_summary, prediction, confidence, is_threat, details=None):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    import json
    details_json = json.dumps(details) if details else None
    
    c.execute('''
        INSERT INTO scan_logs (scan_type, input_summary, prediction, confidence, is_threat, details)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (scan_type, input_summary, prediction, confidence, is_threat, details_json))
    conn.commit()
    scan_id = c.lastrowid
    conn.close()
    return scan_id


def get_recent_activity(limit=10):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('''
        SELECT * FROM scan_logs 
        ORDER BY timestamp DESC 
        LIMIT ?
    ''', (limit,))
    rows = c.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_reports(search_query=None, type_filter=None, start_date=None, end_date=None):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    query = "SELECT * FROM scan_logs WHERE 1=1"
    params = []
    
    if search_query:
        query += " AND (input_summary LIKE ? OR id LIKE ? OR scan_type LIKE ?)"
        params.extend([f'%{search_query}%', f'%{search_query}%', f'%{search_query}%'])
        
    if type_filter and type_filter != 'all':
        query += " AND scan_type = ?"
        params.append(type_filter)
        
    if start_date:
        query += " AND date(timestamp) >= date(?)"
        params.append(start_date)
        
    if end_date:
        query += " AND date(timestamp) <= date(?)"
        params.append(end_date)
        
    query += " ORDER BY timestamp DESC"
    
    c.execute(query, params)
    rows = c.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_report_by_id(report_id):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    c.execute("SELECT * FROM scan_logs WHERE id = ?", (report_id,))
    row = c.fetchone()
    conn.close()
    
    if row:
        return dict(row)
    return None

def create_user(email, name, picture, google_id=None, password_hash=None):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute('''
            INSERT INTO users (email, name, picture, google_id, password_hash)
            VALUES (?, ?, ?, ?, ?)
        ''', (email, name, picture, google_id, password_hash))
        conn.commit()
        user_id = c.lastrowid
    except sqlite3.IntegrityError:
        # User might already exist, update them
        # If google_id is provided, update it. If password_hash is provided, update it.
        # This logic is a bit complex for a simple update, let's just update fields if they are not None
        
        # Construct update query dynamically or just update all nullable fields if provided
        # For simplicity in this context, we assume we are either linking google or setting password
        
        update_fields = []
        params = []
        if name:
            update_fields.append("name = ?")
            params.append(name)
        if picture:
            update_fields.append("picture = ?")
            params.append(picture)
        if google_id:
            update_fields.append("google_id = ?")
            params.append(google_id)
        if password_hash:
            update_fields.append("password_hash = ?")
            params.append(password_hash)
            
        params.append(email)
        
        if update_fields:
            query = f"UPDATE users SET {', '.join(update_fields)} WHERE email = ?"
            c.execute(query, params)
            conn.commit()
            
        c.execute('SELECT id FROM users WHERE email = ?', (email,))
        row = c.fetchone()
        user_id = row[0] if row else None
    finally:
        conn.close()
    return user_id

def get_user_by_email(email):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE email = ?', (email,))
    row = c.fetchone()
    conn.close()
    if row:
        return dict(row)
    return None

def update_user_settings(email, name=None, alert_preferences=None, theme_preference=None, show_badges=None, password_hash=None):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    update_fields = []
    params = []
    
    if name is not None:
        update_fields.append("name = ?")
        params.append(name)
        
    if alert_preferences is not None:
        update_fields.append("alert_preferences = ?")
        params.append(alert_preferences)
        
    if theme_preference is not None:
        update_fields.append("theme_preference = ?")
        params.append(theme_preference)
        
    if show_badges is not None:
        update_fields.append("show_badges = ?")
        params.append(show_badges)

    if password_hash is not None:
        update_fields.append("password_hash = ?")
        params.append(password_hash)
        
    if not update_fields:
        conn.close()
        return False
        
    params.append(email)
    
    try:
        query = f"UPDATE users SET {', '.join(update_fields)} WHERE email = ?"
        c.execute(query, params)
        conn.commit()
        success = c.rowcount > 0
    except Exception as e:
        print(f"Update failed: {e}")
        success = False
    finally:
        conn.close()
        
    return success

def delete_user(email):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute('DELETE FROM users WHERE email = ?', (email,))
        conn.commit()
        success = c.rowcount > 0
    except Exception as e:
        print(f"Delete failed: {e}")
        success = False
    finally:
        conn.close()
    return success
