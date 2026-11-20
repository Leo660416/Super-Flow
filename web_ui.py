import os
import sys
import sqlite3
import json
import socket
import ssl
import urllib.request
import urllib.parse
import urllib.error
import threading
import clickhouse_connect
import ipaddress
import time
import hashlib
import secrets
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo
from concurrent.futures import ThreadPoolExecutor
from typing import Optional, List, Dict, Any, Iterable, Tuple
from fastapi import FastAPI, Query, HTTPException, Request, Response, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

# Standard Taiwan Timezone (UTC+8)
TW_TZ = ZoneInfo("Asia/Taipei")

def now_tw() -> datetime:
    """Return current timezone-aware datetime in Asia/Taipei."""
    return datetime.now(TW_TZ)

def now_tw_str() -> str:
    """Return current datetime string in Asia/Taipei formatted as YYYY-MM-DD HH:MM:SS."""
    return now_tw().strftime("%Y-%m-%d %H:%M:%S")

def parse_tw_datetime(dt_str: str) -> datetime:
    """Parse datetime string and ensure it is timezone-aware in Asia/Taipei."""
    if not dt_str:
        return now_tw()
    clean_str = str(dt_str).strip().replace("T", " ")
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(clean_str, fmt)
            return dt.replace(tzinfo=TW_TZ)
        except ValueError:
            continue
    try:
        dt = datetime.fromisoformat(clean_str)
        if dt.tzinfo is None:
            return dt.replace(tzinfo=TW_TZ)
        return dt.astimezone(TW_TZ)
    except Exception:
        return now_tw()

app = FastAPI(title="Netflow Collector Web UI")

DB_PATH = os.getenv("SQLITE_DB_PATH", "flows.db")

# ---------------- Authentication Utilities ----------------
session_cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}
session_cache_lock = threading.Lock()
SESSION_CACHE_TTL = 60.0  # 60 seconds in-memory cache

def invalidate_session_cache(token: Optional[str] = None, user_id: Optional[int] = None):
    with session_cache_lock:
        if token is not None:
            session_cache.pop(token, None)
        elif user_id is not None:
            to_remove = [t for t, (_, u) in session_cache.items() if u.get("id") == user_id]
            for t in to_remove:
                session_cache.pop(t, None)
        else:
            session_cache.clear()

def hash_password(password: str, salt: str) -> str:
    """Hash password using PBKDF2 HMAC SHA-256."""
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000).hex()

def verify_session_token(token: str) -> Optional[Dict[str, Any]]:
    """Verify session token from cache or SQLite. Returns user dict if valid and unexpired."""
    if not token:
        return None
    now_mono = time.monotonic()
    with session_cache_lock:
        cached = session_cache.get(token)
        if cached and (now_mono - cached[0]) < SESSION_CACHE_TTL:
            return cached[1]

    try:
        conn = sqlite3.connect(DB_PATH, timeout=30.0)
        cur = conn.cursor()
        cur.execute("""
            SELECT s.token, s.user_id, s.username, s.role, s.expires_at, u.is_active, u.must_change_password
            FROM user_sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.token = ?
        """, (token,))
        row = cur.fetchone()
        conn.close()
        if not row:
            invalidate_session_cache(token=token)
            return None
        
        token_str, user_id, username, role, expires_at_str, is_active, must_change_password = row
        if not is_active:
            invalidate_session_cache(token=token)
            return None
            
        expires_at = parse_tw_datetime(expires_at_str)
        if now_tw() > expires_at:
            delete_session(token)
            return None
            
        user_dict = {
            "id": user_id,
            "username": username,
            "role": role,
            "must_change_password": bool(must_change_password)
        }
        with session_cache_lock:
            if len(session_cache) > 1000:
                session_cache.clear()
            session_cache[token] = (now_mono, user_dict)
        return user_dict
    except Exception as e:
        print(f"[Auth] Error verifying session token: {e}")
        return None

def delete_session(token: str):
    """Delete a session token from SQLite."""
    invalidate_session_cache(token=token)
    try:
        conn = sqlite3.connect(DB_PATH, timeout=30.0)
        cur = conn.cursor()
        cur.execute("DELETE FROM user_sessions WHERE token = ?", (token,))
        conn.commit()
        conn.close()
    except Exception:
        pass

def get_current_user_from_request(request: Request) -> Optional[Dict[str, Any]]:
    """Extract and verify session user from request cookie or Authorization header."""
    token = request.cookies.get("session_token")
    if not token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
    return verify_session_token(token) if token else None

ch_thread_local = threading.local()
# Set default USE_SQLITE_MOCK to "0" for production ClickHouse. Set USE_SQLITE_MOCK=1 only for local simulation.
USE_SQLITE_MOCK = os.getenv("USE_SQLITE_MOCK", "0").lower() in ("1", "true", "yes")
ENABLE_MOCK_SEEDING = os.getenv("ENABLE_MOCK_SEEDING", "0").lower() in ("1", "true", "yes")

class _QueryResult:
    def __init__(self, column_names: List[str], result_rows: List[Tuple[Any, ...]]):
        self.column_names = column_names
        self.result_rows = result_rows

class SQLiteClickHouseAdapter:
    """SQLite drop-in adapter that emulates clickhouse_connect Client for local simulation."""
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.conn = sqlite3.connect(self.db_path, timeout=30.0, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode = WAL")
        self._register_functions()

    def _register_functions(self):
        def _is_ipv4(s):
            if not s:
                return 0
            try:
                return 1 if ipaddress.ip_address(str(s).strip()).version == 4 else 0
            except Exception:
                return 0

        def _is_ipv6(s):
            if not s:
                return 0
            try:
                return 1 if ipaddress.ip_address(str(s).strip()).version == 6 else 0
            except Exception:
                return 0

        def _in_range(ip_s, cidr_s):
            if not ip_s or not cidr_s:
                return 0
            try:
                ip_obj = ipaddress.ip_address(str(ip_s).strip())
                net_obj = ipaddress.ip_network(str(cidr_s).strip(), strict=False)
                return 1 if ip_obj in net_obj else 0
            except Exception:
                return 0

        def _if_fn(cond, a, b):
            return a if cond else b

        def _to_start_of_minute(ts_val):
            if not ts_val:
                return ""
            return str(ts_val)[:16] + ":00"

        def _to_start_of_hour(ts_val):
            if not ts_val:
                return ""
            return str(ts_val)[:13] + ":00:00"

        def _to_start_of_day(ts_val):
            if not ts_val:
                return ""
            return str(ts_val)[:10]

        self.conn.create_function("isIPv4String", 1, _is_ipv4)
        self.conn.create_function("isIPv6String", 1, _is_ipv6)
        self.conn.create_function("isIPAddressInRange", 2, _in_range)
        self.conn.create_function("if", 3, _if_fn)
        self.conn.create_function("toStartOfMinute", 1, _to_start_of_minute)
        self.conn.create_function("toStartOfHour", 1, _to_start_of_hour)
        self.conn.create_function("toStartOfDay", 1, _to_start_of_day)
        self.conn.create_function("toDateTime", 1, lambda s: str(s) if s is not None else "")
        self.conn.create_function("toString", 1, lambda s: str(s) if s is not None else "")

    def _translate_sql(self, sql: str, parameters: Optional[Dict[str, Any]] = None) -> Tuple[str, List[Any]]:
        import re
        params = dict(parameters or {})
        s = sql.strip()

        # Handle ClickHouse CREATE TABLE syntax
        if re.match(r"^CREATE\s+TABLE", s, re.IGNORECASE):
            s = re.sub(r"\)\s*ENGINE\s*=\s*MergeTree\(\).*$", ")", s, flags=re.IGNORECASE | re.DOTALL)
            s = re.sub(r"Nullable\(([^)]+)\)", r"\1", s)
            s = re.sub(r"\bUInt(16|32|64)\b", "INTEGER", s)
            s = re.sub(r"\bString\b", "TEXT", s)
            s = re.sub(r"\bDateTime\s+DEFAULT\s+now\(\)", "TEXT DEFAULT (datetime('now', 'localtime'))", s, flags=re.IGNORECASE)
            s = re.sub(r"\bDateTime\b", "TEXT", s, flags=re.IGNORECASE)
            return s, []

        # Handle ALTER TABLE ... MODIFY TTL
        if re.search(r"ALTER\s+TABLE\s+\w+\s+MODIFY\s+TTL", s, re.IGNORECASE):
            return "SELECT 1", []

        # Handle TRUNCATE TABLE
        m_trunc = re.match(r"^TRUNCATE\s+TABLE\s+(\w+)", s, re.IGNORECASE)
        if m_trunc:
            return f"DELETE FROM {m_trunc.group(1)}", []

        # Handle ALTER TABLE <table> DELETE WHERE ...
        m_del = re.match(r"^ALTER\s+TABLE\s+(\w+)\s+DELETE\s+WHERE\s+(.+)$", s, re.IGNORECASE | re.DOTALL)
        if m_del:
            s = f"DELETE FROM {m_del.group(1)} WHERE {m_del.group(2)}"

        # Replace ClickHouse specific functions/expressions
        s = re.sub(r"\bCOUNT\(\s*\)", "COUNT(*)", s, flags=re.IGNORECASE)
        s = re.sub(r"CAST\(NULL,\s*'[^']+'\)", "NULL", s, flags=re.IGNORECASE)
        s = re.sub(r"\bILIKE\b", "LIKE", s, flags=re.IGNORECASE)

        # Time intervals: ts + INTERVAL 8 HOUR -> ts (already stored in local TW time in mock)
        s = re.sub(r"ts\s*\+\s*INTERVAL\s+8\s+HOUR", "ts", s, flags=re.IGNORECASE)
        s = re.sub(r"now\(\)\s*-\s*INTERVAL\s+(\d+)\s+MINUTE", r"datetime('now', 'localtime', '-\1 minutes')", s, flags=re.IGNORECASE)
        s = re.sub(r"now\(\)\s*-\s*INTERVAL\s+(\d+)\s+HOUR", r"datetime('now', 'localtime', '-\1 hours')", s, flags=re.IGNORECASE)
        s = re.sub(r"now\(\)\s*-\s*INTERVAL\s+(\d+)\s+DAY", r"datetime('now', 'localtime', '-\1 days')", s, flags=re.IGNORECASE)
        s = re.sub(r"\bnow\(\)", "datetime('now', 'localtime')", s, flags=re.IGNORECASE)

        # Replace %(key)s parameters (including tuple expansion for IN clauses)
        bind_vals: List[Any] = []
        def _repl_param(match):
            key = match.group(1)
            val = params.get(key)
            if isinstance(val, (tuple, list)):
                if not val:
                    return "(NULL)"
                placeholders = ", ".join("?" for _ in val)
                bind_vals.extend(val)
                return f"({placeholders})"
            else:
                bind_vals.append(val)
                return "?"

        s = re.sub(r"%\(([^)]+)\)s", _repl_param, s)
        return s, bind_vals

    def command(self, sql: str, parameters: Optional[Dict[str, Any]] = None):
        if "multiIf(" in sql:
            raise RuntimeError("multiIf not supported in SQLite fast-path; use row-by-row fallback")
        q, vals = self._translate_sql(sql, parameters)
        cur = self.conn.cursor()
        cur.execute(q, vals)
        self.conn.commit()
        cur.close()

    def query(self, sql: str, parameters: Optional[Dict[str, Any]] = None) -> _QueryResult:
        if "multiIf(" in sql:
            raise RuntimeError("multiIf not supported in SQLite fast-path; use row-by-row fallback")
        q, vals = self._translate_sql(sql, parameters)
        cur = self.conn.cursor()
        cur.execute(q, vals)
        rows = cur.fetchall()
        cols = [d[0] for d in cur.description] if cur.description else []
        cur.close()
        # Convert min(ts)/max(ts) string timestamps to datetime objects when needed
        if cols and len(cols) == 2 and "min(ts)" in cols[0].lower() and rows:
            r0 = list(rows[0])
            for i in (0, 1):
                if isinstance(r0[i], str) and r0[i]:
                    try:
                        r0[i] = datetime.strptime(r0[i][:19], "%Y-%m-%d %H:%M:%S")
                    except Exception:
                        pass
            rows = [tuple(r0)]
        return _QueryResult(cols, rows)

    def insert(self, table: str, data: List[List[Any]], column_names: List[str]):
        if not data:
            return
        placeholders = ", ".join("?" for _ in column_names)
        cols_str = ", ".join(column_names)
        sql = f"INSERT INTO {table} ({cols_str}) VALUES ({placeholders})"
        cleaned_data = []
        for row in data:
            cleaned_row = []
            for v in row:
                if isinstance(v, datetime):
                    cleaned_row.append(v.strftime("%Y-%m-%d %H:%M:%S"))
                else:
                    cleaned_row.append(v)
            cleaned_data.append(cleaned_row)
        cur = self.conn.cursor()
        cur.executemany(sql, cleaned_data)
        self.conn.commit()
        cur.close()

    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass

def get_system_setting(key: str, default_val: str) -> str:
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT value FROM system_settings WHERE key = ?", (key,))
        row = cur.fetchone()
        conn.close()
        return row[0] if row and row[0] is not None else default_val
    except Exception:
        return default_val

def get_ch_client():
    if not hasattr(ch_thread_local, "client") or ch_thread_local.client is None:
        if USE_SQLITE_MOCK:
            ch_thread_local.client = SQLiteClickHouseAdapter(DB_PATH)
        else:
            _ch_host = get_system_setting("clickhouse_host", os.getenv("CLICKHOUSE_HOST", "clickhouse"))
            _ch_port = int(get_system_setting("clickhouse_port", os.getenv("CLICKHOUSE_PORT", "8123")))
            _ch_user = get_system_setting("clickhouse_user", os.getenv("CLICKHOUSE_USER", "admin"))
            _ch_password = get_system_setting("clickhouse_password", os.getenv("CLICKHOUSE_PASSWORD", "111aaaBBB"))
            try:
                ch_thread_local.client = clickhouse_connect.get_client(
                    host=_ch_host,
                    port=_ch_port,
                    username=_ch_user,
                    password=_ch_password
                )
            except Exception as e:
                # Fall back to SQLite adapter if ClickHouse cannot be reached
                print(f"[ClickHouse Client] Notice: Cannot connect to ClickHouse at {_ch_host}:{_ch_port} ({e}). Falling back to SQLite adapter.", file=sys.stderr)
                ch_thread_local.client = SQLiteClickHouseAdapter(DB_PATH)
    return ch_thread_local.client

def reset_ch_client():
    if hasattr(ch_thread_local, "client"):
        try:
            ch_thread_local.client.close()
        except Exception:
            pass
        ch_thread_local.client = None

# Background DNS Resolver setup
dns_executor = ThreadPoolExecutor(max_workers=5)
resolving_ips = set()
resolving_lock = threading.Lock()

def _resolve_and_save(ip: str):
    try:
        # socket.gethostbyaddr returns (hostname, aliaslist, ipaddrlist)
        hostname, _, _ = socket.gethostbyaddr(ip)
    except Exception:
        hostname = ""
    
    try:
        conn = sqlite3.connect(DB_PATH, timeout=30.0)
        cur = conn.cursor()
        cur.execute(
            "INSERT OR REPLACE INTO dns_cache (ip, domain, last_resolved) VALUES (?, ?, ?)",
            (ip, hostname, now_tw_str())
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DNS Resolver] Error writing {ip} -> {hostname} to db: {e}")
    finally:
        with resolving_lock:
            resolving_ips.discard(ip)

def enqueue_dns_resolution(ip: str):
    if not ip or ip == "0.0.0.0" or ip == "-":
        return
    with resolving_lock:
        if ip in resolving_ips:
            return
        resolving_ips.add(ip)
    dns_executor.submit(_resolve_and_save, ip)

def get_dns_mappings(ips: set) -> Dict[str, str]:
    if not ips:
        return {}
    
    dns_map = {}
    now = now_tw()
    
    try:
        conn = sqlite3.connect(DB_PATH, timeout=30.0)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        
        placeholders = ",".join("?" for _ in ips)
        cur.execute(f"SELECT ip, domain, last_resolved FROM dns_cache WHERE ip IN ({placeholders})", list(ips))
        rows = cur.fetchall()
        conn.close()
        
        cached_ips = set()
        for row in rows:
            ip = row["ip"]
            domain = row["domain"]
            last_resolved_str = row["last_resolved"]
            cached_ips.add(ip)
            
            # Check if fresh (24h)
            fresh = True
            if last_resolved_str:
                try:
                    last_resolved = parse_tw_datetime(last_resolved_str)
                    if now - last_resolved > timedelta(days=1):
                        fresh = False
                except Exception:
                    pass
            
            dns_map[ip] = domain
            if not fresh:
                enqueue_dns_resolution(ip)
                
        # For any queried IP that was not in the cache, queue it for resolution
        for ip in ips:
            if ip not in cached_ips:
                enqueue_dns_resolution(ip)
                dns_map[ip] = ""
    except Exception as e:
        print(f"[DNS Cache] Error reading cache: {e}")
        # Queue anyway on error
        for ip in ips:
            enqueue_dns_resolution(ip)
            dns_map[ip] = ""
            
    return dns_map


# Protocol mapping
PROTO_MAP = {
    "icmp": 1,
    "igmp": 2,
    "tcp": 6,
    "udp": 17,
    "ipv6": 41,
    "ospf": 89,
    "sctp": 132,
}

PROTO_NAME_MAP = {v: k.upper() for k, v in PROTO_MAP.items()}

def get_proto_number(proto_str: str) -> Optional[int]:
    if not proto_str:
        return None
    proto_str = proto_str.lower().strip()
    if proto_str.isdigit():
        return int(proto_str)
    return PROTO_MAP.get(proto_str)

def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        name = col[0]
        val = row[idx]
        d[name] = val
    # Add friendly protocol name if present
    if "protocol" in d and d["protocol"] is not None:
        d["proto_name"] = PROTO_NAME_MAP.get(d["protocol"], f"UNKNOWN ({d['protocol']})")
    else:
        d["proto_name"] = "N/A"
    return d

def get_db_connection():
    # Use standard connection with a timeout to avoid URI-parsing bugs on different OS's
    conn = sqlite3.connect(DB_PATH, timeout=30.0)
    conn.row_factory = dict_factory
    
    # SQLite optimization PRAGMAs for high performance reads and concurrent write support
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA cache_size = -64000")  # 64MB Cache
    conn.execute("PRAGMA temp_store = MEMORY")
    conn.execute("PRAGMA synchronous = NORMAL")
    
    return conn

port_aliases_cache = {}
ip_aliases_cache = {}
resolved_cidr_cache: OrderedDict[str, Optional[str]] = OrderedDict()
resolved_cidr_lock = threading.Lock()
MAX_RESOLVED_CIDR_CACHE = 50000
ip_aliases_total_count_cache: Optional[int] = None

def _cache_resolved_ip(ip_str: str, alias: Optional[str]):
    with resolved_cidr_lock:
        resolved_cidr_cache[ip_str] = alias
        resolved_cidr_cache.move_to_end(ip_str)
        if len(resolved_cidr_cache) > MAX_RESOLVED_CIDR_CACHE:
            resolved_cidr_cache.popitem(last=False)

def ip_to_hex(ip_obj) -> str:
    if ip_obj.version == 4:
        return 'v4-' + ip_obj.packed.hex()
    return 'v6-' + ip_obj.packed.hex()

def load_port_aliases():
    global port_aliases_cache
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT port, name FROM port_aliases")
        port_aliases_cache = {row[0]: row[1] for row in cur.fetchall()}
        conn.close()
        print(f"[Startup Init] Loaded {len(port_aliases_cache)} port aliases into cache.")
    except Exception as e:
        print(f"[Startup Init] Error loading port aliases into cache: {e}")

def load_ip_aliases():
    global ip_aliases_cache, ip_aliases_total_count_cache
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        # Only load exact IP matches into memory cache to save memory
        cur.execute("SELECT ip, name FROM ip_aliases WHERE ip NOT LIKE '%/%'")
        rows = cur.fetchall()
        cur.execute("SELECT COUNT(*) FROM ip_aliases")
        ip_aliases_total_count_cache = cur.fetchone()[0]
        conn.close()
        
        ip_aliases_cache = {row[0].strip(): row[1].strip() for row in rows}
        with resolved_cidr_lock:
            resolved_cidr_cache.clear()
        print(f"[Startup Init] Loaded {len(ip_aliases_cache)} exact IP aliases into cache (total rows: {ip_aliases_total_count_cache}).")
    except Exception as e:
        print(f"[Startup Init] Error loading IP aliases into cache: {e}")

def find_ips_by_alias(alias_query: str, max_results: int = 100) -> List[str]:
    """Search SQLite ip_aliases by alias name (exact match or substring match) and return list of IP/CIDR strings."""
    if not alias_query or not str(alias_query).strip():
        return []
    alias_clean = str(alias_query).strip()
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute(
            "SELECT ip FROM ip_aliases WHERE name = ? OR name LIKE ? LIMIT ?",
            (alias_clean, f"%{alias_clean}%", max_results)
        )
        rows = cur.fetchall()
        conn.close()
        return [r[0].strip() for r in rows if r[0]]
    except Exception as e:
        print(f"[find_ips_by_alias] Error: {e}", file=sys.stderr)
        return []

def build_alias_where_clause(col: str, alias_query: str, params: dict, prefix: str) -> str:
    """Build ClickHouse SQL clause that matches records where `col` has an IP belonging to `alias_query`."""
    matched_ips = find_ips_by_alias(alias_query)
    if not matched_ips:
        return "1 = 0"
    
    sub_clauses = []
    for idx, ip_val in enumerate(matched_ips):
        param_k = f"{prefix}_al_{idx}"
        if col in ("any", "any_ip", "ip_alias", "alias"):
            c_src = build_ip_where_clause("src", ip_val, params, f"{param_k}_s")
            c_dst = build_ip_where_clause("dst", ip_val, params, f"{param_k}_d")
            sub_clauses.append(f"({c_src} OR {c_dst})")
        else:
            sub_clauses.append(build_ip_where_clause(col, ip_val, params, param_k))
            
    if len(sub_clauses) == 1:
        return sub_clauses[0]
    return f"({' OR '.join(sub_clauses)})"

def build_ip_where_clause(col: str, ip_query: str, params: dict, param_key: str) -> str:
    val = ip_query.strip().lower()
    safe_col = f"if(isIPv4String({col}) OR isIPv6String({col}), {col}, '0.0.0.0')"
    if val == "internal":
        return (
            f"((isIPv4String({col}) OR isIPv6String({col})) AND "
            f"(isIPAddressInRange({safe_col}, '192.168.0.0/16') OR "
            f"isIPAddressInRange({safe_col}, '172.16.0.0/12') OR "
            f"isIPAddressInRange({safe_col}, '10.0.0.0/8')))"
        )
    elif val == "external":
        return (
            f"((isIPv4String({col}) OR isIPv6String({col})) AND NOT "
            f"(isIPAddressInRange({safe_col}, '192.168.0.0/16') OR "
            f"isIPAddressInRange({safe_col}, '172.16.0.0/12') OR "
            f"isIPAddressInRange({safe_col}, '10.0.0.0/8')))"
        )
    else:
        if "/" in ip_query:
            params[param_key] = ip_query.strip()
            return f"((isIPv4String({col}) OR isIPv6String({col})) AND isIPAddressInRange({safe_col}, %({param_key})s))"
        else:
            raw_str = ip_query.strip()
            # If string contains characters not typical in pure IP prefixes, check alias
            is_ip_like = True
            for ch in raw_str:
                if ch not in "0123456789abcdefABCDEF.:/%":
                    is_ip_like = False
                    break
            if not is_ip_like:
                matched_ips = find_ips_by_alias(raw_str)
                if matched_ips:
                    sub_c = []
                    for idx, mip in enumerate(matched_ips):
                        sub_c.append(build_ip_where_clause(col, mip, params, f"{param_key}_al_{idx}"))
                    return f"({' OR '.join(sub_c)})" if len(sub_c) > 1 else sub_c[0]

            params[param_key] = f"{raw_str}%"
            return f"{col} LIKE %({param_key})s"

def parse_conditions_where_clause(conditions_json: Optional[str], logic: str, params: dict, prefix: str = "dyn") -> Optional[str]:
    """Parse dynamic multi-condition JSON and return combined ClickHouse SQL clause."""
    if not conditions_json or conditions_json == "[]":
        return None
    try:
        import json
        cond_list = json.loads(conditions_json)
        if not isinstance(cond_list, list) or not cond_list:
            return None
        
        clauses = []
        for idx, item in enumerate(cond_list):
            if not isinstance(item, dict):
                continue
            field = str(item.get("field", "")).strip().lower()
            val = str(item.get("val", "")).strip()
            if not val:
                continue

            sub_key = f"{prefix}_{idx}"
            if field in ("src", "src_ip"):
                clauses.append(build_ip_where_clause("src", val, params, f"{sub_key}_src"))
            elif field in ("dst", "dst_ip"):
                clauses.append(build_ip_where_clause("dst", val, params, f"{sub_key}_dst"))
            elif field in ("ip", "any_ip"):
                c_src = build_ip_where_clause("src", val, params, f"{sub_key}_asrc")
                c_dst = build_ip_where_clause("dst", val, params, f"{sub_key}_adst")
                clauses.append(f"({c_src} OR {c_dst})")
            elif field in ("alias", "ip_alias", "any_alias"):
                clauses.append(build_alias_where_clause("any", val, params, f"{sub_key}_alias"))
            elif field in ("src_alias", "source_alias"):
                clauses.append(build_alias_where_clause("src", val, params, f"{sub_key}_salias"))
            elif field in ("dst_alias", "dest_alias"):
                clauses.append(build_alias_where_clause("dst", val, params, f"{sub_key}_dalias"))
            elif field in ("sport", "src_port"):
                try:
                    params[f"{sub_key}_sport"] = int(val)
                    clauses.append(f"sport = %({sub_key}_sport)s")
                except ValueError:
                    pass
            elif field in ("dport", "dst_port"):
                try:
                    params[f"{sub_key}_dport"] = int(val)
                    clauses.append(f"dport = %({sub_key}_dport)s")
                except ValueError:
                    pass
            elif field in ("port", "any_port"):
                try:
                    params[f"{sub_key}_aport"] = int(val)
                    clauses.append(f"(sport = %({sub_key}_aport)s OR dport = %({sub_key}_aport)s)")
                except ValueError:
                    pass
            elif field in ("proto", "protocol"):
                p_num = None
                for num, name in PROTO_NAME_MAP.items():
                    if name.upper() == val.upper():
                        p_num = num
                        break
                if p_num is not None:
                    params[f"{sub_key}_pnum"] = p_num
                    params[f"{sub_key}_pstr"] = val
                    clauses.append(f"(proto ILIKE %({sub_key}_pstr)s OR protocol = %({sub_key}_pnum)s)")
                elif val.isdigit():
                    params[f"{sub_key}_pnum"] = int(val)
                    params[f"{sub_key}_pstr"] = val
                    clauses.append(f"(proto ILIKE %({sub_key}_pstr)s OR protocol = %({sub_key}_pnum)s)")
                else:
                    params[f"{sub_key}_pstr"] = val
                    clauses.append(f"proto ILIKE %({sub_key}_pstr)s")

        if not clauses:
            return None

        join_logic = " OR " if str(logic).strip().upper() == "OR" else " AND "
        return f"({join_logic.join(clauses)})"
    except Exception as e:
        print(f"[parse_conditions_where_clause] Error: {e}", file=sys.stderr)
        return None

def resolve_ip_alias(ip_str: str) -> Optional[str]:
    if not ip_str:
        return None
    ip_str = ip_str.strip()
    ip_lower = ip_str.lower()
    if ip_lower == "internal":
        return "Private IP"
    elif ip_lower == "external":
        return "Public IP"
    
    # 1. Exact match first
    if ip_str in ip_aliases_cache:
        return ip_aliases_cache[ip_str]

    with resolved_cidr_lock:
        if ip_str in resolved_cidr_cache:
            resolved_cidr_cache.move_to_end(ip_str)
            return resolved_cidr_cache[ip_str]
        
    # 2. Fast O(log N) reverse B-Tree CIDR range match from SQLite
    try:
        if "/" in ip_str:
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            cur.execute("SELECT name FROM ip_aliases WHERE ip = ? LIMIT 1", (ip_str,))
            row = cur.fetchone()
            conn.close()
            alias = row[0] if row else None
            _cache_resolved_ip(ip_str, alias)
            return alias

        ip_obj = ipaddress.ip_address(ip_str)
        ip_hex = ip_to_hex(ip_obj)
        min_hex = "v4-00000000" if ip_obj.version == 4 else "v6-00000000000000000000000000000000"
        
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("""
            SELECT name FROM (
                SELECT name, end_ip, prefix_len FROM ip_aliases
                WHERE start_ip <= ? AND start_ip >= ?
                ORDER BY start_ip DESC LIMIT 16
            )
            WHERE end_ip >= ?
            ORDER BY prefix_len DESC LIMIT 1
        """, (ip_hex, min_hex, ip_hex))
        row = cur.fetchone()
        conn.close()
        
        alias = row[0] if row else None
        _cache_resolved_ip(ip_str, alias)
        return alias
    except Exception:
        pass
        
    return None

def resolve_ip_aliases_batch(ips_list: Iterable[str]) -> Dict[str, str]:
    results = {}
    missing_ips = []
    
    for ip in ips_list:
        if not ip:
            continue
        ip_clean = ip.strip()
        ip_lower = ip_clean.lower()
        if ip_lower == "internal":
            results[ip_clean] = "Private IP"
            continue
        elif ip_lower == "external":
            results[ip_clean] = "Public IP"
            continue

        if ip_clean in ip_aliases_cache:
            results[ip_clean] = ip_aliases_cache[ip_clean]
            continue

        with resolved_cidr_lock:
            if ip_clean in resolved_cidr_cache:
                resolved_cidr_cache.move_to_end(ip_clean)
                val = resolved_cidr_cache[ip_clean]
                if val:
                    results[ip_clean] = val
                continue

        missing_ips.append(ip_clean)
            
    if not missing_ips:
        return results
        
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        
        for ip in set(missing_ips):
            try:
                if "/" in ip:
                    cur.execute("SELECT name FROM ip_aliases WHERE ip = ? LIMIT 1", (ip,))
                    row = cur.fetchone()
                    alias = row[0] if row else None
                    _cache_resolved_ip(ip, alias)
                    if alias:
                        results[ip] = alias
                    continue

                ip_obj = ipaddress.ip_address(ip)
                ip_hex = ip_to_hex(ip_obj)
                min_hex = "v4-00000000" if ip_obj.version == 4 else "v6-00000000000000000000000000000000"
                
                cur.execute("""
                    SELECT name FROM (
                        SELECT name, end_ip, prefix_len FROM ip_aliases
                        WHERE start_ip <= ? AND start_ip >= ?
                        ORDER BY start_ip DESC LIMIT 16
                    )
                    WHERE end_ip >= ?
                    ORDER BY prefix_len DESC LIMIT 1
                """, (ip_hex, min_hex, ip_hex))
                row = cur.fetchone()
                alias = row[0] if row else None
                _cache_resolved_ip(ip, alias)
                if alias:
                    results[ip] = alias
            except Exception:
                pass
                
        conn.close()
    except Exception as e:
        print(f"Error in batch resolve: {e}")
        
    return results

def _insert_default_scenarios(cur, tw_now: str):
    """Pre-populate the 5 built-in situational Threat Scenarios for non-expert admins."""
    defaults = [
        (
            "外部惡意威脅與暗網節點連線",
            "惡意威脅連線",
            "high",
            "internal",
            "185.220.101.45,45.155.205.233",
            "",
            "all",
            0,
            "內網主機主動與已知的 Tor 暗網出口節點或外部惡意掃描/C2 中繼站建立連線，極可能已被植入木馬或正在回傳系統資訊。",
            "1. 立即確認該主機目前是否仍與該外部惡意 IP 保持連線。\n2. 至邊界防火牆將目的 IP 加入黑名單封鎖。\n3. 通知該設備使用人員暫時斷網，並執行完整端點防毒／惡意程式掃描。\n4. 檢查同網段是否有其他電腦也連過相同惡意 IP。",
            1,
            1,
            tw_now
        ),
        (
            "核心伺服器非上班時間異常存取",
            "重要資產異常時段存取",
            "high",
            "any",
            "192.168.10.10,192.168.10.20,192.168.10.50",
            "3306,1433,5432,3389,22,445",
            "late_night",
            0,
            "在深夜無人維運時段（00:00～06:00），偵測到設備存取公司核心資料庫（Core-DB）、ERP 或 AD 主機，疑似帳號遭盜用或內部人員非授權操作。",
            "1. 核對當時是否有申請夜間系統維護或自動備份排程。\n2. 檢視來源主機的使用者帳號登入紀錄（AD Event Log / VPN 日誌）。\n3. 若非合法維運，請立即通知資安負責人並停用相關帳號權限，排查資料庫是否被匯出。",
            1,
            1,
            tw_now
        ),
        (
            "員工上班時間影音娛樂大流量",
            "上班娛樂／影音偷懶",
            "behavior",
            "internal",
            "youtube",
            "80,443",
            "work_hours",
            5242880,
            "在正常上班時段（09:00～18:00），偵測到員工電腦連往 YouTube / 串流影音伺服器且產生高傳輸流量（單次或累計達數 MB 以上），可能影響公司對外頻寬與辦公效率。",
            "1. 確認該員工作職掌是否需使用影音平台（如行銷、教育訓練、公關部門）。\n2. 若屬非公務娛樂用途，可先透過部門主管進行口頭提醒。\n3. 若影響整體網路品質，建議於防火牆或上網行為管理設備針對該時段套用影音串流 QoS 限速。",
            1,
            1,
            tw_now
        ),
        (
            "高風險遠端控制與內網橫向移動",
            "遠端與橫向擴散風險",
            "medium",
            "internal",
            "internal",
            "3389,445,22",
            "all",
            0,
            "內網設備之間透過遠端桌面（RDP 3389）、網路芳鄰（SMB 445）或 SSH（22）進行跨機連線，常見於未授權遠端控制、勒索軟體或蠕蟲在內網橫向擴散。",
            "1. 確認來源電腦是否為 IT 管理員之維運工作站。\n2. 若為一般辦公電腦（如財務、人事）主動對多台內網主機發起 445/3389 連線，極可能是勒索軟體感染前兆，請立即斷開該電腦網路線。\n3. 檢查防火牆內網隔離策略，關閉不必要主機的 RDP 與 SMB 存取。",
            1,
            1,
            tw_now
        ),
        (
            "疑似大量資料外洩／異常對外上傳",
            "疑似資料外洩大流量",
            "high",
            "internal",
            "external",
            "",
            "all",
            15728640,
            "內網主機對外部網際網路產生異常巨量傳輸（單筆 Flow 超過 15 MB），疑似將公司內部機密文件大量上傳至外部雲端空間或不明主機。",
            "1. 點擊「查看底層明細」確認目的 IP 是否為公司合法雲端硬碟（如 Google Drive、Microsoft 365）。\n2. 若目的端為未知外部伺服器或個人免費空間，請立即聯繫該設備使用者確認傳輸內容。\n3. 視情況於防火牆暫時限制該設備對外大流量上傳並留存稽核證據。",
            1,
            1,
            tw_now
        ),
        (
            "未納管未知設備連線",
            "新進未知資產",
            "low",
            "192.168.30.220,192.168.30.221,internal",
            "any",
            "80,443,8080",
            "all",
            500,
            "偵測到尚未在 AtheNAC 或網管資產庫註冊的新設備正在發起日常通訊，可能為訪客自攜設備 (BYOD) 或未登記之新進電腦。",
            "1. 檢視該設備的 MAC 位址與 Switch 連接埠，確認是否為合規申請之同仁新電腦。\n2. 若為訪客自攜設備，建議指引其連線至獨立 Guest VLAN，避免直接存取辦公內網。\n3. 確認主機使用者身分後，可至 AtheNAC 進行設備納管登記。",
            1,
            1,
            tw_now
        ),
        (
            "罕見高通訊埠微量連線",
            "非標準通訊埠",
            "low",
            "internal",
            "external",
            "8080-8090,10000-10050",
            "all",
            0,
            "內網設備對外部主機發起罕見之高通訊埠微量通訊（如 8080~8090 或 10000+），通常為特定應用程式背景同步或開發者測試服務。",
            "1. 核對該設備使用者是否為技術研發或系統測試同仁。\n2. 確認連線目的端是否為已知的公務雲端測試站點。\n3. 若非研發測試用途，持續觀察其連線次數是否異常激增。",
            1,
            1,
            tw_now
        ),
    ]
    cur.executemany("""
        INSERT INTO threat_scenarios (
            name, category, severity, src_scope, dst_scope, ports, time_window,
            min_bytes, reason_template, remediation_steps, is_enabled, is_builtin, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, defaults)

def _seed_initial_threat_intel(cur, tw_now: str):
    """Pre-populate initial Threat Intelligence DB records for baseline external threat IPs."""
    seeds = [
        (
            "185.220.101.45",
            "tor-exit-45. Zwiebelfreunde.de",
            95,
            "critical",
            "Critical",
            "Critical",
            "22,443,9001,9030",
            "22,80,443,9001,9030",
            "CVE-2023-48795,CVE-2024-6387",
            "tor,anon-proxy,c2-relay,scanner",
            "DE",
            "Zwiebelfreunde e.V. (Tor Exit Node)",
            "Criminal IP",
            "已知 Tor 暗網出口與 C2 中繼節點，開放高風險管理埠 22 與 Tor ORPort 9001/9030，具多項遠端高風險漏洞。",
            "{}",
            tw_now,
            tw_now
        ),
        (
            "45.155.205.233",
            "scanner-node-233. ChangWay.net",
            88,
            "high",
            "Dangerous",
            "Dangerous",
            "22,3389,4444,8080",
            "22,80,443,3389,4444,8080",
            "CVE-2021-44228,CVE-2023-38408",
            "malware,c2,brute-force,scanner",
            "NL",
            "Chang Way Technologies Co. Limited",
            "Criminal IP",
            "外部惡意掃描與木馬回連中繼站，偵測到高風險遠端控制埠 3389/4444/8080 與已知惡意活動紀錄。",
            "{}",
            tw_now,
            tw_now
        ),
    ]
    cur.executemany("""
        INSERT OR IGNORE INTO threat_intel_cache (
            ip, domain, risk_score, risk_level, inbound_score, outbound_score,
            risky_ports, open_ports, vulns, tags, country, org, provider,
            summary, raw_json, queried_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, seeds)

def init_db():
    """Verify that tables exist, run auto-migration for missing columns, and create indexes on startup."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        
        cur.execute("""CREATE TABLE IF NOT EXISTS dns_cache (
            ip TEXT PRIMARY KEY,
            domain TEXT,
            last_resolved DATETIME DEFAULT CURRENT_TIMESTAMP
        )""")
        
        cur.execute("CREATE INDEX IF NOT EXISTS idx_dns_cache_ip ON dns_cache (ip)")
        
        # Initialize port aliases table
        cur.execute("""CREATE TABLE IF NOT EXISTS port_aliases (
            port INTEGER PRIMARY KEY,
            name TEXT NOT NULL
        )""")
        
        # Check if table is empty to pre-populate defaults
        cur.execute("SELECT COUNT(*) FROM port_aliases")
        if cur.fetchone()[0] == 0:
            defaults = [
                (20, "FTP-Data"),
                (21, "FTP"),
                (22, "SSH"),
                (23, "Telnet"),
                (25, "SMTP"),
                (53, "DNS"),
                (67, "DHCP-Server"),
                (68, "DHCP-Client"),
                (80, "HTTP"),
                (110, "POP3"),
                (123, "NTP"),
                (143, "IMAP"),
                (161, "SNMP"),
                (443, "HTTPS"),
                (445, "Microsoft-DS"),
                (993, "IMAPS"),
                (995, "POP3S"),
                (1433, "MSSQL"),
                (2055, "Netflow"),
                (3306, "MySQL"),
                (3389, "RDP"),
                (4739, "IPFIX"),
                (5432, "PostgreSQL"),
                (8080, "HTTP-ALT")
            ]
            cur.executemany("INSERT INTO port_aliases (port, name) VALUES (?, ?)", defaults)
            conn.commit()
            print("[Startup Init] SQLite default port aliases pre-populated.")
            
        # Initialize ip aliases table
        cur.execute("""CREATE TABLE IF NOT EXISTS ip_aliases (
            ip TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            start_ip TEXT,
            end_ip TEXT,
            prefix_len INTEGER
        )""")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_ip_aliases_range ON ip_aliases (start_ip, end_ip, prefix_len)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_ip_aliases_name ON ip_aliases (name)")
        
        # Initialize audit rules table
        cur.execute("""CREATE TABLE IF NOT EXISTS audit_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            port TEXT,
            flag TEXT CHECK(flag IN ('watch', 'anomaly')),
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(ip, port)
        )""")
        
        # Initialize audit logs table
        cur.execute("""CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_ts DATETIME DEFAULT CURRENT_TIMESTAMP,
            status TEXT,
            records_matched INTEGER DEFAULT 0,
            message TEXT
        )""")

        # Initialize system settings table
        cur.execute("""CREATE TABLE IF NOT EXISTS system_settings (
            key TEXT PRIMARY KEY,
            value TEXT,
            updated_at DATETIME
        )""")
        
        tw_now = now_tw_str()
        cur.execute("INSERT OR IGNORE INTO system_settings (key, value, updated_at) VALUES ('netflow_port', '2055', ?)", (tw_now,))
        cur.execute("INSERT OR IGNORE INTO system_settings (key, value, updated_at) VALUES ('ipfix_port', '4739', ?)", (tw_now,))
        cur.execute("INSERT OR IGNORE INTO system_settings (key, value, updated_at) VALUES ('retention_days', '7', ?)", (tw_now,))
        cur.execute("INSERT OR IGNORE INTO system_settings (key, value, updated_at) VALUES ('retention_schedule_time', '03:00', ?)", (tw_now,))
        cur.execute("INSERT OR IGNORE INTO system_settings (key, value, updated_at) VALUES ('retention_enabled', '1', ?)", (tw_now,))
        cur.execute("INSERT OR IGNORE INTO system_settings (key, value, updated_at) VALUES ('retention_last_run', '', ?)", (tw_now,))
        cur.execute("INSERT OR IGNORE INTO system_settings (key, value, updated_at) VALUES ('retention_next_run', '', ?)", (tw_now,))
        cur.execute("INSERT OR IGNORE INTO system_settings (key, value, updated_at) VALUES ('retention_last_status', 'never', ?)", (tw_now,))
        cur.execute("INSERT OR IGNORE INTO system_settings (key, value, updated_at) VALUES ('retention_last_message', '排程尚未執行', ?)", (tw_now,))
        cur.execute("INSERT OR IGNORE INTO system_settings (key, value, updated_at) VALUES ('athenac_api_url', 'https://192.168.25.180:8001', ?)", (tw_now,))
        cur.execute("INSERT OR IGNORE INTO system_settings (key, value, updated_at) VALUES ('athenac_api_key', '', ?)", (tw_now,))
        cur.execute("INSERT OR IGNORE INTO system_settings (key, value, updated_at) VALUES ('athenac_username', '', ?)", (tw_now,))
        cur.execute("INSERT OR IGNORE INTO system_settings (key, value, updated_at) VALUES ('athenac_password', '', ?)", (tw_now,))
        cur.execute("INSERT OR IGNORE INTO system_settings (key, value, updated_at) VALUES ('athenac_mock_fallback', '1', ?)", (tw_now,))

        # Initialize Threat Scenarios table (Situational Rules Engine)
        cur.execute("""CREATE TABLE IF NOT EXISTS threat_scenarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            severity TEXT NOT NULL CHECK(severity IN ('high', 'medium', 'low', 'behavior')),
            src_scope TEXT DEFAULT 'any',
            dst_scope TEXT DEFAULT 'any',
            ports TEXT DEFAULT '',
            time_window TEXT DEFAULT 'all',
            min_bytes INTEGER DEFAULT 0,
            reason_template TEXT NOT NULL,
            remediation_steps TEXT NOT NULL,
            is_enabled INTEGER DEFAULT 1,
            is_builtin INTEGER DEFAULT 0,
            created_at DATETIME
        )""")

        cur.execute("SELECT COUNT(*) FROM threat_scenarios")
        if cur.fetchone()[0] == 0:
            _insert_default_scenarios(cur, tw_now)

        # Initialize AtheNAC Host Overview cache table
        cur.execute("""CREATE TABLE IF NOT EXISTS athenac_cache (
            ip TEXT PRIMARY KEY,
            hostname TEXT,
            mac TEXT,
            vendor TEXT,
            os_detail TEXT,
            switch_name TEXT,
            port_name TEXT,
            site_name TEXT,
            network_name TEXT,
            is_online INTEGER DEFAULT 1,
            is_simulated INTEGER DEFAULT 0,
            updated_at DATETIME
        )""")

        # Initialize External Threat Intelligence Cache table (Criminal IP / VirusTotal / Shodan / Censys)
        cur.execute("""CREATE TABLE IF NOT EXISTS threat_intel_cache (
            ip TEXT PRIMARY KEY,
            domain TEXT DEFAULT '',
            risk_score INTEGER DEFAULT 0,
            risk_level TEXT DEFAULT 'safe',
            inbound_score TEXT DEFAULT '',
            outbound_score TEXT DEFAULT '',
            risky_ports TEXT DEFAULT '',
            open_ports TEXT DEFAULT '',
            vulns TEXT DEFAULT '',
            tags TEXT DEFAULT '',
            country TEXT DEFAULT '',
            org TEXT DEFAULT '',
            provider TEXT DEFAULT '',
            summary TEXT DEFAULT '',
            raw_json TEXT DEFAULT '',
            queried_at DATETIME,
            updated_at DATETIME
        )""")
        cur.execute("SELECT COUNT(*) FROM threat_intel_cache")
        if cur.fetchone()[0] == 0:
            _seed_initial_threat_intel(cur, tw_now)

        # Initialize users table
        cur.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT DEFAULT 'admin',
            is_active INTEGER DEFAULT 1,
            must_change_password INTEGER DEFAULT 0,
            created_at DATETIME,
            last_login DATETIME
        )""")
        
        # Initialize user sessions table
        cur.execute("""CREATE TABLE IF NOT EXISTS user_sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            role TEXT NOT NULL,
            expires_at DATETIME NOT NULL,
            created_at DATETIME,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )""")
        
        # Initialize collector allowed CIDRs table
        cur.execute("""CREATE TABLE IF NOT EXISTS collector_allowed_cidrs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cidr TEXT NOT NULL UNIQUE,
            description TEXT,
            created_at DATETIME
        )""")
        
        # Pre-populate default admin user if none exists
        cur.execute("SELECT COUNT(*) FROM users")
        if cur.fetchone()[0] == 0:
            salt = secrets.token_hex(16)
            pwd_hash = hash_password("admin", salt)
            cur.execute("""
                INSERT INTO users (username, password_hash, salt, role, is_active, must_change_password, created_at)
                VALUES ('admin', ?, ?, 'admin', 1, 0, ?)
            """, (pwd_hash, salt, tw_now))
            print("[Startup Init] Default admin user initialized (admin / admin, must_change_password=0).")
        
        # Ensure scenario_id and scenario_name exist in audit_rules
        cur.execute("PRAGMA table_info(audit_rules)")
        audit_cols = [c[1] for c in cur.fetchall()]
        if "scenario_id" not in audit_cols:
            cur.execute("ALTER TABLE audit_rules ADD COLUMN scenario_id INTEGER DEFAULT NULL")
        if "scenario_name" not in audit_cols:
            cur.execute("ALTER TABLE audit_rules ADD COLUMN scenario_name TEXT DEFAULT ''")
        
        conn.commit()
        conn.close()
        
        try:
            sync_all_threat_scenarios_to_audit_rules()
        except Exception as _sync_err:
            print(f"[Startup Scenario Sync Notice] {_sync_err}", flush=True)
        print("[Startup Init] SQLite tables (users, sessions, allowed CIDRs, system settings) initialized successfully.")
        
        load_port_aliases()
        load_ip_aliases()
    except Exception as e:
        print(f"[Startup Init] Error initializing SQLite tables: {e}")

    # Initialize ClickHouse tables if they do not exist
    init_clickhouse_tables()

def ensure_matched_flows_table(client=None):
    """Ensure the matched_flows table exists in ClickHouse."""
    try:
        if client is None:
            client = get_ch_client()
        client.command("""
        CREATE TABLE IF NOT EXISTS matched_flows (
            id String,
            exporter String,
            proto String,
            src String,
            dst String,
            sport UInt16,
            dport UInt16,
            packets UInt64,
            octets UInt64,
            protocol Nullable(UInt16),
            json_data String,
            ts DateTime,
            rule_ip Nullable(String),
            rule_port Nullable(String),
            match_flag String,
            match_ts DateTime DEFAULT now()
        ) ENGINE = MergeTree()
        ORDER BY (match_ts, ts, exporter, src, dst)
        """)
    except Exception as e:
        print(f"[Ensure Matched Flows Table] Warning: {e}")

def init_clickhouse_tables(client=None):
    """Initialize ClickHouse tables if they do not exist."""
    try:
        if client is None:
            client = get_ch_client()
        client.command("""
        CREATE TABLE IF NOT EXISTS ipfix (
            id String,
            exporter String,
            proto String,
            src String,
            dst String,
            sport UInt16,
            dport UInt16,
            packets UInt64,
            octets UInt64,
            protocol Nullable(UInt16),
            json_data String,
            ts DateTime DEFAULT now()
        ) ENGINE = MergeTree()
        ORDER BY (ts, exporter, src, dst)
        TTL ts + INTERVAL 7 DAY
        """)
        
        retention_days = int(get_system_setting("retention_days", "7"))
        client.command(f"""
        CREATE TABLE IF NOT EXISTS ipfix (
            id String,
            exporter String,
            proto String,
            src String,
            dst String,
            sport UInt16,
            dport UInt16,
            packets UInt64,
            octets UInt64,
            protocol Nullable(UInt16),
            json_data String,
            ts DateTime DEFAULT now()
        ) ENGINE = MergeTree()
        ORDER BY (ts, exporter, src, dst)
        TTL ts + INTERVAL {retention_days} DAY
        """)
        
        client.command(f"""
        CREATE TABLE IF NOT EXISTS netflow9 (
            id String,
            exporter String,
            proto String,
            src String,
            dst String,
            sport UInt16,
            dport UInt16,
            packets UInt64,
            octets UInt64,
            protocol Nullable(UInt16),
            json_data String,
            ts DateTime DEFAULT now()
        ) ENGINE = MergeTree()
        ORDER BY (ts, exporter, src, dst)
        TTL ts + INTERVAL {retention_days} DAY
        """)
        
        # Initialize matched_flows table (without TTL)
        ensure_matched_flows_table(client)
        
        # Ensure TTL is applied to existing tables if they were created without it
        try:
            client.command(f"ALTER TABLE ipfix MODIFY TTL ts + INTERVAL {retention_days} DAY")
            client.command(f"ALTER TABLE netflow9 MODIFY TTL ts + INTERVAL {retention_days} DAY")
        except Exception as alter_err:
            print(f"[Startup Init] Warning altering ClickHouse TTL: {alter_err}")
            
        print(f"[Startup Init] ClickHouse database tables initialized successfully ({retention_days}-day TTL).")
        if USE_SQLITE_MOCK and ENABLE_MOCK_SEEDING:
            seed_sqlite_mock_data(client)
            ensure_scenario_mock_flows(client)
    except Exception as e:
        print(f"[Startup Init] Error initializing ClickHouse tables: {e}")

def ensure_scenario_mock_flows(client):
    """Ensure scenario-specific demo flows exist so all 5 threat scenarios show vivid results in SQLite mock mode."""
    import random
    import uuid
    try:
        # Seed default threat scenarios if empty
        try:
            _conn_sc = sqlite3.connect(DB_PATH)
            _cur_sc = _conn_sc.cursor()
            _cur_sc.execute("SELECT COUNT(*) FROM threat_scenarios")
            if _cur_sc.fetchone()[0] == 0:
                _insert_default_scenarios(_cur_sc, now_tw_str())
                _conn_sc.commit()
            _conn_sc.close()
        except Exception as _sc_e:
            print(f"[SQLite Mock] Error seeding default scenarios: {_sc_e}")

        # Ensure low severity scenarios exist in DB
        try:
            _conn_sc = sqlite3.connect(DB_PATH)
            _cur_sc = _conn_sc.cursor()
            _cur_sc.execute("SELECT COUNT(*) FROM threat_scenarios WHERE severity = 'low'")
            if _cur_sc.fetchone()[0] == 0:
                _tw = now_tw_str()
                _cur_sc.execute("""
                    INSERT INTO threat_scenarios (
                        name, category, severity, src_scope, dst_scope, ports, time_window,
                        min_bytes, reason_template, remediation_steps, is_enabled, is_builtin, created_at
                    ) VALUES
                    (
                        '未納管未知設備連線', '新進未知資產', 'low',
                        '192.168.30.220,192.168.30.221,internal', 'any', '80,443,8080', 'all', 500,
                        '偵測到尚未在 AtheNAC 或網管資產庫註冊的新設備正在發起日常通訊，可能為訪客自攜設備 (BYOD) 或未登記之新進電腦。',
                        '1. 檢視該設備的 MAC 位址與 Switch 連接埠，確認是否為合規申請之同仁新電腦。\n2. 若為訪客自攜設備，建議指引其連線至獨立 Guest VLAN，避免直接存取辦公內網。\n3. 確認主機使用者身分後，可至 AtheNAC 進行設備納管登記。',
                        1, 1, ?
                    ),
                    (
                        '罕見高通訊埠微量連線', '非標準通訊埠', 'low',
                        'internal', 'external', '8080-8090,10000-10050', 'all', 0,
                        '內網設備對外部主機發起罕見之高通訊埠微量通訊（如 8080~8090 或 10000+），通常為特定應用程式背景同步或開發者測試服務。',
                        '1. 核對該設備使用者是否為技術研發或系統測試同仁。\n2. 確認連線目的端是否為已知的公務雲端測試站點。\n3. 若非研發測試用途，持續觀察其連線次數是否異常激增。',
                        1, 1, ?
                    )
                """, (_tw, _tw))
                _conn_sc.commit()
            _conn_sc.close()
        except Exception as _sc_e:
            print(f"[SQLite Mock] Error verifying low scenarios: {_sc_e}")

        marker = get_system_setting("scenario_mock_seeded_v3", "0")
        if marker == "1":
            return
        now_dt = now_tw()
        cols = ["id", "exporter", "proto", "src", "dst", "sport", "dport", "packets", "octets", "protocol", "json_data", "ts"]
        rows_ipfix = []
        rows_nf9 = []

        # Helper to construct timestamps in a specific hour of today/yesterday
        def _ts_at(hour: int, minute: int, days_ago: int = 0) -> str:
            base = (now_dt - timedelta(days=days_ago)).replace(hour=hour, minute=minute, second=random.randint(5, 55), microsecond=0)
            if base > now_dt:
                base = base - timedelta(days=1)
            return base.strftime("%Y-%m-%d %H:%M:%S")

        random.seed(2026)

        # 1. YouTube streaming during work hours (09:00 - 18:00)
        yt_ips = ["142.250.196.110", "172.217.160.110", "216.58.200.46"]
        for i in range(14):
            src = random.choice(["192.168.30.105", "192.168.30.112", "192.168.30.120"])
            dst = random.choice(yt_ips)
            octets = random.randint(6_500_000, 28_000_000)
            packets = octets // 1250
            ts = _ts_at(random.randint(10, 17), random.randint(0, 59))
            raw_json = json.dumps({"service": "HTTPS / YouTube Streaming", "app": "youtube", "in_if": 2, "out_if": 1})
            r = [str(uuid.uuid4()), "10.10.1.1", "IPFIX", src, dst, random.randint(30000, 62000), 443, packets, octets, 6, raw_json, ts]
            rows_ipfix.append(r)

        # 2. Core DB / ERP access during late night (00:00 - 05:59)
        core_targets = [("192.168.10.10", 3306, "MySQL"), ("192.168.10.20", 3389, "RDP"), ("192.168.10.50", 445, "SMB")]
        for i in range(9):
            src = random.choice(["192.168.30.101", "10.0.5.25", "192.168.20.15"])
            dst, dport, svc = random.choice(core_targets)
            packets = random.randint(120, 1800)
            octets = packets * random.randint(420, 1100)
            ts = _ts_at(random.randint(1, 4), random.randint(0, 59))
            raw_json = json.dumps({"service": svc, "note": "Off-hours core server access", "in_if": 3, "out_if": 4})
            r = [str(uuid.uuid4()), "10.10.1.1", "NetFlow v9", src, dst, random.randint(40000, 64000), dport, packets, octets, 6, raw_json, ts]
            rows_nf9.append(r)

        # 3. Large outbound data exfiltration (> 15 MB)
        for i in range(6):
            src = random.choice(["192.168.30.101", "192.168.10.10"])
            dst = random.choice(["52.95.110.1", "104.16.132.229", "45.155.205.233"])
            octets = random.randint(18_000_000, 85_000_000)
            packets = octets // 1380
            ts = _ts_at(random.randint(8, 22), random.randint(0, 59))
            raw_json = json.dumps({"service": "HTTPS Large Upload", "in_if": 1, "out_if": 5})
            r = [str(uuid.uuid4()), "10.10.2.1", "IPFIX", src, dst, random.randint(20000, 59000), 443, packets, octets, 6, raw_json, ts]
            rows_ipfix.append(r)

        # 4. External Malicious / Tor / C2 connections
        for i in range(8):
            src = random.choice(["192.168.30.101", "192.168.30.112"])
            dst = random.choice(["185.220.101.45", "45.155.205.233"])
            packets = random.randint(40, 850)
            octets = packets * random.randint(180, 900)
            ts = (now_dt - timedelta(minutes=random.randint(15, 600))).strftime("%Y-%m-%d %H:%M:%S")
            raw_json = json.dumps({"service": "Suspicious C2/Tor", "in_if": 2, "out_if": 6})
            r = [str(uuid.uuid4()), "10.10.2.1", "NetFlow v9", src, dst, random.randint(35000, 61000), random.choice([443, 9001, 8080]), packets, octets, 6, raw_json, ts]
            rows_nf9.append(r)

        # 5. Low risk demo flows (Unregistered devices & high port connections)
        low_targets = ["104.21.45.10", "157.240.22.35"]
        for i in range(8):
            src = random.choice(["192.168.30.220", "192.168.30.221"])
            dst = random.choice(low_targets)
            dport = random.choice([8080, 10022, 443])
            packets = random.randint(25, 320)
            octets = packets * random.randint(180, 750)
            ts = _ts_at(random.randint(9, 21), random.randint(0, 59))
            raw_json = json.dumps({"service": "Unregistered Device / High Port", "in_if": 1, "out_if": 2})
            r = [str(uuid.uuid4()), "10.10.1.1", "IPFIX", src, dst, random.randint(30000, 62000), dport, packets, octets, 6, raw_json, ts]
            rows_ipfix.append(r)

        # Ensure IP aliases for YouTube CDN so both IP alias and diagnostics look clear
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        for yt_ip, yt_name in [
            ("142.250.196.110", "YouTube / Google CDN"),
            ("172.217.160.110", "YouTube Video Stream"),
            ("216.58.200.46", "YouTube Media Server"),
            ("192.168.30.112", "Sales-Laptop-12"),
            ("192.168.30.120", "Marketing-PC-20"),
            ("192.168.30.220", "Guest-BYOD-Phone"),
            ("192.168.30.221", "Temp-Office-Laptop"),
            ("10.0.5.25", "RD-Test-Server-25")
        ]:
            try:
                ip_obj = ipaddress.ip_address(yt_ip)
                h = ip_to_hex(ip_obj)
                cur.execute(
                    "INSERT OR IGNORE INTO ip_aliases (ip, name, start_ip, end_ip, prefix_len) VALUES (?, ?, ?, ?, ?)",
                    (yt_ip, yt_name, h, h, 32)
                )
            except Exception:
                pass
        conn.commit()
        conn.close()
        load_ip_aliases()

        if rows_ipfix:
            client.insert("ipfix", rows_ipfix, cols)
        if rows_nf9:
            client.insert("netflow9", rows_nf9, cols)

        set_system_setting("scenario_mock_seeded_v3", "1")
        print(f"[SQLite Mock] Added {len(rows_ipfix) + len(rows_nf9)} scenario demo flows (YouTube work-hours, Late-night Core DB, Large Upload, Tor/C2, Low-risk Unknown Devices).")
    except Exception as e:
        print(f"[SQLite Mock] Error seeding scenario demo flows: {e}")

def seed_sqlite_mock_data(client):
    """Populate realistic NetFlow v9, IPFIX, and matched_flows mock data into SQLite if empty."""
    import random
    import uuid
    try:
        res_ipfix = client.query("SELECT COUNT() FROM ipfix")
        res_nf9 = client.query("SELECT COUNT() FROM netflow9")
        count_total = (res_ipfix.result_rows[0][0] if res_ipfix.result_rows else 0) + (res_nf9.result_rows[0][0] if res_nf9.result_rows else 0)
        if count_total > 0:
            print(f"[SQLite Mock] Existing mock flow records found ({count_total} records). Skipping seed.")
            return

        print("[SQLite Mock] Generating realistic NetFlow v9 / IPFIX & Anomaly mock data in SQLite...")
        now_dt = now_tw()

        # Seed useful IP aliases and audit rules if not present
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        sample_aliases = [
            ("192.168.10.10", "Core-DB-Server"),
            ("192.168.10.20", "ERP-Web-Backend"),
            ("192.168.10.50", "AD-Domain-Controller"),
            ("192.168.20.15", "DevOps-GitLab"),
            ("192.168.30.101", "Finance-Workstation-01"),
            ("192.168.30.105", "HR-Workstation-02"),
            ("10.10.1.1", "HQ-Core-Switch"),
            ("10.10.2.1", "Branch-FortiGate-FW"),
            ("8.8.8.8", "Google-Public-DNS"),
            ("1.1.1.1", "Cloudflare-DNS"),
            ("185.220.101.45", "Tor-Exit-Node-Suspicious"),
            ("45.155.205.233", "Known-Scanner-C2")
        ]
        for ip_str, name in sample_aliases:
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                h = ip_to_hex(ip_obj)
                cur.execute(
                    "INSERT OR IGNORE INTO ip_aliases (ip, name, start_ip, end_ip, prefix_len) VALUES (?, ?, ?, ?, ?)",
                    (ip_str, name, h, h, 32)
                )
            except Exception:
                pass

        cur.execute("SELECT COUNT(*) FROM audit_rules")
        if cur.fetchone()[0] == 0:
            sample_rules = [
                ("185.220.101.45", None, "anomaly"),
                ("45.155.205.233", None, "anomaly"),
                (None, "3389", "anomaly"),
                (None, "445", "watch"),
                ("192.168.10.10", "3306", "watch"),
                (None, "22", "watch"),
            ]
            for r_ip, r_port, r_flag in sample_rules:
                cur.execute(
                    "INSERT OR IGNORE INTO audit_rules (ip, port, flag, created_at) VALUES (?, ?, ?, ?)",
                    (r_ip, r_port, r_flag, now_dt.strftime("%Y-%m-%d %H:%M:%S"))
                )
        conn.commit()
        conn.close()
        load_ip_aliases()

        exporters = ["10.10.1.1", "10.10.2.1", "192.168.1.254"]
        internal_ips = [
            "192.168.10.10", "192.168.10.20", "192.168.10.50",
            "192.168.20.15", "192.168.30.101", "192.168.30.105",
            "192.168.30.112", "192.168.30.120", "10.0.5.25"
        ]
        external_ips = [
            "8.8.8.8", "1.1.1.1", "142.250.196.110", "104.16.132.229",
            "52.95.110.1", "20.190.151.68", "185.220.101.45", "45.155.205.233"
        ]
        common_services = [
            (443, 6, "HTTPS"),
            (80, 6, "HTTP"),
            (53, 17, "DNS"),
            (22, 6, "SSH"),
            (3306, 6, "MySQL"),
            (3389, 6, "RDP"),
            (445, 6, "SMB"),
            (123, 17, "NTP"),
            (8080, 6, "HTTP-ALT"),
            (0, 1, "ICMP")
        ]

        ipfix_rows = []
        nf9_rows = []
        cols = ["id", "exporter", "proto", "src", "dst", "sport", "dport", "packets", "octets", "protocol", "json_data", "ts"]

        random.seed(42)
        for i in range(600):
            # Spread across last 24 hours with heavier weight in recent hours
            mins_ago = int(random.triangular(1, 1440, 120))
            flow_dt = now_dt - timedelta(minutes=mins_ago, seconds=random.randint(0, 59))
            ts_str = flow_dt.strftime("%Y-%m-%d %H:%M:%S")
            exporter = random.choice(exporters)
            dport, proto_num, svc_label = random.choices(
                common_services,
                weights=[35, 18, 15, 7, 6, 4, 4, 5, 4, 2],
                k=1
            )[0]

            if random.random() < 0.65:
                src = random.choice(internal_ips)
                dst = random.choice(external_ips if dport in (80, 443, 53, 123) else internal_ips)
            else:
                src = random.choice(external_ips)
                dst = random.choice(internal_ips)

            sport = 0 if proto_num == 1 else random.randint(10240, 65000)
            packets = random.randint(5, 4500)
            octets = packets * random.randint(64, 1420)
            is_ipfix = (i % 2 == 0)
            proto_label = "IPFIX" if is_ipfix else "NetFlow v9"
            raw_json = json.dumps({
                "service": svc_label,
                "tcp_flags": "0x18" if proto_num == 6 else "0x00",
                "in_if": random.randint(1, 8),
                "out_if": random.randint(1, 8),
                "tos": 0
            })
            row = [
                str(uuid.uuid4()), exporter, proto_label, src, dst,
                sport, dport, packets, octets, proto_num, raw_json, ts_str
            ]
            if is_ipfix:
                ipfix_rows.append(row)
            else:
                nf9_rows.append(row)

        client.insert("ipfix", ipfix_rows, cols)
        client.insert("netflow9", nf9_rows, cols)
        print(f"[SQLite Mock] Seeded {len(ipfix_rows)} IPFIX and {len(nf9_rows)} NetFlow v9 records.")

        # Run initial traffic audit so Anomaly Traffic Report view is populated immediately
        run_traffic_audit((now_dt - timedelta(days=2)).strftime("%Y-%m-%d %H:%M:%S"))
    except Exception as e:
        print(f"[SQLite Mock] Error seeding mock data: {e}")

def get_system_setting(key: str, default_val: str) -> str:
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT value FROM system_settings WHERE key = ?", (key,))
        row = cur.fetchone()
        conn.close()
        return row[0] if row and row[0] is not None else default_val
    except Exception:
        return default_val

def set_system_setting(key: str, value: str):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO system_settings (key, value, updated_at) 
        VALUES (?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
    """, (key, value, now_tw_str()))
    conn.commit()
    conn.close()

# ---------------- Retention Policy & Scheduler Logic ----------------
def calculate_next_retention_run(schedule_time_str: str, last_run_str: str = "") -> datetime:
    """Calculate the next scheduled run datetime in TW_TZ."""
    now = now_tw()
    try:
        parts = schedule_time_str.split(":")
        hour, minute = int(parts[0]), int(parts[1])
    except Exception:
        hour, minute = 3, 0
    
    target_today = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    
    if now < target_today:
        return target_today
    else:
        # Check if already ran today
        if last_run_str:
            try:
                last_dt = parse_tw_datetime(last_run_str)
                if last_dt >= target_today:
                    return target_today + timedelta(days=1)
            except Exception:
                pass
        # Missed today's run or not yet run -> trigger now
        return now

def run_retention_cleanup() -> Dict[str, Any]:
    """Execute retention policy deletion in ClickHouse and update SQLite status."""
    try:
        days = int(get_system_setting("retention_days", "7"))
        current_tw = now_tw()
        cutoff_dt = current_tw - timedelta(days=days)
        cutoff_str = cutoff_dt.strftime("%Y-%m-%d %H:%M:%S")
        
        client = get_ch_client()
        client.command("ALTER TABLE ipfix DELETE WHERE ts < %(cutoff)s", parameters={"cutoff": cutoff_str})
        client.command("ALTER TABLE netflow9 DELETE WHERE ts < %(cutoff)s", parameters={"cutoff": cutoff_str})
        
        # Dynamically align ClickHouse table TTL
        try:
            client.command(f"ALTER TABLE ipfix MODIFY TTL ts + INTERVAL {days} DAY")
            client.command(f"ALTER TABLE netflow9 MODIFY TTL ts + INTERVAL {days} DAY")
        except Exception as ttl_err:
            print(f"[Retention] Warning updating ClickHouse TTL: {ttl_err}")
            
        run_ts_str = current_tw.strftime("%Y-%m-%d %H:%M:%S")
        set_system_setting("retention_last_run", run_ts_str)
        set_system_setting("retention_last_status", "success")
        msg = f"排程清理成功完成：已清除 {cutoff_str} 以前（保留 {days} 天）之流量資料。"
        set_system_setting("retention_last_message", msg)
        print(f"[Retention] {msg}", flush=True)
        return {"status": "success", "message": msg, "cutoff": cutoff_str, "last_run": run_ts_str}
    except Exception as e:
        err_msg = f"排程清理失敗: {e}"
        set_system_setting("retention_last_status", "failed")
        set_system_setting("retention_last_message", err_msg)
        print(f"[Retention] {err_msg}", flush=True)
        return {"status": "failed", "message": err_msg}

def retention_scheduler_loop():
    """Background thread checking retention schedule periodically in Asia/Taipei timezone."""
    print("[Retention] Background retention scheduler thread started.", flush=True)
    try:
        time.sleep(10)
    except Exception:
        pass
    while True:
        try:
            enabled = get_system_setting("retention_enabled", "1") == "1"
            if enabled:
                schedule_time = get_system_setting("retention_schedule_time", "03:00")
                last_run_str = get_system_setting("retention_last_run", "")
                next_run_str = get_system_setting("retention_next_run", "")
                
                if not next_run_str:
                    next_dt = calculate_next_retention_run(schedule_time, last_run_str)
                    next_run_str = next_dt.strftime("%Y-%m-%d %H:%M:%S")
                    set_system_setting("retention_next_run", next_run_str)
                
                next_run_dt = parse_tw_datetime(next_run_str)
                current_tw = now_tw()
                
                # Check if current time is greater than or equal to next scheduled run time
                if current_tw >= next_run_dt:
                    print(f"[Retention] Current TW time ({current_tw.strftime('%Y-%m-%d %H:%M:%S')}) >= Next run ({next_run_str}). Executing scheduled cleanup...", flush=True)
                    run_retention_cleanup()
                    
                    # Schedule next run for tomorrow at specified schedule_time
                    try:
                        parts = schedule_time.split(":")
                        h, m = int(parts[0]), int(parts[1])
                    except Exception:
                        h, m = 3, 0
                    next_target = current_tw.replace(hour=h, minute=m, second=0, microsecond=0) + timedelta(days=1)
                    set_system_setting("retention_next_run", next_target.strftime("%Y-%m-%d %H:%M:%S"))
        except Exception as e:
            print(f"[Retention] Scheduler error: {e}", flush=True)
            
        time.sleep(30)

@app.on_event("startup")
def on_startup():
    init_db()
    # Start background daily traffic audit scheduler
    t1 = threading.Thread(target=audit_scheduler_loop, daemon=True)
    t1.start()
    # Start background retention cleanup scheduler
    t2 = threading.Thread(target=retention_scheduler_loop, daemon=True)
    t2.start()

# ---------------- Request Models ----------------
class LoginRequest(BaseModel):
    username: str
    password: str

class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str

class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: str = "user"  # "admin" or "user"

class UpdateUserRequest(BaseModel):
    role: Optional[str] = None
    is_active: Optional[bool] = None

class ResetUserPasswordRequest(BaseModel):
    new_password: str

class AllowedCidrRequest(BaseModel):
    cidr: str
    description: Optional[str] = ""

class RetentionSettingsRequest(BaseModel):
    retention_days: int = Field(..., ge=1, le=3650)
    schedule_time: str = Field(..., pattern=r"^\d{2}:\d{2}$")
    enabled: bool = True

# ---------------- Authentication Middleware ----------------
@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path = request.url.path
    # Public routes: static assets, root page, login & me check
    if (
        path in ("/", "/favicon.ico")
        or path.startswith("/static/")
        or path in ("/api/auth/login", "/api/auth/me")
    ):
        return await call_next(request)
    
    # Any other /api/* route requires authentication
    if path.startswith("/api/"):
        user = get_current_user_from_request(request)
        if not user:
            return JSONResponse(status_code=401, content={"detail": "未授權或連線逾期，請先登入系統。"})
        request.state.user = user

    return await call_next(request)

# ---------------- Auth API Endpoints ----------------
@app.get("/api/auth/me")
def auth_me(request: Request):
    """Check current login status and user profile."""
    user = get_current_user_from_request(request)
    if not user:
        return {"authenticated": False}
    return {
        "authenticated": True,
        "user": user
    }

@app.post("/api/auth/login")
def auth_login(payload: LoginRequest, response: Response):
    """Log in user and issue session token."""
    username = payload.username.strip()
    password = payload.password
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT id, username, password_hash, salt, role, is_active, must_change_password FROM users WHERE username = ?", (username,))
    user_row = cur.fetchone()
    
    if not user_row:
        conn.close()
        raise HTTPException(status_code=401, detail="帳號或密碼錯誤。")
        
    if not user_row["is_active"]:
        conn.close()
        raise HTTPException(status_code=401, detail="此帳號已停用，請聯繫系統管理員。")
        
    computed_hash = hash_password(password, user_row["salt"])
    if computed_hash != user_row["password_hash"]:
        conn.close()
        raise HTTPException(status_code=401, detail="帳號或密碼錯誤。")
        
    # Generate session token (7-day validity)
    token = secrets.token_hex(32)
    now_dt = now_tw()
    expires_dt = now_dt + timedelta(days=7)
    now_str = now_dt.strftime("%Y-%m-%d %H:%M:%S")
    expires_str = expires_dt.strftime("%Y-%m-%d %H:%M:%S")
    
    cur.execute("""
        INSERT INTO user_sessions (token, user_id, username, role, expires_at, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (token, user_row["id"], user_row["username"], user_row["role"], expires_str, now_str))
    
    cur.execute("UPDATE users SET last_login = ? WHERE id = ?", (now_str, user_row["id"]))
    conn.commit()
    conn.close()
    
    response.set_cookie(
        key="session_token",
        value=token,
        max_age=7 * 86400,
        httponly=True,
        samesite="lax",
        secure=False
    )
    
    return {
        "status": "success",
        "token": token,
        "user": {
            "id": user_row["id"],
            "username": user_row["username"],
            "role": user_row["role"],
            "must_change_password": bool(user_row["must_change_password"])
        }
    }

@app.post("/api/auth/logout")
def auth_logout(request: Request, response: Response):
    """Log out current user and invalidate session."""
    token = request.cookies.get("session_token")
    if token:
        delete_session(token)
    response.delete_cookie("session_token")
    return {"status": "success", "message": "已成功登出。"}

@app.post("/api/auth/change-password")
def auth_change_password(payload: ChangePasswordRequest, request: Request):
    """Change current logged-in user password."""
    user = getattr(request.state, "user", None) or get_current_user_from_request(request)
    if not user:
        raise HTTPException(status_code=401, detail="請先登入。")
        
    if len(payload.new_password) < 6:
        raise HTTPException(status_code=400, detail="新密碼長度至少需為 6 個字元。")
        
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT id, password_hash, salt FROM users WHERE id = ?", (user["id"],))
    row = cur.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="找不到使用者資料。")
        
    if hash_password(payload.old_password, row["salt"]) != row["password_hash"]:
        conn.close()
        raise HTTPException(status_code=400, detail="目前舊密碼輸入不正確。")
        
    new_salt = secrets.token_hex(16)
    new_hash = hash_password(payload.new_password, new_salt)
    cur.execute("""
        UPDATE users 
        SET password_hash = ?, salt = ?, must_change_password = 0 
        WHERE id = ?
    """, (new_hash, new_salt, user["id"]))
    conn.commit()
    conn.close()
    invalidate_session_cache(user_id=user["id"])
    
    return {"status": "success", "message": "密碼已成功修改！"}

# ---------------- User Management API (Admin Only) ----------------
def verify_admin_request(request: Request):
    user = getattr(request.state, "user", None) or get_current_user_from_request(request)
    if not user or user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="權限不足，僅系統管理員可執行此管理操作。")
    return user

@app.get("/api/users")
def get_users(request: Request):
    verify_admin_request(request)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("""
        SELECT id, username, role, is_active, must_change_password, created_at, last_login 
        FROM users 
        ORDER BY id ASC
    """)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows

@app.post("/api/users")
def create_user(payload: CreateUserRequest, request: Request):
    verify_admin_request(request)
    uname = payload.username.strip()
    if not uname or len(uname) < 3:
        raise HTTPException(status_code=400, detail="帳號名稱長度至少需為 3 個字元。")
    if len(payload.password) < 6:
        raise HTTPException(status_code=400, detail="密碼長度至少需為 6 個字元。")
    role = "admin" if payload.role == "admin" else "user"
    
    salt = secrets.token_hex(16)
    pwd_hash = hash_password(payload.password, salt)
    
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO users (username, password_hash, salt, role, is_active, must_change_password, created_at)
            VALUES (?, ?, ?, ?, 1, 0, ?)
        """, (uname, pwd_hash, salt, role, now_tw_str()))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=400, detail=f"帳號 '{uname}' 已存在。")
    conn.close()
    return {"status": "success", "message": f"使用者 '{uname}' 已成功建立。"}

@app.put("/api/users/{user_id}")
def update_user(user_id: int, payload: UpdateUserRequest, request: Request):
    current_admin = verify_admin_request(request)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT id, username, role, is_active FROM users WHERE id = ?", (user_id,))
    target_user = cur.fetchone()
    if not target_user:
        conn.close()
        raise HTTPException(status_code=404, detail="找不到指定的使用者。")
        
    if target_user["username"] == "admin" and payload.is_active is False:
        conn.close()
        raise HTTPException(status_code=400, detail="不可停用預設 admin 管理員帳號。")
        
    updates = []
    params = []
    if payload.role in ("admin", "user"):
        updates.append("role = ?")
        params.append(payload.role)
    if payload.is_active is not None:
        updates.append("is_active = ?")
        params.append(1 if payload.is_active else 0)
        
    if updates:
        params.append(user_id)
        cur.execute(f"UPDATE users SET {', '.join(updates)} WHERE id = ?", params)
        conn.commit()
    conn.close()
    invalidate_session_cache(user_id=user_id)
    return {"status": "success", "message": "使用者資料更新成功。"}

@app.post("/api/users/{user_id}/reset-password")
def reset_user_password(user_id: int, payload: ResetUserPasswordRequest, request: Request):
    verify_admin_request(request)
    if len(payload.new_password) < 6:
        raise HTTPException(status_code=400, detail="新密碼長度至少需為 6 個字元。")
        
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT id, username FROM users WHERE id = ?", (user_id,))
    user = cur.fetchone()
    if not user:
        conn.close()
        raise HTTPException(status_code=404, detail="找不到指定的使用者。")
        
    new_salt = secrets.token_hex(16)
    new_hash = hash_password(payload.new_password, new_salt)
    cur.execute("UPDATE users SET password_hash = ?, salt = ?, must_change_password = 0 WHERE id = ?", (new_hash, new_salt, user_id))
    cur.execute("DELETE FROM user_sessions WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()
    invalidate_session_cache(user_id=user_id)
    return {"status": "success", "message": f"已重設使用者 '{user[1]}' 之密碼。"}

@app.delete("/api/users/{user_id}")
def delete_user(user_id: int, request: Request):
    current_admin = verify_admin_request(request)
    if current_admin["id"] == user_id:
        raise HTTPException(status_code=400, detail="不可刪除目前正在登入的管理員帳號。")
        
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT id, username FROM users WHERE id = ?", (user_id,))
    user = cur.fetchone()
    if not user:
        conn.close()
        raise HTTPException(status_code=404, detail="找不到指定的使用者。")
    if user["username"] == "admin":
        conn.close()
        raise HTTPException(status_code=400, detail="不可刪除系統預設之 admin 帳號。")
        
    cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
    cur.execute("DELETE FROM user_sessions WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()
    invalidate_session_cache(user_id=user_id)
    return {"status": "success", "message": f"使用者 '{user['username']}' 已成功刪除。"}

# ---------------- Retention & Cleanup Settings API ----------------
@app.get("/api/settings/retention")
def get_retention_settings():
    """Retrieve data retention policy configuration and scheduled execution status."""
    try:
        retention_days = int(get_system_setting("retention_days", "7"))
        schedule_time = get_system_setting("retention_schedule_time", "03:00")
        enabled = get_system_setting("retention_enabled", "1") == "1"
        last_run = get_system_setting("retention_last_run", "")
        next_run = get_system_setting("retention_next_run", "")
        last_status = get_system_setting("retention_last_status", "never")
        last_message = get_system_setting("retention_last_message", "排程尚未執行")
        
        if not next_run:
            next_dt = calculate_next_retention_run(schedule_time, last_run)
            next_run = next_dt.strftime("%Y-%m-%d %H:%M:%S")
            set_system_setting("retention_next_run", next_run)
            
        return {
            "retention_days": retention_days,
            "schedule_time": schedule_time,
            "enabled": enabled,
            "last_run": last_run or "尚未執行",
            "next_run": next_run,
            "last_status": last_status,
            "last_message": last_message
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"讀取資料保留設定失敗: {e}")

@app.post("/api/settings/retention")
def update_retention_settings(payload: RetentionSettingsRequest):
    """Update data retention days and scheduled execution time."""
    try:
        set_system_setting("retention_days", str(payload.retention_days))
        set_system_setting("retention_schedule_time", payload.schedule_time)
        set_system_setting("retention_enabled", "1" if payload.enabled else "0")
        
        # Calculate new next run
        last_run = get_system_setting("retention_last_run", "")
        next_dt = calculate_next_retention_run(payload.schedule_time, last_run)
        next_run_str = next_dt.strftime("%Y-%m-%d %H:%M:%S")
        set_system_setting("retention_next_run", next_run_str)
        
        # Update ClickHouse TTL dynamically
        client = get_ch_client()
        try:
            client.command(f"ALTER TABLE ipfix MODIFY TTL ts + INTERVAL {payload.retention_days} DAY")
            client.command(f"ALTER TABLE netflow9 MODIFY TTL ts + INTERVAL {payload.retention_days} DAY")
        except Exception as ttl_err:
            print(f"[Retention] Warning altering ClickHouse TTL: {ttl_err}")
            
        return {
            "status": "success",
            "message": f"資料保留政策已更新：保留 {payload.retention_days} 天，每日 {payload.schedule_time} 定時執行清理。",
            "retention_days": payload.retention_days,
            "schedule_time": payload.schedule_time,
            "enabled": payload.enabled,
            "next_run": next_run_str
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"更新資料保留設定失敗: {e}")

@app.post("/api/flows/cleanup/execute-retention")
def execute_retention_manual():
    """Manually trigger retention cleanup according to the configured retention days."""
    res = run_retention_cleanup()
    if res.get("status") == "failed":
        raise HTTPException(status_code=500, detail=res.get("message"))
    return res

# ---------------- Collector Allowed CIDRs API ----------------
@app.get("/api/settings/collector/cidrs")
def get_collector_cidrs():
    """Get list of allowed NetFlow / IPFIX exporter IP/CIDRs."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT id, cidr, description, created_at FROM collector_allowed_cidrs ORDER BY id ASC")
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"讀取收集器白名單失敗: {e}")

@app.post("/api/settings/collector/cidrs")
def add_collector_cidr(payload: AllowedCidrRequest):
    """Add a new CIDR or IP to the collector allowed whitelist."""
    raw_cidr = payload.cidr.strip()
    if not raw_cidr:
        raise HTTPException(status_code=400, detail="請輸入有效的 IP 或 CIDR 網段。")
    try:
        net = ipaddress.ip_network(raw_cidr, strict=False)
        normalized_cidr = str(net)
    except Exception:
        raise HTTPException(status_code=400, detail="無效的 CIDR 格式，例如 192.168.10.0/24 或 10.0.0.1")
        
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO collector_allowed_cidrs (cidr, description, created_at)
            VALUES (?, ?, ?)
        """, (normalized_cidr, payload.description.strip(), now_tw_str()))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=400, detail=f"網段 '{normalized_cidr}' 已存在於白名單中。")
    conn.close()
    return {"status": "success", "message": f"已成功新增網段 '{normalized_cidr}' 至收集器允許白名單。"}

@app.delete("/api/settings/collector/cidrs/{cidr_id}")
def delete_collector_cidr(cidr_id: int):
    """Remove a CIDR from the collector allowed whitelist."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("DELETE FROM collector_allowed_cidrs WHERE id = ?", (cidr_id,))
    conn.commit()
    conn.close()
    return {"status": "success", "message": "已從收集器白名單移除該網段。"}

exporters_cache: Tuple[float, List[str]] = (0.0, [])
exporters_cache_lock = threading.Lock()
ch_query_executor = ThreadPoolExecutor(max_workers=8)

def _run_ch_query(sql: str, params: Optional[Dict[str, Any]] = None):
    client = get_ch_client()
    return client.query(sql, parameters=params or {})

@app.get("/api/exporters")
def get_exporters():
    """Get a list of all distinct exporter IPs from both tables (cached for 30s)."""
    global exporters_cache
    now_mono = time.monotonic()
    with exporters_cache_lock:
        if now_mono - exporters_cache[0] < 30.0 and exporters_cache[1]:
            return exporters_cache[1]
    try:
        client = get_ch_client()
        result = client.query("""
            SELECT DISTINCT exporter FROM (
                SELECT DISTINCT exporter FROM ipfix WHERE ts >= now() - INTERVAL 7 DAY
                UNION ALL
                SELECT DISTINCT exporter FROM netflow9 WHERE ts >= now() - INTERVAL 7 DAY
            ) WHERE exporter IS NOT NULL AND exporter != ''
        """)
        exporters = [row[0] for row in result.result_rows]
        if not exporters:
            result = client.query("""
                SELECT DISTINCT exporter FROM (
                    SELECT DISTINCT exporter FROM ipfix
                    UNION ALL
                    SELECT DISTINCT exporter FROM netflow9
                ) WHERE exporter IS NOT NULL AND exporter != ''
            """)
            exporters = [row[0] for row in result.result_rows]
        with exporters_cache_lock:
            exporters_cache = (now_mono, exporters)
        return exporters
    except Exception as e:
        reset_ch_client()
        raise HTTPException(status_code=500, detail=str(e))
class CollectorSettingsRequest(BaseModel):
    netflow_port: int = Field(..., ge=1, le=65535, description="NetFlow v9 UDP listening port")
    ipfix_port: int = Field(..., ge=1, le=65535, description="IPFIX UDP listening port")

@app.get("/api/settings/collector")
def get_collector_settings():
    try:
        nf_port = int(get_system_setting("netflow_port", "2055"))
        ipfix_port = int(get_system_setting("ipfix_port", "4739"))
        return {
            "netflow_port": nf_port,
            "ipfix_port": ipfix_port
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load collector settings: {e}")

@app.post("/api/settings/collector")
def update_collector_settings(payload: CollectorSettingsRequest):
    if payload.netflow_port == payload.ipfix_port:
        raise HTTPException(status_code=400, detail="NetFlow port and IPFIX port cannot be the same port.")
    
    try:
        set_system_setting("netflow_port", str(payload.netflow_port))
        set_system_setting("ipfix_port", str(payload.ipfix_port))
        
        return {
            "status": "success",
            "message": f"Collector listening ports updated successfully: NetFlow v9 (UDP {payload.netflow_port}), IPFIX (UDP {payload.ipfix_port}).",
            "netflow_port": payload.netflow_port,
            "ipfix_port": payload.ipfix_port
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update collector settings: {e}")

@app.get("/api/flows")
def get_flows(
    table: str = Query("all", description="Table to search: 'all', 'ipfix', 'netflow9'"),
    ip: Optional[str] = Query(None, description="IP address or prefix (either source or destination)"),
    src: Optional[str] = Query(None, description="Source IP prefix"),
    dst: Optional[str] = Query(None, description="Destination IP prefix"),
    alias: Optional[str] = Query(None, description="IP alias search (either source or destination)"),
    port: Optional[int] = Query(None, description="Port (either source or destination)"),
    sport: Optional[int] = Query(None, description="Source port"),
    dport: Optional[int] = Query(None, description="Destination port"),
    proto: Optional[str] = Query(None, description="Protocol list, comma-separated"),
    exporter: Optional[str] = Query(None, description="Exporter IP"),
    conditions: Optional[str] = Query(None, description="JSON string of dynamic conditions list"),
    logic: str = Query("AND", description="Combination logic: 'AND' or 'OR'"),
    time_range: str = Query("all", description="Time range: '10m', '1h', '24h', '7d', 'all'"),
    start_time: Optional[str] = Query(None, description="Start UTC timestamp (YYYY-MM-DD HH:MM:SS)"),
    end_time: Optional[str] = Query(None, description="End UTC timestamp (YYYY-MM-DD HH:MM:SS)"),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    sort_by: str = Query("ts", description="Sort field: 'type', 'ts', 'exporter', 'src', 'sport', 'dst', 'dport', 'proto', 'packets', 'octets'"),
    sort_order: str = Query("desc", description="Sort order: 'asc', 'desc'"),
    group_by: Optional[str] = Query(None, description="Columns to group by, comma-separated")
):
    """Query flow records with filtering, sorting, optional dynamic grouping, and pagination."""
    try:
        client = get_ch_client()

        where_clauses = []
        params = {}

        if alias:
            where_clauses.append(build_alias_where_clause("any", alias, params, "q_alias"))

        dyn_clause = parse_conditions_where_clause(conditions, logic, params, "flow_dyn")
        if dyn_clause:
            where_clauses.append(dyn_clause)
        else:
            if ip:
                src_c = build_ip_where_clause("src", ip, params, "ip_src")
                dst_c = build_ip_where_clause("dst", ip, params, "ip_dst")
                where_clauses.append(f"({src_c} OR {dst_c})")
            if src:
                where_clauses.append(build_ip_where_clause("src", src, params, "src"))
            if dst:
                where_clauses.append(build_ip_where_clause("dst", dst, params, "dst"))
            if port is not None:
                where_clauses.append("(sport = %(port)s OR dport = %(port)s)")
                params["port"] = port
            if sport is not None:
                where_clauses.append("sport = %(sport)s")
                params["sport"] = sport
            if dport is not None:
                where_clauses.append("dport = %(dport)s")
                params["dport"] = dport
        if exporter:
            exp_parts = [e.strip() for e in exporter.split(",") if e.strip()]
            if exp_parts:
                where_clauses.append("exporter IN %(exporter_list)s")
                params["exporter_list"] = tuple(exp_parts)
        
        # Support multi-select protocols (comma-separated TCP,UDP)
        if proto:
            proto_parts = [p.strip() for p in proto.split(",") if p.strip()]
            if proto_parts:
                proto_nums = []
                has_na = False
                for p in proto_parts:
                    if p.upper() == "N/A":
                        has_na = True
                        continue
                    p_num = get_proto_number(p)
                    if p_num is not None:
                        proto_nums.append(p_num)
                
                sub_clauses = []
                if proto_nums:
                    sub_clauses.append("protocol IN %(proto_nums)s")
                    params["proto_nums"] = tuple(proto_nums)
                if has_na:
                    sub_clauses.append("protocol IS NULL")
                
                if sub_clauses:
                    where_clauses.append("(" + " OR ".join(sub_clauses) + ")")

        # Handle time range (ClickHouse timestamps)
        if start_time or end_time:
            if start_time:
                where_clauses.append("ts >= %(start_time)s")
                params["start_time"] = start_time
            if end_time:
                where_clauses.append("ts <= %(end_time)s")
                params["end_time"] = end_time
        else:
            if time_range == "10m":
                where_clauses.append("ts >= now() - INTERVAL 10 MINUTE")
            elif time_range == "1h":
                where_clauses.append("ts >= now() - INTERVAL 1 HOUR")
            elif time_range == "24h":
                where_clauses.append("ts >= now() - INTERVAL 24 HOUR")
            elif time_range == "7d":
                where_clauses.append("ts >= now() - INTERVAL 7 DAY")

        where_str = ""
        if where_clauses:
            where_str = "WHERE " + " AND ".join(where_clauses)

        # Decide source table/UNION query
        tables = [t.strip().lower() for t in table.split(",") if t.strip()] if table else []
        has_ipfix = "ipfix" in tables or not tables or "all" in tables
        has_nf9 = "netflow9" in tables or not tables or "all" in tables

        if has_ipfix and not has_nf9:
            source_select = "SELECT 'ipfix' as type, id, exporter, proto, src, dst, sport, dport, packets, octets, protocol, json_data, ts FROM ipfix"
        elif has_nf9 and not has_ipfix:
            source_select = "SELECT 'netflow9' as type, id, exporter, proto, src, dst, sport, dport, packets, octets, protocol, json_data, ts FROM netflow9"
        elif has_ipfix and has_nf9:
            source_select = """
                SELECT 'ipfix' as type, id, exporter, proto, src, dst, sport, dport, packets, octets, protocol, json_data, ts FROM ipfix
                UNION ALL
                SELECT 'netflow9' as type, id, exporter, proto, src, dst, sport, dport, packets, octets, protocol, json_data, ts FROM netflow9
            """
        else:
            source_select = "SELECT 'ipfix' as type, id, exporter, proto, src, dst, sport, dport, packets, octets, protocol, json_data, ts FROM ipfix WHERE 1=0"

        # Map sorting field to database column safely to prevent SQL injection
        sort_by_map = {
            "type": "type",
            "ts": "ts",
            "exporter": "exporter",
            "src": "src",
            "sport": "sport",
            "dst": "dst",
            "dport": "dport",
            "proto": "protocol",
            "packets": "packets",
            "octets": "octets"
        }
        db_sort_by = sort_by_map.get(sort_by.lower(), "ts")
        db_sort_order = "DESC" if sort_order.lower() == "desc" else "ASC"

        # Check for dynamic aggregation / group by
        allowed_group_cols = {
            "type": "type",
            "ts": "ts",
            "exporter": "exporter",
            "src": "src",
            "sport": "sport",
            "dst": "dst",
            "dport": "dport",
            "proto": "protocol"
        }

        cols_to_group = []
        if group_by:
            cols_to_group = [allowed_group_cols[c] for c in group_by.split(",") if c in allowed_group_cols]

        if cols_to_group:
            # Adjust sorting fields for aggregated queries to resolve ambiguity in ClickHouse
            if db_sort_by == "packets":
                db_sort_by = "sum_packets"
            elif db_sort_by == "octets":
                db_sort_by = "sum_bytes"
            elif db_sort_by == "ts" and "ts" not in cols_to_group:
                db_sort_by = "max_ts"

            # Aggregate selected fields and pad rest with NULL
            select_list = []
            for col in cols_to_group:
                select_list.append(col)
            
            select_list.append("SUM(packets) as sum_packets")
            select_list.append("SUM(octets) as sum_bytes")
            
            if "ts" not in cols_to_group:
                select_list.append("MAX(ts) as max_ts")
            
            # Pad all unselected/ungrouped fields with NULL
            all_fields = {
                "type": "type",
                "exporter": "exporter",
                "src": "src",
                "sport": "sport",
                "dst": "dst",
                "dport": "dport",
                "protocol": "protocol"
            }
            for key, col in all_fields.items():
                if col not in cols_to_group:
                    select_list.append(f"CAST(NULL, 'Nullable(String)') as {col}" if col in ("type", "exporter", "src", "dst") else f"CAST(NULL, 'Nullable(UInt16)') as {col}")
            
            select_str = ", ".join(select_list)
            group_str = "GROUP BY " + ", ".join(cols_to_group)
            
            sql = f"""
                SELECT {select_str} FROM ({source_select})
                {where_str}
                {group_str}
                ORDER BY {db_sort_by} {db_sort_order}
                LIMIT %(limit)s OFFSET %(offset)s
            """
            
            count_sql = f"""
                SELECT COUNT() as total FROM (
                    SELECT 1 FROM ({source_select})
                    {where_str}
                    {group_str}
                )
            """
        else:
            # Default unaggregated query
            sql = f"""
                SELECT * FROM ({source_select})
                {where_str}
                ORDER BY {db_sort_by} {db_sort_order}
                LIMIT %(limit)s OFFSET %(offset)s
            """
            count_sql = f"""
                SELECT COUNT() as total FROM ({source_select})
                {where_str}
            """

        # Execute count query
        count_res = client.query(count_sql, parameters=params)
        total_count = count_res.result_rows[0][0]

        # Execute data query
        params["limit"] = limit
        params["offset"] = offset
        result = client.query(sql, parameters=params)
        
        records = []
        for r_row in result.result_rows:
            r = dict(zip(result.column_names, r_row))
            # Rename aggregated aliases back to expected keys for frontend compatibility
            if "sum_packets" in r:
                r["packets"] = r["sum_packets"]
            if "sum_bytes" in r:
                r["octets"] = r["sum_bytes"]
            if "max_ts" in r:
                r["ts"] = r["max_ts"]
            # Parse json_data fields for raw detail rendering if requested
            if r.get("json_data"):
                try:
                    r["raw_details"] = json.loads(r["json_data"])
                except Exception:
                    r["raw_details"] = {}
            else:
                r["raw_details"] = {}
                
            # Attaching proto_name
            if "protocol" in r and r["protocol"] is not None:
                r["proto_name"] = PROTO_NAME_MAP.get(r["protocol"], f"UNKNOWN ({r['protocol']})")
            else:
                r["proto_name"] = "N/A"
                
            # Attaching port names from cache
            r["sport_name"] = port_aliases_cache.get(r.get("sport"), "")
            r["dport_name"] = port_aliases_cache.get(r.get("dport"), "")
            
            records.append(r)

        # Collect unique IPs to resolve
        ips_to_resolve = set()
        for r in records:
            if r.get("src"):
                ips_to_resolve.add(r["src"])
            if r.get("dst"):
                ips_to_resolve.add(r["dst"])
        
        # Get DNS and IP Aliases mappings in batch
        dns_map = get_dns_mappings(ips_to_resolve)
        alias_map = resolve_ip_aliases_batch(ips_to_resolve)
        
        # Attach domains to records (IP alias takes priority over DNS cache resolved domain)
        for r in records:
            src_ip = r.get("src")
            dst_ip = r.get("dst")
            r["src_domain"] = alias_map.get(src_ip) or dns_map.get(src_ip, "")
            r["dst_domain"] = alias_map.get(dst_ip) or dns_map.get(dst_ip, "")

        return {
            "total": total_count,
            "limit": limit,
            "offset": offset,
            "records": records
        }
    except Exception as e:
        reset_ch_client()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/flows/export")
def export_flows(
    table: str = Query("all", description="Table to search: 'all', 'ipfix', 'netflow9'"),
    ip: Optional[str] = Query(None, description="IP address or prefix (either source or destination)"),
    src: Optional[str] = Query(None, description="Source IP prefix"),
    dst: Optional[str] = Query(None, description="Destination IP prefix"),
    alias: Optional[str] = Query(None, description="IP alias search (either source or destination)"),
    port: Optional[int] = Query(None, description="Port (either source or destination)"),
    sport: Optional[int] = Query(None, description="Source port"),
    dport: Optional[int] = Query(None, description="Destination port"),
    proto: Optional[str] = Query(None, description="Protocol list, comma-separated"),
    exporter: Optional[str] = Query(None, description="Exporter IP"),
    conditions: Optional[str] = Query(None, description="JSON string of dynamic conditions list"),
    logic: str = Query("AND", description="Combination logic: 'AND' or 'OR'"),
    time_range: str = Query("all", description="Time range: '10m', '1h', '24h', '7d', 'all'"),
    start_time: Optional[str] = Query(None, description="Start UTC timestamp (YYYY-MM-DD HH:MM:SS)"),
    end_time: Optional[str] = Query(None, description="End UTC timestamp (YYYY-MM-DD HH:MM:SS)"),
    sort_by: str = Query("ts", description="Sort field: 'type', 'ts', 'exporter', 'src', 'sport', 'dst', 'dport', 'proto', 'packets', 'octets'"),
    sort_order: str = Query("desc", description="Sort order: 'asc', 'desc'"),
    group_by: Optional[str] = Query(None, description="Columns to group by, comma-separated")
):
    """Query flow records and stream them back as a CSV download."""
    import csv
    import io
    from fastapi.responses import StreamingResponse

    try:
        client = get_ch_client()

        where_clauses = []
        params = {}

        if alias:
            where_clauses.append(build_alias_where_clause("any", alias, params, "exp_alias"))

        dyn_clause = parse_conditions_where_clause(conditions, logic, params, "flow_exp_dyn")
        if dyn_clause:
            where_clauses.append(dyn_clause)
        else:
            if ip:
                src_c = build_ip_where_clause("src", ip, params, "ip_src")
                dst_c = build_ip_where_clause("dst", ip, params, "ip_dst")
                where_clauses.append(f"({src_c} OR {dst_c})")
            if src:
                where_clauses.append(build_ip_where_clause("src", src, params, "src"))
            if dst:
                where_clauses.append(build_ip_where_clause("dst", dst, params, "dst"))
            if port is not None:
                where_clauses.append("(sport = %(port)s OR dport = %(port)s)")
                params["port"] = port
            if sport is not None:
                where_clauses.append("sport = %(sport)s")
                params["sport"] = sport
            if dport is not None:
                where_clauses.append("dport = %(dport)s")
                params["dport"] = dport
        if exporter:
            exp_parts = [e.strip() for e in exporter.split(",") if e.strip()]
            if exp_parts:
                where_clauses.append("exporter IN %(exporter_list)s")
                params["exporter_list"] = tuple(exp_parts)
        
        # Support multi-select protocols (comma-separated TCP,UDP)
        if proto:
            proto_parts = [p.strip() for p in proto.split(",") if p.strip()]
            if proto_parts:
                proto_nums = []
                has_na = False
                for p in proto_parts:
                    if p.upper() == "N/A":
                        has_na = True
                        continue
                    p_num = get_proto_number(p)
                    if p_num is not None:
                        proto_nums.append(p_num)
                
                sub_clauses = []
                if proto_nums:
                    sub_clauses.append("protocol IN %(proto_nums)s")
                    params["proto_nums"] = tuple(proto_nums)
                if has_na:
                    sub_clauses.append("protocol IS NULL")
                
                if sub_clauses:
                    where_clauses.append("(" + " OR ".join(sub_clauses) + ")")

        # Handle time range (ClickHouse timestamps)
        if start_time or end_time:
            if start_time:
                where_clauses.append("ts >= %(start_time)s")
                params["start_time"] = start_time
            if end_time:
                where_clauses.append("ts <= %(end_time)s")
                params["end_time"] = end_time
        else:
            if time_range == "10m":
                where_clauses.append("ts >= now() - INTERVAL 10 MINUTE")
            elif time_range == "1h":
                where_clauses.append("ts >= now() - INTERVAL 1 HOUR")
            elif time_range == "24h":
                where_clauses.append("ts >= now() - INTERVAL 24 HOUR")
            elif time_range == "7d":
                where_clauses.append("ts >= now() - INTERVAL 7 DAY")

        where_str = ""
        if where_clauses:
            where_str = "WHERE " + " AND ".join(where_clauses)

        # Decide source table/UNION query
        tables = [t.strip().lower() for t in table.split(",") if t.strip()] if table else []
        has_ipfix = "ipfix" in tables or not tables or "all" in tables
        has_nf9 = "netflow9" in tables or not tables or "all" in tables

        if has_ipfix and not has_nf9:
            source_select = "SELECT 'ipfix' as type, id, exporter, proto, src, dst, sport, dport, packets, octets, protocol, json_data, ts FROM ipfix"
        elif has_nf9 and not has_ipfix:
            source_select = "SELECT 'netflow9' as type, id, exporter, proto, src, dst, sport, dport, packets, octets, protocol, json_data, ts FROM netflow9"
        elif has_ipfix and has_nf9:
            source_select = """
                SELECT 'ipfix' as type, id, exporter, proto, src, dst, sport, dport, packets, octets, protocol, json_data, ts FROM ipfix
                UNION ALL
                SELECT 'netflow9' as type, id, exporter, proto, src, dst, sport, dport, packets, octets, protocol, json_data, ts FROM netflow9
            """
        else:
            source_select = "SELECT 'ipfix' as type, id, exporter, proto, src, dst, sport, dport, packets, octets, protocol, json_data, ts FROM ipfix WHERE 1=0"

        # Map sorting field to database column safely to prevent SQL injection
        sort_by_map = {
            "type": "type",
            "ts": "ts",
            "exporter": "exporter",
            "src": "src",
            "sport": "sport",
            "dst": "dst",
            "dport": "dport",
            "proto": "protocol",
            "packets": "packets",
            "octets": "octets"
        }
        db_sort_by = sort_by_map.get(sort_by.lower(), "ts")
        db_sort_order = "DESC" if sort_order.lower() == "desc" else "ASC"

        # Check for dynamic aggregation / group by
        allowed_group_cols = {
            "type": "type",
            "ts": "ts",
            "exporter": "exporter",
            "src": "src",
            "sport": "sport",
            "dst": "dst",
            "dport": "dport",
            "proto": "protocol"
        }

        cols_to_group = []
        if group_by:
            cols_to_group = [allowed_group_cols[c] for c in group_by.split(",") if c in allowed_group_cols]

        if cols_to_group:
            # Adjust sorting fields for aggregated queries to resolve ambiguity in ClickHouse
            if db_sort_by == "packets":
                db_sort_by = "sum_packets"
            elif db_sort_by == "octets":
                db_sort_by = "sum_bytes"
            elif db_sort_by == "ts" and "ts" not in cols_to_group:
                db_sort_by = "max_ts"

            # Aggregate selected fields and pad rest with NULL
            select_list = []
            for col in cols_to_group:
                select_list.append(col)
            
            select_list.append("SUM(packets) as sum_packets")
            select_list.append("SUM(octets) as sum_bytes")
            
            if "ts" not in cols_to_group:
                select_list.append("MAX(ts) as max_ts")
            
            # Pad all unselected/ungrouped fields with NULL
            all_fields = {
                "type": "type",
                "exporter": "exporter",
                "src": "src",
                "sport": "sport",
                "dst": "dst",
                "dport": "dport",
                "protocol": "protocol"
            }
            for key, col in all_fields.items():
                if col not in cols_to_group:
                    select_list.append(f"CAST(NULL, 'Nullable(String)') as {col}" if col in ("type", "exporter", "src", "dst") else f"CAST(NULL, 'Nullable(UInt16)') as {col}")
            
            select_str = ", ".join(select_list)
            group_str = "GROUP BY " + ", ".join(cols_to_group)
            
            sql = f"""
                SELECT {select_str} FROM ({source_select})
                {where_str}
                {group_str}
                ORDER BY {db_sort_by} {db_sort_order}
                LIMIT 100000
            """
        else:
            # Default unaggregated query
            sql = f"""
                SELECT * FROM ({source_select})
                {where_str}
                ORDER BY {db_sort_by} {db_sort_order}
                LIMIT 100000
            """

        # Execute data query
        result = client.query(sql, parameters=params)

        # Collect unique IPs to resolve domains and aliases in batch
        ips_to_resolve = set()
        for row in result.result_rows:
            r = dict(zip(result.column_names, row))
            if r.get("src"):
                ips_to_resolve.add(r["src"])
            if r.get("dst"):
                ips_to_resolve.add(r["dst"])
        dns_map = get_dns_mappings(ips_to_resolve)
        alias_map = resolve_ip_aliases_batch(ips_to_resolve)

        # CSV generator
        def csv_generator():
            yield "\ufeff"
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Determine headers to display based on whether we are grouped or not
            # Exclude json_data from CSV export
            header = [col for col in result.column_names if col not in ("json_data", "id")]
            
            # Friendly headers mapping
            csv_headers = []
            for col in header:
                if col in ("ts", "max_ts"):
                    csv_headers.append("Timestamp (UTC)")
                elif col == "sum_packets":
                    csv_headers.append("Packets")
                elif col in ("sum_bytes", "octets"):
                    csv_headers.append("Bytes")
                elif col == "sport":
                    csv_headers.append("Source Port")
                elif col == "dport":
                    csv_headers.append("Destination Port")
                else:
                    csv_headers.append(col.capitalize())
            
            # Append resolved domains and protocol names
            if "src" in header:
                csv_headers.append("Source Domain")
            if "dst" in header:
                csv_headers.append("Destination Domain")
            if "sport" in header:
                csv_headers.append("Source Port Name")
            if "dport" in header:
                csv_headers.append("Destination Port Name")
            csv_headers.append("Protocol Name")

            writer.writerow(csv_headers)
            yield output.getvalue()
            output.seek(0)
            output.truncate(0)

            for row_vals in result.result_rows:
                r = dict(zip(result.column_names, row_vals))
                
                # Remap aggregated columns
                if "sum_packets" in r:
                    r["packets"] = r["sum_packets"]
                if "sum_bytes" in r:
                    r["octets"] = r["sum_bytes"]
                if "max_ts" in r:
                    r["ts"] = r["max_ts"]

                csv_row = []
                for col in header:
                    val = r.get(col, "")
                    if val is None:
                        val = ""
                    csv_row.append(str(val))
                
                # Add domain names (IP alias takes priority over DNS cache resolved domain)
                if "src" in r:
                    csv_row.append(alias_map.get(r["src"]) or dns_map.get(r["src"], ""))
                if "dst" in r:
                    csv_row.append(alias_map.get(r["dst"]) or dns_map.get(r["dst"], ""))
                
                # Add port names
                if "sport" in r:
                    csv_row.append(port_aliases_cache.get(r["sport"], ""))
                if "dport" in r:
                    csv_row.append(port_aliases_cache.get(r["dport"], ""))
                
                # Add protocol friendly name
                if "protocol" in r and r["protocol"] is not None:
                    proto_name = PROTO_NAME_MAP.get(r["protocol"], f"UNKNOWN ({r['protocol']})")
                else:
                    proto_name = "N/A"
                csv_row.append(proto_name)

                writer.writerow(csv_row)
                yield output.getvalue()
                output.seek(0)
                output.truncate(0)

        filename = f"flow_export_{now_tw().strftime('%Y%m%d_%H%M%S')}.csv"
        return StreamingResponse(
            csv_generator(),
            media_type="text/csv",
            headers={
                "Content-Disposition": f"attachment; filename={filename}"
            }
        )

    except Exception as e:
        reset_ch_client()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/stats")
def get_stats(
    table: str = Query("all", description="Table to search: 'all', 'ipfix', 'netflow9'"),
    ip: Optional[str] = Query(None, description="IP address or prefix (either source or destination)"),
    src: Optional[str] = Query(None, description="Source IP prefix"),
    dst: Optional[str] = Query(None, description="Destination IP prefix"),
    alias: Optional[str] = Query(None, description="IP alias search (either source or destination)"),
    port: Optional[int] = Query(None, description="Port (either source or destination)"),
    sport: Optional[int] = Query(None, description="Source port"),
    dport: Optional[int] = Query(None, description="Destination port"),
    proto: Optional[str] = Query(None, description="Protocol list, comma-separated"),
    exporter: Optional[str] = Query(None, description="Exporter IP"),
    conditions: Optional[str] = Query(None, description="JSON string of dynamic conditions list"),
    logic: str = Query("AND", description="Combination logic: 'AND' or 'OR'"),
    time_range: str = Query("24h", description="Time range for stats: '1h', '24h', '7d', 'all'"),
    start_time: Optional[str] = Query(None, description="Start UTC timestamp (YYYY-MM-DD HH:MM:SS)"),
    end_time: Optional[str] = Query(None, description="End UTC timestamp (YYYY-MM-DD HH:MM:SS)")
):
    """Get dashboard overview statistics and chart data."""
    try:
        client = get_ch_client()

        # Build dynamic where clauses
        where_clauses = []
        params = {}

        if alias:
            where_clauses.append(build_alias_where_clause("any", alias, params, "s_alias"))

        if exporter:
            exp_parts = [e.strip() for e in exporter.split(",") if e.strip()]
            if exp_parts:
                where_clauses.append("exporter IN %(exporter_list)s")
                params["exporter_list"] = tuple(exp_parts)

        dyn_clause = parse_conditions_where_clause(conditions, logic, params, "stats_dyn")
        if dyn_clause:
            where_clauses.append(dyn_clause)
        else:
            if ip:
                src_c = build_ip_where_clause("src", ip, params, "ip_src")
                dst_c = build_ip_where_clause("dst", ip, params, "ip_dst")
                where_clauses.append(f"({src_c} OR {dst_c})")
            if src:
                where_clauses.append(build_ip_where_clause("src", src, params, "src"))
            if dst:
                where_clauses.append(build_ip_where_clause("dst", dst, params, "dst"))
            if port is not None:
                where_clauses.append("(sport = %(port)s OR dport = %(port)s)")
                params["port"] = port
            if sport is not None:
                where_clauses.append("sport = %(sport)s")
                params["sport"] = sport
            if dport is not None:
                where_clauses.append("dport = %(dport)s")
                params["dport"] = dport

        # Handle Protocol checklist
        if proto:
            p_list = [p.strip() for p in proto.split(",") if p.strip()]
            if p_list:
                proto_nums = []
                has_na = False
                for p in p_list:
                    if p.upper() == "N/A":
                        has_na = True
                        continue
                    p_num = get_proto_number(p)
                    if p_num is not None:
                        proto_nums.append(p_num)
                
                sub_clauses = []
                if proto_nums:
                    sub_clauses.append("protocol IN %(proto_nums)s")
                    params["proto_nums"] = tuple(proto_nums)
                if has_na:
                    sub_clauses.append("protocol IS NULL")
                
                if sub_clauses:
                    where_clauses.append("(" + " OR ".join(sub_clauses) + ")")

        # Handle time range (ClickHouse timestamps)
        if start_time or end_time:
            if start_time:
                where_clauses.append("ts >= %(start_time)s")
                params["start_time"] = start_time
            if end_time:
                where_clauses.append("ts <= %(end_time)s")
                params["end_time"] = end_time
        else:
            if time_range == "1h":
                where_clauses.append("ts >= now() - INTERVAL 1 HOUR")
            elif time_range == "24h":
                where_clauses.append("ts >= now() - INTERVAL 24 HOUR")
            elif time_range == "7d":
                where_clauses.append("ts >= now() - INTERVAL 7 DAY")

        where_str = ""
        if where_clauses:
            where_str = "WHERE " + " AND ".join(where_clauses)

        # Decide source table/UNION query
        tables = [t.strip().lower() for t in table.split(",") if t.strip()] if table else []
        has_ipfix = "ipfix" in tables or not tables or "all" in tables
        has_nf9 = "netflow9" in tables or not tables or "all" in tables

        if has_ipfix and not has_nf9:
            combined_flows = f"SELECT exporter, src, dst, sport, dport, packets, octets, protocol, ts FROM ipfix {where_str}"
        elif has_nf9 and not has_ipfix:
            combined_flows = f"SELECT exporter, src, dst, sport, dport, packets, octets, protocol, ts FROM netflow9 {where_str}"
        elif has_ipfix and has_nf9:
            combined_flows = f"""
                SELECT exporter, src, dst, sport, dport, packets, octets, protocol, ts FROM ipfix {where_str}
                UNION ALL
                SELECT exporter, src, dst, sport, dport, packets, octets, protocol, ts FROM netflow9 {where_str}
            """
        else:
            combined_flows = f"SELECT exporter, src, dst, sport, dport, packets, octets, protocol, ts FROM ipfix WHERE 1=0"

        # Determine time bin grouping function before firing concurrent queries
        if start_time and end_time:
            try:
                from datetime import datetime as dt
                d1 = dt.strptime(start_time, "%Y-%m-%d %H:%M:%S")
                d2 = dt.strptime(end_time, "%Y-%m-%d %H:%M:%S")
                diff = (d2 - d1).total_seconds()
                if diff < 7200: # < 2 hours
                    time_format = "%Y-%m-%d %H:%M:00"
                    ch_group_fn = "toStartOfMinute(ts + INTERVAL 8 HOUR)"
                elif diff < 172800: # < 48 hours
                    time_format = "%Y-%m-%d %H:00:00"
                    ch_group_fn = "toStartOfHour(ts + INTERVAL 8 HOUR)"
                else:
                    time_format = "%Y-%m-%d"
                    ch_group_fn = "toStartOfDay(ts + INTERVAL 8 HOUR)"
            except Exception:
                time_format = "%Y-%m-%d"
                ch_group_fn = "toStartOfDay(ts + INTERVAL 8 HOUR)"
        else:
            if time_range == "1h":
                time_format = "%Y-%m-%d %H:%M:00"
                ch_group_fn = "toStartOfMinute(ts + INTERVAL 8 HOUR)"
            elif time_range == "24h":
                time_format = "%Y-%m-%d %H:00:00"
                ch_group_fn = "toStartOfHour(ts + INTERVAL 8 HOUR)"
            elif time_range == "7d":
                time_format = "%Y-%m-%d"
                ch_group_fn = "toStartOfDay(ts + INTERVAL 8 HOUR)"
            else:
                time_format = "%Y-%m-%d"
                ch_group_fn = "toStartOfDay(ts + INTERVAL 8 HOUR)"

        # Execute aggregation queries concurrently across ClickHouse thread-local clients
        q_totals = f"SELECT COUNT() as total_flows, SUM(packets) as total_packets, SUM(octets) as total_bytes FROM ({combined_flows})"
        q_top_src = f"SELECT src, SUM(octets) as bytes, SUM(packets) as packets, COUNT() as flows FROM ({combined_flows}) GROUP BY src ORDER BY bytes DESC LIMIT 10"
        q_top_dst = f"SELECT dst, SUM(octets) as bytes, SUM(packets) as packets, COUNT() as flows FROM ({combined_flows}) GROUP BY dst ORDER BY bytes DESC LIMIT 10"
        q_top_exp = f"SELECT exporter, SUM(octets) as bytes, COUNT() as flows FROM ({combined_flows}) GROUP BY exporter ORDER BY flows DESC LIMIT 5"
        q_protos = f"SELECT protocol, COUNT() as count, SUM(octets) as bytes FROM ({combined_flows}) GROUP BY protocol ORDER BY count DESC"
        q_time = f"SELECT {ch_group_fn} as time_bin, SUM(octets) as bytes, SUM(packets) as packets, COUNT() as flows FROM ({combined_flows}) GROUP BY time_bin ORDER BY time_bin ASC"
        q_sport = f"SELECT sport, SUM(octets) as bytes, SUM(packets) as packets, COUNT() as flows FROM ({combined_flows}) WHERE sport IS NOT NULL GROUP BY sport ORDER BY bytes DESC LIMIT 10"
        q_dport = f"SELECT dport, SUM(octets) as bytes, SUM(packets) as packets, COUNT() as flows FROM ({combined_flows}) WHERE dport IS NOT NULL GROUP BY dport ORDER BY bytes DESC LIMIT 10"
        q_top_pairs = f"SELECT src, dst, SUM(octets) as bytes, COUNT() as flows FROM ({combined_flows}) GROUP BY src, dst ORDER BY bytes DESC LIMIT 1000"

        f_totals = ch_query_executor.submit(_run_ch_query, q_totals, params)
        f_top_src = ch_query_executor.submit(_run_ch_query, q_top_src, params)
        f_top_dst = ch_query_executor.submit(_run_ch_query, q_top_dst, params)
        f_top_exp = ch_query_executor.submit(_run_ch_query, q_top_exp, params)
        f_protos = ch_query_executor.submit(_run_ch_query, q_protos, params)
        f_time = ch_query_executor.submit(_run_ch_query, q_time, params)
        f_sport = ch_query_executor.submit(_run_ch_query, q_sport, params)
        f_dport = ch_query_executor.submit(_run_ch_query, q_dport, params)
        f_top_pairs = ch_query_executor.submit(_run_ch_query, q_top_pairs, params)

        # 1. Overall Totals
        res = f_totals.result()
        totals = dict(zip(res.column_names, res.result_rows[0]))
        total_flows = totals["total_flows"] or 0
        total_packets = totals["total_packets"] or 0
        total_bytes = totals["total_bytes"] or 0

        # 2. Top Sources by bytes
        res = f_top_src.result()
        top_sources = [dict(zip(res.column_names, r)) for r in res.result_rows]

        # 3. Top Destinations by bytes
        res = f_top_dst.result()
        top_destinations = [dict(zip(res.column_names, r)) for r in res.result_rows]

        # 4. Top Exporters
        res = f_top_exp.result()
        top_exporters = [dict(zip(res.column_names, r)) for r in res.result_rows]

        # 5. Protocols share
        res = f_protos.result()
        raw_protocols = [dict(zip(res.column_names, r)) for r in res.result_rows]
        protocols = []
        for p in raw_protocols:
            p_num = p["protocol"]
            p_name = PROTO_NAME_MAP.get(p_num, f"OTHER ({p_num})" if p_num is not None else "N/A")
            protocols.append({
                "protocol": p_num,
                "name": p_name,
                "count": p["count"],
                "bytes": p["bytes"] or 0
            })

        # 6. Traffic over time
        res = f_time.result()
        traffic_over_time = []
        for r_row in res.result_rows:
            r = dict(zip(res.column_names, r_row))
            tb = r["time_bin"]
            if isinstance(tb, datetime):
                r["time_bin"] = tb.strftime(time_format)
            traffic_over_time.append(r)

        # 7. Top Source Ports by bytes
        res = f_sport.result()
        top_source_ports = [dict(zip(res.column_names, r)) for r in res.result_rows]

        # 8. Top Destination Ports by bytes
        res = f_dport.result()
        top_destination_ports = [dict(zip(res.column_names, r)) for r in res.result_rows]

        # Collect unique IPs in stats
        stats_ips = set()
        for item in top_sources:
            if item.get("src"):
                stats_ips.add(item["src"])
        for item in top_destinations:
            if item.get("dst"):
                stats_ips.add(item["dst"])
        
        # Get DNS and IP Aliases mappings in batch
        stats_dns_map = get_dns_mappings(stats_ips)
        alias_map = resolve_ip_aliases_batch(stats_ips)
        
        # Attach resolved domains and aliases
        for item in top_sources:
            ip = item.get("src")
            item["domain"] = alias_map.get(ip) or stats_dns_map.get(ip, "")
        for item in top_destinations:
            ip = item.get("dst")
            item["domain"] = alias_map.get(ip) or stats_dns_map.get(ip, "")

        # Attach port aliases
        for item in top_source_ports:
            item["port_name"] = port_aliases_cache.get(item.get("sport"), "") if item.get("sport") is not None else ""
        for item in top_destination_ports:
            item["port_name"] = port_aliases_cache.get(item.get("dport"), "") if item.get("dport") is not None else ""

        # 9. Top IP Aliases (Bidirectional aggregated, deduplicated if both endpoints share same alias)
        res_pairs = f_top_pairs.result()
        pair_rows = [dict(zip(res_pairs.column_names, r)) for r in res_pairs.result_rows]
        pair_ips = set()
        for r in pair_rows:
            if r.get("src"):
                pair_ips.add(r["src"])
            if r.get("dst"):
                pair_ips.add(r["dst"])
        alias_map_pairs = resolve_ip_aliases_batch(pair_ips)
        alias_aggregated = {}
        for r in pair_rows:
            s_alias = alias_map_pairs.get(r.get("src"))
            d_alias = alias_map_pairs.get(r.get("dst"))
            matched_aliases = set()
            if s_alias:
                matched_aliases.add(s_alias)
            if d_alias:
                matched_aliases.add(d_alias)
            for al in matched_aliases:
                if al not in alias_aggregated:
                    alias_aggregated[al] = {"name": al, "bytes": 0, "flows": 0}
                alias_aggregated[al]["bytes"] += (r.get("bytes") or 0)
                alias_aggregated[al]["flows"] += (r.get("flows") or 0)
        top_aliases = sorted(alias_aggregated.values(), key=lambda x: x["bytes"], reverse=True)[:10]

        return {
            "total_flows": total_flows,
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "top_sources": top_sources,
            "top_destinations": top_destinations,
            "top_exporters": top_exporters,
            "protocols": protocols,
            "top_aliases": top_aliases,
            "traffic_over_time": traffic_over_time,
            "top_source_ports": top_source_ports,
            "top_destination_ports": top_destination_ports
        }
    except Exception as e:
        reset_ch_client()
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/flows/delete")
def delete_flows_before(before: str = Query(..., description="Delete data before this datetime, format: YYYY-MM-DD or YYYY-MM-DD HH:MM:SS")):
    try:
        cutoff_dt = parse_tw_datetime(before)
        cutoff_str = cutoff_dt.strftime("%Y-%m-%d %H:%M:%S")
        
        client = get_ch_client()
        client.command("ALTER TABLE ipfix DELETE WHERE ts < %(cutoff)s", parameters={"cutoff": cutoff_str})
        client.command("ALTER TABLE netflow9 DELETE WHERE ts < %(cutoff)s", parameters={"cutoff": cutoff_str})
        
        now_str = now_tw_str()
        set_system_setting("retention_last_run", now_str)
        set_system_setting("retention_last_status", "success")
        msg = f"已成功佇列刪除在 {cutoff_str} (台灣時間) 之前的流量記錄。"
        set_system_setting("retention_last_message", f"手動清理：{msg}")
        
        return {"status": "success", "message": msg, "last_run": now_str}
    except Exception as e:
        reset_ch_client()
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/ports/aliases")
def get_port_aliases():
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT port, name FROM port_aliases ORDER BY port ASC")
        rows = cur.fetchall()
        conn.close()
        return [{"port": r["port"], "name": r["name"]} for r in rows]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/ports/aliases")
def set_port_alias(port: int, name: str):
    name = name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Name cannot be empty")
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("INSERT OR REPLACE INTO port_aliases (port, name) VALUES (?, ?)", (port, name))
        conn.commit()
        conn.close()
        load_port_aliases() # Refresh cache
        return {"status": "success", "message": f"Port {port} named as {name}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/ports/aliases/{port}")
def delete_port_alias(port: int):
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("DELETE FROM port_aliases WHERE port = ?", (port,))
        conn.commit()
        conn.close()
        load_port_aliases() # Refresh cache
        return {"status": "success", "message": f"Deleted alias for port {port}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/ips/aliases")
def get_ip_aliases(
    limit: int = Query(25, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    q: Optional[str] = Query(None)
):
    global ip_aliases_total_count_cache
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        
        where_clause = ""
        params = []
        if q and q.strip():
            q_clean = f"%{q.strip()}%"
            where_clause = "WHERE ip LIKE ? OR name LIKE ?"
            params = [q_clean, q_clean]
            cur.execute(f"SELECT COUNT(*) FROM ip_aliases {where_clause}", params)
            total_count = cur.fetchone()[0]
        else:
            if ip_aliases_total_count_cache is not None:
                total_count = ip_aliases_total_count_cache
            else:
                cur.execute("SELECT COUNT(*) FROM ip_aliases")
                total_count = cur.fetchone()[0]
                ip_aliases_total_count_cache = total_count
        
        params.extend([limit, offset])
        cur.execute(f"SELECT ip, name FROM ip_aliases {where_clause} ORDER BY ip ASC LIMIT ? OFFSET ?", params)
        rows = cur.fetchall()
        conn.close()
        
        return {
            "total": total_count,
            "limit": limit,
            "offset": offset,
            "records": [{"ip": r["ip"], "name": r["name"]} for r in rows]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/ips/aliases")
def set_ip_alias(ip: str, name: str):
    ip = ip.strip()
    name = name.strip()
    if not ip or not name:
        raise HTTPException(status_code=400, detail="IP and Name cannot be empty")
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        start_ip, end_ip, prefix_len = None, None, None
        try:
            if "/" in ip:
                net = ipaddress.ip_network(ip, strict=False)
                start_ip = ip_to_hex(net.network_address)
                end_ip = ip_to_hex(net.broadcast_address)
                prefix_len = net.prefixlen
            else:
                ip_obj = ipaddress.ip_address(ip)
                start_ip = ip_to_hex(ip_obj)
                end_ip = start_ip
                prefix_len = 32 if ip_obj.version == 4 else 128
        except Exception:
            pass
            
        cur.execute("INSERT OR REPLACE INTO ip_aliases (ip, name, start_ip, end_ip, prefix_len) VALUES (?, ?, ?, ?, ?)",
                    (ip, name, start_ip, end_ip, prefix_len))
        conn.commit()
        conn.close()
        load_ip_aliases() # Refresh cache
        return {"status": "success", "message": f"IP {ip} named as {name}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/ips/aliases/{ip:path}")
def delete_ip_alias(ip: str):
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("DELETE FROM ip_aliases WHERE ip = ?", (ip,))
        conn.commit()
        conn.close()
        load_ip_aliases() # Refresh cache
        return {"status": "success", "message": f"Deleted alias for IP {ip}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/aliases/export")
def export_aliases():
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        
        # Get IP aliases
        cur.execute("SELECT ip, name FROM ip_aliases ORDER BY ip ASC")
        ip_rows = cur.fetchall()
        ips = [{"ip": r["ip"], "name": r["name"]} for r in ip_rows]
        
        # Get Port aliases
        cur.execute("SELECT port, name FROM port_aliases ORDER BY port ASC")
        port_rows = cur.fetchall()
        ports = [{"port": r["port"], "name": r["name"]} for r in port_rows]
        
        conn.close()
        return {
            "ip_aliases": ips,
            "port_aliases": ports
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/aliases/import")
def import_aliases(payload: Dict[str, Any]):
    ip_aliases = payload.get("ip_aliases", [])
    port_aliases = payload.get("port_aliases", [])
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        
        imported_ips = 0
        imported_ports = 0
        
        # Insert IP aliases
        for item in ip_aliases:
            if not isinstance(item, dict):
                continue
            ip = item.get("ip")
            name = item.get("name")
            if not ip or not name:
                continue
            ip = str(ip).strip()
            name = str(name).strip()
            if ip and name:
                start_ip, end_ip, prefix_len = None, None, None
                try:
                    if "/" in ip:
                        net = ipaddress.ip_network(ip, strict=False)
                        start_ip = ip_to_hex(net.network_address)
                        end_ip = ip_to_hex(net.broadcast_address)
                        prefix_len = net.prefixlen
                    else:
                        ip_obj = ipaddress.ip_address(ip)
                        start_ip = ip_to_hex(ip_obj)
                        end_ip = start_ip
                        prefix_len = 32 if ip_obj.version == 4 else 128
                except Exception:
                    pass
                cur.execute("INSERT OR REPLACE INTO ip_aliases (ip, name, start_ip, end_ip, prefix_len) VALUES (?, ?, ?, ?, ?)",
                            (ip, name, start_ip, end_ip, prefix_len))
                imported_ips += 1
                
        # Insert Port aliases
        for item in port_aliases:
            if not isinstance(item, dict):
                continue
            port = item.get("port")
            name = item.get("name")
            if port is None or not name:
                continue
            try:
                port_val = int(port)
                if port_val < 1 or port_val > 65535:
                    continue
            except ValueError:
                continue
            name = str(name).strip()
            if name:
                cur.execute("INSERT OR REPLACE INTO port_aliases (port, name) VALUES (?, ?)", (port_val, name))
                imported_ports += 1
                
        conn.commit()
        conn.close()
        
        # Refresh in-memory caches
        load_ip_aliases()
        load_port_aliases()
        
        return {
            "status": "success",
            "message": f"Successfully imported {imported_ips} IP aliases and {imported_ports} Port aliases (overwrote duplicate keys)."
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/aliases/clear")
def clear_all_aliases():
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("DELETE FROM ip_aliases")
        cur.execute("DELETE FROM port_aliases")
        conn.commit()
        conn.close()
        
        # Refresh in-memory caches
        load_ip_aliases()
        load_port_aliases()
        
        return {
            "status": "success",
            "message": "All custom IP and Port aliases cleared successfully."
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Helper validation functions for Audit System
def validate_ip_or_cidr(ip_str: str) -> bool:
    if not ip_str:
        return True
    val = ip_str.strip().lower()
    if val in ("internal", "external"):
        return True
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        pass
    try:
        ipaddress.ip_network(ip_str, strict=False)
        return True
    except ValueError:
        pass
    return False

def validate_port_or_range(port_str: str) -> bool:
    if not port_str:
        return True
    if '-' in port_str:
        parts = port_str.split('-')
        if len(parts) != 2:
            return False
        try:
            start = int(parts[0].strip())
            end = int(parts[1].strip())
            return 0 <= start <= 65535 and 0 <= end <= 65535 and start <= end
        except ValueError:
            return False
    else:
        try:
            val = int(port_str.strip())
            return 0 <= val <= 65535
        except ValueError:
            return False

INTRANET_NETWORKS = [
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("10.0.0.0/8")
]

def is_internal_ip(ip_obj) -> bool:
    for net in INTRANET_NETWORKS:
        if ip_obj in net:
            return True
    return False

def parse_rule_criteria(rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    parsed = []
    for r in rules:
        rule_obj = {
            "id": r["id"],
            "ip_raw": r["ip"],
            "port_raw": r["port"],
            "flag": r["flag"],
            "ip_obj": None,
            "port_obj": None
        }
        if r["ip"]:
            ip_val = r["ip"].strip().lower()
            if ip_val in ("internal", "external"):
                rule_obj["ip_obj"] = ip_val
            else:
                try:
                    if '/' in r["ip"]:
                        rule_obj["ip_obj"] = ipaddress.ip_network(r["ip"], strict=False)
                    else:
                        rule_obj["ip_obj"] = ipaddress.ip_address(r["ip"])
                except Exception:
                    pass
        if r["port"]:
            if '-' in r["port"]:
                parts = r["port"].split('-')
                rule_obj["port_obj"] = (int(parts[0]), int(parts[1]))
            else:
                rule_obj["port_obj"] = int(r["port"])
        parsed.append(rule_obj)
    return parsed

def check_flow_match(flow: Dict[str, Any], parsed_rules: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    flow_src_ip = None
    flow_dst_ip = None
    try:
        flow_src_ip = ipaddress.ip_address(flow.get("src", ""))
    except Exception:
        pass
    try:
        flow_dst_ip = ipaddress.ip_address(flow.get("dst", ""))
    except Exception:
        pass
        
    flow_sport = flow.get("sport")
    flow_dport = flow.get("dport")
    
    for rule in parsed_rules:
        ip_matched = True
        port_matched = True
        
        # IP match
        if rule["ip_obj"]:
            ip_matched = False
            rule_ip = rule["ip_obj"]
            # Check src IP
            if flow_src_ip:
                if rule_ip == "internal":
                    if is_internal_ip(flow_src_ip):
                        ip_matched = True
                elif rule_ip == "external":
                    if not is_internal_ip(flow_src_ip):
                        ip_matched = True
                elif isinstance(rule_ip, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                    if flow_src_ip == rule_ip:
                        ip_matched = True
                else: # Network
                    if flow_src_ip in rule_ip:
                        ip_matched = True
            # Check dst IP
            if not ip_matched and flow_dst_ip:
                if rule_ip == "internal":
                    if is_internal_ip(flow_dst_ip):
                        ip_matched = True
                elif rule_ip == "external":
                    if not is_internal_ip(flow_dst_ip):
                        ip_matched = True
                elif isinstance(rule_ip, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                    if flow_dst_ip == rule_ip:
                        ip_matched = True
                else: # Network
                    if flow_dst_ip in rule_ip:
                        ip_matched = True
                        
        # Port match
        if rule["port_obj"]:
            port_matched = False
            # Check sport
            if flow_sport is not None:
                if isinstance(rule["port_obj"], tuple):
                    if rule["port_obj"][0] <= flow_sport <= rule["port_obj"][1]:
                        port_matched = True
                else:
                    if flow_sport == rule["port_obj"]:
                        port_matched = True
            # Check dport
            if not port_matched and flow_dport is not None:
                if isinstance(rule["port_obj"], tuple):
                    if rule["port_obj"][0] <= flow_dport <= rule["port_obj"][1]:
                        port_matched = True
                else:
                    if flow_dport == rule["port_obj"]:
                        port_matched = True
                        
        if ip_matched and port_matched:
            return rule
            
    return None

def build_rule_sql_condition(rule: Dict[str, Any], idx: int, params: Dict[str, Any]) -> str:
    """
    Build a ClickHouse SQL boolean condition for a single audit rule.
    Supports:
      - IP: internal, external, CIDR (e.g. 192.168.1.0/24), single IP (e.g. 10.0.0.1)
      - Port: single port (e.g. 80), port range (e.g. 80-443)
    Rule matches if: (IP match) AND (Port match)
    """
    sub_conds = []
    
    # 1. IP condition
    ip_raw = rule.get("ip")
    if ip_raw:
        ip_str = str(ip_raw).strip()
        ip_lower = ip_str.lower()
        safe_src = "if(isIPv4String(src) OR isIPv6String(src), src, '0.0.0.0')"
        safe_dst = "if(isIPv4String(dst) OR isIPv6String(dst), dst, '0.0.0.0')"
        if ip_lower == "internal":
            internal_nets = f"isIPAddressInRange({safe_src}, '10.0.0.0/8') OR isIPAddressInRange({safe_src}, '172.16.0.0/12') OR isIPAddressInRange({safe_src}, '192.168.0.0/16')"
            internal_netd = f"isIPAddressInRange({safe_dst}, '10.0.0.0/8') OR isIPAddressInRange({safe_dst}, '172.16.0.0/12') OR isIPAddressInRange({safe_dst}, '192.168.0.0/16')"
            ip_cond = f"(((isIPv4String(src) OR isIPv6String(src)) AND ({internal_nets})) OR ((isIPv4String(dst) OR isIPv6String(dst)) AND ({internal_netd})))"
            sub_conds.append(ip_cond)
        elif ip_lower == "external":
            ext_nets = f"NOT (isIPAddressInRange({safe_src}, '10.0.0.0/8') OR isIPAddressInRange({safe_src}, '172.16.0.0/12') OR isIPAddressInRange({safe_src}, '192.168.0.0/16'))"
            ext_netd = f"NOT (isIPAddressInRange({safe_dst}, '10.0.0.0/8') OR isIPAddressInRange({safe_dst}, '172.16.0.0/12') OR isIPAddressInRange({safe_dst}, '192.168.0.0/16'))"
            ip_cond = f"(((isIPv4String(src) OR isIPv6String(src)) AND ({ext_nets})) OR ((isIPv4String(dst) OR isIPv6String(dst)) AND ({ext_netd})))"
            sub_conds.append(ip_cond)
        elif "/" in ip_str:
            p_name = f"rule_{idx}_cidr"
            params[p_name] = ip_str
            ip_cond = f"(((isIPv4String(src) OR isIPv6String(src)) AND isIPAddressInRange({safe_src}, %({p_name})s)) OR ((isIPv4String(dst) OR isIPv6String(dst)) AND isIPAddressInRange({safe_dst}, %({p_name})s)))"
            sub_conds.append(ip_cond)
        else:
            p_name = f"rule_{idx}_ip"
            params[p_name] = ip_str
            ip_cond = f"(src = %({p_name})s OR dst = %({p_name})s)"
            sub_conds.append(ip_cond)

    # 2. Port condition
    port_raw = rule.get("port")
    if port_raw is not None and str(port_raw).strip() != "":
        port_str = str(port_raw).strip()
        if "-" in port_str:
            parts = port_str.split("-")
            p_start_name = f"rule_{idx}_pstart"
            p_end_name = f"rule_{idx}_pend"
            params[p_start_name] = int(parts[0].strip())
            params[p_end_name] = int(parts[1].strip())
            port_cond = f"((sport >= %({p_start_name})s AND sport <= %({p_end_name})s) OR (dport >= %({p_start_name})s AND dport <= %({p_end_name})s))"
            sub_conds.append(port_cond)
        else:
            p_name = f"rule_{idx}_port"
            params[p_name] = int(port_str)
            port_cond = f"(sport = %({p_name})s OR dport = %({p_name})s)"
            sub_conds.append(port_cond)

    if not sub_conds:
        return "1"
    elif len(sub_conds) == 1:
        return sub_conds[0]
    else:
        return f"({' AND '.join(sub_conds)})"

def generate_audit_insert_sql(
    table_name: str,
    rules: List[Dict[str, Any]],
    start_time_str: str,
    end_time_str: str,
    current_run_str: str
) -> Tuple[str, str, Dict[str, Any]]:
    params: Dict[str, Any] = {
        "start": start_time_str,
        "end": end_time_str,
        "match_ts": current_run_str
    }
    
    rule_conds = []
    multi_if_ip = []
    multi_if_port = []
    multi_if_flag = []
    
    for idx, r in enumerate(rules):
        cond = build_rule_sql_condition(r, idx, params)
        rule_conds.append(cond)
        
        # rule_ip param
        ip_val = r.get("ip")
        if ip_val:
            p_ip = f"r_{idx}_ip_val"
            params[p_ip] = str(ip_val)
            multi_if_ip.append(f"{cond}, %({p_ip})s")
        else:
            multi_if_ip.append(f"{cond}, CAST(NULL, 'Nullable(String)')")
            
        # rule_port param
        port_val = r.get("port")
        if port_val is not None and str(port_val).strip() != "":
            p_port = f"r_{idx}_port_val"
            params[p_port] = str(port_val)
            multi_if_port.append(f"{cond}, %({p_port})s")
        else:
            multi_if_port.append(f"{cond}, CAST(NULL, 'Nullable(String)')")
            
        # rule_flag param
        flag_val = r.get("flag", "anomaly")
        p_flag = f"r_{idx}_flag_val"
        params[p_flag] = flag_val
        multi_if_flag.append(f"{cond}, %({p_flag})s")
        
    combined_cond = " OR ".join(f"({c})" for c in rule_conds)
    
    # Build multiIf expressions
    multi_ip_sql = f"multiIf({', '.join(multi_if_ip)}, CAST(NULL, 'Nullable(String)'))"
    multi_port_sql = f"multiIf({', '.join(multi_if_port)}, CAST(NULL, 'Nullable(String)'))"
    multi_flag_sql = f"multiIf({', '.join(multi_if_flag)}, 'anomaly')"
    
    count_sql = f"""
        SELECT count()
        FROM {table_name}
        WHERE ts >= %(start)s AND ts < %(end)s
          AND ({combined_cond})
    """.strip()
    
    insert_sql = f"""
        INSERT INTO matched_flows (
            id, exporter, proto, src, dst, sport, dport, packets, octets, protocol, json_data, ts,
            rule_ip, rule_port, match_flag, match_ts
        )
        SELECT
            id, exporter, proto, src, dst, sport, dport, packets, octets, protocol, json_data, ts,
            {multi_ip_sql} AS rule_ip,
            {multi_port_sql} AS rule_port,
            {multi_flag_sql} AS match_flag,
            toDateTime(%(match_ts)s) AS match_ts
        FROM {table_name}
        WHERE ts >= %(start)s AND ts < %(end)s
          AND ({combined_cond})
    """.strip()
    
    return count_sql, insert_sql, params

def sync_all_threat_scenarios_to_audit_rules(conn=None):
    """Synchronize all enabled threat scenarios into audit_rules table with scenario tags."""
    close_at_end = False
    if conn is None:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        close_at_end = True
    try:
        cur = conn.cursor()
        # Ensure scenario columns exist
        cur.execute("PRAGMA table_info(audit_rules)")
        audit_cols = [c[1] for c in cur.fetchall()]
        if "scenario_id" not in audit_cols:
            cur.execute("ALTER TABLE audit_rules ADD COLUMN scenario_id INTEGER DEFAULT NULL")
        if "scenario_name" not in audit_cols:
            cur.execute("ALTER TABLE audit_rules ADD COLUMN scenario_name TEXT DEFAULT ''")

        # 1. Fetch all enabled scenarios
        cur.execute("SELECT * FROM threat_scenarios WHERE is_enabled = 1")
        scenarios = [dict(r) for r in cur.fetchall()]
        enabled_ids = {s["id"] for s in scenarios}

        # 2. Rebuild audit_rules 100% from enabled threat_scenarios (unified single rule repository)
        cur.execute("DELETE FROM audit_rules")

        # 3. For each enabled scenario, sync its specific IPs and Ports
        for sc in scenarios:
            sc_id = sc["id"]
            sc_name = sc["name"]
            sev = sc.get("severity", "medium")
            flag = "anomaly" if sev in ("high", "medium") else "watch"
            ports_raw = sc.get("ports", "") or ""
            src_scope = (sc.get("src_scope") or "any").strip().lower()
            dst_scope = (sc.get("dst_scope") or "any").strip().lower()

            # Extract specific IPs / CIDRs (excluding generic scopes any/internal/external)
            specific_ips = []
            for raw_s in (src_scope, dst_scope):
                for tok in raw_s.split(","):
                    t = tok.strip()
                    if not t or t in ("any", "internal", "external"):
                        continue
                    if t == "youtube":
                        if "142.250.0.0/15" not in specific_ips:
                            specific_ips.append("142.250.0.0/15")
                    elif validate_ip_or_cidr(t) and t not in specific_ips:
                        specific_ips.append(t)

            port_tokens = [p.strip() for p in ports_raw.split(",") if p.strip() and validate_port_or_range(p.strip())]

            rule_pairs = []
            if specific_ips and port_tokens:
                if len(specific_ips) * len(port_tokens) <= 6:
                    for ip_v in specific_ips:
                        for p_v in port_tokens:
                            rule_pairs.append((ip_v, p_v))
                else:
                    for ip_v in specific_ips:
                        rule_pairs.append((ip_v, None))
                    for p_v in port_tokens:
                        if p_v not in ("80", "443"):
                            rule_pairs.append(("internal", p_v))
            elif specific_ips:
                for ip_v in specific_ips:
                    rule_pairs.append((ip_v, None))
            elif port_tokens:
                scope_ip = "internal" if "internal" in (src_scope, dst_scope) else ("external" if "external" in (src_scope, dst_scope) else None)
                for p_v in port_tokens:
                    if p_v in ("80", "443") and scope_ip in ("internal", "external", None):
                        continue
                    rule_pairs.append((scope_ip, p_v))

            for ip_val, p_tok in rule_pairs:
                cur.execute("""
                    INSERT INTO audit_rules (ip, port, flag, scenario_id, scenario_name, created_at)
                    VALUES (?, ?, ?, ?, ?, datetime('now', 'localtime'))
                """, (ip_val, p_tok, flag, sc_id, sc_name))
        conn.commit()
    except Exception as e:
        print(f"[Scenario Sync Notice] {e}", flush=True)
    finally:
        if close_at_end:
            conn.close()

def run_traffic_audit(start_time_str: Optional[str] = None, time_range: Optional[str] = None) -> Dict[str, Any]:
    print(f"[Audit] Starting traffic audit (range: {time_range}, start: {start_time_str})...", flush=True)
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        
        # Resync threat scenarios to ensure audit rules list has all active scenario rules
        sync_all_threat_scenarios_to_audit_rules(conn)
        
        cur.execute("SELECT id, ip, port, flag FROM audit_rules")
        rules = [dict(row) for row in cur.fetchall()]
        
        if not rules:
            cur.execute("INSERT INTO audit_logs (status, records_matched, message) VALUES (?, ?, ?)", 
                        ("skipped", 0, "No audit rules configured. Skip matching."))
            conn.commit()
            conn.close()
            return {"status": "skipped", "records_matched": 0, "message": "No audit rules configured."}
            
        current_run_dt = now_tw()
        if time_range:
            tr = str(time_range).strip().lower()
            if tr == "1h":
                last_run_dt = current_run_dt - timedelta(hours=1)
            elif tr == "24h":
                last_run_dt = current_run_dt - timedelta(hours=24)
            elif tr == "7d":
                last_run_dt = current_run_dt - timedelta(days=7)
            elif tr == "all":
                last_run_dt = current_run_dt - timedelta(days=365)
            else:
                last_run_dt = current_run_dt - timedelta(hours=24)
        elif start_time_str:
            try:
                last_run_dt = parse_tw_datetime(start_time_str)
            except Exception:
                last_run_dt = current_run_dt - timedelta(days=7)
        else:
            cur.execute("SELECT run_ts FROM audit_logs WHERE status = 'success' ORDER BY id DESC LIMIT 1")
            row = cur.fetchone()
            if row:
                last_run_str = row["run_ts"]
                try:
                    last_run_dt = parse_tw_datetime(last_run_str)
                except Exception:
                    last_run_dt = current_run_dt - timedelta(days=7)
            else:
                last_run_dt = current_run_dt - timedelta(days=7)
            
        last_run_str = last_run_dt.strftime("%Y-%m-%d %H:%M:%S")
        current_run_str = current_run_dt.strftime("%Y-%m-%d %H:%M:%S")
        
        print(f"[Audit] Audit range: {last_run_str} to {current_run_str} (Asia/Taipei)", flush=True)
        
        client = get_ch_client()
        # Guarantee matched_flows table exists
        ensure_matched_flows_table(client)
        tables = ["ipfix", "netflow9"]
        total_matched_count = 0
        
        # High Performance Fast-Path: In-database vectorized ClickHouse execution
        try:
            for table in tables:
                count_sql, insert_sql, params = generate_audit_insert_sql(
                    table, rules, last_run_str, current_run_str, current_run_str
                )
                
                # 1. Fast check count in ClickHouse
                count_res = client.query(count_sql, parameters=params)
                matched_in_table = count_res.result_rows[0][0] if count_res.result_rows else 0
                
                print(f"[Audit Fast-Path] Table '{table}': {matched_in_table} flows matched.", flush=True)
                
                if matched_in_table > 0:
                    # 2. Vectorized direct insert within ClickHouse
                    client.command(insert_sql, parameters=params)
                    total_matched_count += matched_in_table
                    
        except Exception as fast_path_err:
            print(f"[Audit Fast-Path Warning] Direct SQL execution encountered error: {fast_path_err}. Falling back to row-by-row matching...", flush=True)
            # Fallback path if direct SQL fails (safety net)
            parsed_rules = parse_rule_criteria(rules)
            all_matched_records = []
            for table in tables:
                query = f"""
                    SELECT id, exporter, proto, src, dst, sport, dport, packets, octets, protocol, json_data, ts
                    FROM {table}
                    WHERE ts >= %(start)s AND ts < %(end)s
                """
                result = client.query(query, parameters={"start": last_run_str, "end": current_run_str})
                column_names = result.column_names
                for row_vals in result.result_rows:
                    flow = dict(zip(column_names, row_vals))
                    matching_rule = check_flow_match(flow, parsed_rules)
                    if matching_rule:
                        flow["rule_ip"] = matching_rule["ip_raw"]
                        flow["rule_port"] = matching_rule["port_raw"]
                        flow["match_flag"] = matching_rule["flag"]
                        flow["match_ts"] = current_run_dt
                        all_matched_records.append(flow)
                        
            if all_matched_records:
                insert_data = [
                    [
                        r["id"], r["exporter"], r["proto"], r["src"], r["dst"],
                        r.get("sport", 0), r.get("dport", 0), r.get("packets", 0),
                        r.get("octets", 0), r.get("protocol"), r["json_data"], r["ts"],
                        r["rule_ip"], r["rule_port"], r["match_flag"], r["match_ts"]
                    ] for r in all_matched_records
                ]
                client.insert("matched_flows", insert_data, column_names=[
                    "id", "exporter", "proto", "src", "dst", "sport", "dport", "packets", "octets", "protocol", "json_data", "ts", "rule_ip", "rule_port", "match_flag", "match_ts"
                ])
            total_matched_count = len(all_matched_records)
            
        conn.commit()
        conn.close()

        # Enrich external Public IPs via Criminal IP / VirusTotal / Shodan & DB cache
        intel_stats = enrich_audit_with_threat_intel(client, last_run_str, current_run_str)
        intel_msg = (
            f"Audit completed. Found {total_matched_count} matches | "
            f"ThreatIntel: {intel_stats.get('intel_cached_hits', 0)} DB hits, "
            f"{intel_stats.get('intel_queried_new', 0)} new API queries ({intel_stats.get('intel_provider_used', 'DB')}), "
            f"{intel_stats.get('intel_risky_ips', 0)} risky IPs."
        )

        conn2 = sqlite3.connect(DB_PATH, timeout=15.0)
        cur2 = conn2.cursor()
        cur2.execute("INSERT INTO audit_logs (run_ts, status, records_matched, message) VALUES (?, ?, ?, ?)",
                     (current_run_str, "success", total_matched_count, intel_msg))
        conn2.commit()
        conn2.close()
        
        print(f"[Audit] Audit success. {intel_msg}", flush=True)
        return {
            "status": "success",
            "records_matched": total_matched_count,
            "intel_stats": intel_stats,
            "message": intel_msg
        }
        
    except Exception as e:
        print(f"[Audit] Audit failed: {e}", flush=True)
        try:
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            cur.execute("INSERT INTO audit_logs (status, records_matched, message) VALUES (?, ?, ?)",
                        ("failed", 0, str(e)))
            conn.commit()
            conn.close()
        except Exception as sqlite_err:
            print(f"[Audit] Failed to log failure in SQLite: {sqlite_err}", flush=True)
        return {"status": "failed", "records_matched": 0, "message": str(e)}

def audit_scheduler_loop():
    print("[Audit] Background auto audit scheduler thread started.", flush=True)
    try:
        time.sleep(5)
    except Exception:
        pass
        
    # Check if matched_flows is empty on startup, if so run initial audit immediately
    try:
        client = get_ch_client()
        ensure_matched_flows_table(client)
        res = client.query("SELECT count() FROM matched_flows")
        if res.result_rows and res.result_rows[0][0] == 0:
            print("[Audit Startup] matched_flows is empty, running initial audit...", flush=True)
            run_traffic_audit()
    except Exception as e:
        print(f"[Audit Startup] Notice: {e}", flush=True)
        
    while True:
        try:
            # Run audit incrementally every 5 minutes so matched_flows stays fresh with live traffic
            run_traffic_audit()
        except Exception as sched_err:
            print(f"[Audit] Scheduler loop error: {sched_err}", flush=True)
            
        time.sleep(300)

class AuditRuleCreate(BaseModel):
    ip: Optional[str] = None
    port: Optional[str] = None
    flag: str

class AuditRuleUpdate(BaseModel):
    ip: Optional[str] = None
    port: Optional[str] = None
    flag: str

@app.get("/api/audit/rules")
def get_audit_rules():
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT id, ip, port, flag, created_at, scenario_id, scenario_name FROM audit_rules ORDER BY id DESC")
        rules = [dict(row) for row in cur.fetchall()]
        conn.close()
        rule_ips = {r["ip"] for r in rules if r.get("ip")}
        alias_map = resolve_ip_aliases_batch(rule_ips)
        for rule in rules:
            ip = rule.get("ip")
            rule["ip_alias"] = alias_map.get(ip, "") if ip else ""
            port = rule.get("port")
            try:
                rule["port_name"] = port_aliases_cache.get(int(port), "") if port and str(port).isdigit() else ""
            except Exception:
                rule["port_name"] = ""
        return rules
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/audit/rules/export")
def export_audit_rules():
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT ip, port, flag FROM audit_rules ORDER BY id ASC")
        rows = cur.fetchall()
        conn.close()
        return [{"ip": r["ip"], "port": r["port"], "flag": r["flag"]} for r in rows]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/audit/rules/import")
def import_audit_rules(payload: List[Dict[str, Any]]):
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        imported = 0
        for item in payload:
            if not isinstance(item, dict):
                continue
            ip = item.get("ip")
            port = item.get("port")
            flag = item.get("flag")
            
            # Basic validation
            if flag not in ("watch", "anomaly"):
                continue
                
            ip_val = str(ip).strip() if ip is not None else None
            port_val = str(port).strip() if port is not None else None
            if ip_val == "":
                ip_val = None
            if port_val == "":
                port_val = None
            
            if not ip_val and not port_val:
                continue
                
            cur.execute("""
                INSERT OR REPLACE INTO audit_rules (ip, port, flag)
                VALUES (?, ?, ?)
            """, (ip_val, port_val, flag))
            imported += 1
            
        conn.commit()
        conn.close()
        return {"status": "success", "message": f"成功匯入 {imported} 條盤查規則。"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/audit/rules")
def create_audit_rule(rule: AuditRuleCreate):
    ip_val = rule.ip.strip() if rule.ip else None
    port_val = rule.port.strip() if rule.port else None
    flag_val = rule.flag.strip().lower()
    
    if flag_val not in ("watch", "anomaly"):
        raise HTTPException(status_code=400, detail="標記必須為 'watch' 或 'anomaly'")
        
    if not ip_val and not port_val:
        raise HTTPException(status_code=400, detail="IP 與 Port 至少需填寫其中一項。")
        
    if ip_val and not validate_ip_or_cidr(ip_val):
        raise HTTPException(status_code=400, detail="無效的 IP 或 CIDR 位址格式。")
        
    if port_val and not validate_port_or_range(port_val):
        raise HTTPException(status_code=400, detail="無效的 Port 或 Port 範圍格式（例如 '80' 或 '80-443'）。")
        
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        
        if ip_val is None:
            ip_clause = "(ip IS NULL OR ip = '')"
            ip_params = []
        else:
            ip_clause = "ip = ?"
            ip_params = [ip_val]

        if port_val is None:
            port_clause = "(port IS NULL OR port = '')"
            port_params = []
        else:
            port_clause = "port = ?"
            port_params = [port_val]

        cur.execute(f"SELECT id FROM audit_rules WHERE {ip_clause} AND {port_clause}", ip_params + port_params)
        if cur.fetchone():
            conn.close()
            raise HTTPException(status_code=400, detail="已存在相同 IP/CIDR 與 Port 的規則，不可重複設定。")
            
        cur.execute("INSERT INTO audit_rules (ip, port, flag, created_at) VALUES (?, ?, ?, ?)", (ip_val, port_val, flag_val, now_tw_str()))
        conn.commit()
        conn.close()
        return {"status": "success", "message": "盤查規則新增成功。"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/api/audit/rules/{rule_id}")
def update_audit_rule(rule_id: int, rule: AuditRuleUpdate):
    ip_val = rule.ip.strip() if rule.ip else None
    port_val = rule.port.strip() if rule.port else None
    flag_val = rule.flag.strip().lower()
    
    if flag_val not in ("watch", "anomaly"):
        raise HTTPException(status_code=400, detail="標記必須為 'watch' 或 'anomaly'")
        
    if not ip_val and not port_val:
        raise HTTPException(status_code=400, detail="IP 與 Port 至少需填寫其中一項。")
        
    if ip_val and not validate_ip_or_cidr(ip_val):
        raise HTTPException(status_code=400, detail="無效的 IP 或 CIDR 位址格式。")
        
    if port_val and not validate_port_or_range(port_val):
        raise HTTPException(status_code=400, detail="無效的 Port 或 Port 範圍格式（例如 '80' 或 '80-443'）。")
        
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        
        cur.execute("SELECT id FROM audit_rules WHERE id = ?", (rule_id,))
        if not cur.fetchone():
            conn.close()
            raise HTTPException(status_code=404, detail="找不到欲修改的規則。")
            
        if ip_val is None:
            ip_clause = "(ip IS NULL OR ip = '')"
            ip_params = []
        else:
            ip_clause = "ip = ?"
            ip_params = [ip_val]

        if port_val is None:
            port_clause = "(port IS NULL OR port = '')"
            port_params = []
        else:
            port_clause = "port = ?"
            port_params = [port_val]

        cur.execute(f"SELECT id FROM audit_rules WHERE {ip_clause} AND {port_clause} AND id != ?", ip_params + port_params + [rule_id])
        if cur.fetchone():
            conn.close()
            raise HTTPException(status_code=400, detail="已存在相同 IP/CIDR 與 Port 的規則，不可重複設定。")
            
        cur.execute("""
            UPDATE audit_rules 
            SET ip = ?, port = ?, flag = ?
            WHERE id = ?
        """, (ip_val, port_val, flag_val, rule_id))
        conn.commit()
        conn.close()
        return {"status": "success", "message": "盤查規則已成功更新。"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/audit/rules")
def clear_audit_rules():
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("DELETE FROM audit_rules")
        conn.commit()
        conn.close()
        return {"status": "success", "message": "All audit rules cleared successfully."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/audit/rules/{rule_id}")
def delete_audit_rule(rule_id: int):
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("DELETE FROM audit_rules WHERE id = ?", (rule_id,))
        conn.commit()
        conn.close()
        return {"status": "success", "message": "Audit rule deleted successfully."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

class AuditRunRequest(BaseModel):
    start_time: Optional[str] = None
    time_range: Optional[str] = None

@app.post("/api/audit/run")
def trigger_audit(payload: Optional[AuditRunRequest] = None):
    start_time_str = payload.start_time if payload else None
    time_range = payload.time_range if payload else None
    result = run_traffic_audit(start_time_str=start_time_str, time_range=time_range)
    if result["status"] == "success":
        return result
    else:
        raise HTTPException(status_code=500, detail=result["message"])

@app.get("/api/audit/status")
def get_audit_status():
    def format_tw_str(dt_str: str) -> str:
        if not dt_str or dt_str == "Never":
            return "Never"
        try:
            dt = parse_tw_datetime(dt_str)
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return dt_str

    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        
        # Get last run log (success or failed)
        cur.execute("SELECT run_ts, status, records_matched, message FROM audit_logs ORDER BY id DESC LIMIT 1")
        last_log = cur.fetchone()
        
        # Get last success run to calculate next run
        cur.execute("SELECT run_ts FROM audit_logs WHERE status = 'success' ORDER BY id DESC LIMIT 1")
        last_success = cur.fetchone()
        
        conn.close()
        
        last_run_tw = "Never"
        next_run_tw = "Immediately"
        status = "none"
        records_matched = 0
        message = "No audit has run yet."
        
        if last_log:
            last_run_tw = format_tw_str(last_log["run_ts"])
            status = last_log["status"]
            records_matched = last_log["records_matched"]
            message = last_log["message"]
            
        if last_success:
            dt = parse_tw_datetime(last_success["run_ts"])
            next_dt = dt + timedelta(hours=24)
            next_run_tw = next_dt.strftime("%Y-%m-%d %H:%M:%S")
            
        return {
            "run_ts": last_run_tw,
            "next_run_ts": next_run_tw,
            "status": status,
            "records_matched": records_matched,
            "message": message
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/audit/matches/stats")
def get_audit_matches_stats(
    ip: Optional[str] = Query(None),
    src: Optional[str] = Query(None),
    dst: Optional[str] = Query(None),
    alias: Optional[str] = Query(None),
    sport: Optional[int] = Query(None),
    dport: Optional[int] = Query(None),
    port: Optional[int] = Query(None),
    proto: Optional[str] = Query(None),
    flag: Optional[str] = Query(None),
    conditions: Optional[str] = Query(None, description="JSON string of dynamic conditions list"),
    logic: str = Query("AND", description="Combination logic: 'AND' or 'OR'")
):
    try:
        client = get_ch_client()
        ensure_matched_flows_table(client)
        where_clauses = []
        params = {}

        if alias:
            where_clauses.append(build_alias_where_clause("any", alias, params, "ms_alias"))
        
        dyn_clause = parse_conditions_where_clause(conditions, logic, params, "audit_stats_dyn")
        if dyn_clause:
            where_clauses.append(dyn_clause)
        else:
            if ip:
                src_c = build_ip_where_clause("src", ip, params, "ip_src")
                dst_c = build_ip_where_clause("dst", ip, params, "ip_dst")
                where_clauses.append(f"({src_c} OR {dst_c})")
            if src:
                where_clauses.append(build_ip_where_clause("src", src, params, "src"))
            if dst:
                where_clauses.append(build_ip_where_clause("dst", dst, params, "dst"))
            if sport is not None:
                where_clauses.append("sport = %(sport)s")
                params["sport"] = sport
            if dport is not None:
                where_clauses.append("dport = %(dport)s")
                params["dport"] = dport
            if port is not None:
                where_clauses.append("(sport = %(port)s OR dport = %(port)s)")
                params["port"] = port
            if proto:
                proto_parts = [p.strip() for p in proto.split(",") if p.strip()]
                proto_clauses = []
                for idx, p in enumerate(proto_parts):
                    key = f"proto_p_{idx}"
                    params[key] = p
                    p_num = None
                    for num, name in PROTO_NAME_MAP.items():
                        if name.upper() == p.upper():
                            p_num = num
                            break
                    if p_num is not None:
                        num_key = f"proto_num_{idx}"
                        params[num_key] = p_num
                        proto_clauses.append(f"(proto ILIKE %({key})s OR protocol = %({num_key})s)")
                    elif p.isdigit():
                        num_key = f"proto_num_{idx}"
                        params[num_key] = int(p)
                        proto_clauses.append(f"(proto ILIKE %({key})s OR protocol = %({num_key})s)")
                    else:
                        proto_clauses.append(f"proto ILIKE %({key})s")
                if proto_clauses:
                    where_clauses.append(f"({' OR '.join(proto_clauses)})")
        if flag:
            where_clauses.append("match_flag = %(flag)s")
            params["flag"] = flag.strip().lower()
            
        where_sql = ""
        if where_clauses:
            where_sql = "WHERE " + " AND ".join(where_clauses)
            
        where_sport = f"{where_sql} AND sport IS NOT NULL" if where_sql else "WHERE sport IS NOT NULL"
        where_dport = f"{where_sql} AND dport IS NOT NULL" if where_sql else "WHERE dport IS NOT NULL"

        target_table = "matched_flows"
        chk_res = client.query(f"SELECT count() FROM matched_flows {where_sql}", parameters=params)
        m_count = chk_res.result_rows[0][0] if chk_res.result_rows else 0
        if m_count == 0 and (where_clauses or conditions or ip or src or dst):
            raw_table = """(
                SELECT id, exporter, proto, src, dst, sport, dport, packets, octets, protocol, json_data, ts,
                       '' as rule_ip, toString(dport) as rule_port, 'anomaly' as match_flag, ts as match_ts
                FROM (
                    SELECT * FROM ipfix
                    UNION ALL
                    SELECT * FROM netflow9
                )
            )"""
            try:
                raw_chk = client.query(f"SELECT count() FROM {raw_table} {where_sql}", parameters=params)
                if raw_chk.result_rows and raw_chk.result_rows[0][0] > 0:
                    target_table = raw_table
            except Exception as raw_e:
                print(f"[Matches Stats Fallback Notice] {raw_e}", flush=True)

        f_totals = ch_query_executor.submit(
            _run_ch_query,
            f"SELECT COUNT() as total_flows, SUM(packets) as total_packets, SUM(octets) as total_bytes FROM {target_table} {where_sql}",
            params
        )
        f_top_src = ch_query_executor.submit(
            _run_ch_query,
            f"""
            SELECT src, SUM(octets) as bytes, SUM(packets) as packets, COUNT() as flows
            FROM {target_table}
            {where_sql}
            GROUP BY src
            ORDER BY bytes DESC
            LIMIT 10
            """,
            params
        )
        f_top_dst = ch_query_executor.submit(
            _run_ch_query,
            f"""
            SELECT dst, SUM(octets) as bytes, SUM(packets) as packets, COUNT() as flows
            FROM {target_table}
            {where_sql}
            GROUP BY dst
            ORDER BY bytes DESC
            LIMIT 10
            """,
            params
        )
        f_top_sport = ch_query_executor.submit(
            _run_ch_query,
            f"""
            SELECT sport, SUM(octets) as bytes, COUNT() as flows
            FROM {target_table}
            {where_sport}
            GROUP BY sport
            ORDER BY bytes DESC
            LIMIT 10
            """,
            params
        )
        f_top_dport = ch_query_executor.submit(
            _run_ch_query,
            f"""
            SELECT dport, SUM(octets) as bytes, COUNT() as flows
            FROM {target_table}
            {where_dport}
            GROUP BY dport
            ORDER BY bytes DESC
            LIMIT 10
            """,
            params
        )
        f_top_ports = ch_query_executor.submit(
            _run_ch_query,
            f"""
            SELECT port, SUM(octets) as bytes, COUNT() as flows
            FROM (
                SELECT sport as port, octets FROM {target_table} {where_sport}
                UNION ALL
                SELECT dport as port, octets FROM {target_table} {where_dport}
            )
            GROUP BY port
            ORDER BY bytes DESC
            LIMIT 10
            """,
            params
        )
        f_protocols = ch_query_executor.submit(
            _run_ch_query,
            f"""
            SELECT proto as name, COUNT() as count, SUM(octets) as bytes
            FROM {target_table}
            {where_sql}
            GROUP BY name
            ORDER BY count DESC
            """,
            params
        )
        f_ip_protos = ch_query_executor.submit(
            _run_ch_query,
            f"""
            SELECT protocol as name_num, COUNT() as count, SUM(octets) as bytes
            FROM {target_table}
            {where_sql}
            GROUP BY name_num
            ORDER BY count DESC
            """,
            params
        )
        f_flags = ch_query_executor.submit(
            _run_ch_query,
            f"""
            SELECT match_flag as name, COUNT() as count, SUM(octets) as bytes
            FROM {target_table}
            {where_sql}
            GROUP BY name
            ORDER BY count DESC
            """,
            params
        )
        f_top_pairs = ch_query_executor.submit(
            _run_ch_query,
            f"""
            SELECT src, dst, SUM(octets) as bytes, COUNT() as flows
            FROM {target_table}
            {where_sql}
            GROUP BY src, dst
            ORDER BY bytes DESC
            LIMIT 1000
            """,
            params
        )
        f_range = ch_query_executor.submit(
            _run_ch_query,
            f"SELECT min(ts), max(ts) FROM {target_table} {where_sql}",
            params
        )

        # 8. Traffic over time (launch immediately once range finishes)
        range_res = f_range.result()
        min_ts, max_ts = range_res.result_rows[0]
        
        time_format = "%Y-%m-%d"
        ch_group_fn = "toStartOfDay(ts + INTERVAL 8 HOUR)"
        if min_ts and max_ts:
            diff_secs = (max_ts - min_ts).total_seconds()
            if diff_secs < 172800: # < 48 hours
                time_format = "%Y-%m-%d %H:00"
                ch_group_fn = "toStartOfHour(ts + INTERVAL 8 HOUR)"
                
        f_time = ch_query_executor.submit(
            _run_ch_query,
            f"""
            SELECT {ch_group_fn} as time_bin, SUM(octets) as bytes, SUM(packets) as packets, COUNT() as flows
            FROM {target_table}
            {where_sql}
            GROUP BY time_bin
            ORDER BY time_bin ASC
            """,
            params
        )

        # Collect parallel results
        res = f_totals.result()
        totals = dict(zip(res.column_names, res.result_rows[0]))
        total_flows = totals["total_flows"] or 0
        total_packets = totals["total_packets"] or 0
        total_bytes = totals["total_bytes"] or 0

        res = f_top_src.result()
        top_sources = [dict(zip(res.column_names, r)) for r in res.result_rows]

        res = f_top_dst.result()
        top_destinations = [dict(zip(res.column_names, r)) for r in res.result_rows]

        res = f_top_sport.result()
        top_source_ports = [dict(zip(res.column_names, r)) for r in res.result_rows]

        res = f_top_dport.result()
        top_destination_ports = [dict(zip(res.column_names, r)) for r in res.result_rows]

        res = f_top_ports.result()
        top_ports = [dict(zip(res.column_names, r)) for r in res.result_rows]

        res = f_protocols.result()
        protocols = [dict(zip(res.column_names, r)) for r in res.result_rows]

        res = f_ip_protos.result()
        ip_protocols = []
        for r in res.result_rows:
            p_num = r[0]
            p_name = PROTO_NAME_MAP.get(p_num, f"UNKNOWN ({p_num})" if p_num is not None else "N/A")
            ip_protocols.append({
                "protocol": p_num,
                "name": p_name,
                "count": r[1],
                "bytes": r[2]
            })

        res = f_flags.result()
        flags = [dict(zip(res.column_names, r)) for r in res.result_rows]

        res = f_time.result()
        traffic_over_time = []
        for r_row in res.result_rows:
            r = dict(zip(res.column_names, r_row))
            tb = r["time_bin"]
            if isinstance(tb, datetime):
                r["time_bin"] = tb.strftime(time_format)
            traffic_over_time.append(r)

        # Resolve IPs
        stats_ips = set()
        for item in top_sources:
            if item.get("src"):
                stats_ips.add(item["src"])
        for item in top_destinations:
            if item.get("dst"):
                stats_ips.add(item["dst"])
        # Get DNS and IP Aliases mappings in batch
        stats_dns_map = get_dns_mappings(stats_ips)
        alias_map = resolve_ip_aliases_batch(stats_ips)
        for item in top_sources:
            ip = item.get("src")
            item["domain"] = alias_map.get(ip) or stats_dns_map.get(ip, "")
        for item in top_destinations:
            ip = item.get("dst")
            item["domain"] = alias_map.get(ip) or stats_dns_map.get(ip, "")

        # Resolve Ports
        for item in top_source_ports:
            sport = item.get("sport")
            item["port_name"] = port_aliases_cache.get(sport, "") if sport is not None else ""
        for item in top_destination_ports:
            dport = item.get("dport")
            item["port_name"] = port_aliases_cache.get(dport, "") if dport is not None else ""
        for item in top_ports:
            port = item.get("port")
            item["port_name"] = port_aliases_cache.get(port, "") if port is not None else ""

        # Calculate Top IP Aliases (Bidirectional aggregated, deduplicated if both endpoints share same alias)
        res_pairs = f_top_pairs.result()
        pair_rows = [dict(zip(res_pairs.column_names, r)) for r in res_pairs.result_rows]
        pair_ips = set()
        for r in pair_rows:
            if r.get("src"):
                pair_ips.add(r["src"])
            if r.get("dst"):
                pair_ips.add(r["dst"])
        alias_map_pairs = resolve_ip_aliases_batch(pair_ips)
        alias_aggregated = {}
        for r in pair_rows:
            s_alias = alias_map_pairs.get(r.get("src"))
            d_alias = alias_map_pairs.get(r.get("dst"))
            matched_aliases = set()
            if s_alias:
                matched_aliases.add(s_alias)
            if d_alias:
                matched_aliases.add(d_alias)
            for al in matched_aliases:
                if al not in alias_aggregated:
                    alias_aggregated[al] = {"name": al, "bytes": 0, "flows": 0}
                alias_aggregated[al]["bytes"] += (r.get("bytes") or 0)
                alias_aggregated[al]["flows"] += (r.get("flows") or 0)
        top_aliases = sorted(alias_aggregated.values(), key=lambda x: x["bytes"], reverse=True)[:10]

        return {
            "total_flows": total_flows,
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "top_sources": top_sources,
            "top_destinations": top_destinations,
            "top_source_ports": top_source_ports,
            "top_destination_ports": top_destination_ports,
            "top_ports": top_ports,
            "protocols": protocols,
            "ip_protocols": ip_protocols,
            "top_aliases": top_aliases,
            "flags": flags,
            "traffic_over_time": traffic_over_time
        }
    except Exception as e:
        reset_ch_client()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/audit/matches")
def get_audit_matches(
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    ip: Optional[str] = Query(None),
    src: Optional[str] = Query(None),
    dst: Optional[str] = Query(None),
    alias: Optional[str] = Query(None),
    sport: Optional[int] = Query(None),
    dport: Optional[int] = Query(None),
    port: Optional[int] = Query(None),
    proto: Optional[str] = Query(None),
    flag: Optional[str] = Query(None),
    conditions: Optional[str] = Query(None, description="JSON string of dynamic conditions list"),
    logic: str = Query("AND", description="Combination logic: 'AND' or 'OR'"),
    sort_by: str = Query("match_ts"),
    sort_order: str = Query("desc")
):
    try:
        client = get_ch_client()
        ensure_matched_flows_table(client)
        where_clauses = []
        params = {}

        if alias:
            where_clauses.append(build_alias_where_clause("any", alias, params, "m_alias"))
        
        dyn_clause = parse_conditions_where_clause(conditions, logic, params, "audit_dyn")
        if dyn_clause:
            where_clauses.append(dyn_clause)
        else:
            if ip:
                src_c = build_ip_where_clause("src", ip, params, "ip_src")
                dst_c = build_ip_where_clause("dst", ip, params, "ip_dst")
                where_clauses.append(f"({src_c} OR {dst_c})")
            if src:
                where_clauses.append(build_ip_where_clause("src", src, params, "src"))
            if dst:
                where_clauses.append(build_ip_where_clause("dst", dst, params, "dst"))
            if sport is not None:
                where_clauses.append("sport = %(sport)s")
                params["sport"] = sport
            if dport is not None:
                where_clauses.append("dport = %(dport)s")
                params["dport"] = dport
            if port is not None:
                where_clauses.append("(sport = %(port)s OR dport = %(port)s)")
                params["port"] = port
            if proto:
                proto_parts = [p.strip() for p in proto.split(",") if p.strip()]
                proto_clauses = []
                for idx, p in enumerate(proto_parts):
                    key = f"proto_p_{idx}"
                    params[key] = p
                    p_num = None
                    for num, name in PROTO_NAME_MAP.items():
                        if name.upper() == p.upper():
                            p_num = num
                            break
                    if p_num is not None:
                        num_key = f"proto_num_{idx}"
                        params[num_key] = p_num
                        proto_clauses.append(f"(proto ILIKE %({key})s OR protocol = %({num_key})s)")
                    elif p.isdigit():
                        num_key = f"proto_num_{idx}"
                        params[num_key] = int(p)
                        proto_clauses.append(f"(proto ILIKE %({key})s OR protocol = %({num_key})s)")
                    else:
                        proto_clauses.append(f"proto ILIKE %({key})s")
                if proto_clauses:
                    where_clauses.append(f"({' OR '.join(proto_clauses)})")
        if flag:
            where_clauses.append("match_flag = %(flag)s")
            params["flag"] = flag.strip().lower()
            
        where_sql = ""
        if where_clauses:
            where_sql = "WHERE " + " AND ".join(where_clauses)
            
        count_query = f"SELECT count() FROM matched_flows {where_sql}"
        count_result = client.query(count_query, parameters=params)
        total_records = count_result.result_rows[0][0]

        target_table = "matched_flows"
        if total_records == 0 and (where_clauses or conditions or ip or src or dst):
            raw_table = """(
                SELECT id, exporter, proto, src, dst, sport, dport, packets, octets, protocol, json_data, ts,
                       '' as rule_ip, toString(dport) as rule_port, 'anomaly' as match_flag, ts as match_ts
                FROM (
                    SELECT * FROM ipfix
                    UNION ALL
                    SELECT * FROM netflow9
                )
            )"""
            try:
                raw_count_res = client.query(f"SELECT count() FROM {raw_table} {where_sql}", parameters=params)
                raw_total = raw_count_res.result_rows[0][0] if raw_count_res.result_rows else 0
                if raw_total > 0:
                    total_records = raw_total
                    target_table = raw_table
            except Exception as raw_e:
                print(f"[Matches Fallback Notice] {raw_e}", flush=True)
        
        # Validate sort field to prevent SQL injection
        allowed_cols = {
            "match_ts", "ts", "match_flag", "rule_ip", "rule_port",
            "src", "sport", "dst", "dport", "proto", "packets", "octets", "exporter"
        }
        if sort_by not in allowed_cols:
            sort_by = "ts"
            
        order_sql = "DESC" if sort_order.lower() == "desc" else "ASC"
        
        query = f"""
            SELECT id, exporter, proto, src, dst, sport, dport, packets, octets, protocol, json_data, ts, rule_ip, rule_port, match_flag, match_ts
            FROM {target_table}
            {where_sql}
            ORDER BY {sort_by} {order_sql}, ts DESC
            LIMIT %(limit)s OFFSET %(offset)s
        """
        params["limit"] = limit
        params["offset"] = offset
        
        data_result = client.query(query, parameters=params)
        column_names = data_result.column_names
        records = []
        ips_to_resolve = set()
        
        for row_vals in data_result.result_rows:
            r = dict(zip(column_names, row_vals))
            if isinstance(r["ts"], datetime):
                r["ts"] = r["ts"].strftime("%Y-%m-%d %H:%M:%S")
            if isinstance(r["match_ts"], datetime):
                r["match_ts"] = r["match_ts"].strftime("%Y-%m-%d %H:%M:%S")
            records.append(r)
            if r.get("src"):
                ips_to_resolve.add(r["src"])
            if r.get("dst"):
                ips_to_resolve.add(r["dst"])
            if r.get("exporter"):
                ips_to_resolve.add(r["exporter"])
            if r.get("rule_ip"):
                ips_to_resolve.add(r["rule_ip"])
                
        # Get DNS, IP Aliases, and Threat Intel mappings in batch
        dns_map = get_dns_mappings(ips_to_resolve)
        alias_map = resolve_ip_aliases_batch(ips_to_resolve)
        intel_map = get_threat_intel_batch_from_db(ips_to_resolve)
        for r in records:
            src_ip = r.get("src")
            dst_ip = r.get("dst")
            exporter_ip = r.get("exporter")
            src_intel = intel_map.get(src_ip)
            dst_intel = intel_map.get(dst_ip)
            r["src_intel"] = src_intel
            r["dst_intel"] = dst_intel
            r["src_domain"] = alias_map.get(src_ip) or (src_intel.get("domain") if src_intel else "") or dns_map.get(src_ip, "")
            r["dst_domain"] = alias_map.get(dst_ip) or (dst_intel.get("domain") if dst_intel else "") or dns_map.get(dst_ip, "")
            r["exporter_alias"] = alias_map.get(exporter_ip) or dns_map.get(exporter_ip, "")
            r["sport_name"] = port_aliases_cache.get(r.get("sport"), "") if r.get("sport") is not None else ""
            r["dport_name"] = port_aliases_cache.get(r.get("dport"), "") if r.get("dport") is not None else ""
            rule_ip = r.get("rule_ip")
            r["rule_ip_alias"] = alias_map.get(rule_ip, "") if rule_ip else ""
            if r.get("protocol") is not None:
                r["proto_name"] = PROTO_NAME_MAP.get(r["protocol"], f"UNKNOWN ({r['protocol']})")
            else:
                r["proto_name"] = "N/A"
            
        return {
            "total": total_records,
            "limit": limit,
            "offset": offset,
            "records": records
        }
    except Exception as e:
        reset_ch_client()
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/audit/matches")
def clear_audit_matches():
    try:
        client = get_ch_client()
        ensure_matched_flows_table(client)
        client.command("TRUNCATE TABLE matched_flows")
        return {"status": "success", "message": "Permanently matched records cleared."}
    except Exception as e:
        reset_ch_client()
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/audit/matches/{match_id}")
def delete_single_audit_match(match_id: str):
    try:
        client = get_ch_client()
        ensure_matched_flows_table(client)
        client.command("ALTER TABLE matched_flows DELETE WHERE id = %(id)s", parameters={"id": match_id})
        return {"status": "success", "message": f"Match record {match_id} deleted."}
    except Exception as e:
        reset_ch_client()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/audit/matches/export")
def export_audit_matches(
    ip: Optional[str] = Query(None),
    src: Optional[str] = Query(None),
    dst: Optional[str] = Query(None),
    sport: Optional[int] = Query(None),
    dport: Optional[int] = Query(None),
    port: Optional[int] = Query(None),
    proto: Optional[str] = Query(None),
    flag: Optional[str] = Query(None),
    conditions: Optional[str] = Query(None),
    logic: str = Query("AND")
):
    import io
    import csv
    from fastapi.responses import StreamingResponse
    
    try:
        client = get_ch_client()
        ensure_matched_flows_table(client)
        where_clauses = []
        params = {}
        
        dyn_clause = parse_conditions_where_clause(conditions, logic, params, "audit_exp_dyn")
        if dyn_clause:
            where_clauses.append(f"({dyn_clause})")
            
        if ip:
            src_c = build_ip_where_clause("src", ip, params, "ip_src")
            dst_c = build_ip_where_clause("dst", ip, params, "ip_dst")
            where_clauses.append(f"({src_c} OR {dst_c})")
        if src:
            where_clauses.append(build_ip_where_clause("src", src, params, "src"))
        if dst:
            where_clauses.append(build_ip_where_clause("dst", dst, params, "dst"))
        if sport is not None:
            where_clauses.append("sport = %(sport)s")
            params["sport"] = sport
        if dport is not None:
            where_clauses.append("dport = %(dport)s")
            params["dport"] = dport
        if port is not None:
            where_clauses.append("(sport = %(port)s OR dport = %(port)s)")
            params["port"] = port
        if proto:
            proto_parts = [p.strip() for p in proto.split(",") if p.strip()]
            proto_clauses = []
            for idx, p in enumerate(proto_parts):
                key = f"proto_p_{idx}"
                params[key] = p
                p_num = None
                for num, name in PROTO_NAME_MAP.items():
                    if name.upper() == p.upper():
                        p_num = num
                        break
                if p_num is not None:
                    num_key = f"proto_num_{idx}"
                    params[num_key] = p_num
                    proto_clauses.append(f"(proto ILIKE %({key})s OR protocol = %({num_key})s)")
                elif p.isdigit():
                    num_key = f"proto_num_{idx}"
                    params[num_key] = int(p)
                    proto_clauses.append(f"(proto ILIKE %({key})s OR protocol = %({num_key})s)")
                else:
                    proto_clauses.append(f"proto ILIKE %({key})s")
            if proto_clauses:
                where_clauses.append(f"({' OR '.join(proto_clauses)})")
        if flag:
            where_clauses.append("match_flag = %(flag)s")
            params["flag"] = flag.strip().lower()
            
        where_sql = ""
        if where_clauses:
            where_sql = "WHERE " + " AND ".join(where_clauses)
            
        target_table = "matched_flows"
        chk_res = client.query(f"SELECT count() FROM matched_flows {where_sql}", parameters=params)
        m_count = chk_res.result_rows[0][0] if chk_res.result_rows else 0
        if m_count == 0 and (where_clauses or conditions or ip or src or dst):
            raw_table = """(
                SELECT id, exporter, proto, src, dst, sport, dport, packets, octets, protocol, json_data, ts,
                       '' as rule_ip, toString(dport) as rule_port, 'anomaly' as match_flag, ts as match_ts
                FROM (
                    SELECT * FROM ipfix
                    UNION ALL
                    SELECT * FROM netflow9
                )
            )"""
            try:
                raw_chk = client.query(f"SELECT count() FROM {raw_table} {where_sql}", parameters=params)
                if raw_chk.result_rows and raw_chk.result_rows[0][0] > 0:
                    target_table = raw_table
            except Exception as raw_e:
                print(f"[Matches Export Fallback Notice] {raw_e}", flush=True)

        query = f"""
            SELECT id, exporter, proto, src, dst, sport, dport, packets, octets, protocol, ts, rule_ip, rule_port, match_flag, match_ts
            FROM {target_table}
            {where_sql}
            ORDER BY match_ts DESC, ts DESC
            LIMIT 100000
        """
        
        data_result = client.query(query, parameters=params)
        column_names = data_result.column_names
        
        # Collect unique IPs to resolve domains and aliases in batch
        ips_to_resolve = set()
        for row in data_result.result_rows:
            r = dict(zip(column_names, row))
            if r.get("src"):
                ips_to_resolve.add(r["src"])
            if r.get("dst"):
                ips_to_resolve.add(r["dst"])
            if r.get("exporter"):
                ips_to_resolve.add(r["exporter"])
            if r.get("rule_ip"):
                ips_to_resolve.add(r["rule_ip"])
        dns_map = get_dns_mappings(ips_to_resolve)
        alias_map = resolve_ip_aliases_batch(ips_to_resolve)
        
        # CSV generator
        def csv_generator():
            yield "\ufeff"
            output = io.StringIO()
            writer = csv.writer(output)
            
            # CSV Headers
            headers = [
                "Flow Time", "Flag", "Collector IP", "Collector IP Alias", "Audit Time", "Matched IP Rule", "Matched Port Rule",
                "Source IP", "Source Domain", "Source Port", "Source Port Name",
                "Destination IP", "Destination Domain", "Destination Port", "Destination Port Name",
                "Protocol", "Packets", "Bytes"
            ]
            writer.writerow(headers)
            yield output.getvalue()
            output.seek(0)
            output.truncate(0)
            
            for row_vals in data_result.result_rows:
                r = dict(zip(column_names, row_vals))
                
                # Format dates
                m_ts = r["match_ts"].strftime("%Y-%m-%d %H:%M:%S") if isinstance(r["match_ts"], datetime) else str(r["match_ts"])
                f_ts = r["ts"].strftime("%Y-%m-%d %H:%M:%S") if isinstance(r["ts"], datetime) else str(r["ts"])
                
                # Flag translation
                flag_val = "關注" if r["match_flag"] == "watch" else "異常"
                
                # Collector IP and alias
                exporter_ip = r.get("exporter") or ""
                exporter_alias = alias_map.get(exporter_ip) or dns_map.get(exporter_ip, "")

                # DNS and Aliases resolution
                src_ip = r["src"]
                dst_ip = r["dst"]
                src_domain = alias_map.get(src_ip) or dns_map.get(src_ip, "")
                dst_domain = alias_map.get(dst_ip) or dns_map.get(dst_ip, "")
                
                sport_val = r["sport"]
                dport_val = r["dport"]
                sport_name = port_aliases_cache.get(sport_val, "")
                dport_name = port_aliases_cache.get(dport_val, "")
                
                p_name = PROTO_NAME_MAP.get(r["protocol"], f"UNKNOWN ({r['protocol']})" if r["protocol"] is not None else "N/A")
                rule_ip = r["rule_ip"]
                rule_ip_alias = alias_map.get(rule_ip, "") if rule_ip else ""
                rule_ip_val = f"{rule_ip} ({rule_ip_alias})" if rule_ip and rule_ip_alias else (rule_ip or "(任意)")
                row_data = [
                    f_ts, flag_val, exporter_ip, exporter_alias, m_ts, rule_ip_val, r["rule_port"] or "(任意)",
                    src_ip, src_domain, sport_val, sport_name,
                    dst_ip, dst_domain, dport_val, dport_name,
                    p_name, r["packets"], r["octets"]
                ]
                writer.writerow(row_data)
                yield output.getvalue()
                output.seek(0)
                output.truncate(0)
                
        headers = {
            'Content-Disposition': 'attachment; filename="anomalous_traffic_report.csv"',
            'Content-Type': 'text/csv; charset=utf-8'
        }
        return StreamingResponse(csv_generator(), headers=headers)
        
    except Exception as e:
        reset_ch_client()
        raise HTTPException(status_code=500, detail=str(e))


# ---------------- AtheNAC (PIXIS Open API v3) Integration ----------------
_athenac_token_cache: Dict[str, Any] = {"token": "", "expires_at": 0.0}
_athenac_token_lock = threading.Lock()

SIMULATED_ATHENAC_HOSTS = {
    "192.168.10.10": {"hostname": "CORE-DB-01", "mac": "00-50-56-A1-10-10", "vendor": "VMware, Inc.", "os_detail": "Ubuntu 22.04 LTS", "switch_name": "DC-Core-SW01", "port_name": "Te1/0/1", "site_name": "總部機房", "network_name": "Core-Server-VLAN10", "is_online": True},
    "192.168.10.20": {"hostname": "ERP-APP-01", "mac": "00-50-56-A1-10-20", "vendor": "VMware, Inc.", "os_detail": "Windows Server 2022", "switch_name": "DC-Core-SW01", "port_name": "Te1/0/2", "site_name": "總部機房", "network_name": "Core-Server-VLAN10", "is_online": True},
    "192.168.10.50": {"hostname": "HQ-AD-DC01", "mac": "00-50-56-A1-10-50", "vendor": "VMware, Inc.", "os_detail": "Windows Server 2019", "switch_name": "DC-Core-SW01", "port_name": "Te1/0/5", "site_name": "總部機房", "network_name": "Core-Server-VLAN10", "is_online": True},
    "192.168.20.15": {"hostname": "DEV-GITLAB", "mac": "D4-5D-64-20-15-01", "vendor": "ASUSTek Computer", "os_detail": "Debian 12", "switch_name": "3F-RD-SW02", "port_name": "Gi1/0/15", "site_name": "台北總部", "network_name": "RD-VLAN20", "is_online": True},
    "192.168.30.101": {"hostname": "FIN-WS-01", "mac": "00-50-56-8A-1C-01", "vendor": "Dell Inc.", "os_detail": "Windows 11 Pro", "switch_name": "2F-Office-SW01", "port_name": "Gi1/0/12", "site_name": "台北總部", "network_name": "Office-VLAN30", "is_online": True},
    "192.168.30.105": {"hostname": "HR-NB-02", "mac": "4C-79-6E-30-10-05", "vendor": "Lenovo", "os_detail": "Windows 11 Pro", "switch_name": "2F-Office-SW01", "port_name": "Gi1/0/18", "site_name": "台北總部", "network_name": "Office-VLAN30", "is_online": True},
    "192.168.30.112": {"hostname": "SALES-NB-12", "mac": "AC-BC-32-77-11-12", "vendor": "Apple, Inc.", "os_detail": "macOS 14.6", "switch_name": "1F-Sales-AP01", "port_name": "WLAN-Corp", "site_name": "台北總部", "network_name": "Office-VLAN30", "is_online": True},
    "192.168.30.120": {"hostname": "MKT-PC-20", "mac": "70-85-C2-45-30-20", "vendor": "HP Inc.", "os_detail": "Windows 10 Pro", "switch_name": "2F-Office-SW02", "port_name": "Gi1/0/20", "site_name": "台北總部", "network_name": "Office-VLAN30", "is_online": True},
    "192.168.30.220": {"hostname": "UNKNOWN-DEV-220", "mac": "9C-DA-3E-44-22-20", "vendor": "Xiaomi Communications", "os_detail": "Android 14 (BYOD)", "switch_name": "1F-Lobby-SW01", "port_name": "Gi1/0/8", "site_name": "台北總部", "network_name": "Office-VLAN30", "is_online": True},
    "192.168.30.221": {"hostname": "TEMP-PC-221", "mac": "B8-85-84-11-22-21", "vendor": "ASUSTek Computer", "os_detail": "Windows 11 Home", "switch_name": "3F-RD-SW02", "port_name": "Gi1/0/28", "site_name": "台北總部", "network_name": "RD-VLAN20", "is_online": True},
    "10.0.5.25": {"hostname": "RD-TEST-25", "mac": "52-54-00-05-00-25", "vendor": "QEMU Virtual NIC", "os_detail": "CentOS Stream 9", "switch_name": "3F-Lab-SW01", "port_name": "Gi0/25", "site_name": "研發實驗室", "network_name": "Lab-VLAN5", "is_online": True},
}

def _get_athenac_oauth_token(base_url: str, username: str, password: str) -> str:
    now_ts = time.monotonic()
    with _athenac_token_lock:
        if _athenac_token_cache["token"] and now_ts < _athenac_token_cache["expires_at"] - 30:
            return _athenac_token_cache["token"]

    if not username or not password:
        return ""
    try:
        ctx = ssl._create_unverified_context()
        form_data = urllib.parse.urlencode({
            "grant_type": "password",
            "username": username,
            "password": password,
        }).encode("utf-8")
        req = urllib.request.Request(
            f"{base_url.rstrip('/')}/api/Connect/Token",
            data=form_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST"
        )
        with urllib.request.urlopen(req, context=ctx, timeout=4) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
            tok = payload.get("access_token", "")
            exp = int(payload.get("expires_in", 3600))
            if tok:
                with _athenac_token_lock:
                    _athenac_token_cache["token"] = tok
                    _athenac_token_cache["expires_at"] = now_ts + exp
            return tok
    except Exception as e:
        print(f"[AtheNAC OAuth] Failed to obtain token: {e}")
        return ""

def _build_simulated_athenac_host(ip_str: str) -> Dict[str, Any]:
    if ip_str in SIMULATED_ATHENAC_HOSTS:
        d = dict(SIMULATED_ATHENAC_HOSTS[ip_str])
        d["ip"] = ip_str
        d["is_simulated"] = True
        return d
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if is_internal_ip(ip_obj):
            octets = ip_str.split(".")
            suffix = octets[-1].zfill(2) if len(octets) == 4 else "01"
            mac_tail = "-".join(f"{int(o):02X}" for o in octets) if len(octets) == 4 else "00-00-00-01"
            return {
                "ip": ip_str,
                "hostname": f"HOST-{suffix}",
                "mac": f"00-50-{mac_tail}",
                "vendor": "Standard NIC",
                "os_detail": "Windows / Linux",
                "switch_name": "Access-SW01",
                "port_name": f"Gi1/0/{(int(octets[-1]) % 48) + 1}" if len(octets) == 4 else "Gi1/0/1",
                "site_name": "內部網路",
                "network_name": "Internal-LAN",
                "is_online": True,
                "is_simulated": True
            }
    except Exception:
        pass
    return {
        "ip": ip_str,
        "hostname": "",
        "mac": "",
        "vendor": "",
        "os_detail": "",
        "switch_name": "",
        "port_name": "",
        "site_name": "",
        "network_name": "External Internet",
        "is_online": False,
        "is_simulated": True
    }

def query_athenac_host_overview(ip_str: str, force_refresh: bool = False) -> Dict[str, Any]:
    """Query PIXIS Open API v3 /apiv3/Host/Overview?Ip={ip} with cache and optional simulated fallback."""
    if not ip_str:
        return {}
    ip_clean = ip_str.strip()

    # Only internal IPs exist in NAC
    try:
        if not is_internal_ip(ipaddress.ip_address(ip_clean)):
            return _build_simulated_athenac_host(ip_clean)
    except Exception:
        return {}

    # Check SQLite cache (5 min TTL)
    if not force_refresh:
        try:
            conn = sqlite3.connect(DB_PATH, timeout=10.0)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("SELECT * FROM athenac_cache WHERE ip = ?", (ip_clean,))
            row = cur.fetchone()
            conn.close()
            if row:
                updated_dt = parse_tw_datetime(row["updated_at"])
                if (now_tw() - updated_dt).total_seconds() < 300:
                    return {
                        "ip": row["ip"],
                        "hostname": row["hostname"] or "",
                        "mac": row["mac"] or "",
                        "vendor": row["vendor"] or "",
                        "os_detail": row["os_detail"] or "",
                        "switch_name": row["switch_name"] or "",
                        "port_name": row["port_name"] or "",
                        "site_name": row["site_name"] or "",
                        "network_name": row["network_name"] or "",
                        "is_online": bool(row["is_online"]),
                        "is_simulated": bool(row["is_simulated"]),
                    }
        except Exception:
            pass

    base_url = get_system_setting("athenac_api_url", "https://192.168.25.180:8001").strip()
    api_key = get_system_setting("athenac_api_key", "").strip()
    username = get_system_setting("athenac_username", "").strip()
    password = get_system_setting("athenac_password", "").strip()
    mock_fallback = get_system_setting("athenac_mock_fallback", "1") == "1"

    headers: Dict[str, str] = {"Accept": "application/json"}
    has_creds = False
    if api_key:
        headers["X-Api-Key"] = api_key
        has_creds = True
    elif username and password:
        tok = _get_athenac_oauth_token(base_url, username, password)
        if tok:
            headers["Authorization"] = f"Bearer {tok}"
            has_creds = True

    host_info = None
    if base_url and has_creds:
        try:
            ctx = ssl._create_unverified_context()
            url = f"{base_url.rstrip('/')}/apiv3/Host/Overview?Ip={urllib.parse.quote(ip_clean)}"
            req = urllib.request.Request(url, headers=headers, method="GET")
            with urllib.request.urlopen(req, context=ctx, timeout=4) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                item = data[0] if isinstance(data, list) and data else (data if isinstance(data, dict) else None)
                if item:
                    loc = item.get("Location") or {}
                    host_info = {
                        "ip": ip_clean,
                        "hostname": item.get("HostName") or "",
                        "mac": item.get("Mac") or "",
                        "vendor": item.get("Vendor") or "",
                        "os_detail": item.get("OsDetail") or "",
                        "switch_name": loc.get("SwitchName") or "",
                        "port_name": loc.get("PortName") or "",
                        "site_name": item.get("SiteName") or "",
                        "network_name": item.get("NetworkName") or "",
                        "is_online": bool(item.get("IsOnline", False)),
                        "is_simulated": False,
                    }
        except Exception as e:
            print(f"[AtheNAC] Query /apiv3/Host/Overview failed for {ip_clean}: {e}")

    if host_info is None:
        if mock_fallback:
            host_info = _build_simulated_athenac_host(ip_clean)
        else:
            host_info = {
                "ip": ip_clean, "hostname": "", "mac": "", "vendor": "", "os_detail": "",
                "switch_name": "", "port_name": "", "site_name": "", "network_name": "",
                "is_online": False, "is_simulated": False
            }

    try:
        conn = sqlite3.connect(DB_PATH, timeout=10.0)
        cur = conn.cursor()
        cur.execute("""
            INSERT OR REPLACE INTO athenac_cache (
                ip, hostname, mac, vendor, os_detail, switch_name, port_name,
                site_name, network_name, is_online, is_simulated, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            host_info["ip"], host_info["hostname"], host_info["mac"], host_info["vendor"],
            host_info["os_detail"], host_info["switch_name"], host_info["port_name"],
            host_info["site_name"], host_info["network_name"],
            1 if host_info["is_online"] else 0,
            1 if host_info.get("is_simulated") else 0,
            now_tw_str()
        ))
        conn.commit()
        conn.close()
    except Exception:
        pass

    return host_info

def resolve_athenac_hosts_batch(ips: Iterable[str]) -> Dict[str, Dict[str, Any]]:
    unique_ips = [ip for ip in set(ips) if ip]
    results: Dict[str, Dict[str, Any]] = {}
    if not unique_ips:
        return results
    api_key = get_system_setting("athenac_api_key", "").strip()
    username = get_system_setting("athenac_username", "").strip()
    password = get_system_setting("athenac_password", "").strip()
    mock_fallback = get_system_setting("athenac_mock_fallback", "1") == "1"
    has_creds = bool(api_key or (username and password))
    if not has_creds:
        for ip in unique_ips:
            ip_clean = ip.strip()
            if mock_fallback:
                results[ip_clean] = _build_simulated_athenac_host(ip_clean)
            else:
                results[ip_clean] = {
                    "ip": ip_clean, "hostname": "", "mac": "", "vendor": "", "os_detail": "",
                    "switch_name": "", "port_name": "", "site_name": "", "network_name": "",
                    "is_online": False, "is_simulated": False
                }
        return results
    with ThreadPoolExecutor(max_workers=6) as pool:
        future_map = {pool.submit(query_athenac_host_overview, ip): ip for ip in unique_ips}
        for fut, ip in future_map.items():
            try:
                results[ip] = fut.result(timeout=5)
            except Exception:
                results[ip] = _build_simulated_athenac_host(ip)
    return results

class AtheNACSettingsRequest(BaseModel):
    api_url: str = "https://192.168.25.180:8001"
    api_key: Optional[str] = ""
    username: Optional[str] = ""
    password: Optional[str] = ""
    mock_fallback: bool = True

@app.get("/api/settings/athenac")
def get_athenac_settings():
    api_key = get_system_setting("athenac_api_key", "")
    pwd = get_system_setting("athenac_password", "")
    return {
        "api_url": get_system_setting("athenac_api_url", "https://192.168.25.180:8001"),
        "api_key_masked": (api_key[:8] + "****") if len(api_key) > 8 else ("****" if api_key else ""),
        "has_api_key": bool(api_key),
        "username": get_system_setting("athenac_username", ""),
        "has_password": bool(pwd),
        "mock_fallback": get_system_setting("athenac_mock_fallback", "1") == "1",
    }

@app.post("/api/settings/athenac")
def save_athenac_settings(payload: AtheNACSettingsRequest):
    set_system_setting("athenac_api_url", payload.api_url.strip())
    if payload.api_key is not None and payload.api_key.strip() != "":
        set_system_setting("athenac_api_key", payload.api_key.strip())
    if payload.username is not None:
        set_system_setting("athenac_username", payload.username.strip())
    if payload.password is not None and payload.password.strip() != "":
        set_system_setting("athenac_password", payload.password.strip())
    set_system_setting("athenac_mock_fallback", "1" if payload.mock_fallback else "0")

    # Clear cached tokens/hosts so updated settings take effect immediately
    with _athenac_token_lock:
        _athenac_token_cache["token"] = ""
        _athenac_token_cache["expires_at"] = 0.0
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("DELETE FROM athenac_cache")
        conn.commit()
        conn.close()
    except Exception:
        pass
    return {"status": "success", "message": "AtheNAC (PIXIS Open API v3) 連線設定已儲存並清除快取。"}

@app.post("/api/settings/athenac/test")
def test_athenac_connection(test_ip: str = Query("192.168.30.101")):
    base_url = get_system_setting("athenac_api_url", "https://192.168.25.180:8001").strip()
    api_key = get_system_setting("athenac_api_key", "").strip()
    username = get_system_setting("athenac_username", "").strip()
    password = get_system_setting("athenac_password", "").strip()

    if not api_key and not (username and password):
        return {
            "status": "simulated",
            "message": "尚未設定 AtheNAC API Key 或 OAuth2 帳號密碼，目前自動使用模擬設備資訊展示模式。",
            "sample": _build_simulated_athenac_host(test_ip)
        }

    info = query_athenac_host_overview(test_ip, force_refresh=True)
    if info and not info.get("is_simulated"):
        return {"status": "connected", "message": f"成功連線至 {base_url} 並取得主機資料！", "sample": info}
    return {
        "status": "fallback",
        "message": f"無法從 {base_url} 取得即時資料（可能憑證過期、網路未通或無該 IP 紀錄），已啟用模擬備援資料。",
        "sample": info
    }

# ---------------- External Threat Intelligence Integration (Criminal IP / VirusTotal / Shodan / Censys) ----------------
RISKY_PORTS_SET = {
    21, 22, 23, 25, 135, 139, 445, 1433, 1521, 2375, 2376,
    3306, 3389, 4444, 5432, 5900, 6379, 7001, 8080, 8081,
    8443, 8888, 9001, 9030, 9200, 10000, 11211, 27017
}

class _QuotaExhaustedError(Exception):
    pass

def _is_public_routable_ip(ip_str: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address((ip_str or "").strip())
        if is_internal_ip(ip_obj):
            return False
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast or ip_obj.is_unspecified or ip_obj.is_link_local:
            return False
        return True
    except Exception:
        return False

def _resolve_ptr_domain(ip_clean: str) -> str:
    try:
        host, _, _ = socket.gethostbyaddr(ip_clean)
        if host and host != ip_clean:
            return host
    except Exception:
        pass
    return ""

def _score_str_to_int_and_level(inbound: str, outbound: str) -> Tuple[int, str]:
    mapping = {
        "critical": (95, "critical"),
        "dangerous": (80, "high"),
        "moderate": (55, "medium"),
        "low": (25, "low"),
        "safe": (5, "safe"),
    }
    in_s, in_l = mapping.get((inbound or "").strip().lower(), (10, "safe"))
    out_s, out_l = mapping.get((outbound or "").strip().lower(), (10, "safe"))
    if in_s >= out_s:
        return in_s, in_l
    return out_s, out_l

def _query_criminal_ip(ip_clean: str, api_key: str) -> Dict[str, Any]:
    """Query Criminal IP REST API (/v1/asset/ip/report)."""
    ctx = ssl._create_unverified_context()
    url = f"https://api.criminalip.io/v1/asset/ip/report?ip={urllib.parse.quote(ip_clean)}&full=true"
    req = urllib.request.Request(
        url,
        headers={"x-api-key": api_key, "Accept": "application/json", "User-Agent": "NetflowCollector-ThreatIntel/1.0"},
        method="GET"
    )
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=6) as resp:
            if resp.status == 429:
                raise _QuotaExhaustedError("Criminal IP HTTP 429")
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as he:
        if he.code in (429, 402, 403):
            raise _QuotaExhaustedError(f"Criminal IP HTTP {he.code}")
        raise

    if isinstance(data, dict) and data.get("status") in (429, 402, 403):
        raise _QuotaExhaustedError(f"Criminal IP status {data.get('status')}: {data.get('message', '')}")

    score_obj = data.get("score") or {}
    inbound = str(score_obj.get("inbound") or "Safe")
    outbound = str(score_obj.get("outbound") or "Safe")
    risk_score, risk_level = _score_str_to_int_and_level(inbound, outbound)

    # Extract domain / hostname
    domain = ""
    hn_list = (data.get("hostname") or {}).get("data") or []
    if hn_list and isinstance(hn_list, list):
        domain = hn_list[0].get("domain_name_full") or hn_list[0].get("domain_name_rep") or ""
    if not domain:
        dm_list = (data.get("domain") or {}).get("data") or []
        if dm_list and isinstance(dm_list, list):
            domain = dm_list[0].get("domain") or ""
    if not domain:
        domain = _resolve_ptr_domain(ip_clean)

    # Extract ports & risky ports
    port_list = (data.get("port") or {}).get("data") or []
    open_ports_set = set()
    risky_ports_set = set()
    for p_item in port_list:
        p_no = p_item.get("open_port_no") or p_item.get("port")
        if p_no is not None:
            try:
                p_int = int(p_no)
                open_ports_set.add(p_int)
                if p_int in RISKY_PORTS_SET or p_item.get("is_vulnerability"):
                    risky_ports_set.add(p_int)
            except Exception:
                pass

    # Extract vulnerabilities
    vuln_list = (data.get("vulnerability") or {}).get("data") or []
    vulns = []
    for v_item in vuln_list[:10]:
        cve = v_item.get("cve_id")
        if cve and cve not in vulns:
            vulns.append(cve)
        p_no = v_item.get("open_port_no")
        if p_no:
            try:
                risky_ports_set.add(int(p_no))
            except Exception:
                pass

    if vulns and risk_score < 75:
        risk_score = 80
        risk_level = "high"
    elif risky_ports_set and risk_score < 45:
        risk_score = 50
        risk_level = "medium"

    # Extract tags / issues
    issues = data.get("issues") or {}
    tags = [k.replace("is_", "") for k, v in issues.items() if v is True]

    # Whois org / country
    whois_list = (data.get("whois") or {}).get("data") or []
    org = whois_list[0].get("org_name", "") if whois_list else ""
    country = (whois_list[0].get("org_country_code", "") if whois_list else "").upper()

    open_ports_str = ",".join(str(p) for p in sorted(open_ports_set))
    risky_ports_str = ",".join(str(p) for p in sorted(risky_ports_set))
    vulns_str = ",".join(vulns[:8])
    tags_str = ",".join(tags[:8])

    summary = f"Criminal IP 評定 Inbound={inbound} / Outbound={outbound} (風險值 {risk_score})"
    if risky_ports_str:
        summary += f"｜高風險 Port: {risky_ports_str}"
    if vulns_str:
        summary += f"｜弱點: {vulns_str}"

    return {
        "ip": ip_clean,
        "domain": domain,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "inbound_score": inbound,
        "outbound_score": outbound,
        "risky_ports": risky_ports_str,
        "open_ports": open_ports_str,
        "vulns": vulns_str,
        "tags": tags_str,
        "country": country,
        "org": org,
        "provider": "Criminal IP",
        "summary": summary,
    }

def _query_virustotal_ip(ip_clean: str, api_key: str) -> Dict[str, Any]:
    """Fallback 1: Query VirusTotal REST API v3 (/api/v3/ip_addresses/{ip})."""
    ctx = ssl._create_unverified_context()
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{urllib.parse.quote(ip_clean)}"
    req = urllib.request.Request(
        url,
        headers={"x-apikey": api_key, "Accept": "application/json", "User-Agent": "NetflowCollector-ThreatIntel/1.0"},
        method="GET"
    )
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=6) as resp:
            if resp.status == 429:
                raise _QuotaExhaustedError("VirusTotal HTTP 429")
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as he:
        if he.code in (429, 401, 403):
            raise _QuotaExhaustedError(f"VirusTotal HTTP {he.code}")
        raise

    attrs = ((data or {}).get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    malicious = int(stats.get("malicious") or 0)
    suspicious = int(stats.get("suspicious") or 0)
    total_bad = malicious + suspicious

    if malicious >= 5:
        risk_score, risk_level, in_str = min(98, 75 + malicious * 3), "critical", "Critical"
    elif malicious >= 2 or total_bad >= 3:
        risk_score, risk_level, in_str = min(85, 60 + total_bad * 5), "high", "Dangerous"
    elif total_bad >= 1:
        risk_score, risk_level, in_str = 45, "medium", "Moderate"
    else:
        risk_score, risk_level, in_str = 5, "safe", "Safe"

    cert_subj = ((attrs.get("last_https_certificate") or {}).get("subject") or {})
    domain = cert_subj.get("CN") or _resolve_ptr_domain(ip_clean)
    org = attrs.get("as_owner") or ""
    country = (attrs.get("country") or "").upper()
    tags = attrs.get("tags") or []

    # Supplement open/risky ports via free InternetDB so VT results also include port intel
    open_ports_str, risky_ports_str, vulns_str = "", "", ""
    try:
        idb = _query_internetdb_raw(ip_clean)
        open_ports_str = idb["open_ports"]
        risky_ports_str = idb["risky_ports"]
        vulns_str = idb["vulns"]
        if not domain and idb["domain"]:
            domain = idb["domain"]
        if risky_ports_str and risk_score < 40:
            risk_score = 45
            risk_level = "medium"
            in_str = "Moderate"
    except Exception:
        pass

    summary = f"VirusTotal 惡意引擎檢出 {malicious} 項 / 可疑 {suspicious} 項 (風險值 {risk_score})"
    if risky_ports_str:
        summary += f"｜高風險 Port: {risky_ports_str}"

    return {
        "ip": ip_clean,
        "domain": domain,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "inbound_score": in_str,
        "outbound_score": in_str,
        "risky_ports": risky_ports_str,
        "open_ports": open_ports_str,
        "vulns": vulns_str,
        "tags": ",".join(str(t) for t in tags[:8]),
        "country": country,
        "org": org,
        "provider": "VirusTotal (備援)",
        "summary": summary,
    }

def _query_shodan_ip(ip_clean: str, api_key: str) -> Dict[str, Any]:
    """Fallback 2: Query Shodan Host API (/shodan/host/{ip})."""
    ctx = ssl._create_unverified_context()
    url = f"https://api.shodan.io/shodan/host/{urllib.parse.quote(ip_clean)}?key={urllib.parse.quote(api_key)}"
    req = urllib.request.Request(url, headers={"Accept": "application/json"}, method="GET")
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=6) as resp:
            if resp.status == 429:
                raise _QuotaExhaustedError("Shodan HTTP 429")
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as he:
        if he.code in (429, 401, 403):
            raise _QuotaExhaustedError(f"Shodan HTTP {he.code}")
        raise

    hostnames = data.get("hostnames") or data.get("domains") or []
    domain = hostnames[0] if hostnames else _resolve_ptr_domain(ip_clean)
    ports = [int(p) for p in (data.get("ports") or []) if str(p).isdigit()]
    vulns = list(data.get("vulns") or [])
    tags = list(data.get("tags") or [])
    risky_ports = [p for p in sorted(ports) if p in RISKY_PORTS_SET or vulns]

    if vulns or any(t in ("malware", "compromised", "c2", "tor") for t in tags):
        risk_score, risk_level, in_str = min(95, 70 + len(vulns) * 5), "high", "Dangerous"
    elif risky_ports:
        risk_score, risk_level, in_str = min(70, 40 + len(risky_ports) * 10), "medium", "Moderate"
    elif ports:
        risk_score, risk_level, in_str = 20, "low", "Low"
    else:
        risk_score, risk_level, in_str = 5, "safe", "Safe"

    open_ports_str = ",".join(str(p) for p in sorted(ports))
    risky_ports_str = ",".join(str(p) for p in sorted(set(risky_ports)))
    vulns_str = ",".join(vulns[:8])

    return {
        "ip": ip_clean,
        "domain": domain,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "inbound_score": in_str,
        "outbound_score": in_str,
        "risky_ports": risky_ports_str,
        "open_ports": open_ports_str,
        "vulns": vulns_str,
        "tags": ",".join(tags[:8]),
        "country": (data.get("country_code") or "").upper(),
        "org": data.get("org") or data.get("isp") or "",
        "provider": "Shodan API (備援)",
        "summary": f"Shodan 偵測開放埠 [{open_ports_str or '無'}]｜風險埠 [{risky_ports_str or '無'}] (風險值 {risk_score})",
    }

def _query_internetdb_raw(ip_clean: str) -> Dict[str, str]:
    ctx = ssl._create_unverified_context()
    url = f"https://internetdb.shodan.io/{urllib.parse.quote(ip_clean)}"
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "NetflowCollector/1.0"}, method="GET")
    with urllib.request.urlopen(req, context=ctx, timeout=4) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    hostnames = data.get("hostnames") or []
    ports = [int(p) for p in (data.get("ports") or []) if str(p).isdigit()]
    vulns = list(data.get("vulns") or [])
    tags = list(data.get("tags") or [])
    risky = [p for p in sorted(ports) if p in RISKY_PORTS_SET]
    if vulns and not risky:
        risky = sorted(ports)[:5]
    return {
        "domain": hostnames[0] if hostnames else "",
        "open_ports": ",".join(str(p) for p in sorted(ports)),
        "risky_ports": ",".join(str(p) for p in sorted(set(risky))),
        "vulns": ",".join(vulns[:8]),
        "tags": ",".join(tags[:8]),
        "ports_list": ports,
        "vulns_list": vulns,
        "tags_list": tags,
    }

def _query_internetdb_fallback(ip_clean: str, fallback_note: str = "") -> Dict[str, Any]:
    """Tier 4 Guaranteed Keyless Fallback: Shodan InternetDB + Reverse DNS PTR."""
    domain = ""
    open_ports_str = ""
    risky_ports_str = ""
    vulns_str = ""
    tags_str = ""
    ports_list = []
    vulns_list = []
    tags_list = []

    try:
        idb = _query_internetdb_raw(ip_clean)
        domain = idb["domain"]
        open_ports_str = idb["open_ports"]
        risky_ports_str = idb["risky_ports"]
        vulns_str = idb["vulns"]
        tags_str = idb["tags"]
        ports_list = idb["ports_list"]
        vulns_list = idb["vulns_list"]
        tags_list = idb["tags_list"]
    except Exception:
        pass

    if not domain:
        domain = _resolve_ptr_domain(ip_clean)

    bad_tags = {"malware", "compromised", "c2", "tor", "botnet", "scanner"}
    if len(vulns_list) >= 3 or (set(tags_list) & bad_tags):
        risk_score, risk_level, in_str = min(95, 75 + len(vulns_list) * 4), "high", "Dangerous"
    elif vulns_list or risky_ports_str:
        risk_score, risk_level, in_str = min(72, 45 + len(ports_list) * 5), "medium", "Moderate"
    elif ports_list:
        risk_score, risk_level, in_str = 20, "low", "Low"
    else:
        risk_score, risk_level, in_str = 5, "safe", "Safe"

    prov_label = "Shodan InternetDB (自動備援)" if fallback_note else "Shodan InternetDB"
    summary = f"情資檢測開放埠 [{open_ports_str or '無'}]"
    if risky_ports_str:
        summary += f"｜具風險 Port: {risky_ports_str}"
    if vulns_str:
        summary += f"｜CVE 弱點: {vulns_str}"
    if fallback_note:
        summary += f" ({fallback_note})"

    return {
        "ip": ip_clean,
        "domain": domain,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "inbound_score": in_str,
        "outbound_score": in_str,
        "risky_ports": risky_ports_str,
        "open_ports": open_ports_str,
        "vulns": vulns_str,
        "tags": tags_str,
        "country": "",
        "org": "",
        "provider": prov_label,
        "summary": summary,
    }

def get_threat_intel_batch_from_db(ips: Iterable[str]) -> Dict[str, Dict[str, Any]]:
    """Fetch cached Threat Intelligence records from SQLite for a set of IPs."""
    clean_ips = [str(ip).strip() for ip in set(ips) if ip and str(ip).strip()]
    if not clean_ips:
        return {}
    results: Dict[str, Dict[str, Any]] = {}
    try:
        conn = sqlite3.connect(DB_PATH, timeout=10.0)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        # Query in chunks of 400
        for i in range(0, len(clean_ips), 400):
            chunk = clean_ips[i:i+400]
            ph = ",".join("?" for _ in chunk)
            cur.execute(f"SELECT * FROM threat_intel_cache WHERE ip IN ({ph})", tuple(chunk))
            for row in cur.fetchall():
                d = dict(row)
                d.pop("raw_json", None)
                results[d["ip"]] = d
        conn.close()
    except Exception as e:
        print(f"[ThreatIntel DB Read Notice] {e}", flush=True)
    return results

def query_and_cache_ip_threat_intel(
    ip_str: str,
    force_refresh: bool = False,
    exhausted_providers: Optional[set] = None
) -> Optional[Dict[str, Any]]:
    """
    Query IP threat intelligence with DB-first caching and 4-tier automatic fallback:
    1. Local SQLite DB (`threat_intel_cache`) — if already queried and not force_refresh, return immediately.
    2. Primary: Criminal IP (`/v1/asset/ip/report`)
    3. Fallback 1 (on HTTP 429 / quota / unconfigured): VirusTotal (`/api/v3/ip_addresses/{ip}`)
    4. Fallback 2: Shodan API (`/shodan/host/{ip}`)
    5. Fallback 3 (Keyless guaranteed): Shodan InternetDB + Reverse DNS
    """
    ip_clean = (ip_str or "").strip()
    if not ip_clean or not _is_public_routable_ip(ip_clean):
        return None

    if exhausted_providers is None:
        exhausted_providers = set()

    # 1. Check DB Cache first ("問過的存起來，還沒判斷出來的才會再用 API 去問")
    if not force_refresh:
        cached = get_threat_intel_batch_from_db([ip_clean]).get(ip_clean)
        if cached:
            cached["from_cache"] = True
            return cached

    cip_key = get_system_setting("criminalip_api_key", "").strip()
    vt_key = get_system_setting("virustotal_api_key", "").strip()
    shodan_key = get_system_setting("shodan_api_key", "").strip()

    result = None
    fallback_reason = ""

    # Tier 1: Criminal IP (Main)
    if cip_key and "criminalip" not in exhausted_providers:
        try:
            result = _query_criminal_ip(ip_clean, cip_key)
        except _QuotaExhaustedError as qe:
            exhausted_providers.add("criminalip")
            fallback_reason = f"Criminal IP 額度已滿 ({qe})，自動切換備援"
            print(f"[ThreatIntel] {fallback_reason}", flush=True)
        except Exception as e:
            fallback_reason = f"Criminal IP 連線異常，自動切換備援"
            print(f"[ThreatIntel] Criminal IP error for {ip_clean}: {e}", flush=True)

    # Tier 2: VirusTotal (Fallback 1)
    if result is None and vt_key and "virustotal" not in exhausted_providers:
        try:
            result = _query_virustotal_ip(ip_clean, vt_key)
        except _QuotaExhaustedError as qe:
            exhausted_providers.add("virustotal")
            fallback_reason = f"VirusTotal 額度已滿 ({qe})，自動切換備援"
            print(f"[ThreatIntel] {fallback_reason}", flush=True)
        except Exception as e:
            print(f"[ThreatIntel] VirusTotal error for {ip_clean}: {e}", flush=True)

    # Tier 3: Shodan API (Fallback 2)
    if result is None and shodan_key and "shodan" not in exhausted_providers:
        try:
            result = _query_shodan_ip(ip_clean, shodan_key)
        except _QuotaExhaustedError as qe:
            exhausted_providers.add("shodan")
            fallback_reason = f"Shodan API 額度已滿 ({qe})"
            print(f"[ThreatIntel] {fallback_reason}", flush=True)
        except Exception as e:
            print(f"[ThreatIntel] Shodan error for {ip_clean}: {e}", flush=True)

    # Tier 4: Keyless Shodan InternetDB + Reverse DNS PTR (Guaranteed Fallback)
    if result is None:
        result = _query_internetdb_fallback(ip_clean, fallback_reason)

    now_s = now_tw_str()
    result["queried_at"] = now_s
    result["updated_at"] = now_s
    result["from_cache"] = False

    # Persist into SQLite threat_intel_cache
    try:
        conn = sqlite3.connect(DB_PATH, timeout=15.0)
        cur = conn.cursor()
        cur.execute("""
            INSERT OR REPLACE INTO threat_intel_cache (
                ip, domain, risk_score, risk_level, inbound_score, outbound_score,
                risky_ports, open_ports, vulns, tags, country, org, provider,
                summary, raw_json, queried_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            result["ip"],
            result.get("domain") or "",
            int(result.get("risk_score") or 0),
            result.get("risk_level") or "safe",
            result.get("inbound_score") or "Safe",
            result.get("outbound_score") or "Safe",
            result.get("risky_ports") or "",
            result.get("open_ports") or "",
            result.get("vulns") or "",
            result.get("tags") or "",
            result.get("country") or "",
            result.get("org") or "",
            result.get("provider") or "",
            result.get("summary") or "",
            "{}",
            now_s,
            now_s
        ))
        # If domain was discovered, also cache in dns_cache for fast lookup
        if result.get("domain"):
            cur.execute("""
                INSERT OR REPLACE INTO dns_cache (ip, domain, last_resolved)
                VALUES (?, ?, ?)
            """, (result["ip"], result["domain"], now_s))
        conn.commit()
        conn.close()
    except Exception as db_e:
        print(f"[ThreatIntel DB Save Notice] {db_e}", flush=True)

    return result

def enrich_audit_with_threat_intel(client, start_ts_str: str, end_ts_str: str) -> Dict[str, Any]:
    """
    During '立即盤查', collect candidate external Public IPs from traffic in [start_ts_str, end_ts_str]:
    1. Match against existing `threat_intel_cache` in DB first.
    2. Only query uncached external Public IPs via external APIs (up to batch_limit).
    3. Return summary stats for UI notification.
    """
    stats = {
        "candidate_external_ips": 0,
        "intel_cached_hits": 0,
        "intel_queried_new": 0,
        "intel_risky_ips": 0,
        "intel_provider_used": "Local DB Cache",
    }
    try:
        batch_limit = int(get_system_setting("threat_intel_batch_limit", "25") or 25)
        batch_limit = max(5, min(100, batch_limit))

        # Gather candidate external IPs prioritizing non-standard ports & high bytes
        sql = f"""
            SELECT ip, sum(bytes) as total_bytes, count() as flows
            FROM (
                SELECT dst as ip, octets as bytes FROM ipfix
                WHERE ts >= '{start_ts_str}' AND ts <= '{end_ts_str}'
                  AND NOT (dst LIKE '192.168.%' OR dst LIKE '10.%' OR dst LIKE '172.16.%' OR dst LIKE '172.17.%' OR dst LIKE '172.18.%' OR dst LIKE '172.19.%' OR dst LIKE '172.2_.%' OR dst LIKE '172.30.%' OR dst LIKE '172.31.%' OR dst LIKE '127.%' OR dst LIKE '224.%' OR dst LIKE '255.%')
                LIMIT 3000
                UNION ALL
                SELECT dst as ip, octets as bytes FROM netflow9
                WHERE ts >= '{start_ts_str}' AND ts <= '{end_ts_str}'
                  AND NOT (dst LIKE '192.168.%' OR dst LIKE '10.%' OR dst LIKE '172.16.%' OR dst LIKE '172.17.%' OR dst LIKE '172.18.%' OR dst LIKE '172.19.%' OR dst LIKE '172.2_.%' OR dst LIKE '172.30.%' OR dst LIKE '172.31.%' OR dst LIKE '127.%' OR dst LIKE '224.%' OR dst LIKE '255.%')
                LIMIT 3000
            )
            GROUP BY ip
            ORDER BY total_bytes DESC
            LIMIT 120
        """
        res = client.query(sql)
        candidate_ips = [r[0] for r in res.result_rows if r and r[0] and _is_public_routable_ip(r[0])]
        stats["candidate_external_ips"] = len(candidate_ips)

        if not candidate_ips:
            return stats

        # Step 1: Check existing DB records first
        existing_map = get_threat_intel_batch_from_db(candidate_ips)
        stats["intel_cached_hits"] = len(existing_map)

        missing_ips = [ip for ip in candidate_ips if ip not in existing_map][:batch_limit]
        exhausted_providers: set = set()
        providers_used = set()

        # Step 2: Query only uncached IPs via external API with multi-provider fallback
        if missing_ips:
            with ThreadPoolExecutor(max_workers=5) as pool:
                futs = {
                    pool.submit(query_and_cache_ip_threat_intel, ip, False, exhausted_providers): ip
                    for ip in missing_ips
                }
                for fut, ip in futs.items():
                    try:
                        info = fut.result(timeout=10)
                        if info:
                            existing_map[ip] = info
                            if not info.get("from_cache"):
                                stats["intel_queried_new"] += 1
                            if info.get("provider"):
                                providers_used.add(info["provider"])
                    except Exception:
                        pass

        if providers_used:
            stats["intel_provider_used"] = " / ".join(sorted(providers_used))

        # Step 3: Count risky IPs discovered/matched in this audit
        risky_ips = [
            ip for ip, info in existing_map.items()
            if info.get("risk_level") in ("medium", "high", "critical") or info.get("risky_ports")
        ]
        stats["intel_risky_ips"] = len(risky_ips)
    except Exception as e:
        print(f"[ThreatIntel Audit Enrich Notice] {e}", flush=True)
    return stats

class ThreatIntelSettingsRequest(BaseModel):
    criminalip_api_key: Optional[str] = None
    virustotal_api_key: Optional[str] = None
    shodan_api_key: Optional[str] = None
    censys_api_id: Optional[str] = None
    censys_api_secret: Optional[str] = None
    batch_limit: int = 25

def _mask_secret(val: str) -> str:
    if not val:
        return ""
    return (val[:6] + "****" + val[-3:]) if len(val) > 10 else "****"

@app.get("/api/settings/threat-intel")
def get_threat_intel_settings():
    cip = get_system_setting("criminalip_api_key", "")
    vt = get_system_setting("virustotal_api_key", "")
    shodan = get_system_setting("shodan_api_key", "")
    censys_id = get_system_setting("censys_api_id", "")
    censys_sec = get_system_setting("censys_api_secret", "")
    batch_limit = int(get_system_setting("threat_intel_batch_limit", "25") or 25)

    total_cached = 0
    risky_cached = 0
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM threat_intel_cache")
        total_cached = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM threat_intel_cache WHERE risk_level IN ('medium', 'high', 'critical') OR risky_ports != ''")
        risky_cached = cur.fetchone()[0]
        conn.close()
    except Exception:
        pass

    return {
        "has_criminalip_key": bool(cip),
        "criminalip_key_masked": _mask_secret(cip),
        "has_virustotal_key": bool(vt),
        "virustotal_key_masked": _mask_secret(vt),
        "has_shodan_key": bool(shodan),
        "shodan_key_masked": _mask_secret(shodan),
        "censys_api_id": censys_id,
        "has_censys_secret": bool(censys_sec),
        "batch_limit": batch_limit,
        "total_cached_ips": total_cached,
        "risky_cached_ips": risky_cached,
    }

@app.post("/api/settings/threat-intel")
def save_threat_intel_settings(payload: ThreatIntelSettingsRequest):
    if payload.criminalip_api_key is not None and payload.criminalip_api_key.strip() != "":
        set_system_setting("criminalip_api_key", payload.criminalip_api_key.strip())
    if payload.virustotal_api_key is not None and payload.virustotal_api_key.strip() != "":
        set_system_setting("virustotal_api_key", payload.virustotal_api_key.strip())
    if payload.shodan_api_key is not None and payload.shodan_api_key.strip() != "":
        set_system_setting("shodan_api_key", payload.shodan_api_key.strip())
    if payload.censys_api_id is not None:
        set_system_setting("censys_api_id", payload.censys_api_id.strip())
    if payload.censys_api_secret is not None and payload.censys_api_secret.strip() != "":
        set_system_setting("censys_api_secret", payload.censys_api_secret.strip())
    set_system_setting("threat_intel_batch_limit", str(max(5, min(100, payload.batch_limit))))
    return {"status": "success", "message": "外部威脅情資 API 設定（Criminal IP / VirusTotal / Shodan）已成功儲存！"}

@app.post("/api/settings/threat-intel/test")
def test_threat_intel_api(test_ip: str = Query("1.1.1.1")):
    info = query_and_cache_ip_threat_intel(test_ip, force_refresh=True)
    if not info:
        raise HTTPException(status_code=400, detail="請輸入有效的外部 Public IP 位址進行測試")
    return {
        "status": "success",
        "message": f"測試成功！由【{info.get('provider')}】回傳 {test_ip} 情資（Domain: {info.get('domain') or '無'}, 風險值: {info.get('risk_score')}, 風險 Port: {info.get('risky_ports') or '無'}）",
        "sample": info
    }

@app.get("/api/threat-intel/cache")
def list_threat_intel_cache(
    search: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500)
):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        clauses = []
        params = []
        if search and search.strip():
            s = f"%{search.strip()}%"
            clauses.append("(ip LIKE ? OR domain LIKE ? OR risky_ports LIKE ? OR provider LIKE ? OR summary LIKE ?)")
            params.extend([s, s, s, s, s])
        if risk_level and risk_level.strip():
            clauses.append("risk_level = ?")
            params.append(risk_level.strip().lower())

        where_sql = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        cur.execute(f"""
            SELECT ip, domain, risk_score, risk_level, inbound_score, outbound_score,
                   risky_ports, open_ports, vulns, tags, country, org, provider, summary,
                   queried_at, updated_at
            FROM threat_intel_cache
            {where_sql}
            ORDER BY risk_score DESC, updated_at DESC
            LIMIT ?
        """, tuple(params + [limit]))
        records = [dict(r) for r in cur.fetchall()]

        # Check which IPs are already in threat_scenarios
        cur.execute("SELECT src_scope, dst_scope FROM threat_scenarios")
        scenario_ips = set()
        for s_row in cur.fetchall():
            for raw_sc in (s_row[0] or "", s_row[1] or ""):
                for tok in raw_sc.split(","):
                    t = tok.strip()
                    if t:
                        scenario_ips.add(t)
        for rec in records:
            rec["in_scenarios"] = rec["ip"] in scenario_ips

        cur.execute("SELECT COUNT(*) FROM threat_intel_cache")
        total_count = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM threat_intel_cache WHERE risk_level IN ('high', 'critical')")
        high_count = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM threat_intel_cache WHERE risky_ports != ''")
        risky_port_count = cur.fetchone()[0]
        conn.close()
        return {
            "total": total_count,
            "high_risk_count": high_count,
            "risky_port_count": risky_port_count,
            "records": records
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

class ThreatIntelImportToScenariosRequest(BaseModel):
    ips: List[str]

@app.post("/api/threat-intel/import-to-scenarios")
def import_threat_intel_to_scenarios(payload: ThreatIntelImportToScenariosRequest):
    """
    Import selected IP(s) from `threat_intel_cache` into `threat_scenarios` (智慧情資規則庫).
    Target Port is left empty (all ports to this IP trigger), and risky ports are documented in reason_template.
    """
    target_ips = [ip.strip() for ip in (payload.ips or []) if ip and ip.strip()]
    if not target_ips:
        raise HTTPException(status_code=400, detail="請至少選擇一筆要匯入的外部 IP 情資")

    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        ph = ",".join("?" for _ in target_ips)
        cur.execute(f"SELECT * FROM threat_intel_cache WHERE ip IN ({ph})", tuple(target_ips))
        intel_rows = [dict(r) for r in cur.fetchall()]
        if not intel_rows:
            conn.close()
            raise HTTPException(status_code=404, detail="找不到選取的 IP 情資紀錄")

        imported_count = 0
        updated_count = 0
        tw_now = now_tw_str()

        for rec in intel_rows:
            ip = rec["ip"]
            dom = (rec.get("domain") or "").strip()
            prov = (rec.get("provider") or "ThreatIntel").strip()
            r_score = int(rec.get("risk_score") or 0)
            r_lvl = (rec.get("risk_level") or "safe").lower()
            in_score = rec.get("inbound_score") or r_lvl
            risky_ports = (rec.get("risky_ports") or "").strip()
            open_ports = (rec.get("open_ports") or "").strip()
            vulns = (rec.get("vulns") or "").strip()

            if r_lvl in ("critical", "high"):
                sev = "high"
            elif r_lvl == "medium":
                sev = "medium"
            else:
                sev = "low"

            sc_name = f"外部情資監控 - {dom} ({ip})" if dom else f"外部情資監控 - {ip}"
            sc_cat = f"外部情資風險連線 ({prov})"
            # Per user requirement: leave target port empty so any port connection to this IP triggers,
            # and document risky ports inside the trigger condition description.
            sc_ports = ""
            reason_text = (
                f"經外部威脅情資庫（{prov}）檢測，目標 IP {ip}（Domain: {dom or '無反解 Domain'}）"
                f"風險評定為 {in_score}（風險值: {r_score}）。"
                f"該主機具有風險的 Port 號：[{risky_ports or '無'}]，開放通訊埠：[{open_ports or '無'}]"
                f"{'，已知 CVE 弱點：[' + vulns + ']' if vulns else ''}。"
                f"只要內網設備與該外部 IP（不限 Port）建立連線即觸發告警。"
            )
            remediation_text = (
                f"1. 確認內網主機連往 {ip} ({dom or '無 Domain'}) 是否為合法業務連線需求。\n"
                f"2. 重點清查是否連往該 IP 具有風險的通訊埠 ({risky_ports or '無'}) 或涉及已知漏洞 ({vulns or '無'})。\n"
                f"3. 若確認為非預期或惡意連線，請立即於邊界防火牆封鎖 {ip} 並檢查內網設備。"
            )

            cur.execute("SELECT id FROM threat_scenarios WHERE dst_scope = ?", (ip,))
            existing = cur.fetchone()
            if existing:
                cur.execute("""
                    UPDATE threat_scenarios
                    SET name=?, category=?, severity=?, src_scope='internal', dst_scope=?,
                        ports=?, time_window='all', min_bytes=0, reason_template=?,
                        remediation_steps=?, is_enabled=1
                    WHERE id=?
                """, (sc_name, sc_cat, sev, ip, sc_ports, reason_text, remediation_text, existing["id"]))
                updated_count += 1
            else:
                cur.execute("""
                    INSERT INTO threat_scenarios (
                        name, category, severity, src_scope, dst_scope, ports, time_window,
                        min_bytes, reason_template, remediation_steps, is_enabled, is_builtin, created_at
                    ) VALUES (?, ?, ?, 'internal', ?, ?, 'all', 0, ?, ?, 1, 0, ?)
                """, (sc_name, sc_cat, sev, ip, sc_ports, reason_text, remediation_text, tw_now))
                imported_count += 1

        conn.commit()
        sync_all_threat_scenarios_to_audit_rules(conn)
        conn.close()
        total_done = imported_count + updated_count
        return {
            "status": "success",
            "imported_count": imported_count,
            "updated_count": updated_count,
            "message": f"成功匯入 {total_done} 筆情資至【智慧情資規則庫】（新增 {imported_count} 筆、更新 {updated_count} 筆，目標 Port 均設為不限並已紀錄風險埠說明）！"
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

class ThreatIntelLookupRequest(BaseModel):
    target: str
    force_refresh: bool = True

@app.post("/api/threat-intel/lookup")
def manual_lookup_threat_intel(payload: ThreatIntelLookupRequest):
    target = (payload.target or "").strip()
    if not target:
        raise HTTPException(status_code=400, detail="請輸入要查詢的外部 IP 或 Domain")

    # If user entered a domain name instead of an IP, resolve it or query Criminal IP /v1/domain/reports
    resolved_ip = target
    domain_hint = ""
    try:
        ipaddress.ip_address(target)
    except ValueError:
        domain_hint = target
        try:
            resolved_ip = socket.gethostbyname(target)
        except Exception:
            raise HTTPException(status_code=400, detail=f"無法解析 Domain「{target}」對應的 IP 位址")

    if not _is_public_routable_ip(resolved_ip):
        raise HTTPException(status_code=400, detail=f"IP「{resolved_ip}」屬於私有內網位址，外部情資 API 僅檢測外部 Public IP")

    info = query_and_cache_ip_threat_intel(resolved_ip, force_refresh=payload.force_refresh)
    if info and domain_hint and not info.get("domain"):
        info["domain"] = domain_hint
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.execute("UPDATE threat_intel_cache SET domain = ? WHERE ip = ?", (domain_hint, resolved_ip))
            conn.commit()
            conn.close()
        except Exception:
            pass
    return {"status": "success", "record": info}

@app.delete("/api/threat-intel/cache/{ip}")
def delete_threat_intel_cache_item(ip: str):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("DELETE FROM threat_intel_cache WHERE ip = ?", (ip.strip(),))
        conn.commit()
        conn.close()
        return {"status": "success", "message": f"已從情資資料庫移除 {ip}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ---------------- Threat Scenarios Engine & Smart Diagnostics API ----------------
BUILTIN_SERVICE_PREFIXES = {
    "youtube": ["142.250.", "172.217.", "216.58.", "74.125.", "208.65.153."],
    "streaming": ["142.250.", "172.217.", "216.58.", "23.246.", "45.57.", "198.38.", "198.45."],
}

class ThreatScenarioRequest(BaseModel):
    name: str
    category: str
    severity: str = "medium"  # 'high', 'medium', 'low', 'behavior'
    src_scope: str = "any"
    dst_scope: str = "any"
    ports: str = ""
    time_window: str = "all"
    min_bytes: int = 0
    reason_template: str
    remediation_steps: str
    is_enabled: bool = True

def _match_ip_scope(ip_str: str, scope: str) -> bool:
    if not scope or scope.strip().lower() == "any":
        return True
    if not ip_str:
        return False
    ip_clean = ip_str.strip()
    try:
        ip_obj = ipaddress.ip_address(ip_clean)
    except Exception:
        return False

    tokens = [t.strip() for t in scope.split(",") if t.strip()]
    for tok in tokens:
        tok_l = tok.lower()
        if tok_l == "internal":
            if is_internal_ip(ip_obj):
                return True
        elif tok_l == "external":
            if not is_internal_ip(ip_obj):
                return True
        elif tok_l in BUILTIN_SERVICE_PREFIXES:
            if any(ip_clean.startswith(pref) for pref in BUILTIN_SERVICE_PREFIXES[tok_l]):
                return True
            alias = resolve_ip_alias(ip_clean)
            if alias and tok_l in alias.lower():
                return True
        elif "/" in tok:
            try:
                if ip_obj in ipaddress.ip_network(tok, strict=False):
                    return True
            except Exception:
                pass
        else:
            if ip_clean == tok or ip_clean.startswith(tok):
                return True
    return False

def _match_ports_scope(sport: Optional[int], dport: Optional[int], ports_spec: str) -> bool:
    if not ports_spec or not ports_spec.strip():
        return True
    tokens = [t.strip() for t in ports_spec.split(",") if t.strip()]
    if not tokens:
        return True
    for tok in tokens:
        if "-" in tok:
            try:
                p1, p2 = [int(x.strip()) for x in tok.split("-", 1)]
                if (sport is not None and p1 <= sport <= p2) or (dport is not None and p1 <= dport <= p2):
                    return True
            except Exception:
                pass
        else:
            try:
                p = int(tok)
                if sport == p or dport == p:
                    return True
            except Exception:
                pass
    return False

def _match_time_window(dt: datetime, time_window: str) -> bool:
    if not time_window or time_window.strip().lower() == "all":
        return True
    tw = time_window.strip().lower()
    hhmm = dt.hour * 60 + dt.minute
    if tw == "work_hours":
        return 9 * 60 <= hhmm < 18 * 60
    elif tw == "off_hours":
        return hhmm < 9 * 60 or hhmm >= 18 * 60
    elif tw == "late_night":
        return 0 <= hhmm < 6 * 60
    elif "-" in tw:
        try:
            start_s, end_s = tw.split("-", 1)
            sh, sm = [int(x) for x in start_s.strip().split(":")]
            eh, em = [int(x) for x in end_s.strip().split(":")]
            s_min = sh * 60 + sm
            e_min = eh * 60 + em
            if s_min <= e_min:
                return s_min <= hhmm <= e_min
            else:
                return hhmm >= s_min or hhmm <= e_min
        except Exception:
            return True
    return True

def _describe_time_window(tw: str) -> str:
    m = {
        "all": "全時段 (24H)",
        "work_hours": "上班時段 (09:00–18:00)",
        "off_hours": "非上班時段 (18:00–09:00)",
        "late_night": "深夜無人時段 (00:00–06:00)",
    }
    return m.get((tw or "all").lower(), tw)

@app.get("/api/scenarios")
def list_threat_scenarios():
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT * FROM threat_scenarios ORDER BY is_enabled DESC, id ASC")
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/scenarios")
def create_threat_scenario(payload: ThreatScenarioRequest):
    if payload.severity not in ("high", "medium", "low", "behavior"):
        raise HTTPException(status_code=400, detail="severity must be high, medium, low, or behavior")
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO threat_scenarios (
                name, category, severity, src_scope, dst_scope, ports, time_window,
                min_bytes, reason_template, remediation_steps, is_enabled, is_builtin, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
        """, (
            payload.name.strip(), payload.category.strip(), payload.severity,
            payload.src_scope.strip() or "any", payload.dst_scope.strip() or "any",
            payload.ports.strip(), payload.time_window.strip() or "all",
            max(0, int(payload.min_bytes or 0)),
            payload.reason_template.strip(), payload.remediation_steps.strip(),
            1 if payload.is_enabled else 0, now_tw_str()
        ))
        conn.commit()
        new_id = cur.lastrowid
        try:
            sync_all_threat_scenarios_to_audit_rules(conn)
        except Exception as _sync_err:
            print(f"[Scenario Sync Notice] {_sync_err}", flush=True)
        conn.close()
        return {"status": "success", "id": new_id, "message": f"智慧情境規則「{payload.name}」已建立。"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/api/scenarios/{scenario_id}")
def update_threat_scenario(scenario_id: int, payload: ThreatScenarioRequest):
    if payload.severity not in ("high", "medium", "low", "behavior"):
        raise HTTPException(status_code=400, detail="severity must be high, medium, low, or behavior")
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("""
            UPDATE threat_scenarios
            SET name=?, category=?, severity=?, src_scope=?, dst_scope=?, ports=?,
                time_window=?, min_bytes=?, reason_template=?, remediation_steps=?, is_enabled=?
            WHERE id=?
        """, (
            payload.name.strip(), payload.category.strip(), payload.severity,
            payload.src_scope.strip() or "any", payload.dst_scope.strip() or "any",
            payload.ports.strip(), payload.time_window.strip() or "all",
            max(0, int(payload.min_bytes or 0)),
            payload.reason_template.strip(), payload.remediation_steps.strip(),
            1 if payload.is_enabled else 0, scenario_id
        ))
        conn.commit()
        try:
            sync_all_threat_scenarios_to_audit_rules(conn)
        except Exception as _sync_err:
            print(f"[Scenario Sync Notice] {_sync_err}", flush=True)
        conn.close()
        return {"status": "success", "message": f"情境規則「{payload.name}」已更新。"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/scenarios/{scenario_id}")
def delete_threat_scenario(scenario_id: int):
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("DELETE FROM threat_scenarios WHERE id = ?", (scenario_id,))
        conn.commit()
        try:
            sync_all_threat_scenarios_to_audit_rules(conn)
        except Exception as _sync_err:
            print(f"[Scenario Sync Notice] {_sync_err}", flush=True)
        conn.close()
        return {"status": "success", "message": "情境規則已刪除。"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/scenarios/reset-defaults")
def reset_default_scenarios():
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("DELETE FROM threat_scenarios WHERE is_builtin = 1")
        _insert_default_scenarios(cur, now_tw_str())
        conn.commit()
        try:
            sync_all_threat_scenarios_to_audit_rules(conn)
        except Exception as _sync_err:
            print(f"[Scenario Sync Notice] {_sync_err}", flush=True)
        conn.close()
        return {"status": "success", "message": "已重設並匯入 5 大常見智慧威脅情境範本。"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ---------------- Excel (.xlsx / .csv) Template, Export & Import for Unified Scenario Rules ----------------
import io
import csv
import base64
import zipfile
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape as _xml_escape

SCENARIO_EXCEL_HEADERS = [
    "情境名稱 *",
    "風險分類 *",
    "風險等級 *",
    "觸發時段 *",
    "來源 IP / 範圍 *",
    "目的 IP / 服務群組 *",
    "目標 Port (逗號或範圍)",
    "單筆最小流量門檻 (MB)",
    "觸發條件與方式說明 *",
    "建議處置步驟"
]

def _col_idx_to_excel_letter(idx: int) -> str:
    letters = ""
    n = idx + 1
    while n > 0:
        n, rem = divmod(n - 1, 26)
        letters = chr(65 + rem) + letters
    return letters

def _build_xlsx_bytes(rows: List[List[Any]], sheet_name: str = "智慧情資規則庫") -> bytes:
    """Build a valid Microsoft Excel .xlsx workbook in memory using only Python standard library."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>
</Types>""")
        zf.writestr("_rels/.rels", """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>""")
        zf.writestr("xl/workbook.xml", f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheets>
    <sheet name="{_xml_escape(sheet_name)}" sheetId="1" r:id="rId1"/>
  </sheets>
</workbook>""")
        zf.writestr("xl/_rels/workbook.xml.rels", """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>""")
        zf.writestr("xl/styles.xml", """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <fonts count="2">
    <font><sz val="11"/><name val="Calibri"/></font>
    <font><b/><sz val="11"/><name val="Calibri"/></font>
  </fonts>
  <fills count="2">
    <fill><patternFill patternType="none"/></fill>
    <fill><patternFill patternType="gray125"/></fill>
  </fills>
  <borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>
  <cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
  <cellXfs count="2">
    <xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>
    <xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/>
  </cellXfs>
</styleSheet>""")

        row_xml_parts = []
        for r_idx, row in enumerate(rows, start=1):
            style_attr = ' s="1"' if r_idx == 1 else ''
            cell_parts = []
            for c_idx, val in enumerate(row):
                col_ref = f"{_col_idx_to_excel_letter(c_idx)}{r_idx}"
                s_val = "" if val is None else str(val)
                escaped = _xml_escape(s_val)
                cell_parts.append(f'<c r="{col_ref}" t="inlineStr"{style_attr}><is><t xml:space="preserve">{escaped}</t></is></c>')
            row_xml_parts.append(f'<row r="{r_idx}">{"".join(cell_parts)}</row>')

        sheet_xml = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            f'<sheetData>{"".join(row_xml_parts)}</sheetData>'
            '</worksheet>'
        )
        zf.writestr("xl/worksheets/sheet1.xml", sheet_xml)
    return buf.getvalue()

def _excel_col_letter_to_idx(cell_ref: str) -> int:
    letters = "".join(ch for ch in cell_ref if ch.isalpha()).upper()
    idx = 0
    for ch in letters:
        idx = idx * 26 + (ord(ch) - 64)
    return max(0, idx - 1)

def _parse_xlsx_or_csv_bytes(raw_bytes: bytes, filename: str = "") -> List[List[str]]:
    """Parse either an .xlsx workbook or a .csv text file into a list of string rows."""
    fname_l = (filename or "").lower()
    if fname_l.endswith(".xlsx") or raw_bytes[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(raw_bytes), "r") as zf:
            shared_strings: List[str] = []
            if "xl/sharedStrings.xml" in zf.namelist():
                ss_root = ET.fromstring(zf.read("xl/sharedStrings.xml"))
                for si in ss_root.iter():
                    if si.tag.endswith("}si") or si.tag == "si":
                        texts = [t.text or "" for t in si.iter() if t.tag.endswith("}t") or t.tag == "t"]
                        shared_strings.append("".join(texts))
            sheet_path = "xl/worksheets/sheet1.xml"
            if sheet_path not in zf.namelist():
                worksheets = [n for n in zf.namelist() if n.startswith("xl/worksheets/sheet") and n.endswith(".xml")]
                if not worksheets:
                    raise ValueError("Excel 檔案中找不到工作表")
                sheet_path = sorted(worksheets)[0]
            ws_root = ET.fromstring(zf.read(sheet_path))
            parsed_rows: List[List[str]] = []
            for row_el in ws_root.iter():
                if not (row_el.tag.endswith("}row") or row_el.tag == "row"):
                    continue
                row_dict: Dict[int, str] = {}
                max_col = -1
                for c_el in row_el:
                    if not (c_el.tag.endswith("}c") or c_el.tag == "c"):
                        continue
                    c_ref = c_el.attrib.get("r", "")
                    c_type = c_el.attrib.get("t", "")
                    c_idx = _excel_col_letter_to_idx(c_ref) if c_ref else (max_col + 1)
                    max_col = max(max_col, c_idx)
                    val_str = ""
                    if c_type == "inlineStr":
                        t_texts = [t.text or "" for t in c_el.iter() if t.tag.endswith("}t") or t.tag == "t"]
                        val_str = "".join(t_texts)
                    elif c_type == "s":
                        v_els = [v.text or "" for v in c_el if v.tag.endswith("}v") or v.tag == "v"]
                        if v_els and v_els[0].isdigit():
                            s_idx = int(v_els[0])
                            if 0 <= s_idx < len(shared_strings):
                                val_str = shared_strings[s_idx]
                    else:
                        v_els = [v.text or "" for v in c_el if v.tag.endswith("}v") or v.tag == "v"]
                        val_str = v_els[0] if v_els else ""
                    row_dict[c_idx] = val_str.strip()
                if max_col >= 0:
                    row_list = [row_dict.get(i, "") for i in range(max_col + 1)]
                    if any(cell != "" for cell in row_list):
                        parsed_rows.append(row_list)
            return parsed_rows

    # Otherwise parse as CSV (try utf-8-sig, utf-8, cp950/big5)
    text = ""
    for enc in ("utf-8-sig", "utf-8", "cp950", "big5"):
        try:
            text = raw_bytes.decode(enc)
            break
        except Exception:
            continue
    if not text:
        text = raw_bytes.decode("utf-8", errors="replace")
    reader = csv.reader(io.StringIO(text))
    return [[c.strip() for c in row] for row in reader if any(c.strip() for c in row)]

@app.get("/api/scenarios/template-excel")
def download_scenario_excel_template():
    """Download the standardized Excel (.xlsx) template for importing unified Threat Scenario Rules."""
    sample_rows = [
        SCENARIO_EXCEL_HEADERS,
        [
            "核心 ERP 深夜異常存取",
            "重要資產異常時段存取",
            "high",
            "late_night",
            "internal",
            "192.168.10.10,192.168.10.20",
            "3306,1433,3389,22",
            "0",
            "深夜無人維運時段（00:00~06:00）偵測到內網主機存取核心 ERP 或資料庫管理埠，疑似帳號遭盜用或非授權操作。",
            "1. 核對當時是否有核准之夜間系統維護作業。\n2. 檢查來源主機登入紀錄與連線程序。\n3. 若非合法維運請立即停用帳號並阻斷連線。"
        ],
        [
            "外部可疑中繼節點連線監控",
            "外部情資風險連線",
            "medium",
            "all",
            "internal",
            "203.0.113.50",
            "",
            "0",
            "經外部威脅情資檢測該外部 IP 具有高風險通訊埠 (3389, 8080)，只要內網設備與該 IP 建立任何連線即觸發告警。",
            "1. 確認連往該外部 IP 之業務必要性。\n2. 至邊界防火牆封鎖該外部 IP 並清查內網設備。"
        ]
    ]
    xlsx_data = _build_xlsx_bytes(sample_rows, sheet_name="智慧情資規則匯入範本")
    filename_encoded = urllib.parse.quote("智慧情資規則匯入範本.xlsx")
    return Response(
        content=xlsx_data,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f"attachment; filename*=UTF-8''{filename_encoded}"}
    )

@app.get("/api/scenarios/export-excel")
def export_scenarios_to_excel():
    """Export all existing rules in threat_scenarios as an Excel (.xlsx) file."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM threat_scenarios ORDER BY id ASC")
    rows_db = [dict(r) for r in cur.fetchall()]
    conn.close()

    excel_rows = [SCENARIO_EXCEL_HEADERS]
    for r in rows_db:
        min_mb = round((int(r.get("min_bytes") or 0)) / (1024 * 1024))
        excel_rows.append([
            r.get("name") or "",
            r.get("category") or "",
            r.get("severity") or "medium",
            r.get("time_window") or "all",
            r.get("src_scope") or "any",
            r.get("dst_scope") or "any",
            r.get("ports") or "",
            str(min_mb),
            r.get("reason_template") or "",
            r.get("remediation_steps") or ""
        ])
    xlsx_data = _build_xlsx_bytes(excel_rows, sheet_name="智慧情資規則庫")
    filename_encoded = urllib.parse.quote("智慧情資規則庫備份.xlsx")
    return Response(
        content=xlsx_data,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f"attachment; filename*=UTF-8''{filename_encoded}"}
    )

class ScenarioExcelImportRequest(BaseModel):
    filename: str
    content_base64: str

def _normalize_imported_severity(val: str) -> str:
    v = (val or "").strip().lower()
    if v in ("high", "critical", "高", "高風險", "立即阻斷") or "高" in v:
        return "high"
    if v in ("medium", "moderate", "中", "中風險", "清查確認") or "中" in v:
        return "medium"
    if v in ("behavior", "行為", "行為管理", "頻寬合規") or "行為" in v:
        return "behavior"
    if v in ("low", "低", "低風險", "常規關注") or "低" in v:
        return "low"
    return "medium"

def _normalize_imported_time_window(val: str) -> str:
    v = (val or "").strip().lower()
    if v in ("work_hours", "上班", "上班時段") or "上班" in v and "非" not in v:
        return "work_hours"
    if v in ("off_hours", "非上班", "非上班時段") or "非上班" in v:
        return "off_hours"
    if v in ("late_night", "深夜", "深夜無人時段") or "深夜" in v:
        return "late_night"
    return "all"

@app.post("/api/scenarios/import-excel")
def import_scenarios_from_excel(payload: ScenarioExcelImportRequest):
    """Import rules from an uploaded Excel (.xlsx) or CSV (.csv) file into threat_scenarios."""
    try:
        raw_bytes = base64.b64decode(payload.content_base64)
        rows = _parse_xlsx_or_csv_bytes(raw_bytes, payload.filename)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"無法解析匯入檔案（請確認為範本 .xlsx 或 .csv 格式）: {e}")

    if not rows or len(rows) < 2:
        raise HTTPException(status_code=400, detail="匯入檔案中沒有任何規則資料列")

    # Skip header row if first row contains '情境名稱' or 'name'
    start_idx = 1 if ("情境名稱" in (rows[0][0] if rows[0] else "") or "名稱" in (rows[0][0] if rows[0] else "")) else 0

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    tw_now = now_tw_str()
    imported = 0

    for row in rows[start_idx:]:
        while len(row) < 10:
            row.append("")
        name = row[0].strip()
        category = row[1].strip() or "自訂匯入情境"
        if not name:
            continue
        severity = _normalize_imported_severity(row[2])
        time_window = _normalize_imported_time_window(row[3])
        src_scope = row[4].strip() or "internal"
        dst_scope = row[5].strip() or "any"
        ports = row[6].strip()
        try:
            min_mb = float(row[7].strip() or "0")
        except Exception:
            min_mb = 0.0
        min_bytes = max(0, int(min_mb * 1024 * 1024))
        reason = row[8].strip() or f"觸發自訂匯入情境規則「{name}」（來源: {src_scope} ➔ 目的: {dst_scope}, Port: {ports or '不限'}）。"
        remediation = row[9].strip() or "1. 確認該連線是否屬於授權業務範圍。\n2. 若屬未知或異常連線，請於防火牆進行限制並通知設備負責人。"

        cur.execute("""
            INSERT INTO threat_scenarios (
                name, category, severity, src_scope, dst_scope, ports, time_window,
                min_bytes, reason_template, remediation_steps, is_enabled, is_builtin, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0, ?)
        """, (name, category, severity, src_scope, dst_scope, ports, time_window, min_bytes, reason, remediation, tw_now))
        imported += 1

    conn.commit()
    sync_all_threat_scenarios_to_audit_rules(conn)
    conn.close()
    return {
        "status": "success",
        "imported": imported,
        "message": f"成功從「{payload.filename}」匯入 {imported} 筆規則至【智慧情資規則庫】！"
    }

class DiagPreferenceRequest(BaseModel):
    date: Optional[str] = None
    year: Optional[int] = None
    month: Optional[int] = None
    day: Optional[int] = None
    preset: Optional[str] = None
    start_time: Optional[str] = None
    end_time: Optional[str] = None

@app.get("/api/anomalies/preference")
def get_anomalies_preference():
    """Retrieve saved date and preset preferences for Smart Situational Diagnostics."""
    saved_date = get_system_setting("diag_saved_date", "")
    saved_preset = get_system_setting("diag_saved_preset", "custom" if saved_date else "custom")
    saved_year = get_system_setting("diag_saved_year", "")
    saved_month = get_system_setting("diag_saved_month", "")
    saved_day = get_system_setting("diag_saved_day", "")
    saved_start_time = get_system_setting("diag_saved_start_time", "00:00")
    saved_end_time = get_system_setting("diag_saved_end_time", "23:59")
    return {
        "date": saved_date,
        "year": int(saved_year) if saved_year.isdigit() else None,
        "month": int(saved_month) if saved_month.isdigit() else None,
        "day": int(saved_day) if saved_day.isdigit() else None,
        "preset": saved_preset,
        "start_time": saved_start_time,
        "end_time": saved_end_time
    }

@app.post("/api/anomalies/preference")
def save_anomalies_preference(payload: DiagPreferenceRequest):
    """Save date and preset preferences for Smart Situational Diagnostics."""
    if payload.date:
        set_system_setting("diag_saved_date", payload.date.strip())
    if payload.year is not None:
        set_system_setting("diag_saved_year", str(payload.year))
    if payload.month is not None:
        set_system_setting("diag_saved_month", str(payload.month))
    if payload.day is not None:
        set_system_setting("diag_saved_day", str(payload.day))
    if payload.preset:
        set_system_setting("diag_saved_preset", payload.preset.strip())
    if payload.start_time:
        set_system_setting("diag_saved_start_time", payload.start_time.strip())
    if payload.end_time:
        set_system_setting("diag_saved_end_time", payload.end_time.strip())
    return {
        "status": "success",
        "message": "已成功記錄診斷日期偏好設定",
        "saved": {
            "date": get_system_setting("diag_saved_date", ""),
            "preset": get_system_setting("diag_saved_preset", "custom"),
            "start_time": get_system_setting("diag_saved_start_time", "00:00"),
            "end_time": get_system_setting("diag_saved_end_time", "23:59")
        }
    }

@app.get("/api/anomalies/diagnostics")
def get_anomalies_diagnostics(
    time_range: str = Query("24h", description="custom, today, 1h, 24h, 7d, all"),
    target_date: Optional[str] = Query(None, description="Specific date in YYYY-MM-DD format"),
    start_time: Optional[str] = Query(None, description="Start time filter (HH:MM)"),
    end_time: Optional[str] = Query(None, description="End time filter (HH:MM)"),
    severity: Optional[str] = Query(None, description="high, medium, low, behavior"),
    category: Optional[str] = Query(None, description="Scenario category filter"),
    host_ip: Optional[str] = Query(None, description="Filter by host IP")
):
    """Evaluate Threat Scenarios against recent flows, aggregate events, and enrich with AtheNAC host info."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT * FROM threat_scenarios WHERE is_enabled = 1 ORDER BY id ASC")
        scenarios = [dict(r) for r in cur.fetchall()]
        cur.execute("""
            SELECT ip, domain, risk_score, risk_level, inbound_score, outbound_score,
                   risky_ports, open_ports, vulns, tags, country, org, provider, summary, updated_at
            FROM threat_intel_cache
        """)
        intel_db_map = {r["ip"]: dict(r) for r in cur.fetchall()}
        conn.close()

        client = get_ch_client()
        time_cond = ""
        resolved_date = ""
        resolved_label = "全時段 (24H)"

        # Process start_time and end_time (only apply custom start/end hours when time_range == 'custom')
        if time_range == "custom":
            st = (start_time or "").strip() or get_system_setting("diag_saved_start_time", "00:00")
            et = (end_time or "").strip() or get_system_setting("diag_saved_end_time", "23:59")
        else:
            st = "00:00"
            et = "23:59"
        st_sec = st + ":00" if len(st) == 5 else (st if len(st) == 8 else "00:00:00")
        et_sec = et + ":59" if len(et) == 5 else (et if len(et) == 8 else "23:59:59")

        # Check if specific target_date is requested (only for custom or today)
        if target_date and target_date.strip() and time_range in ("custom", "today"):
            try:
                dt_obj = datetime.strptime(target_date.strip(), "%Y-%m-%d")
                resolved_date = dt_obj.strftime("%Y-%m-%d")
                start_ts = f"{resolved_date} {st_sec}"
                end_ts = f"{resolved_date} {et_sec}"
                time_cond = f"WHERE ts >= '{start_ts}' AND ts <= '{end_ts}'"
                resolved_label = f"{resolved_date} {st[:5]}~{et[:5]}" if (st != "00:00" or et != "23:59") else f"{resolved_date} 全日時段"
            except Exception:
                resolved_date = ""

        if not time_cond:
            if time_range == "custom":
                # Default custom date to today or saved date if not passed
                saved_d = get_system_setting("diag_saved_date", "")
                resolved_date = saved_d if saved_d else now_tw().strftime("%Y-%m-%d")
                start_ts = f"{resolved_date} {st_sec}"
                end_ts = f"{resolved_date} {et_sec}"
                time_cond = f"WHERE ts >= '{start_ts}' AND ts <= '{end_ts}'"
                resolved_label = f"{resolved_date} {st[:5]}~{et[:5]}" if (st != "00:00" or et != "23:59") else f"{resolved_date} 全日時段"
            elif time_range == "today":
                resolved_date = now_tw().strftime("%Y-%m-%d")
                start_ts = f"{resolved_date} 00:00:00"
                end_ts = f"{resolved_date} 23:59:59"
                time_cond = f"WHERE ts >= '{start_ts}' AND ts <= '{end_ts}'"
                resolved_label = f"{resolved_date} 當日全時段"
            elif time_range == "1h":
                time_cond = "WHERE ts >= now() - INTERVAL 1 HOUR"
                resolved_label = "過去 1 小時"
            elif time_range == "24h":
                time_cond = "WHERE ts >= now() - INTERVAL 24 HOUR"
                resolved_label = "過去 24 小時"
            elif time_range == "7d":
                time_cond = "WHERE ts >= now() - INTERVAL 7 DAY"
                resolved_label = "過去 7 天"
            elif time_range == "all":
                time_cond = ""
                resolved_label = "全部歷史週期"
            else:
                time_cond = "WHERE ts >= now() - INTERVAL 24 HOUR"
                resolved_label = "過去 24 小時"

        if isinstance(client, SQLiteClickHouseAdapter):
            sql = f"""
                SELECT src, dst, sport, dport, packets, octets, protocol, ts FROM ipfix {time_cond}
                UNION ALL
                SELECT src, dst, sport, dport, packets, octets, protocol, ts FROM netflow9 {time_cond}
                ORDER BY ts DESC
                LIMIT 5000
            """
        else:
            extra_filter = (
                "AND (dport IN (22, 445, 1433, 3306, 3389, 5432, 8080) "
                "OR sport IN (22, 445, 1433, 3306, 3389, 5432, 8080) "
                "OR (dport >= 8080 AND dport <= 8090) "
                "OR (dport >= 10000 AND dport <= 10050) "
                "OR octets >= 5000000)"
            ) if time_cond else (
                "WHERE (dport IN (22, 445, 1433, 3306, 3389, 5432, 8080) "
                "OR sport IN (22, 445, 1433, 3306, 3389, 5432, 8080) "
                "OR (dport >= 8080 AND dport <= 8090) "
                "OR (dport >= 10000 AND dport <= 10050) "
                "OR octets >= 5000000)"
            )
            sql = f"""
                SELECT src, dst, sport, dport, packets, octets, protocol, ts FROM (
                    SELECT src, dst, sport, dport, packets, octets, protocol, ts FROM ipfix {time_cond} {extra_filter} ORDER BY ts DESC LIMIT 2000
                    UNION ALL
                    SELECT src, dst, sport, dport, packets, octets, protocol, ts FROM netflow9 {time_cond} {extra_filter} ORDER BY ts DESC LIMIT 2000
                    UNION ALL
                    SELECT src, dst, sport, dport, packets, octets, protocol, ts FROM ipfix {time_cond} ORDER BY ts DESC LIMIT 1500
                    UNION ALL
                    SELECT src, dst, sport, dport, packets, octets, protocol, ts FROM netflow9 {time_cond} ORDER BY ts DESC LIMIT 1500
                )
                ORDER BY ts DESC
                LIMIT 5000
            """
        res = client.query(sql)
        cols = res.column_names

        # Aggregators
        events_map: Dict[Tuple[str, int], Dict[str, Any]] = {}
        hourly_bins = {f"{h:02d}:00": {"hour": f"{h:02d}:00", "high": 0, "medium": 0, "low": 0, "behavior": 0, "total": 0} for h in range(24)}

        for row_vals in res.result_rows:
            f = dict(zip(cols, row_vals))
            src = f.get("src") or ""
            dst = f.get("dst") or ""
            sport = f.get("sport")
            dport = f.get("dport")
            octets = int(f.get("octets") or 0)
            packets = int(f.get("packets") or 0)
            ts_raw = f.get("ts")
            if isinstance(ts_raw, datetime):
                flow_dt = ts_raw
                ts_str = ts_raw.strftime("%Y-%m-%d %H:%M:%S")
            else:
                ts_str = str(ts_raw or "")
                flow_dt = parse_tw_datetime(ts_str)

            for sc in scenarios:
                if severity and sc["severity"] != severity:
                    continue
                if category and sc["category"] != category:
                    continue
                if octets < int(sc.get("min_bytes") or 0):
                    continue
                if not _match_ports_scope(sport, dport, sc.get("ports") or ""):
                    continue
                if not _match_time_window(flow_dt, sc.get("time_window") or "all"):
                    continue
                if not (_match_ip_scope(src, sc.get("src_scope") or "any") and _match_ip_scope(dst, sc.get("dst_scope") or "any")):
                    continue

                # Determine primary responsible internal host (prefer src if internal, else dst if internal, else src)
                primary_ip = src
                try:
                    if not is_internal_ip(ipaddress.ip_address(src)) and is_internal_ip(ipaddress.ip_address(dst)):
                        primary_ip = dst
                except Exception:
                    pass

                if host_ip and host_ip.strip() not in (primary_ip, src, dst):
                    continue

                hour_key = f"{flow_dt.hour:02d}:00"
                if hour_key in hourly_bins:
                    sc_sev = sc.get("severity", "medium")
                    if sc_sev in hourly_bins[hour_key]:
                        hourly_bins[hour_key][sc_sev] += 1
                    hourly_bins[hour_key]["total"] += 1

                key = (primary_ip, sc["id"])
                if key not in events_map:
                    events_map[key] = {
                        "event_id": f"evt_{sc['id']}_{primary_ip.replace('.', '_')}",
                        "scenario_id": sc["id"],
                        "scenario_name": sc["name"],
                        "category": sc["category"],
                        "severity": sc["severity"],
                        "time_window_label": (
                            f"{resolved_date} {_describe_time_window(sc.get('time_window') or 'all')}"
                            if resolved_date else _describe_time_window(sc.get("time_window") or "all")
                        ),
                        "host_ip": primary_ip,
                        "target_ips": set(),
                        "ports": set(),
                        "flow_count": 0,
                        "total_packets": 0,
                        "total_bytes": 0,
                        "first_ts": ts_str,
                        "last_ts": ts_str,
                        "reason_template": sc["reason_template"],
                        "remediation_steps": [s.strip() for s in (sc["remediation_steps"] or "").splitlines() if s.strip()],
                        "min_bytes": int(sc.get("min_bytes") or 0),
                    }
                ev = events_map[key]
                peer_ip = dst if primary_ip == src else src
                if peer_ip:
                    ev["target_ips"].add(peer_ip)
                if dport and dport != 0:
                    ev["ports"].add(int(dport))
                ev["flow_count"] += 1
                ev["total_packets"] += packets
                ev["total_bytes"] += octets
                if ts_str < ev["first_ts"]:
                    ev["first_ts"] = ts_str
                if ts_str > ev["last_ts"]:
                    ev["last_ts"] = ts_str

            # Also check if src or dst matches a risky external IP or risky port in threat_intel_cache (DB)
            ext_intel = intel_db_map.get(dst) or intel_db_map.get(src)
            if ext_intel:
                r_level = (ext_intel.get("risk_level") or "safe").lower()
                r_ports_str = ext_intel.get("risky_ports") or ""
                r_ports_set = {int(p) for p in r_ports_str.split(",") if p.strip().isdigit()}
                hit_risky_port = (dport in r_ports_set) or (sport in r_ports_set)
                if r_level in ("critical", "high", "medium") or hit_risky_port:
                    intel_sev = "high" if r_level in ("critical", "high") else "medium"
                    if not (severity and severity != intel_sev) and not (category and category != "外部情資風險連線"):
                        primary_ip = src
                        try:
                            if not is_internal_ip(ipaddress.ip_address(src)) and is_internal_ip(ipaddress.ip_address(dst)):
                                primary_ip = dst
                        except Exception:
                            pass
                        if not (host_ip and host_ip.strip() not in (primary_ip, src, dst)):
                            hour_key = f"{flow_dt.hour:02d}:00"
                            if hour_key in hourly_bins:
                                hourly_bins[hour_key][intel_sev] += 1
                                hourly_bins[hour_key]["total"] += 1
                            sc_id_intel = 9999
                            key_intel = (primary_ip, sc_id_intel)
                            if key_intel not in events_map:
                                prov = ext_intel.get("provider") or "Criminal IP"
                                dom = ext_intel.get("domain") or ext_intel["ip"]
                                events_map[key_intel] = {
                                    "event_id": f"evt_{sc_id_intel}_{primary_ip.replace('.', '_')}",
                                    "scenario_id": sc_id_intel,
                                    "scenario_name": "外部威脅情資高危 IP／風險埠連線",
                                    "category": "外部情資風險連線",
                                    "severity": intel_sev,
                                    "time_window_label": f"{resolved_date} 全時段 (24H)" if resolved_date else "全時段 (24H)",
                                    "host_ip": primary_ip,
                                    "target_ips": set(),
                                    "ports": set(),
                                    "flow_count": 0,
                                    "total_packets": 0,
                                    "total_bytes": 0,
                                    "first_ts": ts_str,
                                    "last_ts": ts_str,
                                    "reason_template": f"經外部威脅情資庫（{prov}）比對，內網設備連往具風險之外部節點 {ext_intel['ip']}（Domain: {dom or '無'}，風險值: {ext_intel.get('risk_score')}，風險 Port: {r_ports_str or '無'}）。{ext_intel.get('summary') or ''}",
                                    "remediation_steps": [
                                        f"1. 檢視情資庫標記之外部 IP ({ext_intel['ip']}) 與 Domain ({dom or '無'}) 是否為合法業務連線。",
                                        f"2. 核對是否存取其高風險通訊埠 ({r_ports_str or '無'}) 或存在已知弱點 ({ext_intel.get('vulns') or '無'})。",
                                        "3. 若屬異常或未知外部節點，建議於防火牆封鎖該外部 IP 並清查內網主機程序。"
                                    ],
                                    "min_bytes": 0,
                                }
                            ev_i = events_map[key_intel]
                            peer_ip = dst if primary_ip == src else src
                            if peer_ip:
                                ev_i["target_ips"].add(peer_ip)
                            if dport and dport != 0:
                                ev_i["ports"].add(int(dport))
                            ev_i["flow_count"] += 1
                            ev_i["total_packets"] += packets
                            ev_i["total_bytes"] += octets
                            if ts_str < ev_i["first_ts"]:
                                ev_i["first_ts"] = ts_str
                            if ts_str > ev_i["last_ts"]:
                                ev_i["last_ts"] = ts_str

        # Collect all IPs for alias + AtheNAC enrichment
        all_host_ips = {ev["host_ip"] for ev in events_map.values()}
        all_peer_ips = set()
        for ev in events_map.values():
            all_peer_ips.update(sorted(ev["target_ips"])[:5])

        alias_map = resolve_ip_aliases_batch(all_host_ips | all_peer_ips)
        athenac_map = resolve_athenac_hosts_batch(all_host_ips)

        sev_order = {"high": 0, "medium": 1, "low": 2, "behavior": 3}
        sev_labels = {
            "high": "高",
            "medium": "中",
            "low": "低",
            "behavior": "行為管理"
        }

        events_list = []
        cat_stats: Dict[str, Dict[str, Any]] = {}
        sc_stats: Dict[int, Dict[str, Any]] = {}
        sev_stats: Dict[str, Dict[str, Any]] = {
            "high": {"severity": "high", "label": "高", "events": 0, "flows": 0, "bytes": 0, "hosts": set()},
            "medium": {"severity": "medium", "label": "中", "events": 0, "flows": 0, "bytes": 0, "hosts": set()},
            "low": {"severity": "low", "label": "低", "events": 0, "flows": 0, "bytes": 0, "hosts": set()},
            "behavior": {"severity": "behavior", "label": "行為管理", "events": 0, "flows": 0, "bytes": 0, "hosts": set()},
        }
        host_stats: Dict[str, Dict[str, Any]] = {}

        for ev in events_map.values():
            hip = ev["host_ip"]
            halias = alias_map.get(hip, "")
            nac = athenac_map.get(hip, {})
            targets = []
            event_intel_list = []
            for tip in sorted(ev["target_ips"]):
                t_intel = intel_db_map.get(tip)
                if t_intel and len(event_intel_list) < 5:
                    event_intel_list.append(t_intel)
            for tip in sorted(ev["target_ips"])[:5]:
                t_intel = intel_db_map.get(tip)
                t_alias = alias_map.get(tip, "") or (t_intel.get("domain", "") if t_intel else "")
                targets.append({
                    "ip": tip,
                    "alias": t_alias,
                    "intel": t_intel
                })
            ports_info = []
            for p in sorted(ev["ports"])[:5]:
                ports_info.append({"port": p, "name": port_aliases_cache.get(p, "")})

            display_host = halias or nac.get("hostname") or hip
            target_summary = ", ".join([f"{t['alias']} ({t['ip']})" if t["alias"] else t["ip"] for t in targets[:3]])
            port_summary = ", ".join([f"{p['port']} ({p['name']})" if p["name"] else str(p["port"]) for p in ports_info[:3]]) or "多埠號"

            anomaly_point = f"設備「{display_host}」於【{ev['time_window_label']}】對目標 [{target_summary}]（Port: {port_summary}）產生 {ev['flow_count']} 筆連線，累計流量 {round(ev['total_bytes'] / (1024 * 1024), 2)} MB。"
            if event_intel_list:
                top_i = event_intel_list[0]
                anomaly_point += f"  🛡️ 情資庫比對：{top_i['ip']} Domain 為「{top_i.get('domain') or '未反解'}」，風險值 {top_i.get('risk_score')} ({top_i.get('inbound_score')})，風險埠 [{top_i.get('risky_ports') or '無'}]（來源：{top_i.get('provider')}）。"

            item = {
                "event_id": ev["event_id"],
                "scenario_id": ev["scenario_id"],
                "scenario_name": ev["scenario_name"],
                "category": ev["category"],
                "severity": ev["severity"],
                "severity_label": sev_labels.get(ev["severity"], ev["severity"]),
                "time_window_label": ev["time_window_label"],
                "host_ip": hip,
                "host_alias": halias,
                "athenac": nac,
                "targets": targets,
                "threat_intel": event_intel_list,
                "ports": ports_info,
                "flow_count": ev["flow_count"],
                "total_packets": ev["total_packets"],
                "total_bytes": ev["total_bytes"],
                "first_ts": ev["first_ts"],
                "last_ts": ev["last_ts"],
                "reason_text": ev["reason_template"],
                "anomaly_point": anomaly_point,
                "remediation_steps": ev["remediation_steps"],
                "remediation_summary": ev["remediation_steps"][0] if ev["remediation_steps"] else "請檢視明細並確認授權狀態",
                "drill_filters": {
                    "ip": hip,
                    "port": str(ports_info[0]["port"]) if len(ports_info) == 1 else ""
                }
            }
            events_list.append(item)

            # Aggregate scenario stats for Tier 2 chart
            sc_id = ev["scenario_id"]
            if sc_id not in sc_stats:
                sc_stats[sc_id] = {
                    "scenario_id": sc_id,
                    "name": ev["scenario_name"],
                    "category": ev["category"],
                    "severity": ev["severity"],
                    "events": 0,
                    "flows": 0,
                    "bytes": 0,
                    "hosts": set(),
                    "ports": set(),
                }
            sc_stats[sc_id]["events"] += 1
            sc_stats[sc_id]["flows"] += ev["flow_count"]
            sc_stats[sc_id]["bytes"] += ev["total_bytes"]
            sc_stats[sc_id]["hosts"].add(hip)
            sc_stats[sc_id]["ports"].update([p["port"] for p in ports_info])

            # Aggregate category stats
            cat = ev["category"]
            if cat not in cat_stats:
                cat_stats[cat] = {"category": cat, "events": 0, "flows": 0, "bytes": 0}
            cat_stats[cat]["events"] += 1
            cat_stats[cat]["flows"] += ev["flow_count"]
            cat_stats[cat]["bytes"] += ev["total_bytes"]

            sv = ev["severity"]
            if sv in sev_stats:
                sev_stats[sv]["events"] += 1
                sev_stats[sv]["flows"] += ev["flow_count"]
                sev_stats[sv]["bytes"] += ev["total_bytes"]
                sev_stats[sv]["hosts"].add(hip)

            if hip not in host_stats:
                host_stats[hip] = {
                    "ip": hip,
                    "alias": halias,
                    "hostname": nac.get("hostname", ""),
                    "mac": nac.get("mac", ""),
                    "switch_port": f"{nac.get('switch_name', '')} {nac.get('port_name', '')}".strip(),
                    "events": 0,
                    "flows": 0,
                    "bytes": 0,
                    "top_scenario": ev["scenario_name"]
                }
            host_stats[hip]["events"] += 1
            host_stats[hip]["flows"] += ev["flow_count"]
            host_stats[hip]["bytes"] += ev["total_bytes"]

        events_list.sort(key=lambda x: (sev_order.get(x["severity"], 9), -x["total_bytes"], -x["flow_count"]))
        top_hosts = sorted(host_stats.values(), key=lambda x: (-x["events"], -x["bytes"]))[:10]
        by_category = sorted(cat_stats.values(), key=lambda x: -x["events"])

        # Format scenario list for Tier 2 chart
        scenario_list = []
        for s in sc_stats.values():
            scenario_list.append({
                "scenario_id": s["scenario_id"],
                "name": s["name"],
                "category": s["category"],
                "severity": s["severity"],
                "events": s["events"],
                "flows": s["flows"],
                "bytes": s["bytes"],
                "hosts_count": len(s["hosts"]),
                "ports_summary": ", ".join(str(p) for p in sorted(list(s["ports"]))[:4]) or "全部"
            })
        scenario_list.sort(key=lambda x: (-x["events"], -x["bytes"]))

        athenac_configured = bool(
            get_system_setting("athenac_api_key", "").strip()
            or (get_system_setting("athenac_username", "").strip() and get_system_setting("athenac_password", "").strip())
        )

        sev_output = [
            {"severity": "high", "label": "高", "events": sev_stats["high"]["events"], "flows": sev_stats["high"]["flows"], "bytes": sev_stats["high"]["bytes"], "hosts": len(sev_stats["high"]["hosts"])},
            {"severity": "medium", "label": "中", "events": sev_stats["medium"]["events"], "flows": sev_stats["medium"]["flows"], "bytes": sev_stats["medium"]["bytes"], "hosts": len(sev_stats["medium"]["hosts"])},
            {"severity": "low", "label": "低", "events": sev_stats["low"]["events"], "flows": sev_stats["low"]["flows"], "bytes": sev_stats["low"]["bytes"], "hosts": len(sev_stats["low"]["hosts"])},
            {"severity": "behavior", "label": "行為管理", "events": sev_stats["behavior"]["events"], "flows": sev_stats["behavior"]["flows"], "bytes": sev_stats["behavior"]["bytes"], "hosts": len(sev_stats["behavior"]["hosts"])}
        ]

        return {
            "summary": {
                "time_range": time_range,
                "target_date": resolved_date or "",
                "time_label": resolved_label,
                "start_time": st[:5],
                "end_time": et[:5],
                "saved_date": get_system_setting("diag_saved_date", ""),
                "saved_preset": get_system_setting("diag_saved_preset", "custom" if get_system_setting("diag_saved_date", "") else "24h"),
                "saved_start_time": get_system_setting("diag_saved_start_time", "00:00"),
                "saved_end_time": get_system_setting("diag_saved_end_time", "23:59"),
                "total_events": len(events_list),
                "total_flows": sum(e["flow_count"] for e in events_list),
                "total_bytes": sum(e["total_bytes"] for e in events_list),
                "high_count": sev_stats["high"]["events"],
                "high_hosts": len(sev_stats["high"]["hosts"]),
                "medium_count": sev_stats["medium"]["events"],
                "medium_hosts": len(sev_stats["medium"]["hosts"]),
                "low_count": sev_stats["low"]["events"],
                "low_hosts": len(sev_stats["low"]["hosts"]),
                "behavior_count": sev_stats["behavior"]["events"],
                "behavior_hosts": len(sev_stats["behavior"]["hosts"]),
                "total_hosts": len(all_host_ips),
                "athenac_mode": "live" if athenac_configured else "simulated",
            },
            "charts": {
                "by_scenario": scenario_list,
                "by_category": by_category,
                "by_severity": sev_output,
                "by_hour": [hourly_bins[f"{h:02d}:00"] for h in range(24)],
                "top_hosts": top_hosts,
            },
            "events": events_list
        }
    except Exception as e:
        reset_ch_client()
        raise HTTPException(status_code=500, detail=str(e))

# Serve Static files. Ensure static directory exists
os.makedirs("static", exist_ok=True)

# Mount files inside static/ directory
app.mount("/", StaticFiles(directory="static", html=True), name="static")

@app.exception_handler(404)
def not_found_handler(request, exc):
    # Fallback to index.html for SPA routing
    index_path = os.path.join("static", "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return JSONResponse(status_code=404, content={"message": "Not Found"})
