# -*- coding: utf-8 -*-
"""
OLM 查看器 —— Outlook for Mac 存档 (.olm) 本地浏览工具

原理:
  .olm 是一个缺少中央目录的流式 ZIP (全部条目 stored 不压缩、zip64)。
  本工具通过链式解析 local file header 遍历全部条目并建立 SQLite 索引,
  之后通过本地 Web 界面浏览邮件 / 附件 / 联系人 / 日历等。

用法:
  python olm_viewer.py <路径/xxx.olm> [--port 8765] [--no-browser] [--reindex]

仅使用 Python 标准库, 无第三方依赖。索引只读 OLM 文件, 不修改它。
"""

import argparse
import html
import json
import os
import re
import sqlite3
import struct
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, quote, unquote

import xml.etree.ElementTree as ET

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# ---------------------------------------------------------------- 常量

NAME_PREFIX_RE = re.compile(r"^(Accounts/|Local/|Root Mailbox/|Categories)")
ATTACH_DIR_MARK = "com.microsoft.__Attachments"

FOLDER_ZH = {
    "Inbox": "收件箱",
    "Sent Items": "已发送",
    "Drafts": "草稿",
    "Trash": "已删除",
    "Deleted Items": "已删除",
    "Junk": "垃圾邮件",
    "Junk E-Mail": "垃圾邮件",
    "Sync Issues": "同步问题",
    "Conversation History": "对话历史记录",
    "RSS Feeds": "RSS 源",
    "Outbox": "发件箱",
    "Archive": "存档",
    "Calendar": "日历",
    "Contacts": "通讯录",
    "Tasks": "任务",
    "Notes": "便笺",
}

PAGE_SIZE_DEFAULT = 100
MAX_XML_BYTES = 64 * 1024 * 1024  # 单个 XML 条目解析上限


def human_size(n):
    try:
        n = float(n)
    except Exception:
        return "?"
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return ("%.0f %s" if unit == "B" else "%.1f %s") % (n, unit)
        n /= 1024.0


def log(msg):
    print(time.strftime("[%H:%M:%S] ") + msg, flush=True)


def to_bool(v):
    # OLM 把布尔存成 "1E0"/"0E0" (Excel 风格科学计数法)
    try:
        return int(float(v)) != 0
    except Exception:
        return False


def to_int_size(v):
    try:
        return int(float(v))
    except Exception:
        return 0


def safe_parse_xml(data):
    """解析存档内的 XML; 拒绝 DTD/实体以防实体扩展攻击, 限制大小。"""
    if len(data) > MAX_XML_BYTES:
        raise ValueError("XML 条目过大 (%s)" % human_size(len(data)))
    head = data[:8192]
    if b"<!DOCTYPE" in head or b"<!ENTITY" in head or b"<!DOCTYPE" in data[:65536]:
        raise ValueError("XML 包含 DTD/实体声明, 已拒绝解析")
    return ET.fromstring(data)


# ---------------------------------------------------------------- OLM 文件读取

class OlmArchive:
    def __init__(self, path):
        self.path = path
        self.size = os.path.getsize(path)
        self._fh = None
        self._lock = threading.Lock()

    def _open(self):
        if self._fh is None:
            self._fh = open(self.path, "rb")
        return self._fh

    def read_at(self, off, n):
        with self._lock:
            f = self._open()
            f.seek(off)
            return f.read(n)

    def read_chunked(self, off, n, chunk=4 * 1024 * 1024):
        """大条目分块读, 避免一次性占用内存。"""
        with self._lock:
            f = self._open()
            f.seek(off)
            remaining = n
            while remaining > 0:
                b = f.read(min(chunk, remaining))
                if not b:
                    break
                yield b
                remaining -= len(b)

    def try_header(self, off, data=None):
        """解析 offset 处的 local file header; 不合法返回 None。"""
        if off < 0 or off >= self.size:
            return None
        if data is None:
            data = self.read_at(off, 1024)
        if len(data) < 34 or data[:4] != b"PK\x03\x04":
            return None
        (ver, flag, comp, mt, md, crc, csize, usize, nlen, elen) = struct.unpack(
            "<HHHHHIIIHH", data[4:30]
        )
        if nlen == 0 or nlen > 1000 or elen > 200:
            return None
        try:
            name = data[30 : 30 + nlen].decode("utf-8")
        except UnicodeDecodeError:
            return None
        if not NAME_PREFIX_RE.match(name):
            return None
        real_csize, real_usize = csize, usize
        if csize == 0xFFFFFFFF or usize == 0xFFFFFFFF:
            extra = data[30 + nlen : 30 + nlen + elen]
            j, ok = 0, False
            while j + 4 <= len(extra):
                hid, hsz = struct.unpack("<HH", extra[j : j + 4])
                if hid == 1:  # zip64 extended information
                    vals = extra[j + 4 : j + 4 + hsz]
                    p = 0
                    if usize == 0xFFFFFFFF and p + 8 <= len(vals):
                        real_usize = struct.unpack("<Q", vals[p : p + 8])[0]
                        p += 8
                    if csize == 0xFFFFFFFF and p + 8 <= len(vals):
                        real_csize = struct.unpack("<Q", vals[p : p + 8])[0]
                        p += 8
                    ok = True
                    break
                j += 4 + hsz
            if not ok:
                return None
        data_off = off + 30 + nlen + elen
        if real_csize > self.size - data_off:
            return None
        return (off, data_off, data_off + real_csize, real_csize, real_usize, name)

    def scan_chain(self, start, steps):
        """从 start 起连续验证 steps 步链是否成立 (用于区分真假签名)。"""
        off = start
        for _ in range(steps):
            r = self.try_header(off)
            if not r:
                return False
            off = r[2]
        return True

    def resync(self, off, window=16 * 1024 * 1024):
        """断链后在 [off, off+window) 内寻找可验证的真签名。"""
        end = min(self.size, off + window)
        length = end - off
        data = self.read_at(off, length)
        pos = 0
        while True:
            pos = data.find(b"PK\x03\x04", pos)
            if pos < 0:
                return None
            r = self.try_header(off + pos, data[pos : pos + 1024])
            if r and self.scan_chain(off + pos, 3):
                return off + pos
            pos += 4


# ---------------------------------------------------------------- 索引 (SQLite)

class Index:
    SCHEMA_VERSION = "3"

    def __init__(self, db_path):
        self.db_path = db_path
        self._local = threading.local()
        with self._conn() as c:
            c.executescript(
                """
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS entries(
                  name TEXT PRIMARY KEY, off INTEGER, data_off INTEGER, size INTEGER);
                CREATE TABLE IF NOT EXISTS messages(
                  entry TEXT PRIMARY KEY, folder TEXT,
                  subject TEXT, from_name TEXT, from_addr TEXT, to_text TEXT,
                  sort_ts TEXT, sent TEXT, received TEXT,
                  has_att INTEGER, att_count INTEGER, size INTEGER,
                  preview TEXT, is_read INTEGER, is_outgoing INTEGER, conv TEXT);
                CREATE TABLE IF NOT EXISTS attachments(
                  mail_entry TEXT, url TEXT, name TEXT, type TEXT, size INTEGER,
                  PRIMARY KEY(mail_entry, url));
                CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
                """
            )
            # schema 升级: 结构不符时清空邮件表并触发重索引
            ver = None
            for row in c.execute("SELECT value FROM meta WHERE key='schema_version'"):
                ver = row[0]
            cols = [r[1] for r in c.execute("PRAGMA table_info(messages)")]
            if ver != self.SCHEMA_VERSION or "conv" not in cols:
                c.execute("DROP TABLE IF EXISTS messages")
                c.execute("DROP TABLE IF EXISTS attachments")
                c.execute(
                    """
                    CREATE TABLE IF NOT EXISTS messages(
                      entry TEXT PRIMARY KEY, folder TEXT,
                      subject TEXT, from_name TEXT, from_addr TEXT, to_text TEXT,
                      sort_ts TEXT, sent TEXT, received TEXT,
                      has_att INTEGER, att_count INTEGER, size INTEGER,
                      preview TEXT, is_read INTEGER, is_outgoing INTEGER, conv TEXT);
                    """
                )
                c.execute(
                    """
                    CREATE TABLE IF NOT EXISTS attachments(
                      mail_entry TEXT, url TEXT, name TEXT, type TEXT, size INTEGER,
                      PRIMARY KEY(mail_entry, url));
                    """
                )
                c.execute("DELETE FROM meta WHERE key IN ('meta_done','meta_percent')")
                c.execute(
                    "INSERT INTO meta(key,value) VALUES('schema_version',?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (self.SCHEMA_VERSION,),
                )
            c.execute("CREATE INDEX IF NOT EXISTS ix_msg_folder_ts ON messages(folder, sort_ts)")
            c.execute("CREATE INDEX IF NOT EXISTS ix_msg_conv ON messages(conv, sort_ts)")

    def _conn(self):
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.db_path, timeout=30)
            conn.execute("PRAGMA busy_timeout=30000")
            conn.execute("PRAGMA synchronous=NORMAL")
            self._local.conn = conn
        return conn

    def meta_get(self, key, default=None):
        row = self._conn().execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row[0] if row else default

    def meta_set(self, key, value):
        with self._conn() as c:
            c.execute(
                "INSERT INTO meta(key,value) VALUES(?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, str(value)),
            )

    # ---- 条目

    def add_entry(self, off, data_off, size, name):
        with self._conn() as c:
            c.execute(
                "INSERT OR REPLACE INTO entries VALUES(?,?,?,?)",
                (name, off, data_off, size),
            )

    def get_entry(self, name):
        return self._conn().execute(
            "SELECT name, off, data_off, size FROM entries WHERE name=?", (name,)
        ).fetchone()

    def entries_count(self):
        return self._conn().execute("SELECT COUNT(*) FROM entries").fetchone()[0]

    def raw_items(self, like):
        return self._conn().execute(
            "SELECT name, size FROM entries "
            "WHERE name LIKE ? AND name NOT LIKE ? AND name LIKE '%.xml' "
            "ORDER BY name LIMIT 400",
            (like, "%/" + ATTACH_DIR_MARK + "/%"),
        ).fetchall()

    # ---- 邮件元数据

    def add_message(self, m):
        with self._conn() as c:
            c.execute(
                "INSERT OR REPLACE INTO messages VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    m["entry"], m["folder"], m["subject"], m["from_name"], m["from_addr"],
                    m["to_text"], m["sort_ts"], m["sent"], m["received"],
                    m["has_att"], m["att_count"], m["size"],
                    m["preview"], m["is_read"], m["is_outgoing"], m["conv"],
                ),
            )

    def folder_stats(self):
        return self._conn().execute(
            "SELECT folder, COUNT(*), MAX(sort_ts) FROM messages GROUP BY folder"
        ).fetchall()

    def _msg_where(self, folder, q):
        where, args = [], []
        if folder:
            where.append("folder = ?")
            args.append(folder)
        if q:
            like = "%" + q + "%"
            where.append(
                "(subject LIKE ? OR from_name LIKE ? OR from_addr LIKE ? OR to_text LIKE ? OR preview LIKE ?)"
            )
            args += [like] * 5
        return where, args

    def query_messages(self, folder, q, order, offset, limit):
        """扁平列表 (时间排序)。"""
        sql = "SELECT entry, subject, from_name, from_addr, to_text, sort_ts, has_att, size, preview, is_read, is_outgoing FROM messages"
        where, args = self._msg_where(folder, q)
        if where:
            sql += " WHERE " + " AND ".join(where)
        with self._conn() as c:
            total = c.execute(
                "SELECT COUNT(*) FROM messages" + (" WHERE " + " AND ".join(where) if where else ""), args
            ).fetchone()[0]
            rows = c.execute(
                sql + " ORDER BY sort_ts " + ("ASC" if order == "asc" else "DESC")
                + " LIMIT ? OFFSET ?",
                args + [limit, offset],
            ).fetchall()
        return total, rows

    def query_conversations(self, folder, q, order, offset, limit):
        """会话分组: 返回 (会话总数, [会话])。排序/代表行按过滤后的子集,
        组内带回全部相关邮件 (跨文件夹的标 folder 供前端灰显)。"""
        where_sql, args = self._msg_where(folder, q)
        W = (" WHERE " + " AND ".join(where_sql)) if where_sql else ""
        with self._conn() as c:
            total = c.execute(
                "SELECT COUNT(DISTINCT conv) FROM messages" + W + (" AND conv != ''" if where_sql else " WHERE conv != ''"),
                args,
            ).fetchone()[0]
            convs = c.execute(
                "SELECT conv, MAX(sort_ts) AS mt, COUNT(*) FROM messages" + W
                + (" AND conv != ''" if where_sql else " WHERE conv != ''")
                + " GROUP BY conv ORDER BY mt " + ("ASC" if order == "asc" else "DESC")
                + " LIMIT ? OFFSET ?",
                args + [limit, offset],
            ).fetchall()
            if not convs:
                return total, []
            keys = [cv[0] for cv in convs]
            marks = ",".join("?" * len(keys))
            rows = c.execute(
                "SELECT conv, entry, subject, from_name, from_addr, to_text, sort_ts, has_att, size, preview, is_read, is_outgoing, folder"
                " FROM messages WHERE conv IN (" + marks + ") ORDER BY sort_ts DESC",
                keys,
            ).fetchall()
        by_conv = {cv[0]: [] for cv in convs}
        for r in rows:
            by_conv[r[0]].append(r[1:])
        out = [(cv[0], cv[1], cv[2], by_conv.get(cv[0], [])) for cv in convs]
        return total, out

    def mail_entries(self):
        return self._conn().execute(
            "SELECT name, size FROM entries "
            "WHERE name GLOB '*com.microsoft.__Messages/*/message_*.xml' ORDER BY name"
        ).fetchall()

    # ---- 附件

    def add_attachments(self, rows):
        if not rows:
            return
        with self._conn() as c:
            c.executemany(
                "INSERT OR REPLACE INTO attachments VALUES(?,?,?,?,?)", rows
            )

    def clear_attachments(self):
        with self._conn() as c:
            c.execute("DELETE FROM attachments")

    def attachments_count(self):
        return self._conn().execute("SELECT COUNT(*) FROM attachments").fetchone()[0]

    def attachment_entries_count(self):
        return self._conn().execute(
            "SELECT COUNT(*) FROM entries WHERE name LIKE '%com.microsoft.__Attachments%'"
        ).fetchone()[0]

    def query_attachments(self, q, offset, limit):
        where, args = "", []
        if q:
            like = "%" + q + "%"
            where = "WHERE a.name LIKE ? OR a.type LIKE ? OR m.subject LIKE ?"
            args = [like] * 3
        with self._conn() as c:
            total = c.execute(
                "SELECT COUNT(*) FROM attachments a LEFT JOIN messages m ON m.entry=a.mail_entry "
                + where,
                args,
            ).fetchone()[0]
            rows = c.execute(
                "SELECT a.url, a.name, a.type, a.size, m.subject, m.sort_ts, m.entry"
                " FROM attachments a LEFT JOIN messages m ON m.entry=a.mail_entry "
                + where +
                " ORDER BY m.sort_ts DESC LIMIT ? OFFSET ?",
                args + [limit, offset],
            ).fetchall()
        return total, rows


# ---------------------------------------------------------------- 扫描线程

def scan_worker(archive, index, stop_evt):
    if index.meta_get("scan_done") == "1":
        log("条目扫描已完成, 跳过")
        return
    off = int(index.meta_get("scan_offset", "0") or 0)
    if off == 0 and args_reindex_check(index):
        with index._conn() as c:
            c.execute("DELETE FROM entries")
            c.execute("DELETE FROM messages")
            c.execute("DELETE FROM meta WHERE key != 'olm_path'")
    if off > 0:
        log("从 %.1f%% 处继续扫描 ..." % (100.0 * off / archive.size))
    else:
        log("开始扫描 OLM 条目 ...")

    n_new, resyncs, t0 = 0, 0, time.time()
    last_report = time.time()
    pending = []

    def flush_entries():
        for name, o, doff, sz in pending:
            index.add_entry(o, doff, sz, name)
        pending.clear()

    while off is not None and off < archive.size:
        if stop_evt.is_set():
            return
        r = archive.try_header(off)
        if not r:
            nr = archive.resync(off)
            if nr is None:
                log("扫描结束: 偏移 %s 之后无法继续解析" % off)
                break
            resyncs += 1
            off = nr
            continue
        o, data_off, next_off, csize, usize, name = r
        pending.append((name, o, data_off, csize))
        n_new += 1
        off = next_off
        if len(pending) >= 2000:
            flush_entries()
            index.meta_set("scan_offset", off)
        now = time.time()
        if now - last_report >= 10:
            last_report = now
            pct = 100.0 * off / archive.size
            speed = n_new / max(now - t0, 0.1)
            log("扫描进度 %.1f%%  条目 %d  (%.0f 条/秒, resync %d 次)" % (pct, index.entries_count(), speed, resyncs))
            index.meta_set("scan_offset", off)
            index.meta_set("scan_percent", "%.2f" % pct)
            flush_entries()

    flush_entries()
    index.meta_set("scan_offset", str(archive.size))
    index.meta_set("scan_percent", "100.00")
    index.meta_set("scan_done", "1")
    log("条目扫描完成: 共 %d 条, 耗时 %.0f 秒, resync %d 次" % (index.entries_count(), time.time() - t0, resyncs))


def args_reindex_check(index):
    return False  # --reindex 时已在 main 中删除库文件


# ---------------------------------------------------------------- 邮件 XML 解析

def TAG_TEXT(el):
    return (el.text or "").strip()


def _strip_html(s):
    s = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", s)
    s = re.sub(r"(?is)<xml[^>]*>.*?</xml>", " ", s)  # Word 导出的 xml 数据岛
    s = re.sub(r"<[^>]+>", " ", s)
    s = html.unescape(s)
    return re.sub(r"\s+", " ", s).strip()


def parse_mail(data, entry_name, entry_size):
    """解析邮件 XML -> dict (供 messages 表)。"""
    folder = entry_name.rsplit("/", 1)[0]
    m = {
        "entry": entry_name, "folder": folder, "subject": "", "from_name": "", "from_addr": "",
        "to_text": "", "sort_ts": "", "sent": "", "received": "", "has_att": 0, "att_count": 0,
        "size": entry_size, "preview": "", "is_read": 1, "is_outgoing": 0, "conv": "", "_atts": [],
    }
    conv = {"x": "", "g": "", "t": "", "s": ""}
    try:
        root = safe_parse_xml(data)
    except Exception:
        # 兜底: 正则粗提取 (同样先排除 DTD)
        if b"<!DOCTYPE" in data[:8192] or b"<!ENTITY" in data[:8192]:
            return m
        s = lambda tag: _text_of(data, tag)
        m["subject"] = s("OPFMessageCopySubject")
        m["received"] = s("OPFMessageCopyReceivedTime")
        m["sent"] = s("OPFMessageCopySentTime")
        m["sort_ts"] = m["received"] or m["sent"]
        m["conv"] = "s:" + (m["subject"] or entry_name)
        m["preview"] = _strip_html(s("OPFMessageCopyHTMLBody") or s("OPFMessageCopyBody"))[:200]
        return m

    email = root.find("email")
    if email is None:
        email = root

    for el in email:
        tag = el.tag
        if tag == "OPFMessageCopySubject" or tag == "OPFMessageCopyThreadTopic":
            if not m["subject"]:
                m["subject"] = TAG_TEXT(el)
        elif tag == "OPFMessageCopyExchangeConversationId":
            conv["x"] = TAG_TEXT(el)
        elif tag == "OPFMessageCopyLocalThreadGUID":
            conv["g"] = TAG_TEXT(el)
        elif tag == "OPFMessageCopyThreadIndex":
            conv["t"] = TAG_TEXT(el)
        elif tag == "OPFMessageCopyReceivedTime":
            m["received"] = TAG_TEXT(el)
        elif tag == "OPFMessageCopySentTime":
            m["sent"] = TAG_TEXT(el)
        elif tag == "OPFMessageCopyModDate":
            m.setdefault("_mod", TAG_TEXT(el))
        elif tag.endswith("Addresses"):
            names, addrs = [], []
            for a in el.iter("emailAddress"):
                nm = a.get("OPFContactEmailAddressName") or ""
                ad = a.get("OPFContactEmailAddressAddress") or ""
                if nm:
                    names.append(nm)
                if ad:
                    addrs.append(ad)
            role = tag.replace("OPFMessageCopy", "").replace("Addresses", "")
            joined = ", ".join(names) or ", ".join(addrs)
            if role in ("To", "Cc", "Bcc") and joined:
                m["to_text"] = (m["to_text"] + ("; " if m["to_text"] else "") + joined)[:500]
            elif role == "From":
                m["from_name"] = ", ".join(names)[:200]
                m["from_addr"] = ", ".join(addrs)[:200]
        elif tag == "OPFMessageCopyAttachmentList":
            atts = list(el.iter("messageAttachment"))
            m["att_count"] = len(atts)
            m["has_att"] = 1 if atts else 0
            m["_atts"] = [
                {
                    "url": a.get("OPFAttachmentURL") or "",
                    "name": a.get("OPFAttachmentName") or (a.get("OPFAttachmentURL") or "").rsplit("/", 1)[-1],
                    "type": a.get("OPFAttachmentContentType") or "",
                    "size": to_int_size(a.get("OPFAttachmentContentFileSize")),
                }
                for a in atts
            ]
        elif tag == "OPFMessageGetIsRead":
            m["is_read"] = 1 if to_bool(el.text) else 0
        elif tag == "OPFMessageIsOutgoing":
            m["is_outgoing"] = 1 if to_bool(el.text) else 0
        elif tag in ("OPFMessageCopyBody", "OPFMessageCopyHTMLBody"):
            if not m["preview"]:
                m["preview"] = _strip_html(TAG_TEXT(el))[:200]

    if not m["sort_ts"]:
        m["sort_ts"] = m["received"] or m["sent"] or m.get("_mod", "")
    # 会话键: Exchange 会话ID > 本地线程GUID > ThreadIndex 前缀 > 归一化主题
    import base64 as _b64

    if conv["x"]:
        m["conv"] = "x:" + conv["x"]
    elif conv["g"]:
        m["conv"] = "g:" + conv["g"]
    elif conv["t"]:
        try:
            raw_idx = _b64.b64decode(conv["t"] + "===")
            m["conv"] = "t:" + _b64.b16encode(raw_idx[:22]).decode("ascii")
        except Exception:
            m["conv"] = "t:" + conv["t"][:40]
    else:
        norm = re.sub(r"^(?i)(re|fw|fwd|答复|回复|转发)\s*[:：]\s*", "", m["subject"] or "").strip().lower()
        m["conv"] = "s:" + (norm or entry_name)
    return m


def _text_of(data, tag):
    mm = re.search(("<%s[^>]*>(.*?)</%s>" % (tag, tag)).encode(), data, re.S)
    if not mm:
        return ""
    try:
        return html.unescape(mm.group(1).decode("utf-8", "replace")).strip()
    except Exception:
        return ""


def read_entry_bytes(archive, index, name):
    e = index.get_entry(name)
    if not e:
        return None
    _, _, data_off, size = e
    if size > MAX_XML_BYTES * 2:
        return b""
    return b"".join(archive.read_chunked(data_off, size))


def meta_worker(archive, index, stop_evt):
    """后台解析全部邮件条目的元数据。"""
    if index.meta_get("meta_done") == "1":
        log("邮件元数据索引已完成, 跳过")
        return
    if index.meta_get("scan_done") != "1":
        log("等待条目扫描完成后再索引邮件元数据 ...")
        while not stop_evt.is_set() and index.meta_get("scan_done") != "1":
            time.sleep(2)
    if stop_evt.is_set():
        return

    rows = index.mail_entries()
    total = len(rows)
    index.clear_attachments()
    log("开始索引邮件元数据: 共 %d 封" % total)
    t0, done = time.time(), 0
    batch, att_batch = [], []
    for name, size in rows:
        if stop_evt.is_set():
            index.meta_set("meta_percent", "%.2f" % (100.0 * done / max(total, 1)))
            return
        done += 1
        raw = read_entry_bytes(archive, index, name)
        if raw:
            try:
                mm = parse_mail(raw, name, size)
                batch.append(mm)
                for a in mm.get("_atts", ()):
                    att_batch.append((name, a["url"], a["name"], a["type"], a["size"]))
            except Exception as ex:
                log("解析失败 %s: %s" % (name, ex))
        if len(batch) >= 500:
            for x in batch:
                index.add_message(x)
            index.add_attachments(att_batch)
            batch, att_batch = [], []
            pct = 100.0 * done / max(total, 1)
            index.meta_set("meta_percent", "%.2f" % pct)
            if done % 2000 < 500:
                speed = done / max(time.time() - t0, 0.1)
                log("元数据索引 %.1f%%  (%d/%d, %.0f 封/秒)" % (pct, done, total, speed))
    for x in batch:
        index.add_message(x)
    index.add_attachments(att_batch)
    index.meta_set("meta_percent", "100.00")
    index.meta_set("meta_done", "1")
    log("邮件元数据索引完成, 耗时 %.0f 秒" % (time.time() - t0))


# ---------------------------------------------------------------- 通用 XML -> JSON

def xml_to_json(el, depth=0, maxdepth=8, maxtext=2000):
    node = {"tag": el.tag, "attrs": {k: v for k, v in el.attrib.items()}, "text": "", "children": []}
    txt = (el.text or "").strip()
    if txt:
        node["text"] = txt[:maxtext]
    if depth < maxdepth:
        for ch in el:
            node["children"].append(xml_to_json(ch, depth + 1, maxdepth, maxtext))
    elif len(el):
        node["children_truncated"] = len(el)
    return node


# ---------------------------------------------------------------- HTTP 服务

class Handler(BaseHTTPRequestHandler):
    server_version = "OLMViewer/1.0"

    def log_message(self, fmt, *args):
        pass  # 静默访问日志

    # ---- 工具

    def _json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _file(self, body, ctype="text/html; charset=utf-8"):
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    @property
    def index(self):
        return self.server.index

    @property
    def archive(self):
        return self.server.archive

    # ---- 路由

    def do_GET(self):
        try:
            u = urlparse(self.path)
            q = parse_qs(u.query)
            g = lambda k, d="": unquote(q.get(k, [d])[0])
            if u.path == "/":
                return self._file(FRONTEND.encode("utf-8"))
            if u.path == "/api/status":
                return self.api_status()
            if u.path == "/api/tree":
                return self.api_tree()
            if u.path == "/api/messages":
                return self.api_messages(
                    g("folder"), g("q"), g("order", "desc"),
                    int(g("page", "1") or 1), int(g("pagesize", str(PAGE_SIZE_DEFAULT)) or PAGE_SIZE_DEFAULT),
                    conv_mode=g("conv", "1") != "0",
                )
            if u.path == "/api/attachments":
                return self.api_attachments(
                    g("q"), int(g("page", "1") or 1), int(g("pagesize", "100") or 100)
                )
            if u.path == "/api/message":
                return self.api_message(g("entry"))
            if u.path == "/api/attachment":
                return self.api_attachment(g("entry"), inline=g("inline") == "1")
            if u.path == "/api/raw":
                return self.api_raw(
                    g("entry"), int(g("page", "1") or 1), int(g("pagesize", "100") or 100)
                )
            self._json({"error": "not found"}, 404)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
            try:
                self._json({"error": str(e)}, 500)
            except Exception:
                pass

    # ---- API 实现

    def api_status(self):
        ix = self.index
        return self._json({
            "file": self.archive.path,
            "file_size": self.archive.size,
            "entries": ix.entries_count(),
            "scan_done": ix.meta_get("scan_done") == "1",
            "scan_percent": float(ix.meta_get("scan_percent", "0") or 0),
            "meta_done": ix.meta_get("meta_done") == "1",
            "meta_percent": float(ix.meta_get("meta_percent", "0") or 0),
        })

    def api_tree(self):
        ix = self.index
        groups = []

        # 全部邮件 (跨文件夹)
        mail_total = ix._conn().execute("SELECT COUNT(*) FROM messages").fetchone()[0]
        groups.append({
            "title": "", "kind": "mail",
            "folders": [{"path": "__all__", "name": "全部邮件", "count": mail_total, "latest": ""}],
        })

        # 邮件文件夹 (按账户分组)
        acct = {}
        for folder, cnt, maxts in ix.folder_stats():
            parts = folder.split("/")
            if len(parts) >= 4 and parts[2] == "com.microsoft.__Messages":
                owner = "本地" if parts[0] == "Local" else parts[1]
                sub = "/".join(parts[3:])
                acct.setdefault(owner, []).append({
                    "path": folder,
                    "name": display_folder(sub),
                    "count": cnt,
                    "latest": maxts,
                })
        for owner, items in acct.items():
            items.sort(key=lambda x: -x["count"])
            groups.append({"title": "邮件 · %s" % owner, "kind": "mail", "folders": items})

        # 附件浏览 (全部附件文件)
        att_total = ix.attachment_entries_count()
        if att_total:
            groups.append({
                "title": "", "kind": "atts",
                "folders": [{"path": "__attachments__", "name": "全部附件", "count": att_total}],
            })

        # 其他类别 (通用 XML 查看)
        others = [
            ("联系人", ["%/Contacts/%", "%通讯簿%"]),
            ("日历", ["%Calendar%", "%日历%"]),
            ("任务", ["%Tasks%", "%任务%"]),
            ("便笺", ["%Notes%", "%便笺%"]),
        ]
        for title, likes in others:
            names, seen = [], set()
            for like in likes:
                for name, size in ix.raw_items(like):
                    if name in seen:
                        continue
                    seen.add(name)
                    if "/com.microsoft.__Messages/" in name or "/com.microsoft.__Attachments" in name:
                        continue
                    if "com.microsoft.__Messages" in name and not name.endswith("Contacts.xml"):
                        continue
                    names.append({"path": name, "name": name.rsplit("/", 1)[-1], "size": size})
            if names:
                groups.append({"title": title, "kind": "raw", "folders": names})

        return self._json({"groups": groups, "scan_done": ix.meta_get("scan_done") == "1"})

    def api_messages(self, folder, q, order, page, pagesize, conv_mode=True):
        pagesize = max(10, min(pagesize, 500))
        page = max(1, page)
        fld = folder if folder != "__all__" else ""
        items = []
        if conv_mode:
            total, convs = self.index.query_conversations(
                fld, q, order, (page - 1) * pagesize, pagesize
            )
            for conv, mt, cnt, mails in convs:
                msgs = [
                    {
                        "entry": r[0], "subject": r[1] or "(无主题)", "from_name": r[2] or r[3],
                        "to_text": r[4], "date": r[5], "has_att": r[6], "size": r[7],
                        "preview": r[8], "is_read": r[9], "is_outgoing": r[10],
                        "folder": r[11],
                    }
                    for r in mails
                ]
                if not msgs:
                    continue
                # 代表行/未读: 优先取当前文件夹内的邮件 (与页序一致)
                in_folder = [m for m in msgs if not fld or m["folder"] == fld] or msgs
                last = in_folder[0]
                any_unread = any(not m["is_read"] for m in in_folder)
                any_att = any(m["has_att"] for m in msgs)
                items.append({
                    "conv": conv, "count": cnt, "date": last["date"],
                    "subject": last["subject"], "from_name": last["from_name"],
                    "preview": last["preview"], "unread": any_unread, "has_att": any_att,
                    "msgs": msgs,
                })
            return self._json({"total": total, "page": page, "pagesize": pagesize,
                               "mode": "conv", "items": items})
        total, rows = self.index.query_messages(fld, q, order, (page - 1) * pagesize, pagesize)
        for r in rows:
            items.append({
                "entry": r[0], "subject": r[1] or "(无主题)", "from_name": r[2] or r[3],
                "to_text": r[4], "date": r[5], "has_att": r[6], "size": r[7],
                "preview": r[8], "is_read": r[9], "is_outgoing": r[10],
            })
        return self._json({"total": total, "page": page, "pagesize": pagesize,
                           "mode": "flat", "items": items})

    def api_attachments(self, q, page, pagesize):
        pagesize = max(10, min(pagesize, 500))
        page = max(1, page)
        total, rows = self.index.query_attachments(q, (page - 1) * pagesize, pagesize)
        items = [
            {
                "url": r[0], "name": r[1], "type": r[2], "size": r[3],
                "mail_subject": r[4] or "(邮件索引中)", "date": r[5], "mail_entry": r[6],
            }
            for r in rows
        ]
        return self._json({"total": total, "page": page, "pagesize": pagesize, "items": items})

    def api_message(self, entry):
        raw = read_entry_bytes(self.archive, self.index, entry)
        if raw is None:
            return self._json({"error": "条目不存在 (索引可能仍在进行中)"}, 404)
        try:
            root = safe_parse_xml(raw)
        except Exception as e:
            return self._json({"error": "邮件 XML 解析失败: %s" % e}, 500)
        email = root.find("email") if root.tag == "emails" else root

        info = {"entry": entry, "subject": "", "from": {}, "to": [], "cc": [], "bcc": [],
                "sent": "", "received": "", "attachments": [], "body_html": "", "body_text": ""}

        cid_map = {}
        for el in email:
            tag = el.tag
            if tag == "OPFMessageCopySubject":
                info["subject"] = TAG_TEXT(el)
            elif tag == "OPFMessageCopySentTime":
                info["sent"] = TAG_TEXT(el)
            elif tag == "OPFMessageCopyReceivedTime":
                info["received"] = TAG_TEXT(el)
            elif tag.endswith("Addresses"):
                role = tag.replace("OPFMessageCopy", "").replace("Addresses", "").lower()
                lst = [
                    {"name": a.get("OPFContactEmailAddressName") or "",
                     "addr": a.get("OPFContactEmailAddressAddress") or ""}
                    for a in el.iter("emailAddress")
                ]
                if role == "from":
                    info["from"] = lst[0] if lst else {}
                elif role in ("to", "cc", "bcc"):
                    info[role] = lst
            elif tag == "OPFMessageCopyAttachmentList":
                for a in el.iter("messageAttachment"):
                    url = a.get("OPFAttachmentURL") or ""
                    att = {
                        "name": a.get("OPFAttachmentName") or url.rsplit("/", 1)[-1],
                        "url": url,
                        "type": a.get("OPFAttachmentContentType") or "application/octet-stream",
                        "size": to_int_size(a.get("OPFAttachmentContentFileSize")),
                        "cid": a.get("OPFAttachmentContentID") or "",
                    }
                    info["attachments"].append(att)
                    if att["cid"]:
                        cid_map[att["cid"]] = url
            elif tag == "OPFMessageCopyHTMLBody":
                if not info["body_html"]:
                    info["body_html"] = TAG_TEXT(el)
            elif tag == "OPFMessageCopyBody":
                if not info["body_html"] and not info["body_text"]:
                    t = TAG_TEXT(el)
                    if t.lstrip().startswith("<"):
                        info["body_html"] = t
                    else:
                        info["body_text"] = t

        if info["body_html"]:
            for cid, url in cid_map.items():
                info["body_html"] = info["body_html"].replace(
                    "cid:" + cid, "/api/attachment?inline=1&entry=" + quote(url, safe="")
                )
        return self._json(info)

    def api_attachment(self, entry, inline=False):
        e = self.index.get_entry(entry)
        if not e:
            return self._json({"error": "附件不存在 (索引可能仍在进行中)"}, 404)
        _, _, data_off, size = e
        name = entry.rsplit("/", 1)[-1]
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        disp = "inline" if inline else "attachment"
        self.send_header("Content-Disposition", "%s; filename*=UTF-8''%s" % (disp, quote(name, safe="")))
        self.send_header("Content-Length", str(size))
        self.end_headers()
        for chunk in self.archive.read_chunked(data_off, size):
            self.wfile.write(chunk)

    def api_raw(self, entry, page=1, pagesize=100):
        raw = read_entry_bytes(self.archive, self.index, entry)
        if raw is None:
            return self._json({"error": "条目不存在"}, 404)
        try:
            root = safe_parse_xml(raw)
        except Exception as e:
            return self._json({"error": "XML 解析失败: %s" % e}, 500)
        tree = xml_to_json(root, maxtext=4000)
        kids = tree.get("children", [])
        pagesize = max(10, min(pagesize, 500))
        page = max(1, page)
        start = (page - 1) * pagesize
        items = tree.get("children", [])[start : start + pagesize]
        return self._json({
            "entry": entry, "item_count": len(kids), "page": page,
            "pagesize": pagesize, "items": items,
        })


def display_folder(sub):
    parts = sub.split("/")
    return "/".join(FOLDER_ZH.get(p, p) for p in parts)


# ---------------------------------------------------------------- 前端页面

FRONTEND = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>OLM 存档查看器</title>
<style>
:root{--bg:#f5f6f8;--panel:#fff;--line:#e3e6ea;--fg:#24292f;--muted:#6a737d;--acc:#0366d6;--accbg:#f1f8ff}
*{box-sizing:border-box}
html,body{height:100%;margin:0}
body{font:14px/1.5 -apple-system,"Segoe UI","Microsoft YaHei",sans-serif;color:var(--fg);background:var(--bg);display:flex;flex-direction:column}
header{display:flex;align-items:center;gap:12px;padding:8px 14px;background:#1f6feb;color:#fff;flex:none}
header h1{font-size:15px;margin:0;font-weight:600;white-space:nowrap}
#banner{font-size:12px;opacity:.95;background:rgba(255,255,255,.18);padding:3px 10px;border-radius:10px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
#main{flex:1;display:flex;min-height:0}
#sidebar{width:250px;flex:none;background:var(--panel);border-right:1px solid var(--line);overflow:auto;padding:8px 0}
#listwrap{width:400px;flex:none;background:var(--panel);border-right:1px solid var(--line);display:flex;flex-direction:column;min-height:0}
#readwrap{flex:1;display:flex;flex-direction:column;min-width:0;background:var(--panel)}
.gtitle{padding:8px 14px 4px;font-size:12px;color:var(--muted);font-weight:600}
.fitem{display:flex;justify-content:space-between;padding:5px 14px;cursor:pointer;gap:6px;align-items:center}
.fitem:hover{background:var(--accbg)}
.fitem.active{background:#dbeafe;font-weight:600}
.fitem .nm{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.fitem .ct{color:var(--muted);font-size:12px;flex:none}
#searchbar{padding:8px;border-bottom:1px solid var(--line);display:flex;gap:6px}
#q{flex:1;padding:5px 8px;border:1px solid var(--line);border-radius:6px;font-size:13px;min-width:60px}
button{padding:5px 10px;border:1px solid var(--line);background:#fafbfc;border-radius:6px;cursor:pointer;font-size:13px}
button:hover{background:#f0f3f6}
#list{flex:1;overflow:auto}
.mitem{padding:7px 12px;border-bottom:1px solid var(--line);cursor:pointer}
.mitem:hover{background:var(--accbg)}
.mitem.active{background:#dbeafe}
.mitem .r1{display:flex;justify-content:space-between;gap:8px}
.mitem .frm{font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.mitem.read .frm{font-weight:400;color:#444}
.mitem .dt{color:var(--muted);font-size:12px;flex:none}
.mitem .sj{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.mitem .pv{color:var(--muted);font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;margin-top:1px}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:#1f6feb;margin-right:5px}
.att-ico{color:#b08800;margin-left:4px;font-size:12px}
.conv{border-bottom:1px solid var(--line)}
.chead{display:flex;align-items:center;gap:7px;padding:8px 12px;cursor:pointer}
.chead:hover{background:var(--accbg)}
.chead .tri{color:var(--muted);font-size:11px;flex:none;width:10px}
.chead .csubject{font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1}
.chead .ccount{background:#d1d9e0;color:#444;border-radius:10px;font-size:11px;padding:1px 7px;flex:none}
.chead .cwho{color:var(--muted);font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:110px;flex:none}
.chead .dt{color:var(--muted);font-size:12px;flex:none}
.mitem.indent{padding-left:26px;border-bottom:1px dashed #eef0f3}
.mitem.other .frm,.mitem.other .pv{color:#9aa4ae}
.foldtag{display:inline-block;background:#eef1f4;color:#6a737d;border-radius:4px;font-size:10px;padding:0 5px;margin-right:4px;vertical-align:1px;font-weight:400}
#pager{padding:6px 10px;border-top:1px solid var(--line);display:flex;gap:8px;align-items:center;font-size:13px;color:var(--muted)}
#readhead{padding:10px 16px;border-bottom:1px solid var(--line)}
#readhead h2{font-size:16px;margin:0 0 6px}
.meta{color:var(--muted);font-size:13px;line-height:1.7}
.meta b{color:var(--fg);font-weight:600}
#attbar{padding:8px 16px;border-bottom:1px solid var(--line);flex-wrap:wrap;gap:6px}
.atchip{display:inline-flex;align-items:center;gap:5px;padding:3px 10px;background:#f6f8fa;border:1px solid var(--line);border-radius:14px;font-size:12px;color:var(--acc);text-decoration:none}
.atchip:hover{background:#eef3f8}
#placeholder{flex:1;display:flex;align-items:center;justify-content:center;color:var(--muted);font-size:15px}
#loading{padding:20px;text-align:center;color:var(--muted)}
.spin{display:inline-block;width:14px;height:14px;border:2px solid #c9d4e0;border-top-color:#1f6feb;border-radius:50%;animation:sp 1s linear infinite;vertical-align:-2px;margin-right:6px}
@keyframes sp{to{transform:rotate(360deg)}}
</style>
</head>
<body>
<header>
  <h1>📬 OLM 存档查看器</h1>
  <div id="banner">正在加载状态…</div>
</header>
<div id="main">
  <div id="sidebar"></div>
  <div id="listwrap">
    <div id="searchbar">
      <input id="q" placeholder="搜索主题/发件人/摘要 (回车=全局)">
      <button id="btnSearch" title="在当前文件夹内搜索">搜索</button>
      <button id="btnAll" title="在全部邮件中搜索">全局</button>
      <button id="btnOrder" title="切换时间排序">↓</button>
      <button id="btnConv" title="切换 会话分组/按时间平铺">会话</button>
    </div>
    <div id="list"><div id="loading"><span class="spin"></span>等待索引…</div></div>
    <div id="pager">
      <button id="pgPrev">上一页</button><span id="pgInfo">- / -</span><button id="pgNext">下一页</button>
      <input id="pgJump" title="输入页码" style="width:56px;padding:3px 6px;border:1px solid var(--line);border-radius:5px"><button id="pgGo">跳转</button>
      <span style="margin-left:auto" id="totalInfo"></span>
    </div>
  </div>
  <div id="readwrap"><div id="placeholder">选择左侧文件夹, 再点击邮件阅读</div></div>
</div>
<script>
const $=s=>document.querySelector(s);
let state={folder:null,q:"",scope:"folder",order:"desc",page:1,total:0,pages:1,allDone:false,convMode:true,view:"mail"};
let treeTimer=null;

function esc(s){return (s||"").replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]))}
function fmtDT(s){if(!s)return"";return s.replace("T"," ").slice(0,16)}
function fmtSize(n){if(n==null)return"";if(n<1024)return n+" B";if(n<1048576)return (n/1024).toFixed(1)+" KB";return (n/1048576).toFixed(1)+" MB"}

async function api(path){const r=await fetch(path);if(!r.ok){let m;try{m=(await r.json()).error}catch(e){m=r.statusText}throw new Error(m)}return r.json()}

// ---------- 状态横幅
async function pollStatus(){
  try{
    const st=await api("/api/status");
    const b=$("#banner");
    if(!st.scan_done){
      b.textContent="正在扫描存档条目 "+st.scan_percent.toFixed(1)+"% (已发现 "+st.entries.toLocaleString()+" 项) — 已扫到的内容可先浏览";
      setTimeout(pollStatus,4000);
    }else if(!st.meta_done){
      b.textContent="正在建立邮件索引 "+st.meta_percent.toFixed(1)+"% — 部分文件夹可能暂时不完整";
      setTimeout(pollStatus,4000);
      if(!state.allDone&&treeTimer===null){treeTimer=setInterval(loadTree,8000)}
    }else{
      b.textContent="共 "+st.entries.toLocaleString()+" 项 · 索引就绪 ("+(st.file_size/1073741824).toFixed(1)+" GB)";
      if(treeTimer!==null){clearInterval(treeTimer);treeTimer=null;loadTree()}
    }
  }catch(e){$("#banner").textContent="状态获取失败: "+e.message;setTimeout(pollStatus,6000)}
}

// ---------- 文件夹树
async function loadTree(){
  try{
    const t=await api("/api/tree");
    const sb=$("#sidebar");sb.innerHTML="";
    for(const g of t.groups){
      const h=document.createElement("div");h.className="gtitle";h.textContent=g.title;sb.appendChild(h);
      for(const f of g.folders){
        const active = g.kind==="mail" ? state.folder===f.path : (g.kind==="atts" ? state.view==="atts" : state.folder==="raw:"+f.path);
        const d=document.createElement("div");d.className="fitem"+(active?" active":"");
        d.innerHTML='<span class="nm">'+esc(f.name)+'</span><span class="ct">'+((g.kind==="mail"||g.kind==="atts")?f.count.toLocaleString():fmtSize(f.size))+"</span>";
        d.onclick=()=>{
          if(g.kind==="mail"){state.view="mail";state.folder=f.path;state.q="";$("#q").value="";state.scope="folder";state.page=1;loadList()}
          else if(g.kind==="atts"){state.view="atts";state.folder="__attachments__";state.q="";$("#q").value="";state.page=1;loadList()}
          else{openRaw(f.path)}
        };
        sb.appendChild(d);
      }
    }
  }catch(e){$("#sidebar").innerHTML='<div class="gtitle">树加载失败: '+esc(e.message)+"</div>"}
}

// ---------- 邮件列表 (会话分组 / 扁平) / 附件列表
function setLoading(msg){$("#list").innerHTML='<div id="loading"><span class="spin"></span>'+esc(msg)+"</div>"}
async function loadList(){
  if(state.view==="atts"){return loadAtts()}
  if(state.folder==null)return;
  setLoading("加载中…");
  const p=new URLSearchParams({folder:state.scope==="all"?"__all__":state.folder,q:state.q,order:state.order,page:state.page,pagesize:100,conv:state.convMode?"1":"0"});
  try{
    const r=await api("/api/messages?"+p);
    const per=r.mode==="conv"?r.pagesize:r.pagesize;
    state.total=r.total;state.pages=Math.max(1,Math.ceil(r.total/per));
    const el=$("#list");
    if(!r.items.length){el.innerHTML='<div id="loading">'+(state.q?"没有匹配的邮件":"该文件夹暂无邮件 (若索引未完成, 稍后会自动出现)")+"</div>";updatePager();return}
    if(r.mode==="conv"){
      const curF = state.scope==="all" ? "" : state.folder;
      el.innerHTML=r.items.map((cv,i)=>{
        const n=cv.msgs.length;
        const who=cv.msgs.map(m=>m.is_outgoing?("我"):m.from_name).filter((v,idx,arr)=>v&&arr.indexOf(v)===idx).slice(0,3).join(", ");
        const body=n>1
          ? '<div class="cbody" style="display:none">'+cv.msgs.map((m,j)=>msgRow(m,j,false,curF)).join("")+"</div>"
          : msgRow(cv.msgs[0],0,true,curF);
        return '<div class="conv" data-i="'+i+'">'
          +(n>1?'<div class="chead"><span class="tri">▸</span><span class="csubject">'+(cv.unread?'<span class="dot"></span>':"")+esc(cv.subject)+(cv.has_att?'<span class="att-ico">📎</span>':"")+'</span><span class="ccount">'+n+'</span><span class="cwho">'+esc(who)+'</span><span class="dt">'+fmtDT(cv.date)+"</span></div>":"")
          +body+"</div>";
      }).join("");
      el.querySelectorAll(".chead").forEach(h=>h.onclick=()=>{
        const b=h.parentElement.querySelector(".cbody");
        const open=b.style.display!=="none";
        b.style.display=open?"none":"block";
        h.querySelector(".tri").textContent=open?"▸":"▾";
      });
      el.querySelectorAll(".mitem").forEach(nd=>nd.onclick=()=>openMsg(r.items[+nd.closest(".conv").dataset.i].msgs[+nd.dataset.j],nd));
    }else{
      el.innerHTML=r.items.map((m,i)=>{
        const who=m.is_outgoing?("→ "+esc((m.to_text||"").slice(0,40))):esc(m.from_name||"(未知发件人)");
        return '<div class="mitem'+(m.is_read?" read":"")+'" data-i="'+i+'">'
          +'<div class="r1"><span class="frm">'+(m.is_read?"":'<span class="dot"></span>')+(m.is_outgoing?'<span style="color:#1f6feb">↗</span> ':"")+who+'</span><span class="dt">'+fmtDT(m.date)+"</span></div>"
          +'<div class="r2"><span class="sj">'+esc(m.subject)+(m.has_att?'<span class="att-ico">📎</span>':"")+"</span></div>"
          +'<div class="pv">'+esc(m.preview||"")+"</div></div>";
      }).join("");
      el.querySelectorAll(".mitem").forEach(n=>n.onclick=()=>openMsg(r.items[+n.dataset.i],n));
    }
    updatePager(r.mode);
  }catch(e){$("#list").innerHTML='<div id="loading">加载失败: '+esc(e.message)+"</div>"}
}
function msgRow(m,j,single,curFolder){
  const who=m.is_outgoing?("↗ "+esc((m.to_text||"").slice(0,30))):esc(m.from_name||"(未知)");
  const other = curFolder && m.folder && m.folder!==curFolder;
  const foldTag = other ? '<span class="foldtag">'+esc(displayFold(m.folder))+"</span> " : "";
  return '<div class="mitem'+(m.is_read?" read":"")+(single?"":" indent")+(other?" other":"")+'" data-j="'+j+'">'
    +'<div class="r1"><span class="frm">'+(m.is_read?"":'<span class="dot"></span>')+foldTag+who+'</span><span class="dt">'+fmtDT(m.date)+"</span></div>"
    +(single?'<div class="r2"><span class="sj">'+esc(m.subject)+(m.has_att?'<span class="att-ico">📎</span>':"")+"</span></div>":"")
    +'<div class="pv">'+esc(m.preview||"")+"</div></div>";
}
function displayFold(f){
  const m=f.match(/com\.microsoft\.__Messages\/([^/]+)\/(.*)$/);
  if(m){const owner=m[1]==="本地"?"本地":m[1];return owner+"/"+m[2]}
  return f.split("/").slice(-1)[0];
}
function updatePager(mode){
  const unit=mode==="conv"?"会话":(mode==="att"?"个":"封");
  $("#pgInfo").textContent=state.page+" / "+state.pages;
  $("#totalInfo").textContent="共 "+state.total.toLocaleString()+" "+unit;
}
$("#pgGo").onclick=()=>{
  const p=parseInt($("#pgJump").value,10);
  if(!(p>=1))return;
  state.page=Math.min(p,state.pages);
  state.view==="atts"?loadAtts():loadList();
};
$("#pgJump").addEventListener("keydown",e=>{if(e.key==="Enter")$("#pgGo").onclick()});

// ---------- 附件浏览
async function loadAtts(){
  setLoading("加载中…");
  const p=new URLSearchParams({q:state.q,page:state.page,pagesize:100});
  try{
    const r=await api("/api/attachments?"+p);
    state.total=r.total;state.pages=Math.max(1,Math.ceil(r.total/r.pagesize));
    const el=$("#list");
    if(!r.items.length){el.innerHTML='<div id="loading">'+(state.q?"没有匹配的附件":"暂无附件")+"</div>";updatePager("att");return}
    el.innerHTML=r.items.map((a,i)=>{
      const img=a.type&&a.type.startsWith("image/");
      const href="/api/attachment?entry="+encodeURIComponent(a.url)+(img?"&inline=1":"");
      return '<div class="mitem attrow" data-i="'+i+'">'
        +'<div class="r1"><span class="frm">📎 <a href="'+href+'" target="_blank"'+(img?"":" download")+' onclick="event.stopPropagation()">'+esc(a.name)+"</a></span><span class='dt'>"+fmtSize(a.size)+"</span></div>"
        +'<div class="pv">'+esc(a.mail_subject||"")+(a.date?" · "+fmtDT(a.date):"")+"</div></div>";
    }).join("");
    el.querySelectorAll(".attrow").forEach(n=>n.onclick=()=>{
      const a=r.items[+n.dataset.i];
      if(!a.mail_entry)return;
      openMsg({entry:a.mail_entry, subject:a.mail_subject}, n);
    });
    updatePager("att");
  }catch(e){$("#list").innerHTML='<div id="loading">加载失败: '+esc(e.message)+"</div>"}
}
$("#pgPrev").onclick=()=>{if(state.page>1){state.page--;loadList()}};
$("#pgNext").onclick=()=>{if(state.page<state.pages){state.page++;loadList()}};
$("#btnSearch").onclick=()=>{state.q=$("#q").value.trim();state.scope="folder";state.page=1;loadList()};
$("#btnAll").onclick=()=>{state.q=$("#q").value.trim();state.scope="all";state.page=1;loadList()};
$("#q").addEventListener("keydown",e=>{if(e.key==="Enter"){state.q=$("#q").value.trim();state.scope="all";state.page=1;loadList()}});
$("#btnOrder").onclick=()=>{state.order=state.order==="desc"?"asc":"desc";$("#btnOrder").textContent=state.order==="desc"?"↓":"↑";state.page=1;loadList()};
$("#btnConv").onclick=()=>{state.convMode=!state.convMode;$("#btnConv").style.fontWeight=state.convMode?"600":"400";$("#btnConv").textContent=state.convMode?"会话":"平铺";state.page=1;loadList()};

// ---------- 阅读邮件
async function openMsg(m,node){
  document.querySelectorAll(".mitem.active").forEach(n=>n.classList.remove("active"));
  node.classList.add("active");
  const rw=$("#readwrap");
  rw.innerHTML='<div id="loading"><span class="spin"></span>读取邮件…</div>';
  try{
    const d=await api("/api/message?entry="+encodeURIComponent(m.entry));
    const addr=a=>a&&a.addr?(a.name?a.name+" <"+a.addr+">":a.addr):"";
    const attsHtml=d.attachments.map(a=>{
      const href="/api/attachment?entry="+encodeURIComponent(a.url)+(a.type&&a.type.startsWith("image/")?"&inline=1":"");
      return '<a class="atchip" href="'+href+'" target="_blank"'+(a.type&&a.type.startsWith("image/")?"":" download")+' title="'+esc(a.type||"")+" · "+fmtSize(a.size)+'">📎 '+esc(a.name)+" <span style='color:#8a94a0'>"+fmtSize(a.size)+"</span></a>";
    }).join("");
    rw.innerHTML='<div id="readhead"><h2>'+esc(d.subject||"(无主题)")+"</h2>"
      +'<div class="meta">'
      +(addr(d.from)?"<b>发件人</b> "+esc(addr(d.from))+"<br>":"")
      +(d.to.length?"<b>收件人</b> "+esc(d.to.map(addr).join(", "))+"<br>":"")
      +(d.cc.length?"<b>抄送</b> "+esc(d.cc.map(addr).join(", "))+"<br>":"")
      +"<b>时间</b> "+esc(fmtDT(d.received||d.sent))
      +(d.received&&d.sent&&d.received!==d.sent?" <span style='color:#9aa4ae'>(发送于 "+esc(fmtDT(d.sent))+")</span>":"")
      +"</div></div>"
      +(d.attachments.length?'<div id="attbar" style="display:flex">'+attsHtml+"</div>":"")
      +'<iframe id="body" sandbox=""></iframe>';
    const fr=rw.querySelector("#body");
    fr.style.cssText="flex:1;border:0;width:100%;background:#fff";
    let doc=d.body_html;
    if(doc){
      doc='<!DOCTYPE html><html><head><meta charset="utf-8"><style>body{font-family:-apple-system,"Segoe UI","Microsoft YaHei",sans-serif;margin:12px 16px;color:#24292f}img{max-width:100%;height:auto}</style></head><body>'+doc+"</body></html>";
      fr.srcdoc=doc;
    }else{
      fr.srcdoc='<!DOCTYPE html><html><body style="font-family:sans-serif;margin:16px;color:#6a737d"><pre style="white-space:pre-wrap;font-family:inherit">'+esc(d.body_text||"(此邮件没有可显示的正文)")+"</pre></body></html>";
    }
  }catch(e){
    rw.innerHTML='<div id="readhead"><h2>读取失败</h2></div><div id="loading">'+esc(e.message)+"</div>";
  }
}

// ---------- 通用 XML 查看 (联系人/日历/任务/便笺)
function renderXmlNode(n,depth){
  let h="";
  const attrs=Object.entries(n.attrs||{}).map(([k,v])=>'<span style="color:#953800">'+esc(k)+'</span>=<span style="color:#0a3069">"'+esc(v)+'"</span>').join(" ");
  const hasContent=n.text||(n.children&&n.children.length);
  h+='<div style="margin-left:'+(depth?18:0)+'px">';
  h+='<span style="color:#116329">&lt;'+esc(n.tag)+"</span>"+(attrs?" "+attrs:"")+(!hasContent?" />":">");
  if(hasContent){
    if(n.text)h+='<span>'+esc(n.text)+"</span>";
    if(n.children&&n.children.length)h+="<br>"+n.children.map(c=>renderXmlNode(c,depth+1)).join("");
    h+='<span style="color:#116329">&lt;/'+esc(n.tag)+"&gt;</span>";
  }
  h+="</div>";
  return h;
}
async function openRaw(path,page){
  page=page||1;
  const rw=$("#readwrap");
  rw.innerHTML='<div id="loading"><span class="spin"></span>读取 …</div>';
  try{
    const d=await api("/api/raw?entry="+encodeURIComponent(path)+"&page="+page+"&pagesize=100");
    const pages=Math.max(1,Math.ceil(d.item_count/d.pagesize));
    rw.innerHTML='<div id="readhead"><h2>'+esc(path.split("/").pop())
      +' <span style="font-weight:400;color:#6a737d;font-size:13px">('+d.item_count+' 项 · 第 '+d.page+' / '+pages+' 页)</span></h2>'
      +(pages>1?'<div style="margin-top:6px"><button id="rawPrev" '+(d.page<=1?"disabled":"")+'>上一页</button> <button id="rawNext" '+(d.page>=pages?"disabled":"")+'>下一页</button></div>':"")
      +'</div><div style="flex:1;overflow:auto;padding:12px 16px;font:12px/1.6 Consolas,monospace;background:#fbfbfc">'
      +d.items.map(k=>renderXmlNode(k,0)).join("")+"</div>";
    const pv=rw.querySelector("#rawPrev"), nx=rw.querySelector("#rawNext");
    if(pv)pv.onclick=()=>openRaw(path,page-1);
    if(nx)nx.onclick=()=>openRaw(path,page+1);
  }catch(e){rw.innerHTML='<div id="loading">读取失败: '+esc(e.message)+"</div>"}
}

// ---------- 启动
pollStatus();loadTree();
</script>
</body>
</html>"""


# ---------------------------------------------------------------- main

def build_index_path(olm_path):
    import hashlib

    h = hashlib.md5((os.path.abspath(olm_path) + str(os.path.getsize(olm_path))).encode("utf-8")).hexdigest()[:12]
    base = os.path.dirname(os.path.abspath(__file__))
    d = os.path.join(base, "olm_index")
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, h + ".db")


def ensure_port_free(port):
    import socket

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        # 不设 SO_REUSEADDR: Windows 上它允许与既有服务并存监听同一端口
        s.bind(("127.0.0.1", port))
    except OSError:
        print("端口 %d 已被占用, 请用 --port 换一个端口" % port)
        sys.exit(1)
    finally:
        s.close()


def main():
    ap = argparse.ArgumentParser(description="Outlook for Mac .olm 存档查看器")
    ap.add_argument("olm", help=".olm 文件路径")
    ap.add_argument("--port", type=int, default=8791)
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("--reindex", action="store_true", help="丢弃已有索引并重建")
    args = ap.parse_args()

    olm = os.path.abspath(args.olm)
    if not os.path.isfile(olm):
        print("找不到文件: %s" % olm)
        sys.exit(1)
    ensure_port_free(args.port)

    db_path = build_index_path(olm)
    if args.reindex:
        for p in (db_path, db_path + "-wal", db_path + "-shm"):
            if os.path.exists(p):
                os.remove(p)

    archive = OlmArchive(olm)
    index = Index(db_path)
    index.meta_set("olm_path", olm)

    stop_evt = threading.Event()
    threading.Thread(target=scan_worker, args=(archive, index, stop_evt), daemon=True).start()
    threading.Thread(target=meta_worker, args=(archive, index, stop_evt), daemon=True).start()

    url = "http://127.0.0.1:%d/" % args.port
    httpd = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    httpd.archive = archive
    httpd.index = index
    log("OLM: %s (%s)" % (olm, human_size(archive.size)))
    log("索引库: %s" % db_path)
    log("查看器地址: %s  (Ctrl+C 退出, 索引进度已持久化, 随时可关)" % url)
    if not args.no_browser:
        threading.Timer(1.5, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        log("退出中 ...")
        stop_evt.set()
        httpd.shutdown()


if __name__ == "__main__":
    main()
