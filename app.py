"""Veltrix Tickets — private transcript website on Render.

Production uses PostgreSQL (e.g. Neon). No local transcript storage; suitable
for Render Free's ephemeral filesystem. WSGI application: gunicorn app:app.
"""
from __future__ import annotations

import hashlib
import hmac
import html
import io
import json
import logging
import os
import re
import secrets
import time
import zlib
from urllib.parse import urlsplit

LOG = logging.getLogger('veltrix.portal')
MAX_HTML = 5_800_000
MAX_BODY = MAX_HTML + 100
LINK_LIFETIME = 7 * 24 * 3600
TOKEN_REGEX = re.compile(r'^[A-Za-z0-9_-]{40,100}$')
API_PREFIX = '/api/v1'
CSP = ("default-src 'none'; script-src 'none'; object-src 'none'; "
       "img-src https://cdn.discordapp.com https://media.discordapp.net; "
       "style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; "
       "frame-ancestors 'none'; frame-src 'none'")

BASE_HEADERS = [
    ('X-Content-Type-Options', 'nosniff'),
    ('Referrer-Policy', 'no-referrer'),
    ('X-Frame-Options', 'DENY'),
    ('X-Robots-Tag', 'noindex, nofollow, noarchive'),
    ('Cache-Control', 'private, no-store, max-age=0'),
    ('Content-Security-Policy', CSP),
]


def public_base(raw):
    raw = (raw or '').strip().rstrip('/')
    try:
        url = urlsplit(raw)
        if (url.scheme != 'https' or not url.hostname or url.username or url.password
                or url.path not in ('', '/') or url.query or url.fragment
                or url.hostname.lower() in ('localhost', '127.0.0.1', '0.0.0.0')
                or len(raw) > 512 or any(ord(c) < 33 for c in raw)):
            return ''
        return raw
    except (ValueError, AttributeError):
        return ''


def positive_id(raw):
    try:
        if not isinstance(raw, (int, str)) or isinstance(raw, bool):
            return None
        s = str(raw)
        if not s.isascii() or not s.isdecimal() or len(s) > 20:
            return None
        result = int(s)
        return result if 0 < result < 2**63 else None
    except (ValueError, TypeError):
        return None


class PostgresStore:
    """All transcript bytes and link hashes are kept in PostgreSQL."""
    def __init__(self, dsn):
        self.dsn = dsn
        self._initialized = False

    def _connect(self):
        import psycopg  # Only Render runtime requires psycopg; stdlib test suite needs none.
        return psycopg.connect(self.dsn, connect_timeout=12)

    def _init(self):
        if self._initialized:
            return
        with self._connect() as db:
            db.execute('''CREATE TABLE IF NOT EXISTS veltrix_documents (
                guild_id BIGINT NOT NULL,
                ticket_id BIGINT NOT NULL,
                html_compressed BYTEA NOT NULL,
                raw_size INTEGER NOT NULL,
                saved_at BIGINT NOT NULL,
                PRIMARY KEY(guild_id, ticket_id)
            )''')
            db.execute('''CREATE TABLE IF NOT EXISTS veltrix_links (
                token_hash TEXT PRIMARY KEY,
                guild_id BIGINT NOT NULL,
                ticket_id BIGINT NOT NULL,
                issued_to BIGINT NOT NULL,
                expires_at BIGINT NOT NULL,
                FOREIGN KEY (guild_id, ticket_id)
                  REFERENCES veltrix_documents(guild_id, ticket_id) ON DELETE CASCADE
            )''')
            db.execute('''CREATE INDEX IF NOT EXISTS veltrix_links_expiry
                          ON veltrix_links(expires_at)''')
        self._initialized = True

    def ping(self):
        self._init()
        with self._connect() as db:
            return db.execute('SELECT 1').fetchone()[0] == 1

    def save(self, guild_id, ticket_id, content):
        self._init()
        packed = zlib.compress(content, level=6)
        with self._connect() as db:
            db.execute('''INSERT INTO veltrix_documents(guild_id,ticket_id,html_compressed,raw_size,saved_at)
                VALUES(%s,%s,%s,%s,%s)
                ON CONFLICT (guild_id,ticket_id) DO UPDATE SET
                  html_compressed=EXCLUDED.html_compressed,
                  raw_size=EXCLUDED.raw_size,
                  saved_at=EXCLUDED.saved_at''',
                (guild_id, ticket_id, packed, len(content), int(time.time())))
        return True

    def exists(self, guild_id, ticket_id):
        self._init()
        with self._connect() as db:
            return db.execute('''SELECT 1 FROM veltrix_documents
                                 WHERE guild_id=%s AND ticket_id=%s''',
                              (guild_id, ticket_id)).fetchone() is not None

    def create_link(self, guild_id, ticket_id, issued_to):
        self._init()
        token = secrets.token_urlsafe(36)
        digest = hashlib.sha256(token.encode('ascii')).hexdigest()
        now = int(time.time())
        with self._connect() as db:
            db.execute('DELETE FROM veltrix_links WHERE expires_at<=%s', (now,))
            result = db.execute('''INSERT INTO veltrix_links
                (token_hash,guild_id,ticket_id,issued_to,expires_at)
                SELECT %s,%s,%s,%s,%s WHERE EXISTS (
                    SELECT 1 FROM veltrix_documents WHERE guild_id=%s AND ticket_id=%s)
                RETURNING token_hash''', (digest,guild_id,ticket_id,issued_to,
                                         now+LINK_LIFETIME,guild_id,ticket_id)).fetchone()
        return token if result else None

    def resolve(self, token):
        self._init()
        digest = hashlib.sha256(token.encode('ascii')).hexdigest()
        with self._connect() as db:
            row = db.execute('''SELECT d.html_compressed,d.raw_size FROM veltrix_links l
                JOIN veltrix_documents d ON d.guild_id=l.guild_id AND d.ticket_id=l.ticket_id
                WHERE l.token_hash=%s AND l.expires_at>%s''',
                (digest,int(time.time()))).fetchone()
        if not row:
            return None
        packed, raw_size = row
        if not 0 < raw_size <= MAX_HTML:
            return None
        obj = zlib.decompressobj()
        output = obj.decompress(bytes(packed), MAX_HTML+1)
        if len(output) != raw_size or not obj.eof or obj.unconsumed_tail:
            return None
        return output


def landing_page():
    return '''<!DOCTYPE html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Veltrix • Transcrições</title><style>
:root{color-scheme:dark;font-family:system-ui,-apple-system,Segoe UI,Arial,sans-serif}
*{box-sizing:border-box}body{margin:0;min-height:100vh;background:#0c0d10;color:#f5f5f5;
 display:grid;place-items:center;padding:24px}main{max-width:620px;width:100%;border:1px solid #35363d;
 border-radius:22px;background:#17181d;padding:clamp(28px,6vw,54px);box-shadow:0 25px 90px #0007}
.logo{display:inline-grid;place-items:center;width:56px;height:56px;background:#30313b;border-radius:17px;
 font-size:28px}h1{font-size:clamp(27px,5vw,40px);margin:22px 0 12px;letter-spacing:-1px}
p{color:#afb1bd;line-height:1.7}strong{color:#e6e7ec}.line{height:1px;background:#35363d;margin:30px 0}
small{color:#878a97}.tag{font-weight:700;letter-spacing:.14em;color:#aeb0b9;font-size:11px}
</style></head><body><main><span class="logo">🎫</span><h1>Veltrix Tickets</h1>
<p>Seu espaço para visualizar transcrições de atendimento com o visual de uma conversa.</p>
<div class="line"></div><p><strong>🔒 Conversas privadas</strong></p>
<p>Para acessar uma transcrição, utilize o botão <strong>Abrir transcrição</strong> enviado
pela Veltrix ou o comando <strong>/meuticket</strong> dentro do Discord.</p>
<small>Links temporários • Acesso somente com endereço individual</small></main></body></html>'''.encode('utf-8')


class PortalApp:
    def __init__(self, store=None, *, api_key=None, base_url=None):
        self.key = (api_key if api_key is not None else os.environ.get('VELTRIX_PORTAL_API_KEY', '')).strip()
        self.base_url = public_base(base_url if base_url is not None else
            (os.environ.get('PUBLIC_BASE_URL') or os.environ.get('RENDER_EXTERNAL_URL') or ''))
        dsn = os.environ.get('DATABASE_URL', '').strip()
        self.store = store if store is not None else (PostgresStore(dsn) if dsn else None)
        self.configured = bool(len(self.key) >= 32 and self.base_url and self.store)

    @staticmethod
    def reply(start_response, status, content=b'', kind='text/plain; charset=utf-8', extra=()):
        headers = [('Content-Type', kind), ('Content-Length', str(len(content)))]+BASE_HEADERS+list(extra)
        start_response(status, headers)
        return [content]

    @classmethod
    def json_reply(cls, start_response, status, data):
        return cls.reply(start_response, status, json.dumps(data, ensure_ascii=False).encode('utf-8'),
                         'application/json; charset=utf-8')

    def authenticate(self, environ):
        presented = environ.get('HTTP_AUTHORIZATION', '')
        if not self.configured or not presented.startswith('Bearer '):
            return False
        return hmac.compare_digest(presented[7:].encode('utf-8'), self.key.encode('utf-8'))

    def body(self, environ, limit):
        try:
            size = int(environ.get('CONTENT_LENGTH') or '0')
        except ValueError:
            return None
        if size <= 0 or size > limit:
            return None
        data = environ.get('wsgi.input', io.BytesIO()).read(size)
        return data if len(data) == size else None

    def __call__(self, environ, start_response):
        method = environ.get('REQUEST_METHOD', 'GET')
        path = environ.get('PATH_INFO', '/')
        try:
            if method == 'GET' and path == '/':
                return self.reply(start_response,'200 OK',landing_page(),'text/html; charset=utf-8')
            if method == 'GET' and path == '/health':
                if not self.configured:
                    return self.json_reply(start_response,'503 Service Unavailable', {'ok':False,'reason':'not configured'})
                if not self.store.ping():
                    return self.json_reply(start_response,'503 Service Unavailable', {'ok':False})
                return self.json_reply(start_response,'200 OK', {'ok':True,'service':'veltrix-tickets'})
            if method == 'GET' and path.startswith('/t/'):
                token = path[3:]
                if not TOKEN_REGEX.fullmatch(token) or not self.configured:
                    return self.reply(start_response,'404 Not Found',b'Link invalido ou expirado.')
                result = self.store.resolve(token)
                if result is None:
                    return self.reply(start_response,'404 Not Found',b'Link invalido ou expirado.')
                return self.reply(start_response,'200 OK',result,'text/html; charset=utf-8',
                                  (('Content-Disposition','inline'),))
            if not path.startswith(API_PREFIX+'/'):
                return self.reply(start_response,'404 Not Found',b'Pagina nao encontrada.')
            if not self.authenticate(environ):
                return self.json_reply(start_response,'401 Unauthorized', {'error':'unauthorized'})

            if method == 'POST' and path == API_PREFIX+'/documents':
                gid = positive_id(environ.get('HTTP_X_VELTRIX_GUILD_ID'))
                tid = positive_id(environ.get('HTTP_X_VELTRIX_TICKET_ID'))
                body = self.body(environ,MAX_BODY)
                if not gid or not tid or not body or len(body)>MAX_HTML:
                    return self.json_reply(start_response,'400 Bad Request',{'error':'invalid_document'})
                if not (b'<html' in body[:2000].lower() or b'<!doctype html' in body[:2000].lower()):
                    return self.json_reply(start_response,'400 Bad Request',{'error':'html_required'})
                body.decode('utf-8', 'strict')
                self.store.save(gid,tid,body)
                return self.json_reply(start_response,'201 Created',{'saved':True})
            match = re.fullmatch(r'/api/v1/documents/(\d+)/(\d+)', path)
            if method == 'GET' and match:
                gid,tid = positive_id(match.group(1)),positive_id(match.group(2))
                if not gid or not tid:
                    return self.json_reply(start_response,'400 Bad Request', {'error':'invalid_id'})
                return self.json_reply(start_response,'200 OK',{'exists':bool(self.store.exists(gid,tid))})
            if method == 'POST' and path == API_PREFIX+'/links':
                body = self.body(environ, 4096)
                try:
                    obj = json.loads(body) if body else None
                except (UnicodeDecodeError,ValueError):
                    obj = None
                if not isinstance(obj,dict):
                    return self.json_reply(start_response,'400 Bad Request', {'error':'invalid_json'})
                gid = positive_id(obj.get('guild_id'))
                tid = positive_id(obj.get('ticket_id'))
                uid = positive_id(obj.get('issued_to'))
                if not all((gid,tid,uid)):
                    return self.json_reply(start_response,'400 Bad Request', {'error':'invalid_id'})
                token = self.store.create_link(gid,tid,uid)
                if not token:
                    return self.json_reply(start_response,'404 Not Found', {'error':'not_found'})
                return self.json_reply(start_response,'201 Created', {'url':self.base_url+'/t/'+token,
                                                                     'expires_in':LINK_LIFETIME})
            return self.json_reply(start_response,'405 Method Not Allowed',{'error':'unsupported_method'})
        except UnicodeDecodeError:
            return self.json_reply(start_response,'400 Bad Request',{'error':'utf8_required'})
        except Exception:
            LOG.exception('Request failed path=%s method=%s', path[:40], method)
            return self.json_reply(start_response,'503 Service Unavailable',{'error':'service_unavailable'})


from staff_web import StaffWeb

app = StaffWeb(PortalApp())
