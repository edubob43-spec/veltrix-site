"""Veltrix Staff: OAuth2-protected log administration for the existing ticket portal.

The Render service NEVER connects to Discord as the bot. It stores desired
changes, and the KataBump bot validates and applies them using its own guild
permissions. The existing /t/... transcript application is not modified.
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
from urllib.parse import urlencode, parse_qs, urlsplit
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

LOG=logging.getLogger('veltrix.staff')
GROUPS={
 'mensagens':'💬 Chat', 'moderacao':'🔨 Banimentos e punições',
 'membros':'👥 Membros', 'cargos':'🎭 Cargos',
 'canais':'📁 Canais', 'voz':'🎙️ Voz', 'todos':'📋 Todos os logs',
}
VALID_ACTIONS=('route','group_enabled','logging','content')
MANAGE_GUILD=0x20
ADMINISTRATOR=0x8
SESSION_AGE=3600
OAUTH_STATE_AGE=600


def hid(raw):
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()


def esc(text):
    return html.escape(str(text),quote=True)


def uid(value):
    try:
        val=str(value)
        if not val.isascii() or not val.isdecimal() or not 0<int(val)<2**63:
            return None
        return int(val)
    except (TypeError,ValueError):
        return None


def can_manage(value):
    try:
        flags=int(value)
        return bool(flags & (MANAGE_GUILD|ADMINISTRATOR))
    except (TypeError,ValueError):
        return False


def get_cookie(environ,name):
    values={}
    for pair in environ.get('HTTP_COOKIE','').split(';'):
        k,_,v=pair.strip().partition('=')
        values[k]=v
    value=values.get(name,'')
    return value if re.fullmatch(r'[A-Za-z0-9_-]{20,120}',value) else None


def form_body(environ):
    try:
        size=int(environ.get('CONTENT_LENGTH','0') or 0)
    except ValueError:
        return None
    if not 0<size<10000:
        return None
    raw=environ.get('wsgi.input',io.BytesIO()).read(size)
    if len(raw)!=size:
        return None
    try:
        return {k:v[0] for k,v in parse_qs(raw.decode('utf-8'),keep_blank_values=True).items()}
    except UnicodeDecodeError:
        return None


CSS='''<style>
:root{color-scheme:dark;font-family:system-ui,-apple-system,Segoe UI,Arial,sans-serif}
*{box-sizing:border-box}body{margin:0;background:#0c0d10;color:#ededf2;min-height:100vh}
header{padding:20px max(22px,calc((100vw - 1000px)/2));background:#16171c;border-bottom:1px solid #303039}
header a{color:inherit;text-decoration:none;font-weight:800;letter-spacing:-.02em}
main{max-width:1000px;margin:0 auto;padding:32px 22px 80px}
h1{font-size:clamp(26px,4vw,40px);margin:8px 0 12px}h2{font-size:20px}
p,.muted{color:#abb0bb;line-height:1.6}.sub{font-size:14px}
.panel{background:#191b22;border:1px solid #393c48;border-radius:17px;padding:22px;margin:18px 0}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(270px,1fr));gap:16px}
.group{background:#232630;border:1px solid #393c48;border-radius:12px;padding:18px}
label{display:block;font-weight:650;margin:8px 0}select{background:#11141b;border:1px solid #464958;border-radius:8px;color:#f8f8fa;padding:11px;width:100%;max-width:500px}
button,.btn{display:inline-block;background:#ececf3;color:#15151b;padding:10px 15px;border:0;border-radius:9px;font-size:14px;font-weight:750;cursor:pointer;text-decoration:none;margin:8px 5px 0 0}
.secondary{background:#393c47;color:#f4f4f6}.mutedbtn{background:#2f343e;color:#eee}
.flag{display:inline-block;background:#343743;border-radius:8px;padding:4px 9px;font-size:12px;color:#cbd0da}
.ok{color:#a7ebc3}.warning{color:#fbd48a}a{color:#b9bcff}
hr{border:0;border-top:1px solid #363946;margin:22px 0}
footer{text-align:center;color:#888d9a;margin-top:60px;font-size:12px}
</style>'''


def page(title,body):
    return ('''<!DOCTYPE html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>'''+esc(title)+''' · Veltrix</title>'''+CSS+'''</head><body><header><a href="/staff">🛡️ Veltrix • Staff</a></header><main>'''+body+'''<footer>Veltrix Staff • Painel protegido por Discord OAuth2 • Configurações executadas pelo bot</footer></main></body></html>''').encode('utf-8')


class StaffDB:
    def __init__(self,store):
        self.store=store
        self._ready=False

    def init(self):
        if self._ready: return
        with self.store._connect() as db:
            db.execute('''CREATE TABLE IF NOT EXISTS veltrix_staff_states (
                hash TEXT PRIMARY KEY, expires_at BIGINT NOT NULL)''')
            db.execute('''CREATE TABLE IF NOT EXISTS veltrix_staff_sessions (
                hash TEXT PRIMARY KEY, csrf_hash TEXT NOT NULL,
                user_id BIGINT NOT NULL, username TEXT NOT NULL,
                guilds_json TEXT NOT NULL, expires_at BIGINT NOT NULL)''')
            db.execute('''CREATE TABLE IF NOT EXISTS veltrix_staff_guilds (
                guild_id BIGINT PRIMARY KEY, guild_name TEXT NOT NULL,
                channels_json TEXT NOT NULL, settings_json TEXT NOT NULL,
                last_seen BIGINT NOT NULL)''')
            db.execute('''CREATE TABLE IF NOT EXISTS veltrix_staff_changes (
                id BIGSERIAL PRIMARY KEY, guild_id BIGINT NOT NULL, actor_id BIGINT NOT NULL,
                action TEXT NOT NULL, payload_json TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'pending',
                result TEXT, created_at BIGINT NOT NULL, finished_at BIGINT)''')
            db.execute('''CREATE INDEX IF NOT EXISTS veltrix_staff_changes_pending
                          ON veltrix_staff_changes(state,id)''')
        self._ready=True

    def state_new(self,token):
        self.init()
        now=int(time.time())
        with self.store._connect() as db:
            db.execute('DELETE FROM veltrix_staff_states WHERE expires_at < %s',(now,))
            db.execute('INSERT INTO veltrix_staff_states(hash,expires_at) VALUES(%s,%s)',(hid(token),now+OAUTH_STATE_AGE))

    def state_pop(self,token):
        self.init()
        with self.store._connect() as db:
            row=db.execute('''DELETE FROM veltrix_staff_states WHERE hash=%s AND expires_at>%s
                RETURNING hash''',(hid(token),int(time.time()))).fetchone()
            return bool(row)

    def session_new(self,user_id,username,guilds):
        self.init()
        sid=secrets.token_urlsafe(36)
        csrf=secrets.token_urlsafe(32)
        with self.store._connect() as db:
            db.execute('''INSERT INTO veltrix_staff_sessions(hash,csrf_hash,user_id,username,guilds_json,expires_at)
            VALUES(%s,%s,%s,%s,%s,%s)''',(hid(sid),hid(csrf),user_id,str(username)[:80],
                json.dumps(guilds),int(time.time())+SESSION_AGE))
        return sid,csrf

    def session(self,sid):
        self.init()
        if not sid: return None
        with self.store._connect() as db:
            row=db.execute('''SELECT csrf_hash,user_id,username,guilds_json FROM veltrix_staff_sessions
                WHERE hash=%s AND expires_at>%s''',(hid(sid),int(time.time()))).fetchone()
        if not row:return None
        return {'csrf_hash':row[0],'user_id':int(row[1]),'username':row[2],
                'guilds':json.loads(row[3])}

    def logout(self,sid):
        self.init()
        if sid:
            with self.store._connect() as db:
                db.execute('DELETE FROM veltrix_staff_sessions WHERE hash=%s',(hid(sid),))

    def sync(self,guilds):
        self.init()
        with self.store._connect() as db:
            for g in guilds:
                guild_id=uid(g.get('id'))
                if not guild_id: continue
                channels=g.get('channels') or []
                allowed=[]
                for c in channels[:550]:
                    channel_id=uid(c.get('id')) if isinstance(c,dict) else None
                    if channel_id and isinstance(c.get('name'),str):
                        allowed.append({'id':channel_id,'name':c['name'][:100]})
                settings=g.get('settings') if isinstance(g.get('settings'),dict) else {}
                db.execute('''INSERT INTO veltrix_staff_guilds(guild_id,guild_name,channels_json,settings_json,last_seen)
                  VALUES(%s,%s,%s,%s,%s) ON CONFLICT(guild_id) DO UPDATE SET
                  guild_name=EXCLUDED.guild_name,channels_json=EXCLUDED.channels_json,
                  settings_json=EXCLUDED.settings_json,last_seen=EXCLUDED.last_seen''',
                  (guild_id,str(g.get('name') or 'Servidor')[:100],json.dumps(allowed),
                   json.dumps(settings),int(time.time())))

    def guild(self,gid):
        self.init()
        with self.store._connect() as db:
            row=db.execute('''SELECT guild_name,channels_json,settings_json,last_seen
                FROM veltrix_staff_guilds WHERE guild_id=%s''',(gid,)).fetchone()
        if not row:return None
        return {'name':row[0],'channels':json.loads(row[1]),'settings':json.loads(row[2]),
                'last_seen':row[3]}

    def enqueue(self,gid,actor,action,params):
        self.init()
        with self.store._connect() as db:
            # Limit queued requests from stale/misbehaving browsers.
            count=db.execute('''SELECT count(*) FROM veltrix_staff_changes
              WHERE guild_id=%s AND state='pending' ''',(gid,)).fetchone()[0]
            if count>30: raise ValueError('Muitas alterações pendentes; aguarde o bot.')
            db.execute('''INSERT INTO veltrix_staff_changes(guild_id,actor_id,action,payload_json,created_at)
               VALUES(%s,%s,%s,%s,%s)''',(gid,actor,action,json.dumps(params),int(time.time())))

    def pending(self,guild_ids):
        self.init()
        guild_ids=[uid(x) for x in guild_ids]
        guild_ids=[x for x in guild_ids if x]
        if not guild_ids:return []
        with self.store._connect() as db:
            # Keep this query limited to currently connected bot guilds.
            rows=db.execute('''SELECT id,guild_id,actor_id,action,payload_json
              FROM veltrix_staff_changes WHERE state='pending' AND guild_id=ANY(%s)
              ORDER BY id LIMIT 25''',(guild_ids,)).fetchall()
        return [{'id':r[0],'guild_id':r[1],'actor_id':r[2],
                 'action':r[3],'params':json.loads(r[4])} for r in rows]

    def ack(self,change_id,success,result):
        self.init()
        with self.store._connect() as db:
            db.execute('''UPDATE veltrix_staff_changes SET state=%s,result=%s,finished_at=%s
              WHERE id=%s AND state='pending' ''',
              ('done' if success else 'denied',str(result or '')[:300],int(time.time()),int(change_id)))

    def recent(self,gid):
        self.init()
        with self.store._connect() as db:
            rows=db.execute('''SELECT action,state,result,created_at FROM veltrix_staff_changes
              WHERE guild_id=%s ORDER BY id DESC LIMIT 10''',(gid,)).fetchall()
        return rows


class StaffWeb:
    def __init__(self,transcripts):
        self.transcripts=transcripts
        self.db=StaffDB(transcripts.store) if transcripts.store else None
        self.base=transcripts.base_url
        self.client_id=os.getenv('DISCORD_CLIENT_ID','').strip()
        self.client_secret=os.getenv('DISCORD_CLIENT_SECRET','').strip()
        self.oauth_ready=(bool(self.db and self.client_id.isdigit() and
                               len(self.client_secret)>12 and self.base))

    def response(self,start,status,body=b'',content_type='text/html; charset=utf-8',extra=()):
        headers=[('Content-Type',content_type),('Content-Length',str(len(body))),
                 ('Cache-Control','no-store,private'),('X-Content-Type-Options','nosniff'),
                 ('X-Frame-Options','DENY'),('Referrer-Policy','no-referrer'),
                 ('X-Robots-Tag','noindex,nofollow'),
                 ('Content-Security-Policy',"default-src 'none'; style-src 'unsafe-inline'; "
                  "form-action 'self'; base-uri 'none'; frame-ancestors 'none'")]
        start(status,headers+list(extra))
        return [body]

    def redirect(self,start,url,extra=()):
        return self.response(start,'302 Found',b'',extra=[('Location',url),*extra])

    def failure(self,start,text,status='400 Bad Request'):
        return self.response(start,status,page('Erro',f'<h1>⚠️ {esc(text)}</h1><p><a href="/staff">Voltar ao painel</a></p>'))

    def discord_json(self,url,*,data=None,headers=None):
        req=Request(url,data=data,headers=headers or {},method='POST' if data else 'GET')
        with urlopen(req,timeout=15) as res:
            raw=res.read(300_000)
            return json.loads(raw.decode('utf-8'))

    def auth(self,environ):
        sid=get_cookie(environ,'vxstaff')
        return self.db.session(sid) if self.db else None

    def permitted(self,session,gid):
        return any(int(g['id'])==gid for g in session['guilds'])

    def _oauth_login(self,start):
        if not self.oauth_ready:
            return self.failure(start,'Configure DISCORD_CLIENT_ID e DISCORD_CLIENT_SECRET no Render.',
                                '503 Service Unavailable')
        state=secrets.token_urlsafe(32)
        self.db.state_new(state)
        params=urlencode({'client_id':self.client_id,'response_type':'code',
            'scope':'identify guilds', 'redirect_uri':self.base+'/staff/callback',
            'state':state,'prompt':'consent'})
        return self.redirect(start,'https://discord.com/oauth2/authorize?'+params)

    def _oauth_callback(self,environ,start):
        params=parse_qs(environ.get('QUERY_STRING',''))
        code=(params.get('code') or [''])[0]
        state=(params.get('state') or [''])[0]
        if not re.fullmatch(r'[A-Za-z0-9_-]{20,120}',state) or not self.db.state_pop(state):
            return self.failure(start,'Sessão de login inválida ou expirada.')
        if not code or len(code)>2048:
            return self.failure(start,'O Discord não autorizou o acesso.')
        form=urlencode({'client_id':self.client_id,'client_secret':self.client_secret,
            'grant_type':'authorization_code','code':code,
            'redirect_uri':self.base+'/staff/callback'}).encode('utf-8')
        token=self.discord_json('https://discord.com/api/v10/oauth2/token',data=form,
            headers={'Content-Type':'application/x-www-form-urlencoded'})
        access=token.get('access_token','')
        if not access:
            return self.failure(start,'Falha na autorização do Discord.')
        headers={'Authorization':'Bearer '+access}
        user=self.discord_json('https://discord.com/api/v10/users/@me',headers=headers)
        guilds=self.discord_json('https://discord.com/api/v10/users/@me/guilds',headers=headers)
        user_id=uid(user.get('id'))
        if not user_id or not isinstance(guilds,list):
            return self.failure(start,'Não consegui confirmar as permissões da conta.')
        allowed=[{'id':int(g['id']),'name':str(g.get('name','Servidor'))[:100]}
                 for g in guilds if isinstance(g,dict) and uid(g.get('id')) and
                 can_manage(g.get('permissions',0))]
        sid,csrf=self.db.session_new(user_id,user.get('global_name') or user.get('username') or 'Staff',allowed)
        cookie=('vxstaff='+sid+'; Path=/staff; Secure; HttpOnly; SameSite=Lax; Max-Age=3600')
        # CSRF secret is separate from the HTTP-only session cookie, and presented
        # as a signed-looking opaque form field in every POST.
        csrfcookie=('vxcsrf='+csrf+'; Path=/staff; Secure; SameSite=Strict; Max-Age=3600')
        return self.redirect(start,'/staff',extra=[('Set-Cookie',cookie),('Set-Cookie',csrfcookie)])

    def home(self,session,start):
        body='<h1>🛡️ Painel da Staff</h1><p>Olá, <strong>'+esc(session['username'])+'</strong>. Configure os logs dos servidores que você administra.</p>'
        body+='<div class="grid">'
        for g in session['guilds']:
            gid=int(g['id'])
            rec=self.db.guild(gid)
            if not rec:continue
            stale=int(time.time())-rec['last_seen']>300
            body+=('<div class="panel"><h2>'+esc(g['name'])+'</h2><span class="flag">'
                   +('Bot offline / sincronização atrasada' if stale else 'Bot conectado')+'</span>'
                   +'<p>Gerencie canais de logs, eventos e captura de mensagens.</p>'
                   +'<a class="btn" href="/staff/g/'+str(gid)+'">Configurar logs</a></div>')
        body+='</div>'
        if not any(self.db.guild(int(g['id'])) for g in session['guilds']):
            body+='<div class="panel"><p>Não há servidores sincronizados. Confira se a Veltrix V31.44 está ligada e conectada ao portal.</p></div>'
        body+='<p class="sub">Por segurança, alterações ficam pendentes até a Veltrix confirmar que você ainda é administrador.</p>'
        return self.response(start,'200 OK',page('Staff',body))

    def group_page(self,gid,session,start,environ):
        guild=self.db.guild(gid)
        if not guild:return self.failure(start,'Este servidor ainda não foi sincronizado pela Veltrix.','404 Not Found')
        cookie=get_cookie(environ,'vxcsrf') or ''
        if not hmac.compare_digest(hid(cookie),session['csrf_hash']):
            return self.failure(start,'Sessão sem token CSRF. Faça login novamente.','403 Forbidden')
        csrf='<input type="hidden" name="csrf" value="'+esc(cookie)+'">'
        settings=guild['settings'];routes=settings.get('routes',{})
        body='<p><a href="/staff">‹ Servidores</a></p><h1>📋 Logs · '+esc(guild['name'])+'</h1>'
        body+='<p>Escolha <strong>um canal privado para cada grupo</strong>. O bot aplica as configurações e mantém as regras antigas de segurança.</p>'
        if time.time()-guild['last_seen']>300:
            body+='<div class="panel warning">⚠️ O bot não sincroniza há mais de cinco minutos. Alterações podem ficar pendentes.</div>'
        logging_on=bool(settings.get('enabled'))
        content_on=bool(settings.get('include_content'))
        body+='<div class="panel"><h2>Configurações gerais</h2>'
        for action,title,on in [('logging','Sistema de logs',logging_on),('content','Conteúdo de mensagens editadas/apagadas',content_on)]:
            body+='<form method="POST" action="/staff/g/'+str(gid)+'/save">'+csrf
            body+='<input type="hidden" name="action" value="'+action+'"><input type="hidden" name="enabled" value="'+('0' if on else '1')+'">'
            body+='<p><b>'+esc(title)+'</b> • <span class="flag">'+('Ligado' if on else 'Desligado')+'</span></p>'
            body+='<button class="'+('secondary' if on else '')+'" type="submit">'+('Desativar' if on else 'Ativar')+'</button></form>'
        body+='</div><div class="grid">'
        for group,label in GROUPS.items():
            cats=[c for c in GROUPS if c!='todos'] if group=='todos' else [group]
            channel_id=routes.get(group)
            channel_name=next((c['name'] for c in guild['channels'] if c['id']==channel_id),'Não configurado')
            if group=='todos':
                channel_ids={routes.get(c) for c in GROUPS if c!='todos'}
                if len(channel_ids)==1 and None not in channel_ids:
                    channel_name=next((ch['name'] for ch in guild['channels'] if ch['id'] in channel_ids),'Canal configurado')
                elif len(channel_ids)>1:
                    channel_name='Canais diferentes por grupo'
            body+='<div class="group"><h2>'+esc(label)+'</h2>'
            body+='<p class="sub">Atual: <b>'+esc(channel_name)+'</b></p>'
            body+='<form method="POST" action="/staff/g/'+str(gid)+'/save">'+csrf
            body+='<input type="hidden" name="action" value="route"><input type="hidden" name="group" value="'+esc(group)+'">'
            body+='<label for="dest-'+group+'">Canal privado</label><select id="dest-'+group+'" name="channel_id" required>'
            body+='<option value="">Selecione...</option>'
            for c in guild['channels']:
                body+='<option value="'+str(c['id'])+'">#'+esc(c['name'])+'</option>'
            body+='</select><button type="submit">Aplicar ao grupo inteiro</button></form>'
            body+='<p class="sub">Aplicar também limpa destinos exclusivos anteriores deste grupo.</p>'
            if group!='todos':
                events=settings.get('events',{})
                total=sum(1 for ev,val in (settings.get('event_categories') or {}).items() if val==group)
                body+='<form method="POST" action="/staff/g/'+str(gid)+'/save">'+csrf
                body+='<input type="hidden" name="action" value="group_enabled"><input type="hidden" name="group" value="'+group+'">'
                body+='<button class="secondary" type="submit" name="enabled" value="1">Ativar todos</button>'
                body+='<button class="mutedbtn" type="submit" name="enabled" value="0">Desativar todos</button></form>'
            body+='</div>'
        body+='</div><div class="panel"><h2>Últimas alterações</h2>'
        for action,state,result,created in self.db.recent(gid):
            body+='<p class="sub"><span class="flag">'+esc(state)+'</span> '+esc(action)+' • '+esc(result or 'Aguardando Veltrix')+'</p>'
        body+='</div>'
        return self.response(start,'200 OK',page('Logs · '+guild['name'],body))

    def apply_form(self,gid,session,start,environ):
        origin=environ.get('HTTP_ORIGIN','')
        if origin and origin!=self.base:
            return self.failure(start,'Origem não autorizada.','403 Forbidden')
        form=form_body(environ)
        if not form:
            return self.failure(start,'Formulário inválido.')
        cookie=get_cookie(environ,'vxcsrf') or ''
        csrf=form.get('csrf','')
        if not csrf or not cookie or not hmac.compare_digest(cookie,csrf) or not hmac.compare_digest(hid(csrf),session['csrf_hash']):
            return self.failure(start,'Token de segurança inválido.','403 Forbidden')
        guild=self.db.guild(gid)
        if not guild or time.time()-guild['last_seen']>600:
            return self.failure(start,'A Veltrix precisa estar online e sincronizada antes de alterar configurações.')
        action=form.get('action')
        if action not in VALID_ACTIONS:return self.failure(start,'Ação inválida.')
        params={}
        if action in ('route','group_enabled'):
            group=form.get('group','')
            if group not in GROUPS:return self.failure(start,'Grupo inválido.')
            params['group']=group
        if action=='route':
            channel=uid(form.get('channel_id'))
            if channel is None or channel not in [c['id'] for c in guild['channels']]:
                return self.failure(start,'Selecione um canal privado válido.')
            params['channel_id']=channel
        else:
            if form.get('enabled') not in ('0','1'):
                return self.failure(start,'Valor inválido.')
            params['enabled']=form['enabled']=='1'
        self.db.enqueue(gid,session['user_id'],action,params)
        return self.redirect(start,'/staff/g/'+str(gid))

    def __call__(self,environ,start):
        path=environ.get('PATH_INFO','/')
        if not (path.startswith('/staff') or path.startswith('/api/v1/staff/')):
            return self.transcripts(environ,start)
        method=environ.get('REQUEST_METHOD','GET')
        try:
            if path.startswith('/api/v1/staff/'):
                if not self.transcripts.authenticate(environ):
                    return self.transcripts.json_reply(start,'401 Unauthorized',{'error':'unauthorized'})
                if method=='POST' and path=='/api/v1/staff/sync':
                    raw=self.transcripts.body(environ,175_000)
                    obj=json.loads(raw) if raw else None
                    if not isinstance(obj,dict) or not isinstance(obj.get('guilds'),list) or len(obj['guilds'])>100:
                        return self.transcripts.json_reply(start,'400 Bad Request',{'error':'invalid_sync'})
                    self.db.sync(obj['guilds'])
                    return self.transcripts.json_reply(start,'200 OK',{'ok':True})
                if method=='POST' and path=='/api/v1/staff/queue':
                    raw=self.transcripts.body(environ,20000)
                    obj=json.loads(raw) if raw else None
                    gids=obj.get('guild_ids') if isinstance(obj,dict) else None
                    if not isinstance(gids,list) or len(gids)>150:
                        return self.transcripts.json_reply(start,'400 Bad Request',{'error':'invalid_guilds'})
                    return self.transcripts.json_reply(start,'200 OK',{'changes':self.db.pending(gids)})
                if method=='POST' and path=='/api/v1/staff/ack':
                    raw=self.transcripts.body(environ,4000)
                    obj=json.loads(raw) if raw else None
                    if not isinstance(obj,dict) or not isinstance(obj.get('id'),int):
                        return self.transcripts.json_reply(start,'400 Bad Request',{'error':'invalid_ack'})
                    self.db.ack(obj['id'],bool(obj.get('ok')),obj.get('reason',''))
                    return self.transcripts.json_reply(start,'200 OK',{'ok':True})
                return self.transcripts.json_reply(start,'404 Not Found',{'error':'not_found'})
            if not self.oauth_ready:
                return self.response(start,'200 OK',page('Configuração pendente',
                    '<h1>🛡️ Painel Staff</h1><p>O portal de transcrições está no ar. Para ativar o painel da staff, configure <code>DISCORD_CLIENT_ID</code> e <code>DISCORD_CLIENT_SECRET</code> no Render e registre o redirect OAuth2.</p>'))
            if method=='GET' and path=='/staff/login':return self._oauth_login(start)
            if method=='GET' and path=='/staff/callback':return self._oauth_callback(environ,start)
            session=self.auth(environ)
            if not session:
                return self.response(start,'200 OK',page('Entrar',
                    '<h1>🛡️ Veltrix Staff</h1><p>Gerencie os logs com autenticação do Discord. O bot confere suas permissões antes de cada alteração.</p><a class="btn" href="/staff/login">Entrar com Discord</a>'))
            if method=='GET' and path in ('/staff','/staff/'):
                return self.home(session,start)
            match=re.fullmatch(r'/staff/g/(\d+)(/save)?',path)
            if match:
                gid=uid(match.group(1))
                if not gid or not self.permitted(session,gid):
                    return self.failure(start,'Você não tem Gerenciar Servidor neste servidor.','403 Forbidden')
                if method=='GET' and not match.group(2):
                    return self.group_page(gid,session,start,environ)
                if method=='POST' and match.group(2):
                    return self.apply_form(gid,session,start,environ)
            return self.failure(start,'Página não encontrada.','404 Not Found')
        except (HTTPError,URLError,TimeoutError):
            LOG.exception('Discord OAuth request failed')
            return self.failure(start,'Falha temporária na autorização com Discord. Tente novamente.','503 Service Unavailable')
        except Exception:
            LOG.exception('Staff portal request failed path=%s',path[:90])
            return self.failure(start,'Falha temporária no painel. Confira os logs do Render.','503 Service Unavailable')
