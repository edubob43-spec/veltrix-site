import io
import json
import os
import sys
import unittest
from pathlib import Path
from urllib.parse import urlencode
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from staff_web import StaffWeb, hid, can_manage
from app import PortalApp

class FakeStore:
    def ping(self): return True
class FakeDB:
    def __init__(self):self.change=None
    def session(self,sid):return self.staff if sid=='testsessionABC234567890' else None
    def guild(self,gid):
        if gid!=100:return None
        return {'name':'Serv & Cia','channels':[{'id':900,'name':'logs-staff'}],
                'settings':{'enabled':True,'include_content':False,'routes':{'mensagens':900},'events':{}},
                'last_seen':__import__('time').time()}
    def recent(self,gid):return []
    def enqueue(self,gid,actor,action,params):self.change=(gid,actor,action,params)
    def sync(self,items):self.items=items
    def pending(self,ids):return [{'id':4,'guild_id':100,'actor_id':42,'action':'route','params':{'group':'mensagens','channel_id':900}}]
    def ack(self,id,good,reason):self.ack_data=(id,good,reason)

class StaffTests(unittest.TestCase):
    def setUp(self):
        self.key='A'*48
        core=PortalApp(FakeStore(),api_key=self.key,base_url='https://veltrix-tickets.onrender.com')
        self.app=StaffWeb(core)
        self.app.oauth_ready=True
        self.app.db=FakeDB()
        self.csrf='csrfTokenForTest1234567890abcdef'
        self.app.db.staff={'username':'Edu <admin>','user_id':42,
            'guilds':[{'id':100,'name':'Nome <script>'}], 'csrf_hash':hid(self.csrf)}

    def request(self,method,path,form=None,cookie=None,auth=None,origin=None):
        data=urlencode(form).encode() if form else b''
        env={'REQUEST_METHOD':method,'PATH_INFO':path,'CONTENT_LENGTH':str(len(data)),
             'wsgi.input':io.BytesIO(data)}
        if cookie:env['HTTP_COOKIE']=cookie
        if auth:env['HTTP_AUTHORIZATION']='Bearer '+auth
        if origin:env['HTTP_ORIGIN']=origin
        cap={}
        def sr(status,headers):cap['status']=int(status[:3]);cap['headers']=dict(headers)
        response=b''.join(self.app(env,sr))
        return cap['status'],response,cap['headers']

    def test_no_session_asks_for_discord(self):
        status,body,_=self.request('GET','/staff')
        self.assertEqual(status,200)
        self.assertIn(b'Entrar com Discord',body)

    def test_guild_requires_session_and_permissions(self):
        status,_,_=self.request('GET','/staff/g/100')
        self.assertEqual(status,200) # login screen, not settings
        self.assertEqual(self.request('GET','/staff/g/200',cookie='vxstaff=testsessionABC234567890')[0],403)
        status,body,_=self.request('GET','/staff/g/100',cookie='vxstaff=testsessionABC234567890; vxcsrf='+self.csrf)
        self.assertEqual(status,200)
        self.assertNotIn(b'<script>',body)
        self.assertIn(b'logs-staff',body)

    def test_csrf_and_origin(self):
        cookie='vxstaff=testsessionABC234567890; vxcsrf='+self.csrf
        form={'action':'route','group':'mensagens','channel_id':'900','csrf':self.csrf}
        self.assertEqual(self.request('POST','/staff/g/100/save',form,cookie,origin='https://evil.net')[0],403)
        bad=dict(form,csrf='forged')
        self.assertEqual(self.request('POST','/staff/g/100/save',bad,cookie)[0],403)
        invalid=dict(form,channel_id='901')
        self.assertEqual(self.request('POST','/staff/g/100/save',invalid,cookie)[0],400)
        self.assertFalse(self.app.db.change)
        status,_,_=self.request('POST','/staff/g/100/save',form,cookie,origin=self.app.base)
        self.assertEqual(status,302)
        self.assertEqual(self.app.db.change,(100,42,'route',{'group':'mensagens','channel_id':900}))

    def test_bot_api_auth(self):
        payload=json.dumps({'guild_ids':[100]}).encode()
        env={'REQUEST_METHOD':'POST','PATH_INFO':'/api/v1/staff/queue',
             'CONTENT_LENGTH':str(len(payload)),'wsgi.input':io.BytesIO(payload)}
        def run(auth):
            e=dict(env)
            e['wsgi.input']=io.BytesIO(payload)
            if auth:e['HTTP_AUTHORIZATION']='Bearer '+auth
            cap={}
            data=b''.join(self.app(e,lambda s,h:cap.update(status=int(s[:3]))))
            return cap['status'],json.loads(data)
        self.assertEqual(run(None)[0],401)
        code,response=run(self.key)
        self.assertEqual(code,200)
        self.assertEqual(response['changes'][0]['actor_id'],42)

    def test_discord_permission_bits(self):
        self.assertTrue(can_manage('32'))
        self.assertTrue(can_manage('8'))
        self.assertFalse(can_manage('0'))
        self.assertFalse(can_manage('garbage'))

if __name__=='__main__':unittest.main()
