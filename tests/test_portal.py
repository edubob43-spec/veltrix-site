import hashlib
import io
import json
import os
import secrets
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import PortalApp, LINK_LIFETIME, public_base


class FakeStore:
    def __init__(self):
        self.docs = {}
        self.links = {}
        self.calls = 0
    def ping(self): return True
    def save(self, guild_id,ticket_id,content):
        self.docs[(guild_id,ticket_id)] = content
        return True
    def exists(self,guild_id,ticket_id):
        return (guild_id,ticket_id) in self.docs
    def create_link(self,guild_id,ticket_id,uid):
        if not self.exists(guild_id,ticket_id): return None
        token=secrets.token_urlsafe(36)
        self.links[token] = (guild_id,ticket_id,uid,int(time.time())+LINK_LIFETIME)
        return token
    def resolve(self,token):
        link=self.links.get(token)
        if link and link[3]>time.time():
            return self.docs.get(link[:2])
        return None


class WSGITests(unittest.TestCase):
    def setUp(self):
        self.store=FakeStore()
        self.key='K'*48
        self.app=PortalApp(self.store,api_key=self.key,base_url='https://veltrix-tickets.onrender.com')

    def call(self,method,path,body=b'',authorized=False,headers=None):
        env={'REQUEST_METHOD':method,'PATH_INFO':path,'CONTENT_LENGTH':str(len(body)),
             'wsgi.input':io.BytesIO(body)}
        if authorized: env['HTTP_AUTHORIZATION']='Bearer '+self.key
        if headers: env.update(headers)
        captured={}
        def start(status,header_list):
            captured['status']=int(status.split(' ')[0]);captured['headers']=dict(header_list)
        response=b''.join(self.app(env,start))
        return captured['status'],response,captured['headers']

    def test_home_public_but_doesnt_list_tickets(self):
        status,body,hdr=self.call('GET','/')
        self.assertEqual(status,200)
        self.assertIn(b'Veltrix Tickets',body)
        self.assertNotIn(b'/api/v1/documents',body)

    def test_requires_bearer(self):
        code,body,_=self.call('GET','/api/v1/documents/1/5')
        self.assertEqual(code,401)
        code,_,_=self.call('GET','/api/v1/documents/1/5',headers={'HTTP_AUTHORIZATION':'Bearer wrong'})
        self.assertEqual(code,401)

    def test_complete_upload_and_private_link_flow(self):
        content=b'<!DOCTYPE html><html lang="pt-BR"><body>Ticket #5 privado</body></html>'
        headers={'HTTP_X_VELTRIX_GUILD_ID':'4','HTTP_X_VELTRIX_TICKET_ID':'5'}
        code,body,_=self.call('POST','/api/v1/documents',content,True,headers)
        self.assertEqual(code,201)
        self.assertEqual(self.store.docs[(4,5)],content)
        code,body,_=self.call('GET','/api/v1/documents/4/5',authorized=True)
        self.assertEqual(code,200)
        self.assertTrue(json.loads(body)['exists'])
        obj=json.dumps({'guild_id':4,'ticket_id':5,'issued_to':123}).encode()
        code,body,_=self.call('POST','/api/v1/links',obj,True)
        self.assertEqual(code,201)
        url=json.loads(body)['url']
        self.assertTrue(url.startswith('https://veltrix-tickets.onrender.com/t/'))
        code,rendered,headers=self.call('GET','/t/'+url.rsplit('/',1)[-1])
        self.assertEqual(code,200)
        self.assertEqual(rendered,content)
        self.assertEqual(headers['Cache-Control'],'private, no-store, max-age=0')
        self.assertIn("script-src 'none'",headers['Content-Security-Policy'])

    def test_missing_document_cannot_create_link(self):
        obj=json.dumps({'guild_id':4,'ticket_id':5,'issued_to':123}).encode()
        code,_,_=self.call('POST','/api/v1/links',obj,True)
        self.assertEqual(code,404)

    def test_expired_and_forged_links(self):
        token='X'*48
        self.store.links[token]=(4,5,123,int(time.time())-1)
        self.store.docs[(4,5)]=b'<html></html>'
        code,_,_=self.call('GET','/t/'+token)
        self.assertEqual(code,404)
        code,_,_=self.call('GET','/t/'+'A'*48)
        self.assertEqual(code,404)
        code,_,_=self.call('GET','/t/../etc')
        self.assertEqual(code,404)

    def test_guild_isolation(self):
        self.store.save(4,5,b'<html>guild 4</html>')
        code,body,_=self.call('GET','/api/v1/documents/6/5',authorized=True)
        self.assertEqual(code,200)
        self.assertFalse(json.loads(body)['exists'])

    def test_validation_and_big_documents(self):
        code,_,_=self.call('POST','/api/v1/documents',b'not html',True,
                          {'HTTP_X_VELTRIX_GUILD_ID':'4','HTTP_X_VELTRIX_TICKET_ID':'5'})
        self.assertEqual(code,400)
        code,_,_=self.call('POST','/api/v1/documents',b'<!doctype html>'+b'X'*5800000,True,
                          {'HTTP_X_VELTRIX_GUILD_ID':'4','HTTP_X_VELTRIX_TICKET_ID':'5'})
        self.assertEqual(code,400)
        code,_,_=self.call('POST','/api/v1/documents',b'<!doctype html>',True,
                          {'HTTP_X_VELTRIX_GUILD_ID':'4','HTTP_X_VELTRIX_TICKET_ID':'-1'})
        self.assertEqual(code,400)

    def test_unconfigured_cannot_accept_uploads(self):
        app=PortalApp(FakeStore(),api_key='',base_url='')
        self.assertFalse(app.configured)
        env={'REQUEST_METHOD':'GET','PATH_INFO':'/health'}
        observed={}
        body=b''.join(app(env, lambda s,h: observed.update(status=s)))
        self.assertTrue(observed['status'].startswith('503'))

    def test_public_base_rejects_unsafe_url(self):
        for url in ('http://domain.com','https://user:pw@domain.com','https://localhost',
                    'https://domain.com/path','https://domain.com?next=x'):
            self.assertFalse(public_base(url))

    def test_health(self):
        status,body,_=self.call('GET','/health')
        self.assertEqual(status,200)
        self.assertEqual(json.loads(body)['ok'],True)


if __name__=='__main__': unittest.main()
