import importlib.util
import os
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from fastapi.testclient import TestClient
from common import security

ROOT = Path(__file__).resolve().parents[1]

class SecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        cls.pub=cls.key.public_key()
        cls.app=FastAPI(docs_url=None,openapi_url=None)
        security.protect(cls.app,lambda req:'orders.read' if req.method=='GET' else 'orders.write')
        @cls.app.get('/orders')
        def orders():return {'ok':True}
        cls.client=TestClient(cls.app)
        cls.patch=patch.object(security.jwks_client,'get_signing_key_from_jwt',return_value=SimpleNamespace(key=cls.pub));cls.patch.start()
    @classmethod
    def tearDownClass(cls):cls.patch.stop()
    def token(self,scope='orders.read',**changes):
        now=int(time.time()); claims={'iss':security.ISSUER,'aud':security.AUDIENCE,'sub':'student','iat':now,'exp':now+120,'typ':'Bearer','scope':scope};claims.update(changes)
        return jwt.encode(claims,self.key,algorithm='RS256')
    def get(self,token=None,origin=None):
        h={};
        if token:h['Authorization']='Bearer '+token
        if origin:h['Origin']=origin
        return self.client.get('/orders',headers=h)
    def test_missing_token_401_with_cors(self):
        r=self.get(origin='https://cad.kpi.ua');self.assertEqual(r.status_code,401);self.assertEqual(r.headers.get('access-control-allow-origin'),'https://cad.kpi.ua')
    def test_valid_scope(self):self.assertEqual(self.get(self.token()).status_code,200)
    def test_missing_scope_403(self):self.assertEqual(self.get(self.token('reports.read')).status_code,403)
    def test_bad_issuer_audience_expiration_and_type(self):
        for kw in ({'iss':'http://evil'},{'aud':'other'},{'exp':int(time.time())-60},{'typ':'ID'}):
            with self.subTest(kw=kw):self.assertEqual(self.get(self.token(**kw)).status_code,401)
    def test_invalid_signature(self):
        claims=jwt.decode(self.token(),options={'verify_signature':False}); other=rsa.generate_private_key(public_exponent=65537,key_size=2048); token=jwt.encode(claims,other,algorithm='RS256');self.assertEqual(self.get(token).status_code,401)
    def test_preflight_permitted_and_rejected(self):
        h={'Origin':'https://cad.kpi.ua','Access-Control-Request-Method':'GET','Access-Control-Request-Headers':'authorization'}
        r=self.client.options('/orders',headers=h);self.assertEqual(r.status_code,200);self.assertEqual(r.headers.get('access-control-allow-origin'),'https://cad.kpi.ua')
        h['Origin']='https://untrusted.example';r=self.client.options('/orders',headers=h);self.assertEqual(r.status_code,400);self.assertNotIn('access-control-allow-origin',r.headers)
    def test_actual_order_endpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            old=os.environ.get('ORDER_DB_PATH');os.environ['ORDER_DB_PATH']=str(Path(tmp)/'test.sqlite')
            try:
                spec=importlib.util.spec_from_file_location('lab5_order_app',ROOT/'order-sample-service/app.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);module.init_db()
                c=TestClient(module.app)
                self.assertEqual(c.get('/orders/by-barcode/CODE128-1001').status_code,401)
                self.assertEqual(c.get('/orders/by-barcode/CODE128-1001',headers={'Authorization':'Bearer '+self.token('reports.read')}).status_code,403)
                r=c.get('/orders/by-barcode/CODE128-1001',headers={'Authorization':'Bearer '+self.token()});self.assertEqual(r.status_code,200);self.assertEqual(r.json()['order']['barcode'],'CODE128-1001')
            finally:
                if old is None:os.environ.pop('ORDER_DB_PATH',None)
                else:os.environ['ORDER_DB_PATH']=old
if __name__=='__main__': unittest.main()
