"""Keepalive ownership/reconnect/read-bound tests use a local anonymous RPC."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
import time
import unittest
sys.path.insert(0,str(Path(__file__).parents[1]))
import transition_capture as C
from transition_rpc_transport import PooledRpc


@contextmanager
def server():
    class Server(ThreadingHTTPServer):
        accepts=0
        def get_request(self):
            result=super().get_request();self.accepts+=1;return result
    class Handler(BaseHTTPRequestHandler):
        protocol_version='HTTP/1.1'
        def log_message(self,*_):pass
        def do_POST(self):
            req=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            mode=req['params'][0]if req['params']else 'ok'
            raw=json.dumps({'jsonrpc':'2.0','id':1,'result':'0xa'}).encode()
            if mode=='big':raw=json.dumps({'id':1,'result':'x'*1024}).encode()
            if mode=='bad':raw=b'not JSON'
            if mode=='wrong-id':raw=json.dumps({'id':2,'result':'0xa'}).encode()
            if mode=='rpc-error':raw=json.dumps({'id':1,'error':{'code':-32603,'message':'Internal error'}}).encode()
            self.send_response(200);self.send_header('Content-Length',str(len(raw)))
            if mode=='close':self.send_header('Connection','close');self.close_connection=True
            self.end_headers()
            if mode=='slow':time.sleep(.1)
            try:self.wfile.write(raw)
            except(BrokenPipeError,ConnectionResetError):pass
    s=Server(('127.0.0.1',0),Handler);thread=threading.Thread(target=s.serve_forever,daemon=True);thread.start()
    try:yield s,f'http://127.0.0.1:{s.server_port}'
    finally:s.shutdown();s.server_close();thread.join()


class PoolTests(unittest.TestCase):
    def test_reuses_connection_and_reconnects_after_close(self):
        with server()as(s,url),PooledRpc(url)as pool:
            for _ in range(3):self.assertEqual(C.rpc(url,'eth_chainId',[],transport=pool),'0xa')
            self.assertEqual(pool.connections_created,1);self.assertEqual(s.accepts,1)
            C.rpc(url,'eth_chainId',['close'],transport=pool)
            C.rpc(url,'eth_chainId',[],transport=pool)
            self.assertEqual(pool.connections_created,2)
        with self.assertRaises(C.RpcFailure):C.rpc(url,'eth_chainId',[],transport=pool)
    def test_same_parser_rejects_invalid_and_oversized_responses(self):
        with server()as(_,url),PooledRpc(url)as pool:
            for mode,status in [('bad','non_json_response'),('wrong-id','invalid_rpc_response'),('rpc-error','rpc_error')]:
                with self.assertRaises(C.RpcFailure)as error:C.rpc(url,'eth_chainId',[mode],transport=pool)
                self.assertEqual(error.exception.report['status'],status)
            with self.assertRaises(C.RpcFailure)as error:C.rpc(url,'eth_chainId',['big'],cap=64,transport=pool)
            self.assertEqual(error.exception.report['status'],'response_byte_cap')
            self.assertEqual(C.rpc(url,'eth_chainId',[],transport=pool),'0xa')
            self.assertEqual(pool.connections_created,2)
    def test_read_timeout_updates_reused_socket(self):
        with server()as(_,url),PooledRpc(url)as pool:
            C.rpc(url,'eth_chainId',[],timeout=1,transport=pool)
            with self.assertRaises(C.RpcFailure)as error:C.rpc(url,'eth_chainId',['slow'],timeout=.01,transport=pool)
            self.assertEqual(error.exception.report['status'],'transport_unavailable')
    def test_threads_own_independent_connections(self):
        with server()as(_,url),PooledRpc(url)as pool:
            barrier=threading.Barrier(2)
            def work(_):
                barrier.wait()
                return [C.rpc(url,'eth_chainId',[],transport=pool)for _ in range(3)]
            with ThreadPoolExecutor(max_workers=2)as workers:results=list(workers.map(work,range(2)))
            self.assertEqual(results,[['0xa']*3]*2)
            self.assertEqual(pool.connections_created,2);self.assertEqual(pool.requests,6)


if __name__=='__main__':unittest.main()
