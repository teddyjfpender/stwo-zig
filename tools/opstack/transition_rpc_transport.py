"""Explicitly owned, per-thread HTTP keepalive for bounded capture RPC only."""
import http.client
import ssl
import threading
import urllib.parse
import weakref

import transition_capture as C


class _Owner:
    def __init__(self):self.connection=None
    def close(self):
        if self.connection is not None:
            self.connection.close();self.connection=None
    def __del__(self):self.close()


class PooledRpc:
    def __init__(self,url):
        C.endpoint_label(url)
        self.url=url;self.parsed=urllib.parse.urlsplit(url)
        self.local=threading.local();self.lock=threading.Lock();self.owners=weakref.WeakSet();self.closed=False
        self.connections_created=0;self.requests=0
    def _owner(self):
        with self.lock:
            if self.closed:raise C.RpcFailure('transport_retired')
            owner=getattr(self.local,'owner',None)
            if owner is None:
                owner=_Owner();self.local.owner=owner;self.owners.add(owner)
            return owner
    def request(self,url,payload,cap,timeout):
        if url!=self.url or cap<1 or timeout<=0:raise ValueError('RPC pool endpoint or bound mismatch')
        owner=self._owner();p=self.parsed
        if owner.connection is None:
            if p.scheme=='https':owner.connection=http.client.HTTPSConnection(p.hostname,p.port,timeout=timeout,context=ssl.create_default_context())
            else:owner.connection=http.client.HTTPConnection(p.hostname,p.port,timeout=timeout)
            with self.lock:self.connections_created+=1
        conn=owner.connection;conn.timeout=timeout
        if conn.sock is not None:conn.sock.settimeout(timeout)
        target=p.path or '/'
        if p.query:target+='?'+p.query
        response=None
        try:
            conn.request('POST',target,body=payload,headers={'Content-Type':'application/json'})
            response=conn.getresponse();status=None if 200<=response.status<300 else response.status
            data=response.read(cap+1)
            with self.lock:self.requests+=1
            if len(data)>cap:
                owner.close();raise C.RpcFailure('response_byte_cap',status)
            if response.will_close:owner.close()
            return status,data
        except (OSError,TimeoutError,http.client.HTTPException)as error:
            owner.close();raise C.RpcFailure('transport_unavailable')from error
        finally:
            if response is not None:response.close()
    def close(self):
        with self.lock:
            self.closed=True;owners=list(self.owners)
        for owner in owners:owner.close()
    def __enter__(self):return self
    def __exit__(self,*_):self.close()
