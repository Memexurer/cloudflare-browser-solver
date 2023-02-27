import ssl
import requests

from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager 
from requests.packages.urllib3.util.ssl_ import create_urllib3_context, DEFAULT_CIPHERS

CIPHERS = DEFAULT_CIPHERS + "HIGH:!DH:!aNULL"

class TlsAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        context = create_urllib3_context(ciphers=CIPHERS)
        kwargs["ssl_context"] = context
        return super().init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, *args, **kwargs):
        context = create_urllib3_context(ciphers=CIPHERS)
        kwargs["ssl_context"] = context
        return super().proxy_manager_for(*args, **kwargs)
                                       
def apply_session(session: requests.Session):
    adapter = TlsAdapter()
    session.mount('https://', adapter)