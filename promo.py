import requests
import time
import secrets
import sslspoof
import asyncio
import websockets
import logging
import json
import re
import string
import time
import sys
from collections import OrderedDict
from colorama import Back, Fore, Style, init

DEBUG = True

API_HOST = sys.argv[1]
CLEARANCE_URL = f"http://{API_HOST}/clearance"
MAIL_URL = sys.argv[2]
MAIL_DOMAIN = sys.argv[3]
PROXY_HOST = sys.argv[4]
PROXY_PASSWORD = sys.argv[5]

init()

logging.addLevelName( logging.WARNING, Back.YELLOW + logging.getLevelName(logging.WARNING) + Style.RESET_ALL)
logging.addLevelName( logging.ERROR, Back.RED + logging.getLevelName(logging.ERROR) + Style.RESET_ALL)
logging.addLevelName( logging.INFO, Fore.CYAN + logging.getLevelName(logging.INFO) + Style.RESET_ALL)

def error_hook(exctype, value, traceback):
    if exctype == CloudflareRatelimit:
        logging.error("Cloudflare ratelimit: %s", value)
    elif exctype == CloudflareAccessDenied:
        logging.error("Cloudflare access denied: %s", value)
    else:
        sys.__excepthook__(exctype, value, traceback)
sys.excepthook = error_hook

if DEBUG:
  logging.basicConfig(
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
    level=logging.INFO,
  )

start = time.time()

session = requests.session()
sslspoof.apply_session(session)

clearances = list(requests.get(CLEARANCE_URL).json().items())
if len(clearances) == 0:
  logging.error("No cloudflare tokens available!")
  exit(3)
  
clearance = clearances[0]

session.headers = OrderedDict({
    'Accept-Encoding': 'gzip, deflate, br',
    'User-Agent': clearance[1]["user_agent"],
})

session.cookies.set("cf_clearance", clearance[1]["cookie"])
def set_proxy_ip(ip):
  ip = ip.replace(":", "%3A")
  session.proxies.update({"https":"http://" + ip + f":{PROXY_PASSWORD}@{PROXY_HOST}"})
def set_random_ip():
  set_proxy_ip(f"2a10:cc46:19{secrets.token_hex(1)}:{secrets.token_hex(2)}:{secrets.token_hex(2)}:{secrets.token_hex(2)}:{secrets.token_hex(2)}:{secrets.token_hex(2)}")
  
set_proxy_ip(clearance[0])

mail = str(int(time.time())) + '@' + MAIL_DOMAIN
password = ''.join(secrets.choice(string.ascii_uppercase + string.ascii_lowercase + string.punctuation) for i in range(8))

# step 1 - register account
reg = session.post(
  'https://accounts.steelseries.com/register',
  json={
      'email': mail,
      'password': password,
      'password_confirm': password,
      'subscribe_to_newsletter': True,
      'accepted_privacy_policy': True,
  },
)

class CloudflareAccessDenied(Exception):
    def __init__(self, message):
      requests.delete(CLEARANCE_URL, json={"ip": clearance[0]})
      super().__init__(message)
    
class CloudflareRatelimit(Exception):
    def __init__(self, message):
      requests.delete(CLEARANCE_URL, json={"ip": clearance[0]})
      super().__init__(message)
    
if reg.status_code != 204:
  if "<title>Captcha | SteelSeries</title>" in reg.text:
    raise CloudflareAccessDenied("Registration failed")
  else:
    logging.warn("Unknown error detected")
  exit(2)
  
# step 2 - verify mail
def handle_mailbox_response(message):
  if message['to'] != mail:
    logging.info("Target mail doesnt match: %s -> %s", message['to'],mail)
    return True
  
  link = re.findall(r"https:\/\/accounts\.steelseries\.com\/verify\?token=.{256}", message['content'])[0]
  logging.debug(link)
  
  mailek = session.get(link)
  if mailek.status_code != 200:
    if "<title>Captcha | SteelSeries</title>" in mailek.text:
      raise CloudflareAccessDenied(f"Mail verification failed ({mailek.status_code})")
  if mailek.status_code == 429:
    raise CloudflareRatelimit("Mail verification ratelimit")
  get_promo_link()
  return False
    
# step 3 - get discord promo link
def get_promo_link():
  register = session.post('https://steelseries.com/oauth2/token', headers={
    "Authorization": 'Basic OThlNTQ1NWE5ZjY4MGM5YTVmZDcwNjo='
  }, data={"password":password,"username":mail,"grant_type":"password"})
  if 'access_token' not in register.text:
    raise Exception('Failed to login')
  access_token = register.json()['access_token']
  
  user_profile = session.get('https://steelseries.com/api/profile', headers={
   'User-Agent': 'SteelSeries GG/29.2.0 (os=Windows 10; version=10.0.19042; arch=amd64)',
   'Authorization': 'Bearer ' + access_token
  }).json()
  
  logging.debug(access_token)
  resp = session.post('https://steelseries.com/api/v1/promos/discordnitrodec2022', headers={
   'User-Agent': 'SteelSeries GG/29.2.0 (os=Windows 10; version=10.0.19042; arch=amd64)',
   'Authorization': 'Bearer ' + access_token
  }, json={'uuid': user_profile['id']})
  if "1015" in resp.text:
    logging.info("Cf ratelimit when getting promo, trying to bypass...")
    set_random_ip()
    resp = session.post('https://steelseries.com/api/v1/promos/discordnitrodec2022', headers={
      'User-Agent': 'SteelSeries GG/29.2.0 (os=Windows 10; version=10.0.19042; arch=amd64)',
      'Authorization': 'Bearer ' + access_token
    }, json={'uuid': user_profile['id']})
    
  resp = resp.json()
  if 'promo_code_url' not in resp:
    raise Exception("couldnt get promo, maybe the mail wasnt verified")
  else:
    logging.info("got promo: %s in %.2fs", resp['promo_code_url'], time.time() - start)
    with open('promos.txt', 'a') as file:
      file.write(resp['promo_code_url'] + "\n")
  exit(0)

async def handle_mailbox():
    async with websockets.connect(MAIL_URL) as websocket:
      while handle_mailbox_response(json.loads(await websocket.recv())):
        pass
          
asyncio.run(handle_mailbox())