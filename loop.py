import os

PROXY_HOST = "ssh.grupahakerskapiotr.us:2139"
PROXY_PASSWORD = "dorgproxy420"
API_HOST = "mail.rozpierdalacz.pl:8000"
MAIL_URL = "ws://mail.rozpierdalacz.pl:2137"
MAIL_DOMAIN = "rozpierdalacz.pl"

for i in range(0, 100):
  ret = os.system(f'python promo.py {API_HOST} {MAIL_URL} {MAIL_DOMAIN} {PROXY_HOST} {PROXY_PASSWORD}')
  if ret == 3:
    os.system(f'python cloudflare.py -u https://accounts.steelseries.com/verify?token=sex -p {PROXY_HOST} -pa {PROXY_PASSWORD} -a {API_HOST} -d -v')