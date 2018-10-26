import os
import subprocess
from multiprocessing import Process


def get_cert_env():
  """
  Get all certbot env variables
  :return dict all certbot env 
  """
  try:
    env = {
      'token': os.environ.get('CERTBOT_TOKEN'),
      'validation': os.environ.get('CERTBOT_VALIDATION'),
      'domain': os.environ.get('CERTBOT_DOMAIN'),
      'sni': os.environ.get('CERTBOT_SNI_DOMAIN'),
      'cert_apth': os.environ.get('CERTBOT_CERT_PATH'),
      'key_path': os.environ.get('CERTBOT_KEY_PATH'),
    }
    #env['challenge_key'] = '_acme-challenge.' + env['domain'] if 'domain' in env else None 
  except ValueError:
    print("Fail to get variable environments")
  return env

def run_certbot(domain, hookfile):
  """
  Run certbot command in server 
  :param 
    domain (string) : domain to generate certificates
    hookfile (string) : path to hook file run with certbot
  :return None
  """
  cmd = '/root/certbot/certbot-auto  certonly --manual-public-ip-logging-ok\
      --manual --preferred-challenges dns\
      --manual-auth-hook {}\
      -d {} --noninteractive\
      --agree-tos --email quy196hp@gmail.com'.format(hookfile, domain)
  print(cmd)
  print('Run command generate certificates')
  args = cmd.split()
  print(args)
  FNULL = open(os.devnull, 'w')
  res  = subprocess.call(args, stdout=FNULL, stderr=subprocess.STDOUT)
  if res == 0:
    print('Cmd run successful')
  else:
    print('Cmd run failed')

