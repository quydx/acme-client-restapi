#!/usr/bin/env python3.6
import os 
import time
import timeout_decorator
import requests 
import redis 
from multiprocessing import Process

rds = redis.StrictRedis(host='127.0.0.1', port=6379, db=0)

@timeout_decorator.timeout(30)
def check_result():
  """
  Check response from cdn portal utils get pass response
  """
  print('Wait for customer fill dns txt')
  while True:
    #request to cdn api to check response
    time.sleep(1)
    print('A sec is gone')
    #res = requests.get('http://192.168.158.86:8000/rest/res/').json()
    #  print(r)
    #if res is ok, break
    #if res == 1:
      #  break

def get_env():
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
	'cert_path': os.environ.get('CERTBOT_CERT_PATH'),
	'key_path': os.environ.get('CERTBOT_KEY_PATH'),
    }
    env['challenge_key'] = '_acme-challenge.' + env['domain'] 
  except ValueError:
    print("Fail to get variable environments")
  print('all env is :')
  print(env)
  return env


env = get_env()
rds.hmset(env['domain'], env)
print('Set key '+ env['domain'] + 'in redis.')
p1 = Process(target=check_result)
p1.start()

#check_result()

