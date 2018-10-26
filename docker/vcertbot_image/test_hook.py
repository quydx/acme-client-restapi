#!/usr/bin/python
import os 
import time
import timeout_decorator
#import requests 
import redis 
#from multiprocessing import Process

rds = redis.StrictRedis(host='192.168.158.86', port=6379, db=0)

#@timeout_decorator.timeout(30)

def check_result():
  """
  Check response from cdn portal utils get pass response
  """
  print('Wait for customer fill dns txt')
  counter = 0
  while True:
    #request to cdn api to check response
    time.sleep(2)
    print('A sec is gone')
    #res = requests.get('http://192.168.158.86:8000/rest/res/').json()
    #  print(r)
    #if res is ok, break
    #if res == 1:
      #  break
    if counter == 10:
         break
    counter += 1

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


#env = get_env()
print(os.environ.get('CERTBOT_TOKEN'))
print(os.environ.get('CERTBOT_VALIDATION'))
print(os.environ.get('CERTBOT_DOMAIN'))
env = get_env()
rds.hmset(env['domain'], env)
print('Set key '+ env['domain'] + 'in redis.')
#p1 = Process(target=check_result)
#p1.start()

check_result()
