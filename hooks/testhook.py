#!/usr/bin/env python3
import os 
import time 
import requests 



def check_result():
  """
  Check response from cdn portal utils o
  """
  while True:
    #request to cdn api to check response 

    #if res is ok, break
    

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
	'cert_apth': os.environ.get('CERTBOT_CERT_PATH'),
	'key_path': os.environ.get('CERTBOT_KEY_PATH'),
    }
    env['challenge_key'] = '_acme-challenge.' + env['domain'] 
  except ValueError:
    print("Fail to get variable environments")

  return env


env = get_env()
#  print(env)
# test pause the hook for completing verify task
#  for i in range(10):
#    print(i)
#    time.sleep(1)
check_result()

