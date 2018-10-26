#!/usr/bin/env python3.6
import requests
import random
import string
from pprint import pprint

somestring = ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))
test_domain = somestring + '.com'

def auth(email, domain, type_req, url='http://192.168.158.86:8001/rest/reg/'):
  data = {
    'email': email,
    'domain': domain,
    'type_req': type_req
  }
  r = requests.post(url, data)
  res = r.json()
  return res

def verify(email, domain, type_req, url='http://192.168.158.86:8001/rest/verify/'):
  data = {
    'email': email,
    'domain': domain,
    'type_req': type_req
  } 
  r = requests.post(url, data)
  res = r.json()
  return res

if __name__ == '__main__':
  pass
