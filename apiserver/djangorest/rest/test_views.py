#from django.shortcuts import render
#from rest_framework.generics import (
#    ListCreateAPIView,
#    RetrieveUpdateDestroyAPIView,)
import json
#from django.http import HttpResponseRedirect, HttpResponse
#from certbot_utils import run_certbot
# Create your views here.
from multiprocessing import Process
import time
import redis
import string
#from django.views.decorators.csrf import csrf_exempt
rds = redis.StrictRedis(host='192.168.158.86', port=6379, db=0)

p_list = []


def test_get_token_for_domain():
    domains = ["quydx11.tk"]
    for domain in domains:
        print('Domain need generate certificates is '+ domain)
        #  run_certbot('*.testppdpp.com', 'rest/hooks/testhook.py')
        #file_hook = 'hooks/testhook_%s.py' % domain
        #p = Process(target=run_certbot, args=(domain, file_hook))
        #p_list.append(p)

        #p.start()

        #print('Number of process is {}'.format(len(p_list)))
        print('Run certbot command is started !')
        #chg = dict()
        for i in range(15):
            if rds.exists(domain):
                print('Getting key '+ domain + ' from redis')
                chg = rds.hgetall(domain)
                print(chg)
                break
            else:
                print('Key '+ domain + ' not existed')
                time.sleep(1)
                continue
        env = {}
        for key, val in chg.items():
            env[str(key)] = str(val)
        chg = env
        #p.join()
        res = rds.delete(domain)
        if res == 1:
            print('Deleted key '+ domain + 'in redis')
        else:
            print('delete {} in redis = {}'.format(domain, res))
        #time.sleep(5)
    #for one_process in p_list:
    #      one_process.join()

test_get_token_for_domain()
