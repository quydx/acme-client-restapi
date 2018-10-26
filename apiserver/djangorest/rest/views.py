
from rest_framework.generics import (ListCreateAPIView, RetrieveUpdateDestroyAPIView,)
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import IsAuthenticated
from rest_framework import viewsets
from rest_framework import serializers
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate
from rest_framework.status import (
    HTTP_400_BAD_REQUEST,
    HTTP_404_NOT_FOUND,
    HTTP_200_OK
)
from rest_framework.renderers import JSONRenderer
from rest_framework.parsers import JSONParser
from django.shortcuts import render
from django.http import HttpResponseRedirect, HttpResponse, JsonResponse
from django.core.serializers.json import DjangoJSONEncoder
from django.forms.models import model_to_dict
import subprocess
import json
import time
from datetime import datetime
import string
import shutil
import os
from pprint import pprint
from django.views.decorators.csrf import csrf_exempt
from .models import Customer, Certificate
# from manuale.register import register
from OpenSSL.crypto import FILETYPE_PEM, load_privatekey, load_certificate
from manuale.crypto import (
    generate_rsa_key,
    load_private_key,
)
from pprint import pprint
from manuale.account import Account
from manuale.account import deserialize as deserialize_account
from manuale.issue import issue
from manuale.info import info
from manuale.revoke import revoke
from manuale.errors import ManualeError
from manuale.acme import Acme
import manuale
from .acme_custom.register import register
from .acme_custom.authorize import authorize, load_account, retrieve_verification
from .filelib import *
from .configs import *
from rest.serializers import ParamsSerializer

__version__ = '1.0'
DEFAULT_HEADERS = {
    'User-Agent': "manuale {} (https://github.com/veeti/manuale)".format(__version__),
}

LETS_ENCRYPT_PRODUCTION = "https://acme-v01.api.letsencrypt.org/"

DEFAULT_ACCOUNT_PATH = 'account.json'
DEFAULT_CERT_KEY_SIZE = 2048


ACCOUNT_STORE_FOLDER = '/usr/keyssl'

# global variable for store session infomation
auths = {}


def clear_domain_in_auths(email, domain):
  global auths
  print('clear domain {} in auths[{}]'.format(domain, email))
  if email in auths:
    if domain in auths[email]:
      auths[email].pop(domain, None)
    if not auths[email]:
      print('auths[{}] is empty, clear!'.format(email))
      auths.pop(email, None)
  print('keys in auths')
  print(auths.keys())
  

def get_cert_time(cert_path):
  crt = open(cert_path)
  result = load_certificate(FILETYPE_PEM, crt.read())
  crt.close()
  _from = datetime.strptime(result.get_notBefore().decode(), "%Y%m%d%H%M%SZ")
  _to = datetime.strptime(result.get_notAfter().decode(), "%Y%m%d%H%M%SZ")
  return (_from.strftime("%Y/%m/%d %H:%M:%S"), _to.strftime("%Y/%m/%d %H:%M:%S"))

def update_cert_model(email, domain):
  cert = Certificate.objects.filter(domain=domain)[0] 
  key_content = read_allfile(cert.key_path)
  cert_content = read_allfile(cert.cert_path)
  _from, _to = get_cert_time(cert.cert_path)
  cert.cert = cert_content
  cert.key = key_content
  cert.valid_in = _from 
  cert.expire_in = _to
  cert.save()

def gen_path(email, domain):
  email_dir = '{}/{}'.format(ACCOUNT_STORE_FOLDER, email)
  domain_key_file = '{}/{}.key'.format(email_dir, domain)
  crt_dir = '{}/{}'.format(email_dir, domain)
  account_json = '{}/{}.json'.format(email_dir, email)
  account_key = '{}/{}.key'.format(email_dir, email)
  crt_file = '{}/{}.crt'.format(crt_dir, domain)
  ret = {
    'crt_file': crt_file,
    'email_dir': email_dir,
    'domain_key_file': domain_key_file,
    'crt_dir': crt_dir,
    'account_json': account_json,
    'account_key': account_key
  }
  return ret 

###############################
def download_key(email, domain):
  """
  Download cert and key of a valid domain
  :email (string): email of client 
  :verify_domain (string): domain need to download key anf crt
  :return True if success else False
  """
  email_dir = '{}/{}'.format(ACCOUNT_STORE_FOLDER, email)
  domain_key_file = '{}/{}.key'.format(email_dir, domain)
  output_path = '{}/{}'.format(email_dir, domain)
  print(output_path)
  account_path = '{}/{}.json'.format(email_dir, email)
  account = load_account(account_path)
  print(account)
  print(domain_key_file)

  bak_path = None
  if os.path.isdir(output_path):
    if len(os.listdir(output_path)) != 0:
      bak_path = shutil.move(output_path, '{}.bak'.format(output_path))
      os.mkdir(output_path)
    else:
      pass

  elif not os.path.isdir(output_path):
    os.mkdir(output_path)

  try:
    issue(LETS_ENCRYPT_PRODUCTION, account, [domain], DEFAULT_CERT_KEY_SIZE, domain_key_file , None, output_path)
    if bak_path:
      shutil.rmtree(bak_path)
  except:
    shutil.rmtree(output_path)
    if bak_path:
      shutil.move(bak_path, '{}'.format(output_path))
    print('issue failed, limit rate for this domain or some other reason')
    return False
  return True


@csrf_exempt
@api_view(["POST"])
@permission_classes((AllowAny,))
def login(request):
    username = request.data.get("username")
    password = request.data.get("password")
    if username is None or password is None:
      return Response({'error': 'Please provide both username and password'}, status=HTTP_400_BAD_REQUEST)
    user = authenticate(username=username, password=password)
    if not user:
        return Response({'error': 'Invalid Credentials'}, status=HTTP_404_NOT_FOUND)
    token, _ = Token.objects.get_or_create(user=user)
    return Response({'token': token.key}, status=HTTP_200_OK)

############################
@csrf_exempt
@api_view(['POST'])
def auth_domain(request):
  """
  POST API use to authorize domain 
  :param request.POST.email (string): customer email 
  :param request.POST.domain (string): domain need to be authorize
  :param request.POST.type_req (string): 'renew' or 'create' to renew a old cert or create a new one
  
  """
  global auths
  response_data = {}
  print('-----auths in head auth_domain()')
  for key in auths.keys():
    print(key)
  print('------------end----------------')
  serializer = ParamsSerializer(data=request.data)
  if not serializer.is_valid():
    response_data = FORBIDDEN_CODE 
    data_in_json = json.dumps(response_data, sort_keys=True, indent=4)
    return HttpResponse(data_in_json, content_type="application/json")
  else:
    email = request.data['email']
    domain = request.data['domain']
    type_req = request.data['type_req']
  #check if folder key for this email is exist, create folder if not 

  email_dir = '{}/{}'.format(ACCOUNT_STORE_FOLDER, email)
  key_path = '{}/{}.key'.format(email_dir, email)
  account_json_path = '{}/{}.json'.format(email_dir, email)
  domain_key_path = '{}/{}.key'.format(email_dir, domain)
  
  if not os.path.exists(email_dir):
    os.mkdir(email_dir)
  
  # gen key_path and account_path file in string
  gen_key_cmd = 'openssl genrsa 4096'
  args = gen_key_cmd.split()

  if not os.path.exists(key_path):
    #gen a account key file 
    with open(key_path,'w+') as f1:
      subprocess.run(args, stdout=f1)

  if not os.path.exists(domain_key_path):
    #gen a domain key 
    with open(domain_key_path, 'w+') as f2:
      subprocess.run(args, stdout=f2)

    #gen account.json
  customers = Customer.objects.filter(email=email)
  if not os.path.exists(account_json_path):
    # register account with email and key 
    register(LETS_ENCRYPT_PRODUCTION, account_json_path, email, key_path)
      # save info to database
    if len(customers) == 0:
      print('create account model')
      account_dict = read_file_tojson(account_json_path)
      account_key_text = account_dict['key']
      account_uri_text = account_dict['uri']
      c = Customer(email=email, uri=account_uri_text, key=account_key_text, path=account_json_path)
      c.save()
      response_data['custom_id'] = c.id
  else:
    response_data['custom_id'] = customers[0].id

  #################################   AUTH STEP ###################################
  # create params for authorize
  account = load_account(account_json_path)

  
  
  # authen step 
  # if domain not in auths[email].keys():
  res = authorize(LETS_ENCRYPT_PRODUCTION, account, domain, type_req, 'dns')
  #domain is already valid, return status verified,
  #else return auth challenges and status unverified
  res = res[domain]

  if res['status'] == 'invalid':
  # if email not in auths , create key for this email :::auths[email][domain]
    if email in auths.keys():
      print('Authz for {} is already existed'.format(email))
      #print(auths[email])
    else:
      auths[email] = {}
    auths[email][domain] = {}
    auths[email][domain].update(res)

  
  if res['status'] == 'valid' and type_req == 'renew':
    print('download valid cert')
    if download_key(email, domain) == True:
      update_cert_model(email, domain)
      response_data['renew_status'] = SUCCESS_CODE
    else:
      response_data = LIMIT_RATE_ERROR

    data_in_json = json.dumps(response_data, sort_keys=True, indent=4)
    return HttpResponse(data_in_json, content_type="application/json")


  print('-----auths in end auth_domain()')
  for key in auths.keys():
    print(key)
  print('------------end----------------')
  
  if res['status'] == 'invalid':
    response_data['key_txt'] = ' _acme-challenge.{}.'.format(domain)
    response_data['val_txt'] = res['authz'][domain]['txt_record']
    response_data['status'] = 'challenge'
  # response for client
  elif res['status'] == 'valid' and type_req == 'create':
    response_data['status'] = 'valid'
    response_data['from'], response_data['to'] = get_cert_time(gen_path(email, domain)['crt_file'])

  data_in_json = json.dumps(response_data, sort_keys=True, indent=4)
  return HttpResponse(data_in_json, content_type="application/json")
 
    
@csrf_exempt
@api_view(['POST'])
def verify_auth(request):
  """
  POST API to verify domain is already pass challenges
  :param request.POST.email (string): customer email 
  :param request.POST.domain (string): domain need to be verify
  :param request.POST.type_req (string): 'renew' or 'create' to renew a old cert or create a new one
  """
  global auths
  print('-----auths in head verify_auth()')
  for key in auths.keys():
    print(key)
  print('------------end----------------')
  data = {}
  serializer = ParamsSerializer(data=request.data)
  if not serializer.is_valid():
    response_data = FORBIDDEN_CODE 
    data_in_json = json.dumps(response_data, sort_keys=True, indent=4)
    return HttpResponse(data_in_json, content_type="application/json")
  else:
    email = request.data['email']
    domain = request.data['domain']
    type_req = request.data['type_req']
  method = 'dns-01'
  print('-----auths in middle verify_auth()')
  for key in auths.keys():
    print(key)
  print('------------end----------------')
  
  if email in auths.keys():
    if domain in auths[email].keys():
      res = auths[email][domain]
      #  pprint(res)
      ## if domain is cetificated  and type = create, return valid status 
      if res['status'] == 'valid' and type_req != 'renew':
        data['status'] = 'valid'
      # else , force create a new cert
      else:
        auth = res['authz'][domain]
        #  pprint(auth)
        challenge = auth['challenge']
        acme = res['acme']
        acme.validate_authorization(challenge['uri'], method, auth['key_authorization'])
        if retrieve_verification(acme, domain, auth, method):
          if download_key(email, domain) == True:
            print('download file success')
            data['status'] = SUCCESS_CODE
            #### save info about cert 
            email_dir = '{}/{}'.format(ACCOUNT_STORE_FOLDER, email)
            cert_path='{}/{}/{}.crt'.format(email_dir, domain, domain)
            key_path = '{}/{}.key'.format(email_dir, domain)
            customer = Customer.objects.filter(email=email)[0]
            old_cert_models = Certificate.objects.filter(domain=domain)
            if len(old_cert_models) != 0:
              for ob in old_cert_models:
                ob.delete()
            _from, _to =  get_cert_time(cert_path)

            cert = Certificate(
                domain=domain, 
                cert=read_allfile(cert_path), 
                key=read_allfile(key_path), 
                cert_path=cert_path, 
                key_path=key_path, 
                owner=customer,
                valid_in = _from,
                expire_in = _to
            )
            cert.save()
            print('cert id is {}'.format(cert.id))
            data['cert_id'] = cert.id
          else:
            print('Failed to download cert for domain {}'.format(domain))
            data = {**data, **LIMIT_RATE_ERROR}
        else:
          data = {**data, **CHALLENGE_ERROR }
    else:
      print('domain is not exists in auths {}'.format(domain))
      data = {**data, **DOMAIN_NOT_ORDER}
  else:
    print('email is not exist in auths')
    data = {**data, **EMAIL_NOT_ORDER}

  clear_domain_in_auths(email, domain) 
  data_in_json = json.dumps(data, sort_keys=True, indent=4)
  return HttpResponse(data_in_json, content_type="application/json")

class CertificateListSerializer(serializers.ModelSerializer):
  class Meta:
    model = Certificate
    fields = '__all__'

class CustomerListSerializer(serializers.ModelSerializer):
  class Meta:
    model = Customer
    fields = '__all__'

class CustomerListCreateAPIView(viewsets.GenericViewSet, ListCreateAPIView):
  serializer_class = CustomerListSerializer
  queryset = Customer.objects.all()

class CertificateListCreateAPIView(viewsets.GenericViewSet, ListCreateAPIView):
  serializer_class = CertificateListSerializer
  queryset = Certificate.objects.all()

class CustomerDetailUpdateAPIView(viewsets.GenericViewSet, RetrieveUpdateDestroyAPIView):
  queryset = Customer.objects.all()
  serializer_class = CustomerListSerializer
  lookup_field = 'id'

class CertificateDetailUpdateAPIView(viewsets.GenericViewSet, RetrieveUpdateDestroyAPIView):
  queryset = Certificate.objects.all()
  serializer_class = CertificateListSerializer
  lookup_field = 'id'

@api_view(['GET', 'POST'])
def list_cert(request):
  if request.method == 'POST':
    return Response(request.data, status=status.HTTP_400_BAD_REQUEST)
  else:
    all_data = []
    all_clients = Customer.objects.all()
    for client in all_clients:
      client_certs = Certificate.objects.filter(owner=client)
      for cert in client_certs: 
        data = {
          'email': client.email,
          'account_path': client.path,
          'domain': cert.domain,
          'cert_path': cert.cert_path,
          'key_path': cert.key_path
        }
        _from, _to = get_cert_time(data['cert_path'])
        data['from'] = _from
        data['to'] = _to
        all_data.append(data)
        
    data_in_json = json.dumps(all_data, sort_keys=True, indent=4 , cls=DjangoJSONEncoder)
    return HttpResponse(data_in_json, content_type="application/json")


@api_view(['GET', 'POST'])
def renew(request):
  """
  Renew all cert 
  """
  ## 
  all_data = []
  all_clients = Customer.objects.all()
  for client in all_clients:
    client_certs = Certificate.objects.filter(owner=client)
    for cert in client_certs: 
      all_data.append({
        'email': client.email,
        'account_path': client.path,
        'domain': cert.domain,
        'cert_path': cert.cert_path,
        'key_path': cert.key_path
      })
  ##
  for data in all_data:
    account = load_account(data['account_path'])
    res = authorize(LETS_ENCRYPT_PRODUCTION, account, data['domain'], 'auto-renew', 'dns')
    if res[data['domain']]['status'] == 'valid':
      data['status'] = 'valid'
      data['expires'] = res[data['domain']]['expires']
      data['key_authorization'] = res[data['domain']]['key_authorization']
      data['uri'] = res[data['domain']]['uri']
      _from, _to = get_cert_time(data['cert_path'])
      data['from'] = _from
      data['to'] = _to
      domain = data['domain']
      is_downloaded = download_key(data['email'], data['domain'])
      data['updated'] = is_downloaded
      if is_downloaded:
        update_cert_model(data['email'], domain)
    else:
      data['status'] = 'invalid'
        
  data_in_json = json.dumps(all_data, sort_keys=True, indent=4 , cls=DjangoJSONEncoder)
  return HttpResponse(data_in_json, content_type="application/json")
