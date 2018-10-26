#!/bin/sh

/certbot_hook/certbot-auto certonly --manual-public-ip-logging-ok --manual --preferred-challenges dns --manual-auth-hook /certbot_hook/test_hook.py -d ${DOMAIN} --noninteractive --agree-tos --email quy196hp@gmail.com