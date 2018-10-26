FROM centos:centos7
MAINTAINER quydx <quy196hp@gmail.com>

RUN yum install epel-release -y 
RUN yum install -y https://centos7.iuscommunity.org/ius-release.rpm
## python3.6 + uwsgi
RUN yum update -y
RUN yum groupinstall -y "Development Tools"
RUN yum install -y python36u python36u-libs python36u-devel python36u-pip
RUN yum install -y nginx supervisor
RUN yum install -y mysql-devel
RUN pip3.6 install uwsgi

## project folder
ADD ./apiserver /home/docker/apiserver
RUN pip3.6 install -r /home/docker/apiserver/requirements.txt
ADD ./conf/nginx-app.conf /etc/nginx/conf.d/nginx-app.conf 
ADD ./conf/apiserver.ini /etc/uwsgi/sites/apiserver.ini
ADD ./conf/supervisor-app.ini /etc/supervisord.d/
RUN mkdir -p /var/log/uwsgi
RUN touch /var/log/uwsgi/restapi.log
RUN echo "daemon off;" >> /etc/nginx/nginx.conf
# RUN python3.6 /home/docker/apiserver/djangorest/manage.py collectstatic
EXPOSE 8000
# RUN python3.6 /home/docker/apiserver/djangorest/manage.py runserver 0.0.0.0:8000 &
CMD ["supervisord", "-n"]








