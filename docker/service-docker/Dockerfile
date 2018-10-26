FROM centos:centos7
MAINTAINER quydx <quy196hp@gmail.com>

RUN yum install epel-release -y 
RUN yum install -y https://centos7.iuscommunity.org/ius-release.rpm
## python3.6 + uwsgi
RUN yum update -y
RUN yum groupinstall -y "Development Tools"
RUN yum install -y python36u python36u-libs python36u-devel python36u-pip
RUN yum install -y nginx supervisor
RUN pip3.6 install uwsgi

## project folder
ADD ../../apiserver /home/docker/apiserver
ADD ./conf/nginx-app.conf /etc/nginx/conf.d/nginx-app.conf 
ADD ./conf/apiserver.ini /etc/uwsgi/sites/apiserver.ini


RUN pip3.6 install -r /home/docker/apiserver/requirements.txt

RUN /home/docker/apiserver/djangorest/manage.py collectstatic
EXPOSE 80

CMD ["supervisord", "-n"]






