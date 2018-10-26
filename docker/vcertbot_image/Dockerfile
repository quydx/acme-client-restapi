FROM centos
MAINTAINER toanbs
RUN yum install wget epel-release -y
RUN yum update -y
RUN yum install python-pip -y
RUN pip install redis
RUN wget https://dl.eff.org/certbot-auto
RUN chmod a+x certbot-auto
RUN mkdir /certbot_hook
COPY test_hook.py /certbot_hook
RUN mv certbot-auto /certbot_hook
COPY run.sh /certbot_hook
RUN chmod a+x /certbot_hook/test_hook.py
ENTRYPOINT ["/bin/sh", "/certbot_hook/run.sh"]