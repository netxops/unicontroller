FROM centos:latest

RUN yum -y install systemd curl

COPY deployment-agent /usr/local/bin/
COPY test-script.sh /

CMD ["/bin/bash", "/test-script.sh"]
