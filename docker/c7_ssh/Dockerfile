#docker build --rm -t centos7_ssh .
#docker run -id centos7_ssh
#docker inspect [new container]
#ssh [inspect>NetworkSettings>IPAddres]

FROM centos:7
#sudo and iproute for ansible readyness
RUN yum -y update
RUN yum -y install openssh-server openssh-clients sudo iproute
COPY start.sh /start.sh
COPY id_rsa.pub /root/.ssh/authorized_keys
COPY id_rsa /root/.ssh/id_rsa
RUN chown -R root:root /root/.ssh
RUN chmod 600 /root/.ssh/authorized_keys
CMD /bin/bash /start.sh
