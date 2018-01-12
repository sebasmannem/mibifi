ssh-keygen -t ecdsa -f /etc/ssh/ssh_host_ecdsa_key -N ''
/usr/sbin/sshd
#cat
#for docker run -ti, cat holds forever, but for docker run -d, cat gets no stdin and stops, stopping container.
#use this loop instead of cat, to hold forever. Of coarse, /bin/true could be any otehr test aswel, 
#giving you the options to end container without killing this script.
while /bin/true; do sleep 60; done
