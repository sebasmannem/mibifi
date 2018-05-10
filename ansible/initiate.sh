#!/bin/bash
yum update -y
yum install -y epel-release
yum install -y ansible
cd /ansible
ansible-playbook all.yml
