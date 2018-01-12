#!/bin/bash
proj=$1
mkdir -p ~/$proj
cd ~/$proj
test -x .git || git init --bare
touch git-daemon-export-ok
test -x hooks/post-update || mv hooks/post-update.sample hooks/post-update
chmod a+x hooks/post-update
git update-server-info
