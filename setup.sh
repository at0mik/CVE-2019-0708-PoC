#!/bin/bash
pip install impacket
pip install structure
git clone https://github.com/SecureAuthCorp/impacket.git
touch ./impacket/__init__.py
git pull
echo "done!"
