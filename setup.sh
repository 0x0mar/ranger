#!/bin/bash
:<<'COMMENT'
Author: Chris Duffy
Date: 2015
Name: setup.sh
Purpose: This installation file does the basic installation of PIP, and relevant Python libraries.
Systems: This has only been tested on Kali
Copyright (c) 2015, Christopher Duffy All rights reserved.
Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met: * Redistributions
of source code must retain the above copyright notice, this list of conditions and
the following disclaimer. * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution. * Neither the
name of the nor the names of its contributors may be used to endorse or promote
products derived from this software without specific prior written permission.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL CHRISTOPHER DUFFY BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
COMMENT

# Installing PIP
#apt-get clean && apt-get update && apt-get upgrade -y && apt-get dist-upgrade -y # Uncomment if necessary
apt-get -y install python-setuptools python-dev python-pip

# Update setup tools
pip install setuptools --upgrade

# Install Python libraries
pip install netifaces python-nmap
# Upgrade requests
pip install request --upgrade

mkdir -p /opt/ranger/smb
mkdir -p /opt/ranger/web
touch /opt/ranger/web/pv.ps1 && rm /opt/ranger/web/pv.ps1
touch /opt/ranger/web/im.ps1 && rm /opt/ranger/web/im.ps1
touch /opt/ranger/smb/pv.ps1 && rm /opt/ranger/smb/pv.ps1
touch /opt/ranger/smb/im.ps1 && rm /opt/ranger/smb/im.ps1
cd /opt/ranger
chmod 705 smb
chmod 705 web
cd web
wget https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerView/powerview.ps1 -O pv.ps1
wget https://raw.githubusercontent.com/mattifestation/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1 -O im.ps1
chmod a+x pv.ps1 im.ps1
cp -p pv.ps1 im.ps1 /opt/ranger/smb/

touch /opt/ranger/impacket && rmdir /opt/ranger/impacket

cd /opt/ranger && wget https://pypi.python.org/packages/source/i/impacket/impacket-0.9.13.tar.gz &&  tar -xzvf impacket-0.9.13.tar.gz
rm  tar -xzvf impacket-0.9.13.tar.gz && mv mv impacket-0.9.13 impacket
touch /usr/bin/ranger && rm /usr/bin/ranger
cd /opt/ranger/impacket/examples && wget https://raw.githubusercontent.com/funkandwagnalls/ranger/master/ranger.py && chmod a+x ranger.py
ln -s /opt/ranger/impacket/examples/ranger.py /usr/bin/ranger
