############################################################################
# 
# Copyright 2017 Lee Mitchell <lee@indigopepper.com>
# This file is part of JN51xx 802.15.4 Sniffer Server
# 
# JN51xx 802.15.4 Sniffer Server is free software: you can redistribute it
# and/or modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation, either version 3 of the License,
# or (at your option) any later version.
# 
# JN51xx 802.15.4 Sniffer Server is distributed in the hope that it will be
# useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with JN51xx 802.15.4 Sniffer Server.  If not,
# see <http://www.gnu.org/licenses/>.
# 
############################################################################

TARGET=JN51xx-802.15.4-Sniffer-Server.exe

CC=gcc

all:
	$(CC) -o $(TARGET) main.c uart.c -lws2_32
	
clean:
	rm -rf $(TARGET)