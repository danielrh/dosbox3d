/*
 *  Copyright (C) 2002-2015  The DOSBox Team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */


#include "dosbox.h"

#include <string.h>
#include <time.h>
#include <stdio.h>
#include "cross.h"
#include "support.h"
#include "cpu.h"
#include "regs.h"
#include "inout.h"

#include "debug.h"
#include "callback.h"
#include "dos_system.h"
#include "mem.h"
#include "timer.h"
#include "programs.h"
#include "pic.h"

class WCNET : public Program {
public:
	void HelpCommand(const char *helpStr) {
		// Help on connect command
		if(strcasecmp("connect", helpStr) == 0) {
			WriteOut("WCNET CONNECT opens a connection to an IPX tunneling server running on another\n");
			WriteOut("DosBox session.  The \"address\" parameter specifies the IP address or host name\n");
			WriteOut("of the server computer.  One can also specify the UDP port to use.  By default\n");
			WriteOut("WCNET uses port 13255, the default port for Wing commander TCP/IP\n\n");
			WriteOut("The syntax for WCNET CONNECT is:\n\n");
			WriteOut("WCNET CONNECT address <port>\n\n");
			return;
		}
		// Help on the disconnect command
		if(strcasecmp("disconnect", helpStr) == 0) {
			WriteOut("WCNET DISCONNECT closes the connection to the WCP TCP/IP server.\n\n");
			WriteOut("The syntax for WCNET DISCONNECT is:\n\n");
			WriteOut("WCNET DISCONNECT\n\n");
			return;
		}
		// Help on the startserver command
		if(strcasecmp("startserver", helpStr) == 0) {
			WriteOut("WCNET STARTSERVER starts a TCP/IP server on this DosBox session. By default\n");
			WriteOut("the server will accept connections on TCP port 13255, though this can be\n");
			WriteOut("changed.  Once the server is started, other clients may connect\n");
			WriteOut("connection to the WC tunneling server.\n\n");
			WriteOut("The syntax for WCNET STARTSERVER is:\n\n");
			WriteOut("WCNET STARTSERVER <port>\n\n");
			return;
		}
		// Help on the stop server command
		if(strcasecmp("stopserver", helpStr) == 0) {
			WriteOut("WCNET STOPSERVER stops the TCP/IP server running on this DosBox\nsession.");
			WriteOut("  Care should be taken to ensure that all other connections have\nterminated ");
			WriteOut("as well sinnce stoping the server may cause lockups on other\nmachines still using ");
			WriteOut("the TCP/IP Wing Commander server.\n\n");
			WriteOut("The syntax for WCNET STOPSERVER is:\n\n");
			WriteOut("WCNET STOPSERVER\n\n");
			return;
		}
		// Help on the status command
		if(strcasecmp("status", helpStr) == 0) {
			WriteOut("WCNET STATUS reports the current state of this DosBox's sessions IPX tunneling\n");
			WriteOut("network.  For a list of the computers connected to the network use the WCNET \n");
			WriteOut("PING command.\n\n");
			WriteOut("The syntax for WCNET STATUS is:\n\n");
			WriteOut("WCNET STATUS\n\n");
			return;
		}
	}

	void Run(void)
	{
		WriteOut("IPX Tunneling utility for DosBox\n\n");
		if(!cmd->GetCount()) {
			WriteOut("The syntax of this command is:\n\n");
			WriteOut("WCNET [ CONNECT | DISCONNECT | STARTSERVER | STOPSERVER | HELP |\n         STATUS ]\n\n");
			return;
		}
		
		if(cmd->FindCommand(1, temp_line)) {
			if(strcasecmp("help", temp_line.c_str()) == 0) {
				if(!cmd->FindCommand(2, temp_line)) {
					WriteOut("The following are valid WCNET commands:\n\n");
					WriteOut("WCNET CONNECT        WCNET DISCONNECT       WCNET STARTSERVER\n");
					WriteOut("WCNET STOPSERVER     WCNET PING             WCNET STATUS\n\n");
					WriteOut("To get help on a specific command, type:\n\n");
					WriteOut("WCNET HELP command\n\n");

				} else {
					HelpCommand(temp_line.c_str());
					return;
				}
				return;
			} 
			if(strcasecmp("startserver", temp_line.c_str()) == 0) {
				return;
			}
			if(strcasecmp("stopserver", temp_line.c_str()) == 0) {
				return;
			}
			if(strcasecmp("connect", temp_line.c_str()) == 0) {
//				if(incomingPacket.connected) {
//					WriteOut("IPX Tunneling Client already connected.\n");
//					return;
//				}
				if(!cmd->FindCommand(2, temp_line)) {
					WriteOut("TCP Server address not specified.\n");
					return;
				}
                char *strHost = strdup(temp_line.c_str());
                const char * udpPort;

				if(!cmd->FindCommand(3, temp_line)) {
					udpPort = "13255";
				} else {
					udpPort = strdup(temp_line.c_str());
				}
/*
				if(ConnectToServer(strHost)) {
                	WriteOut("IPX Tunneling Client connected to server at %s.\n", strHost);
				} else {
					WriteOut("IPX Tunneling Client failed to connect to server at %s.\n", strHost);
                    }*/
				return;
			}
			
			if(strcasecmp("disconnect", temp_line.c_str()) == 0) {
				return;
			}

			if(strcasecmp("status", temp_line.c_str()) == 0) {
				return;
			}

		}
	}
};

void WCNET_ProgramStart(Program * * make) {
	*make=new WCNET;
}

void VFILE_Remove(const char *name);



