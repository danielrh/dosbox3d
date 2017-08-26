#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <errno.h>
#include "cpu.h"
#include "paging.h"
#include <vector>
#include "wc_net.h"
NetConfig net_config;

struct ServerState {
	int listenSocket;
    typedef std::vector<int> ClientVec;
	ClientVec clients;
} *server;

struct ClientState {
	int clientSocket;
} *client;

int manualDoDamage = 0;




int fire_fifo = open("/tmp/fire.fifo", O_RDONLY|O_NONBLOCK);
FILE *memlog = fopen("/tmp/mem.txt", "a");
FILE *debuglog = fopen("/tmp/debug.txt", "a");



void init_network() {
    struct addrinfo hints, *res, *res0;
    int error;
    int s;
    const char *cause = NULL;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (net_config.host && net_config.host[0]) {
        client = new ClientState();
        error = getaddrinfo(net_config.host, net_config.portstr, &hints, &res0);
    } else {
	    server = new ServerState();
        hints.ai_flags = AI_PASSIVE;
        error = getaddrinfo(NULL, net_config.portstr, &hints, &res0);
    }
    if (error) {
        fprintf(stderr, "getaddrinfo %s\n", gai_strerror(error));
        abort();
    }
    s = -1;
    for (res = res0; res; res = res->ai_next) {
        s = socket(res->ai_family, res->ai_socktype,
            res->ai_protocol);
        if (s < 0) {
                cause = "socket";
                continue;
        }

        if (server) {
            if (bind(s, res->ai_addr, res->ai_addrlen) < 0) {
                cause = "connect";
                close(s);
                s = -1;
                continue;
            }
            if (listen(s, 5) < 0) {
                cause = "listen";
                close(s);
                s = -1;
                continue;
            }
        } else {
            if (connect(s, res->ai_addr, res->ai_addrlen) < 0) {
                cause = "connect";
                close(s);
                s = -1;
                continue;
            }
        }

        break;  /* okay we got one */
    }
    if (s < 0) {
            fprintf(stderr, "socket/connect %s\n", cause);
            abort();
    }
    freeaddrinfo(res0);
    if (server) {
        server->listenSocket = s;
    }
    if (client) {
        client->clientSocket = s;
    }
}

//GameState gs;

void recv_msg(int sock) {
    char data[1];
    if (recv(sock, data, 1, 0) <= 0) {
        // We need to handle disconnects here.
        perror("recv failed");
        abort();
    }
    printf("got %c\n", data[0]);
}

void send_msg(int sock, const char *data) {
    if (send(sock, data, 1, 0) < 0) {
        // We need to handle disconnects here.
        perror("send failed");
        abort();
    }
}

void process_network() {
    if (!client && !server) {
        init_network();
        if (client) {
            send_msg(client->clientSocket, "b"); // Connect
            recv_msg(client->clientSocket); // GameState
        }
    }

    if (server) {
        for (ServerState::ClientVec::iterator c = server->clients.begin(), ce=server->clients.end(); c != ce; ++c) {
            recv_msg(*c); // Frame
        }
        for (ServerState::ClientVec::iterator c = server->clients.begin(), ce=server->clients.end(); c != ce; ++c) {
            send_msg(*c, "s"); // Frame
        }
        while (true) {
            int flags = fcntl(server->listenSocket, F_GETFL, 0);
            if (server->clients.empty()) {
                fcntl(server->listenSocket, F_SETFL, flags & ~O_NONBLOCK);
            } else {
                fcntl(server->listenSocket, F_SETFL, flags | O_NONBLOCK);
            }
            sockaddr addr;
            socklen_t addrlen = sizeof(addr);
            int s = accept(server->listenSocket, &addr, &addrlen);
            if (s < 0) {
                break;
            }
            flags = fcntl(server->listenSocket, F_GETFL, 0);
            fcntl(server->listenSocket, F_SETFL, flags & ~O_NONBLOCK);
            server->clients.push_back(s);
            recv_msg(s); // Connect
            send_msg(s, "g"); // GameState
        }
    } else {
        send_msg(client->clientSocket, "c"); // Frame
        recv_msg(client->clientSocket); // Frame
    }



#if 0
    static int ctr = 0;
    if ((ctr++ % 500) == 0) {
        /*fprintf(memlog, "pos: ");
        for (int addr = 0x1E6F2; addr < 0x1e6f2 + 12; addr += 4) {
            unsigned int val;
            mem_readd_checked(addr, &val);
            fprintf(memlog, "%d ", (int)val);
        }*/
        for (int addr = 0xA9C2+0x13d30, i=0; i<0x3e; i += 1, addr+=12) {
            unsigned int valx;
            unsigned int valy;
            unsigned int valz;
            mem_readd_checked(addr, &valx);
            mem_readd_checked(addr + 0x4, &valy);
            mem_readd_checked(addr + 0x8, &valz);
            if (valx != 0 || valy != 0 || valz != 0) {
                fprintf(memlog, "%d:(%8d,%8d,%8d)", i, valx, valy, valz);
            }
        }
        /*
        fprintf(memlog, " pos: ");
        for (int addr = 0xA9C2+0x13d30, i=0; i<6; i += 1, addr+=4) {
            unsigned int val;
            mem_readd_checked(addr, &val);
            fprintf(memlog, "%.02f ", ((float)(int)val)/256.);
            if (i == 2) {
                addr += (0x3d - 1) * 12;
            }
        }
        fprintf(memlog, " vel: ");
        for (int addr = 0xCAE2+0x13d30, i=0; i<6; i += 1, addr+=4) {
            unsigned int val;
            mem_readd_checked(addr, &val);
            fprintf(memlog, "%.02f ", ((float)(int)val)/256.);
            if (i == 2) {
                addr += (0x3d - 1) * 12;
            }
        }
        fprintf(memlog, " RGT: ");
        for (int addr = 0xAEB6+0x13d30, i=0; i<6; i += 1, addr+=4) {
            unsigned int val;
            mem_readd_checked(addr, &val);
            fprintf(memlog, "%.02f ", ((float)(int)val)/256.);
            if (i == 2) {
                addr += (0x3d - 1) * 12;
            }
        }
        fprintf(memlog, " UP: ");
        for (int addr = 0xB1B6+0x13d30, i=0; i<6; i += 1, addr+=4) {
            unsigned int val;
            mem_readd_checked(addr, &val);
            fprintf(memlog, "%.02f ", ((float)(int)val)/256.);
            if (i == 2) {
                addr += (0x3d - 1) * 12;
            }
        }
        fprintf(memlog, " FWD: ");
        for (int addr = 0xB4B6+0x13d30, i=0; i<6; i += 1, addr+=4) {
            unsigned int val;
            mem_readd_checked(addr, &val);
            fprintf(memlog, "%.02f ", ((float)(int)val)/256.);
            if (i == 2) {
                addr += (0x3d - 1) * 12;
            }
        }
        */
        fprintf(memlog, "\n");
        fflush(memlog);
    }
#endif
    {
        char buf[1];
        if (read(fire_fifo, &buf, 1) > 0) {
            fprintf(debuglog, "cs:eip = %04x:%04x\n", SegValue(cs), reg_eip);
            CPU_Push16((Bit16u)SegValue(cs));
            CPU_Push16((Bit16u)reg_eip);
            uint32_t data_segment_start = 0x13d30;
            uint32_t loading_wing_commander_start = 0x0187;
            if (buf[0] == ' ') { // fire all guns
                Bit8u shellcode[] = {
                    0x00, // nul terminate string
                    // push flags, push all regs, xor si,si, push si
                    0x9C, 0x60, 0x33, 0xF6, 0x56,
                    // call far 12d7:0156
                    0x9A, 0x56, 0x01, 0xd7, 0x12,
                    // pop si, pop all regs, pop flags, retf
                    0x5E, 0x61, 0x9D, 0xCB
                };
                for (int i = 0; i < sizeof(shellcode); i++) {
                    mem_writeb_checked(data_segment_start + loading_wing_commander_start + i, shellcode[i]);
                }
            } else if (buf[0] == ',') {
                Bit8u shellcode[] = {
                    0x00, // nul terminate string
                    // push flags, push all regs, xor si,si, push si
                    0x9C, 0x60, 0x33, 0xF6, 0x56, 0x56,
                    // call far 12d7:012E
                    0x9A, 0x56, 0x01, 0xd7, 0x12,
                    // pop si, pop all regs, pop flags, retf
                    0x5E, 0x5E, 0x61, 0x9D, 0xCB
                };
                for (int i = 0; i < sizeof(shellcode); i++) {
                    mem_writeb_checked(data_segment_start + loading_wing_commander_start + i, shellcode[i]);
                }
            } else if (buf[0] == '.') {
                Bit8u shellcode[] = {
                    0x00, // nul terminate string
                    // push flags, push all regs, xor si,si, push si
                    0x9C, 0x60,
                    0xbe, 0, 0,// mov si <-- gun_id
                    0x56,
                    // call far 12d7:012E
                    0x9A, 0x56, 0x01, 0xd7, 0x12,
                    // pop si, pop all regs, pop flags, retf
                    0x5E, 0x61, 0x9D, 0xCB
                };
                for (int i = 0; i < sizeof(shellcode); i++) {
                    mem_writeb_checked(data_segment_start + loading_wing_commander_start + i, shellcode[i]);
                }
            } else if (buf[0] == 'f') { // fire one gun from a selected ship
                buf[0] = 0;
                read(fire_fifo, &buf, 1);
                uint32_t gun_id = 0;
                uint32_t ship_id = 0;
                if (buf[0] >= '0' && buf[0] <= '9') {
                    gun_id = buf[0] - '0';
                } else if (buf[0] >= 'a' && buf[0] <= 'z') {
                    gun_id = buf[0] - 'a';
                    ship_id = 1;
                } else if (buf[0] >= 'A' && buf[0] <= 'Z') {
                    gun_id = buf[0] - 'A';
                    ship_id = 2;
                }
                Bit8u shellcode[] = {
                    0x00, // nul terminate string
                    // push flags,
                    0x9C, //PUSHF
                    //push all regs, xor si,si, push si
                    0x60, //PUSHA
                    0xbe, gun_id & 0xff, gun_id >> 8,// mov si <-- gun_id
                    0x56, // push si
                    0xbe, ship_id & 0xff, ship_id >> 8, // mov si <- ship_id
                    0x56, // push si
                    // call far 12d7:012E
                    0x9A, 0x2E, 0x01, 0xd7, 0x12,
                    // pop si, pop si, pop all regs, pop flags, retf
                    0x5E, 0x5E, 0x61, 0x9D, 0xCB
                };
                for (int i = 0; i < sizeof(shellcode); i++) {
                    mem_writeb_checked(data_segment_start + loading_wing_commander_start + i, shellcode[i]);
                }                
            } else if (buf[0] == 'd') {
                unsigned short arg_0, arg_2, arg_4, arg_6;
                char argbuf[100] = {0};
                int i;
                for (i = 0; i < 99;) {
                    if (read(fire_fifo, argbuf + i, 1) <= 0) {
                        if (errno != EAGAIN && errno != EINTR) {
                            break;
                        }
                    } else {
                        if (argbuf[i] == '\n') {
                            break;
                        }
                        i++;
                    }
                }
                argbuf[i] = '\0';
                sscanf(argbuf ,"%hd %hd %hd %hd", &arg_0, &arg_2, &arg_4, &arg_6);
                Bit8u shellcode[] = {
                    0x00, // nul terminate string
                    // push flags,
                    0x9C, //PUSHF
                    //push all regs, xor si,si, push si
                    0x60, //PUSHA
                    0xbe, arg_6 & 0xff, arg_6 >> 8,
                    0x56, // push si
                    0xbe, arg_4 & 0xff, arg_4 >> 8,
                    0x56, // push si
                    0xbe, arg_2 & 0xff, arg_2 >> 8,
                    0x56, // push si
                    0xbe, arg_0 & 0xff, arg_0 >> 8,
                    0x56, // push si
                    // call far 12d7:012E
                    0x9A, 0x84, 0x00, 0xd7, 0x12,
                    // pop si, pop si, pop all regs, pop flags, retf
                    0x5E, 0x5E, 0x5E, 0x5E, 0x61, 0x9D, 0xCB
                };
                for (int i = 0; i < sizeof(shellcode); i++) {
                    mem_writeb_checked(data_segment_start + loading_wing_commander_start + i, shellcode[i]);
                }
            }
            manualDoDamage ++;
            SegSet16(cs, data_segment_start >> 4);
            reg_eip = loading_wing_commander_start + 1;
            fprintf(debuglog, "cs:eip = %04x:%04x\n", SegValue(cs), reg_eip);
        }
    }

}

void doDamage() {
    Bit16u arg0 = mem_readw(0x13d30 + reg_esp + 4);
    Bit16u arg2 = mem_readw(0x13d30 + reg_esp + 6);
    Bit16u arg4 = mem_readw(0x13d30 + reg_esp + 8);
    Bit16u arg6 = mem_readw(0x13d30 + reg_esp + 10);
    Bit32u xcoord = mem_readd(0x13d30 + arg6);
    Bit32u ycoord = mem_readd(0x13d30 + arg6 + 4);
    Bit32u zcoord = mem_readd(0x13d30 + arg6 + 8);
    Bit32u randomSeed = mem_readd(0x13d30 + 0x7728);
    fprintf(stderr, "\r\ndoDamage(%d, %d, %d, <%d, %d, %d>) rng=%x\r\n",
            arg0, arg2, arg4, xcoord, ycoord, zcoord, randomSeed);
    reg_eip = 0x0d44;
}
void process_damage() {
    // beginning of doDamage.
    if (manualDoDamage) {
        manualDoDamage --;
    } else {
        doDamage();
    }
}
