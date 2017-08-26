#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <stddef.h>
#include <stdio.h>
#include <errno.h>
#include "cpu.h"
#include "paging.h"
#include <vector>
#include "wc_net.h"
#include "../wc.pb.h"
NetConfig net_config;

NetConfig::NetConfig() {
    host = getenv("WCHOST");
    portstr = getenv("WCPORT");
    port = portstr ? (uint16_t)atoi(portstr) : 0;
    if (port < 1024) {
        fprintf(stderr, "You must set the WCPORT and (optionally) WCHOST env variables!\n");
        abort();
    }
}

int really_close(int s) {
    int retval = -1;
    while ((retval = close(s)) == -1 && errno == EINTR) {}
    return retval;
}

// SendOrRecvFunction(void*, size_t) -> ssize_t
template <class BufferType, class SendOrRecvFunction>
ptrdiff_t send_or_recv_all(const SendOrRecvFunction &sorf, BufferType *buffer, size_t size) {
    if (size == 0) {
        fprintf(stderr, "Warning: ask to send or recv of size 0\n");
    }
    const BufferType* constbuffer = const_cast<const BufferType *>(buffer);
    static_assert(sizeof(*buffer)==1, "buffer must be possibly const char*");

    size_t read_so_far = 0;
    while (size) {
        ptrdiff_t cur = sorf(buffer, size);
        if (cur < 0) {
            if (errno == EINTR) {
                continue;
            }
            return cur;
        } else if (cur == 0) {
            return read_so_far;
        } else {
            read_so_far += cur;
            buffer += cur;
            size -= cur;
        }
    }
    return read_so_far;
}

class SendFunctor {
    int mSocket;
public:
    SendFunctor(int socket) : mSocket(socket) {
    }

    ssize_t operator() (const void* data, size_t len) const {
        return ::send(mSocket, data, len, 0);
    }
};

class RecvFunctor {
    int mSocket;
public:
    RecvFunctor(int socket) : mSocket(socket) {
    }

    ssize_t operator() (void* data, size_t len) const {
        return ::recv(mSocket, data, len, 0);
    }
};

class ReadFunctor {
    int mFd;
public:
    ReadFunctor(int fd) : mFd(fd) {
    }

    ssize_t operator() (void* data, size_t len) const {
        return ::read(mFd, data, len);
    }
};

struct RemoteClient {
    int clientSocket;
    std::string callsign;
    RemoteClient() {
        clientSocket = -1;
    }
    bool is_disconnected() const {
        return clientSocket == -1;
    }
    void disconnect() {
        if (clientSocket != -1) {
            really_close(clientSocket);
        }
        clientSocket = -1;
    }
};
struct ServerState {
	int listenSocket;
    typedef std::vector<RemoteClient> ClientVec;
	ClientVec clients;
    ServerState() {
        listenSocket = -1;
    }
    ~ServerState() {
        if (listenSocket != -1) {
            really_close(listenSocket);
        }
        for (ServerState::ClientVec::iterator c = clients.begin(), ce=clients.end(); c != ce; ++c) {
            c->disconnect();
        }
    }
} *server;

struct ClientState {
	int clientSocket;
    ClientState() {
        clientSocket = -1;
    }
    ~ClientState() {
        if (clientSocket != -1) {
            really_close(clientSocket);
        }
    }
} *client;

int manualDoDamage = 0;




int fire_fifo = open("/tmp/fire.fifo", O_RDONLY|O_NONBLOCK);
FILE *memlog = fopen("/tmp/mem.txt", "a");
FILE *debuglog = fopen("/tmp/debug.txt", "a");

void uninit_network() {
    if (server) {
        delete server;
        server = NULL;
    }
    if (client) {
        delete client;
        client = NULL;
    }
}

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
            fprintf(stderr, "socket error during ");
            perror(cause);
            uninit_network();
            freeaddrinfo(res0);
            return;
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

struct RecvStatus {
    bool _ok;
    static RecvStatus OK() {
        RecvStatus ret;
        ret._ok = true;
        return ret;
    }
    static RecvStatus FAIL() {
        RecvStatus ret;
        ret._ok = false;
        return ret;
    }
    bool ok() const {
        return _ok;
    }
};

template<bool (NetworkMessage::*Checker)() const>
RecvStatus recv_msg(int sock, NetworkMessage &msg) {
    NetworkMessage networkMessage;
    unsigned char lengthData[3];
    ssize_t ret;
    if ((ret = send_or_recv_all(RecvFunctor(sock), lengthData, sizeof(lengthData))) < sizeof(lengthData)) {
        // We need to handle disconnects here.
        if (ret < 0) {
            perror("recv length failed");
        } else {
            fprintf(stderr, "recv length socket closed %d\n", (int)ret);
        }
        return RecvStatus::FAIL();
    }
    size_t dataLength = ((size_t)lengthData[0] << 16) |
        ((size_t)lengthData[1] << 8) |
        ((size_t)lengthData[2]);
    if (dataLength == 0) {
        fprintf(stderr, "empty message received!\n");
        return RecvStatus::FAIL();
    }
    std::vector<unsigned char> recvData(dataLength);
    if ((ret = send_or_recv_all(RecvFunctor(sock), recvData.data(), recvData.size())) < recvData.size()) {
        // We need to handle disconnects here.
        if (ret < 0) {
            perror("recv data failed");
        } else {
            fprintf(stderr, "recv data socket closed %d\n", (int)ret);
        }
        return RecvStatus::FAIL();
    }
    bool success = msg.ParseFromArray(recvData.data(), recvData.size());
    if (!success) {
        fprintf(stderr, "protobuf parse failed\n");
        return RecvStatus::FAIL();
    }
    if (!(msg.*Checker)()) {
        const char *type = NULL;
        if (msg.has_connect()) {
            type = type ? "multi" : "connect";
        }
        if (msg.has_game()) {
            type = type ? "multi" : "game";
        }
        if (msg.has_frame()) {
            type = type ? "multi" : "frame";
        }
        type = type ? type : "none";
        fprintf(stderr, "type mismatch want %s have %s\n",
#if defined(__GNUC__)
                __PRETTY_FUNCTION__
#elif defined(_MSC_VER)
                __FUNCSIG__
#else
                "unknown"
#endif
                , type);
        return RecvStatus::FAIL();
    }

    return RecvStatus::OK();
}

RecvStatus send_msg(int sock, const NetworkMessage &msg) {
    std::string toSend = "XXX";
    bool success = msg.AppendToString(&toSend); // encode protobuf
    if (!success) {
        fprintf(stderr, "serialize failed\n");
        abort();
    }
    size_t dataLength = toSend.length() - 3;
    if (dataLength >= (1L<<24)) {
        fprintf(stderr, "protobuf output too large\n");
        abort();
    }
    if (dataLength == 0) {
        fprintf(stderr, "protobuf output too small %d\n", (int)dataLength);
        abort();
    }
    toSend[0] = (char)(dataLength >> 16);
    toSend[1] = (char)(dataLength >> 8);
    toSend[2] = (char)(dataLength);
    fprintf(stderr, "start send %d\n", dataLength);
    if (send_or_recv_all(SendFunctor(sock), toSend.data(), toSend.length()) < 0) {
        // We need to handle disconnects here.
        perror("send failed");
        return RecvStatus::FAIL();
    }
    return RecvStatus::OK();
}

void populate_server_frame(Frame *frame) {
}

void populate_client_frame(Frame *frame) {
}

void apply_frame(const Frame &frame) {
}

void process_network() {
    static NetworkMessage networkMessage;
    networkMessage.Clear();
    if (!client && !server) {
        init_network();
        if (client) {
            networkMessage.Clear();
            Connect *connect = networkMessage.mutable_connect();
            connect->set_callsign("Maniac");
            if (!send_msg(client->clientSocket, networkMessage).ok()) {
                uninit_network();
                return;
            }
            networkMessage.Clear();
            if (!recv_msg<&NetworkMessage::has_game>(client->clientSocket, networkMessage).ok()) {
                uninit_network();
                return;
            }
            const Game &game = networkMessage.game();
            if (game.has_starting_state()) {
                apply_frame(game.starting_state());
            }
        }
    }

    if (server) {
        for (ServerState::ClientVec::iterator c = server->clients.begin(), ce=server->clients.end(); c != ce; ++c) {
            if (!c->is_disconnected()) {
                if (!recv_msg<&NetworkMessage::has_frame>(c->clientSocket, networkMessage).ok()) {
                    c->disconnect();
                }
            }
        }
        for (ServerState::ClientVec::iterator c = server->clients.begin(), ce=server->clients.end(); c != ce; ++c) {
            if (c->is_disconnected()) {
                networkMessage.Clear();
                Frame *frame = networkMessage.mutable_frame();
                populate_server_frame(frame);
                if (!send_msg(c->clientSocket, networkMessage).ok()) { // Frame
                    c->disconnect();
                }
            }
        }
        while (!server->clients.empty()) {
            if (server->clients.back().is_disconnected())  {
                server->clients.pop_back();
            } else {
                break;
            }
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
            if (!recv_msg<&NetworkMessage::has_connect>(s, networkMessage).ok()) {
                really_close(s);
                break;
            }
            const Connect &connect = networkMessage.connect();
            fprintf(stderr, "Some guy connected: %s\n", connect.callsign().c_str());
            networkMessage.Clear();
            Game * game = networkMessage.mutable_game();
            Frame * frame = game->mutable_starting_state();
            populate_server_frame(frame);
            if (!send_msg(s, networkMessage).ok()) {
                really_close(s);
                break;
            }
            bool found = false;
            RemoteClient cl;
            cl.clientSocket = s;
            cl.callsign = "UNKNOWN";
            for (ServerState::ClientVec::iterator c = server->clients.begin(), ce=server->clients.end(); c != ce; ++c) {
                if (c->is_disconnected()) {
                    *c = cl;
                    found = true;
                }
            }
            if (!found) {
                server->clients.push_back(cl);
            }
        }
    } else if (client) {
        networkMessage.Clear();
        Frame *frame = networkMessage.mutable_frame();
        populate_client_frame(frame);
        if (!send_msg(client->clientSocket, networkMessage).ok()) {
            uninit_network();
            return;
        }
        if (!recv_msg<&NetworkMessage::has_frame>(client->clientSocket, networkMessage).ok()) { // Frame
            uninit_network();
            return;
        }
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
                send_or_recv_all(ReadFunctor(fire_fifo), &buf, 1);
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
