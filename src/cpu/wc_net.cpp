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

bool DEBUG_PROTOBUF =
#ifdef HEAVY_NET_DEBUG
    true
#else
    false
#endif
    ;

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
    STATIC_ASSERT(sizeof(*buffer)==1, "buffer must be possibly const char*");

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
    NetworkShipId id;
    int clientSocket;
    std::string callsign;
    RemoteClient(NetworkShipId id)
      : clientSocket(-1),
        id(id) {
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
    std::vector<NetworkShipId> allowedShipIds;

    ServerState() {
        listenSocket = -1;
        allowedShipIds.push_back(NetworkShipId::from_net(1));
        allowedShipIds.push_back(NetworkShipId::from_net(3));
    }

    RemoteClient *get_client(NetworkShipId id) {
        int ship_id = id.to_net();
        if (ship_id >= clients.size()) {
            return NULL;
        }
        if (!clients[ship_id].is_disconnected()) {
            return &clients[ship_id];
        }
        return NULL;
    }

    RemoteClient *create_client() {
        for (std::vector<NetworkShipId>::const_iterator it = allowedShipIds.begin(), ite = allowedShipIds.end(); it != ite; ++it) {
            int ship_id = it->to_net();
            while (ship_id >= clients.size()) {
                clients.push_back(RemoteClient(NetworkShipId::from_net(clients.size())));
            }
            if (clients[ship_id].is_disconnected()) {
                return &clients[ship_id];
            }
        }
        return NULL;
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
    NetworkShipId shipId;
    std::string callsign;
    ClientState()
      : clientSocket(-1),
        shipId(NetworkShipId::from_net(0))
    {
        const char *cs = getenv("WCCALLSIGN");
        if (cs) {
            callsign = cs;
        }
        if (callsign.empty()) {
            callsign = "Maniac";
        }
    }
    ~ClientState() {
        if (clientSocket != -1) {
            really_close(clientSocket);
        }
    }
    bool is_authoritative(NetworkShipId id) {
        if (id == this->shipId) {
            return true;
        }
        return false;
    }
} *client;

struct PendingState {
    NetworkMessage frameMessage;

    Frame &frame () {
        return *frameMessage.mutable_frame();
    }

} pendingState;

ShipUpdate &get_update(Frame &fr, NetworkShipId id) {
    int ship_id = id.to_net();
    while (ship_id >= fr.update_size()) {
        fr.add_update();
    }

    ShipUpdate *ret = fr.mutable_update(ship_id);
    ret->set_ship_id(ship_id);
    return *ret;
}

int NetworkShipId::remap_ship_id(int ship_id) {
    if (!client) {
        return ship_id; // server does not remap.
    }
    if (ship_id == 0) {
        return client->shipId.to_net();
    }
    if (ship_id == client->shipId.to_net()) {
        return 0;
    }
    return ship_id;
}

bool should_simulate_damage(NetworkShipId src, NetworkShipId dst) {
    if (client) {
        return false; //return (src_ship_id == 0 || dst_ship_id == 0);
    }
    if (server) {
        return true;
        /*
        if (server->get_client(src_ship_id) || server->get_client(dst_ship_id)) {
        }
        for (size_t i = 0; i < server->clients.size(); i++) {
            if (
        }
        return (src_ship_id
        */
    }
    fprintf(stderr, "Not client or server\n");
    return false;
}

bool should_simulate_fire(NetworkShipId src) {
    if (client) {
        return src == client->shipId;
    }
    if (server) {
        return server->get_client(src) == NULL;
    }
    fprintf(stderr, "Not client or server\n");
    return false;
}

bool is_client_authoritative(NetworkShipId sender, NetworkShipId id) {
    return sender == id;
}

int manualDoDamage = 0;
int manualDoFire = 0;

int fire_fifo = open("/tmp/fire.fifo", O_RDONLY|O_NONBLOCK);
FILE *memlog = fopen("/tmp/mem.txt", "a");
FILE *debuglog = fopen("/tmp/debug.txt", "a");

void uninit_network() {
    pendingState.frameMessage.Clear();
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
            int enable = 1;
            if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
                perror("setsockopt(SO_REUSEADDR) failed");
                abort();
            }
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

const char * message_type(const NetworkMessage &msg) {
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
    return type;
}
template<bool (NetworkMessage::*Checker)() const>
RecvStatus recv_msg(int sock, NetworkMessage &msg) {
    NetworkMessage networkMessage;
    unsigned char lengthData[3];
    ssize_t ret;
    const char * func_type = 
#if defined(__GNUC__)
                __PRETTY_FUNCTION__
#elif defined(_MSC_VER)
                __FUNCSIG__
#else
                "unknown"
#endif
        ;
#ifdef HEAVY_NET_DEBUG
    fprintf(stderr, "Begin Receive %s\n",
                func_type);
#endif
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
        fprintf(stderr, "type mismatch want %s have %s\n",
                func_type,
                message_type(msg));

        return RecvStatus::FAIL();
    }
#ifdef HEAVY_NET_DEBUG
    fprintf(stderr, "Finished message %s have %s len %d\n",
            func_type,
            message_type(msg),
            (int)recvData.size() + 3);
#endif

    if (DEBUG_PROTOBUF) {
        std::string debug = msg.DebugString();
        fprintf(stderr, "%s\n", debug.c_str());
    }
    return RecvStatus::OK();
}

RecvStatus send_msg(int sock, const NetworkMessage &msg) {
    if (DEBUG_PROTOBUF) {
        std::string debug = msg.DebugString();
        fprintf(stderr, "SEND %s\n", debug.c_str());
    }
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
#ifdef HEAVY_NET_DEBUG
    fprintf(stderr, "start send %s: %d\n", message_type(msg), (int)dataLength);
#endif
    if (send_or_recv_all(SendFunctor(sock), toSend.data(), toSend.length()) < 0) {
        // We need to handle disconnects here.
        perror("send failed");
        return RecvStatus::FAIL();
    }
#ifdef HEAVY_NET_DEBUG
    fprintf(stderr, "send ok %d\n", (int)dataLength);
#endif
    return RecvStatus::OK();
}

const int DS = 0x13d3;
const int DS_OFF = DS * 0x10;
enum DataSegValues {
    DS_Pos = 0xA9C2,
    DS_Vel = 0xCAE2,
    DS_Right = 0xAEB6,
    DS_Up = 0xB1B6,
    DS_Forward = 0xB4B6,
    DS_RandomSeed = 0x7728,
    DS_loading_wing_commander = 0x0187,
    DS_error_has_occurred = 0x0395,
    shellcode_start = DS_error_has_occurred, // 249 bytes
    DS_tmpvector = DS_loading_wing_commander // 107 bytes
    //DS_tmpvector = DS_Pos + (12 * 0x3f)
};

template <class VectorClass>
void populate_vector(VectorClass *vec, int addr, NetworkShipId array_index) {
    return populate_vector(vec, addr + 12 * array_index.to_local());
}

template <class VectorClass>
void populate_vector(VectorClass *vec, int naddr) {
    int faraddr = DS_OFF + naddr;
    unsigned int valx;
    unsigned int valy;
    unsigned int valz;
    mem_readd_checked(faraddr, &valx);
    mem_readd_checked(faraddr + 0x4, &valy);
    mem_readd_checked(faraddr + 0x8, &valz);
    vec->set_x((int)valx);
    vec->set_y((int)valy);
    vec->set_z((int)valz);
}

template <class VectorClass>
void store_vector(const VectorClass &vec, int addr, NetworkShipId array_index) {
    return store_vector(vec, addr + 12 * array_index.to_local());
}

template <class VectorClass>
void store_vector(const VectorClass &vec, int naddr) {
    int faraddr = DS_OFF + naddr;
    mem_writed(faraddr, vec.x());
    mem_writed(faraddr + 0x4, vec.y());
    mem_writed(faraddr + 0x8, vec.z());
}

void populate_ship_update(Frame *frame, NetworkShipId ship_id) {
    ShipUpdate &su = get_update(*frame, ship_id);
    su.set_ship_id(ship_id.to_net());
    Location *loc = su.mutable_loc();
    populate_vector(loc->mutable_pos(), DS_Pos, ship_id);
    populate_vector(loc->mutable_vel(), DS_Vel, ship_id);
    populate_vector(loc->mutable_right(), DS_Right, ship_id);
    populate_vector(loc->mutable_up(), DS_Up, ship_id);
    populate_vector(loc->mutable_fore(), DS_Forward, ship_id);
}

void populate_server_frame(Frame *frame) {
    for (int i = 0; i < 0x3c; i++) {
        populate_ship_update(frame, NetworkShipId::from_net(i));
    }
}

void populate_client_frame(Frame *frame) {
    populate_ship_update(frame, client->shipId);
}

void apply_ship_update_location(const ShipUpdate &su) {
    if (!su.has_ship_id()) {
        return;
    }
    NetworkShipId ship_id = NetworkShipId::from_net(su.ship_id());
    if (!su.has_loc()) {
        return;
    }
    const Location &loc = su.loc();
    if (loc.has_pos()) {
        store_vector(loc.pos(), DS_Pos, ship_id);
    }
    if (loc.has_vel()) {
        store_vector(loc.vel(), DS_Vel, ship_id);
    }
    if (loc.has_right() && loc.has_up() && loc.has_fore()) {
        store_vector(loc.right(), DS_Right, ship_id);
        store_vector(loc.up(), DS_Up, ship_id);
        store_vector(loc.fore(), DS_Forward, ship_id);
    }
}

void apply_damage(const Damage &dam, NetworkShipId ship_id) {
    int dam_src = -1;
    if (dam.has_src()) {
        dam_src = dam.src();
    }
    /*if (!should_simulate_damage(ship_id, dam_src)) {
        return;
    }*/
    int src = -1;
    if (dam.has_src()) {
        src = NetworkShipId::from_net(dam.src()).to_local();
    }
    int dst = ship_id.to_local();
    int dbgx, dbgy, dbgz;
    if (dam.has_pos()) {
        store_vector(dam.pos(), DS_tmpvector);
        dbgx = dam.pos().x();
        dbgy = dam.pos().y();
        dbgz = dam.pos().z();
    } else {
        Vector defaultPos;
        defaultPos.set_x(0);
        defaultPos.set_y(0);
        defaultPos.set_z(256);
        dbgx = 0;
        dbgy = 0;
        dbgz = 256;
        store_vector(defaultPos, DS_tmpvector);
    }
        ;
    fprintf(stderr, "\r\napply_damage(%d->%d, %d->%d, %d, <%d, %d, %d>) rng=%x\r\n",
            NetworkShipId::from_local(src).to_net(), src, NetworkShipId::from_local(dst).to_net(), dst, dam.quantity(), dbgx, dbgy, dbgz, dam.seed());
    {
        CPU_Push16((Bit16u)SegValue(cs));
        CPU_Push16((Bit16u)reg_eip);
        if (dam.has_seed()) {
            mem_writed(DS_OFF + DS_RandomSeed, dam.seed());
        }
        unsigned short arg_0 = src, arg_2 = dst, arg_4 = dam.quantity(), arg_6 = DS_tmpvector;
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
            mem_writeb_checked(DS_OFF + shellcode_start + i, shellcode[i]);
        }
        manualDoDamage ++;
        SegSet16(cs, DS);
        reg_eip = shellcode_start + 1;
        fprintf(debuglog, "cs:eip = %04x:%04x\n", SegValue(cs), reg_eip);
    }
}

void apply_weapon_fire(const WeaponFire &fire, NetworkShipId id) {
    /*if (!should_simulate_damage(ship_id, ship_id)) {
        return;
    }*/
    uint32_t gun_id = 0;
    if (fire.has_gun_id()) {
        gun_id = fire.gun_id();
    }
    uint32_t ship_id = id.to_local();
    fprintf(stderr, "\r\napply_fire(%d->%d, %d)\r\n",
            id.to_net(), id.to_local(), gun_id);
    {
        CPU_Push16((Bit16u)SegValue(cs));
        CPU_Push16((Bit16u)reg_eip);
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
            mem_writeb_checked(DS_OFF + shellcode_start + i, shellcode[i]);
        }
        manualDoFire ++;
        SegSet16(cs, DS);
        reg_eip = shellcode_start + 1;
        fprintf(debuglog, "cs:eip = %04x:%04x\n", SegValue(cs), reg_eip);
    }
}

void merge_pending_frame(RemoteClient *sender, const Frame &frame) {
    for (int i = 0; i < frame.update_size(); i++) {
        const ShipUpdate &su = frame.update(i);
        if (!su.has_ship_id()) {
            continue;
        }
        NetworkShipId ship_id = NetworkShipId::from_net(su.ship_id());
        ShipUpdate *update = &get_update(pendingState.frame(), ship_id);
        if (sender && is_client_authoritative(sender->id, ship_id)) {
            if (su.has_loc()) {
                *update->mutable_loc() = su.loc();
            }
        }
        for (int i = 0; i < su.fire_size(); i++) {
            const WeaponFire &fire = su.fire(i);
            *update->add_fire() = fire;
        }
        for (int i = 0; i < su.damage_size(); i++) {
            const Damage &dam = su.damage(i);
            *update->add_damage() = dam;
        }
    }
}

void apply_frame(const Frame &frame) {
    for (int i = 0; i < frame.update_size(); i++) {
        const ShipUpdate &su = frame.update(i);
        if (!su.has_ship_id()) {
            continue;
        }
        NetworkShipId ship_id = NetworkShipId::from_net(su.ship_id());
        if ((client && !client->is_authoritative(ship_id)) || (server && ship_id.to_local() != 0)) {
            apply_ship_update_location(su);
        }
    }
    for (int i = 0; i < frame.update_size(); i++) {
        const ShipUpdate &su = frame.update(i);
        if (!su.has_ship_id()) {
            return;
        }
        NetworkShipId ship_id = NetworkShipId::from_net(su.ship_id());
        for (int i = 0; i < su.fire_size(); i++) {
            const WeaponFire &fire = su.fire(i);
            apply_weapon_fire(fire, ship_id);
            return; // FIXME: Bugs happen when pushing more than one call to the stack per frame
        }
    }
    for (int i = 0; i < frame.update_size(); i++) {
        const ShipUpdate &su = frame.update(i);
        if (!su.has_ship_id()) {
            return;
        }
        NetworkShipId ship_id = NetworkShipId::from_net(su.ship_id());
        for (int i = 0; i < su.damage_size(); i++) {
            const Damage &dam = su.damage(i);
            apply_damage(dam, ship_id);
            return; // FIXME: Bugs happen when pushing more than one call to the stack per frame
        }
    }
}

void apply_starting_frame(const Frame &frame) {
    for (int i = 0; i < frame.update_size(); i++) {
        const ShipUpdate &su = frame.update(i);
        if (!su.has_ship_id()) {
            continue;
        }
        apply_ship_update_location(su);
    }
}

void process_network() {
    static NetworkMessage networkMessage;
    networkMessage.Clear();
    if (!client && !server) {
        init_network();
        if (client) {
            networkMessage.Clear();
            Connect *connect = networkMessage.mutable_connect();
            connect->set_callsign(client->callsign);
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
                client->shipId = NetworkShipId::from_net(game.assigned_player_id());
                apply_starting_frame(game.starting_state());
            }
        }
    }

    if (server) {
        populate_server_frame(&pendingState.frame());
        for (ServerState::ClientVec::iterator c = server->clients.begin(), ce=server->clients.end(); c != ce; ++c) {
            if (!c->is_disconnected()) {
                if (!recv_msg<&NetworkMessage::has_frame>(c->clientSocket, networkMessage).ok()) {
                    c->disconnect();
                    continue;
                }
                merge_pending_frame(&*c, networkMessage.frame());
            }
        }
        apply_frame(pendingState.frame());
        for (ServerState::ClientVec::iterator c = server->clients.begin(), ce=server->clients.end(); c != ce; ++c) {
            if (!c->is_disconnected()) {
                if (!send_msg(c->clientSocket, pendingState.frameMessage).ok()) { // Frame
                    c->disconnect();
                }
            }
        }
        pendingState.frameMessage.Clear();
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
                if (errno != EWOULDBLOCK && errno != EAGAIN) {
                    perror("accept failed");
                }
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
            RemoteClient * cl = server->create_client();
            if (!cl) {
                really_close(s);
                break;
            }
            cl->clientSocket = s;
            cl->callsign = connect.callsign();

            networkMessage.Clear();
            Game * game = networkMessage.mutable_game();
            game->set_assigned_player_id(cl->id.to_net());
            Frame * frame = game->mutable_starting_state();
            populate_server_frame(frame);
            if (!send_msg(s, networkMessage).ok()) {
                cl->disconnect();
                break;
            }
        }
    } else if (client) {
        networkMessage.Clear();
        populate_client_frame(&pendingState.frame());
        if (!send_msg(client->clientSocket, pendingState.frameMessage).ok()) {
            uninit_network();
            return;
        }
        pendingState.frameMessage.Clear();
        if (!recv_msg<&NetworkMessage::has_frame>(client->clientSocket, networkMessage).ok()) { // Frame
            uninit_network();
            return;
        }
        apply_frame(networkMessage.frame());
    }

    {
        char buf[1];
        if (read(fire_fifo, &buf, 1) > 0) {
            fprintf(debuglog, "cs:eip = %04x:%04x\n", SegValue(cs), reg_eip);
            if (buf[0] == ' ') { // fire all guns
                CPU_Push16((Bit16u)SegValue(cs));
                CPU_Push16((Bit16u)reg_eip);
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
                    mem_writeb_checked(DS_OFF + shellcode_start + i, shellcode[i]);
                }
                SegSet16(cs, DS);
                reg_eip = shellcode_start + 1;
                fprintf(debuglog, "cs:eip = %04x:%04x\n", SegValue(cs), reg_eip);
            } else if (buf[0] == ',') {
                CPU_Push16((Bit16u)SegValue(cs));
                CPU_Push16((Bit16u)reg_eip);
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
                    mem_writeb_checked(DS_OFF + shellcode_start + i, shellcode[i]);
                }
                SegSet16(cs, DS);
                reg_eip = shellcode_start + 1;
                fprintf(debuglog, "cs:eip = %04x:%04x\n", SegValue(cs), reg_eip);
            } else if (buf[0] == '.') {
                CPU_Push16((Bit16u)SegValue(cs));
                CPU_Push16((Bit16u)reg_eip);
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
                    mem_writeb_checked(DS_OFF + shellcode_start + i, shellcode[i]);
                }
                SegSet16(cs, DS);
                reg_eip = shellcode_start + 1;
                fprintf(debuglog, "cs:eip = %04x:%04x\n", SegValue(cs), reg_eip);
            } else if (buf[0] == 'f') { // fire one gun from a selected ship
                CPU_Push16((Bit16u)SegValue(cs));
                CPU_Push16((Bit16u)reg_eip);
                manualDoFire ++;
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
                    mem_writeb_checked(DS_OFF + shellcode_start + i, shellcode[i]);
                }
                SegSet16(cs, DS);
                reg_eip = shellcode_start + 1;
                fprintf(debuglog, "cs:eip = %04x:%04x\n", SegValue(cs), reg_eip);
            } else if (buf[0] == 'F') { // fire one gun from a selected ship
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
                WeaponFire wf;
                wf.set_gun_id(gun_id);
                apply_weapon_fire(wf, NetworkShipId::from_local(ship_id));
            } else if (buf[0] == 'd') {
                CPU_Push16((Bit16u)SegValue(cs));
                CPU_Push16((Bit16u)reg_eip);
                manualDoDamage ++;
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
                    // call far 12d7:0084
                    0x9A, 0x84, 0x00, 0xd7, 0x12,
                    // pop si, pop si, pop all regs, pop flags, retf
                    0x5E, 0x5E, 0x5E, 0x5E, 0x61, 0x9D, 0xCB
                };
                for (int i = 0; i < sizeof(shellcode); i++) {
                    mem_writeb_checked(DS_OFF + shellcode_start + i, shellcode[i]);
                }
                SegSet16(cs, DS);
                reg_eip = shellcode_start + 1;
                fprintf(debuglog, "cs:eip = %04x:%04x\n", SegValue(cs), reg_eip);
            }
        }
    }

}

void damage_hook() {
    NetworkShipId src = NetworkShipId::from_memory_word(DS_OFF + reg_esp + 4);
    NetworkShipId dst = NetworkShipId::from_memory_word(DS_OFF + reg_esp + 6);
    Bit16u quantity = mem_readw(DS_OFF + reg_esp + 8);
    Bit16u vectorAddr = mem_readw(DS_OFF + reg_esp + 10);
    Bit32u randomSeed = mem_readd(DS_OFF + DS_RandomSeed);
    Vector localVec;
    Vector *vec = &localVec;
    bool shouldSim = false;
    if (should_simulate_damage(src, dst)) {
        shouldSim = true;
        ShipUpdate &update = get_update(pendingState.frame(), dst);
        Damage *damage = update.add_damage();
        damage->set_src(src.to_net());
        damage->set_quantity(quantity);
        vec = damage->mutable_pos();
        damage->set_seed(randomSeed);
    }
    populate_vector(vec, vectorAddr);
    fprintf(stderr, "\r\ndoDamage%s(%d->%d, %d->%d, %d, <%d, %d, %d>) rng=%x\r\n",
            shouldSim ? "[simulated]" : "[ignored]",
            src.to_net(), src.to_local(), dst.to_net(), dst.to_local(), quantity, vec->x(), vec->y(), vec->z(), randomSeed);

    // return -- do not apply damage
    reg_eip = 0x0d44;
}

void fire_hook() {
    NetworkShipId src = NetworkShipId::from_memory_word(DS_OFF + reg_esp + 4);
    Bit16u gun_id = mem_readw(DS_OFF + reg_esp + 6);
    //Bit32u randomSeed = mem_readd(DS_OFF + DS_RandomSeed);
    bool shouldSim = false;
    if (should_simulate_fire(src)) {
        shouldSim = true;
        ShipUpdate &update = get_update(pendingState.frame(), src);
        WeaponFire *fire = update.add_fire();
        fire->set_gun_id(gun_id);
    }
    fprintf(stderr, "\r\ndoFire%s(%d, %d)\r\n",
            shouldSim ? "[simulated]" : "[ignored]",
            src.to_net(), gun_id);

    // return -- do not apply damage
    reg_eip = 0x0d44;
}

void process_fire() {
    // beginning of doDamage.
    if (manualDoFire) {
        manualDoFire --;
    } else {
        fire_hook();
    }
}

void process_damage() {
    // beginning of doDamage.
    if (manualDoDamage) {
        manualDoDamage --;
    } else {
        damage_hook();
    }
}
