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
#include <deque>
#include <sstream>
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

// only in heavy debug;
extern bool forceBreak;



NetConfig::NetConfig() {
    host = getenv("WCHOST");
    portstr = getenv("WCPORT");
    portstr = portstr ? portstr : "13255";
    port = (uint16_t)atoi(portstr);
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
        allowedShipIds.push_back(NetworkShipId::client_wingman_id());
        //allowedShipIds.push_back(NetworkShipId::from_net(3, 0));
    }

    RemoteClient *get_client(NetworkShipId id) {
        int ship_id = id.to_local();
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
            int ship_id = it->to_local();
            if (ship_id < 0) {
                return NULL;
            }
            while (ship_id >= clients.size()) {
                clients.push_back(RemoteClient(NetworkShipId::from_local(clients.size())));
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
    std::vector<int> netToLocalMapping;
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
    int local_to_net(int localid) {
        // Don't interact with NetworkShipId objects in here.
        for (unsigned int i = 0; i < netToLocalMapping.size(); i++) {
            if (netToLocalMapping[i] == localid) {
                return i;
            }
        }
        fprintf(stderr, "Failed to find local_to_net %d!\n", localid);
        return localid;
    }
    int net_to_local(int netid) {
        // Don't interact with NetworkShipId objects in here.
        if (netid < 0 || netid >= netToLocalMapping.size()) {
            fprintf(stderr, "Received invalid ship %d!\n", netid);
            return netid;
        }
        if (netToLocalMapping[netid] == -1) {
            fprintf(stderr, "Failed to find net_to_local %d!\n", netid);
            return netid;
        }
        return netToLocalMapping[netid];
    }
    void insert_spawn_id(int netid, int localid) {
        if (netid < WCE_MIN_PERMANENT_ID || netid > WCE_MAX_PERMANENT_ID) {
            fprintf(stderr, "Avoid inserting temporary object %d to %d!\n",
                    netid, localid);
            return;
        }
        while (netToLocalMapping.size() <= netid) {
            netToLocalMapping.push_back(-1);
        }
        if (netid == this->shipId.to_net()) {
            netToLocalMapping[netid] = 0; // this client must fly the player ship 0
            netToLocalMapping[0] = localid; // the server's player ship gets what just spawned.
        } else {
            netToLocalMapping[netid] = localid;
        }
    }
} *client;

struct PendingState {
    NetworkMessage frameMessage;
    std::map<NetworkShipId, Spawn> currentlySpawnedShips;

    Frame &frame () {
        return *frameMessage.mutable_frame();
    }

    void add_ship(const Spawn &spawn) {
        if (!spawn.has_ship_id()) {
            return;
        }
        NetworkShipId shipId = NetworkShipId::from_net(spawn.ship_id());
        if (currentlySpawnedShips.find(shipId) != currentlySpawnedShips.end()) {
            fprintf(stderr, "Spawn ship %d already in currentlySpawnedShips.\n",
                    shipId.to_net());
        }
        currentlySpawnedShips[shipId] = spawn;
    }

    void remove_ship(NetworkShipId shipId) {
        if (currentlySpawnedShips.erase(shipId) == 0) {
            fprintf(stderr, "Despawn ship %d not in currentlySpawnedShips.\n",
                    shipId.to_net());
        }
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

NetworkShipId NetworkShipId::remap_ship_id_to_net(int ship_id) {
    if (!server && !client) {
        return NetworkShipId::make_invalid; // server does not remap.
    }
    if (ship_id >= WCE_MIN_TEMPORARY_ID && ship_id <= WCE_MAX_TEMPORARY_ID) {
        return NetworkShipId::make_invalid;
    }
    NetworkShipId ret;
    // mapping of server-sent spawn-ids to return of id generation on client.
    if (client) {
        ret = client->local_to_net(ship_id);
    }
    if (server) {
        ret = server->local_to_net(ship_id);
    }
    if (ship_id == 0) {
        if (ret != client->shipId.to_net()) {
            fprintf(stderr, "Assertion: server ship id must return client id\n");
        }
    }
    if (ship_id == client->shipId.to_net()) {
        if (ret != 0) {
            fprintf(stderr, "Assertion: client ship id must return 0\n");
        }
    }
    return ret;
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

bool is_client_authoritative(NetworkShipId sender, NetworkShipId id) {
    return sender == id;
}

std::deque<Event> queuedEvents;
Event gCurrentEvent;

bool isServer = (getenv("WCHOST") == NULL);
int manualSpawnShip = -1;
int manualDespawnShip = -1;
int gFrameNum = 0;
bool gIgnoreNextProcessNetwork = false;
bool gIsProcessingTrampoline = false;

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

const Bit8u trampoline_code[6] = {
    0x55, // PUSH BP
    0x8B, // MOV SP, BP
    0xEC, // MOV SP, BP
    0x90, //NOP <-- We hook into this instruction.
    0x5D, //POP BP
    0xCB //RETF
};

const int DS = 0x13d3;
const int DS_OFF = DS * 0x10;
const Bit8u Instr_RETF = 0xCB;
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
    DS_tmpvector = DS_loading_wing_commander, // 12 bytes
    DS_mission_loader = DS_loading_wing_commander + 12, // ???
    DS_trampoline = DS_loading_wing_commander + 101, // 6 bytes
    DS_tramp_ret_NOP = DS_trampoline + 3, // NOP instruction we hook into
    //DS_tmpvector = DS_Pos + (12 * 0x3f)
    DS_entity_types = 0xBD1A,
    DS_entity_allocated = 0xACC4
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

static NetworkShipId find_first_free_ship_entity() {
    for (Bit16u i = WCE_MIN_PERMANENT_ID; i <= WCE_MAX_PERMANENT_ID; i++) {
        if (mem_readw(DS_OFF + DS_entity_types + i * 2) == 0) {
            fprintf(stderr, "found free %d [%d->%d]\n", (int)i, NetworkShipId::from_local(i).to_net(), NetworkShipId::from_local(i).to_local());
            return NetworkShipId::from_local(i);
        }
    }
    fprintf(stderr, "Bad: no free ship entities!\n");
    return NetworkShipId::invalid();
}

/*
struct SavedShipEntities {
    Bit16u entities[WCE_MIN_TEMPORARY_ID];
};
std::vector<SavedShipEntities> saved_ship_types;
static void force_ship_spawn_entity_id(NetworkShipId whichShip) {
    if (!saved_ship_types.empty()) {
        fprintf(stderr, "BAD: restore_ship-entites again during restore\n");
    }
    Bit16u which = whichShip.to_local();
    SavedShipEntities sse;
    memset(&sse, 0, sizeof(sse));
    for (Bit16u i = 1; i < WCE_MIN_TEMPORARY_ID; i++) {
        Bit32u addr = DS_OFF + DS_entity_types + i * 2;
        sse.entities[i] = mem_readw(addr);
        if (i != which) {
            mem_writew(addr, 1);
        }
        if (i == which && mem_readw(addr) != 0) {
            fprintf(stderr, "Client desync: entity %d is %d not free\n",
                    which, mem_readw(addr));
        }
    }
    saved_ship_types.push_back(sse);
}

static void restore_ship_spawn_entities(NetworkShipId whichShip) {
    if (saved_ship_types.empty()) {
        fprintf(stderr, "BAD: restore_ship-entites called without match\n");
        return;
    }
    SavedShipEntities sse = saved_ship_types.back();
    saved_ship_types.pop_back();
    Bit16u which = whichShip.to_local();
    for (Bit16u i = 1; i < WCE_MIN_TEMPORARY_ID; i++) {
        Bit32u addr = DS_OFF + DS_entity_types + i * 2;
        if (i != which) {
            mem_writew (addr, sse.entities[i]);
        }
        if (i == which && mem_readw(addr) == 0) {
            fprintf(stderr, "Client desync: entity %d not successfully spawned\n",
                    which);
        }
    }
}
*/

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
    for (int i = 0; i <= WCE_MAX_PERMANENT_ID; i++) {
        Bit32u addr = DS_OFF + DS_entity_types + i * 2;
        Bit16u typ = mem_readw(addr);
        if (typ != 0) {
            populate_ship_update(frame, NetworkShipId::from_net(i));
        }
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

void apply_damage(const Damage &dam) {
    NetworkShipId ship_id = NetworkShipId::from_net(dam.ship_id());
    int dam_src = -1;
    if (dam.has_shooter()) {
        dam_src = dam.shooter();
    }
    /*if (!should_simulate_damage(ship_id, dam_src)) {
        return;
    }*/
    int src = -1;
    if (dam.has_shooter()) {
        src = NetworkShipId::from_net(dam.shooter()).to_local();
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
            //0x9C, //PUSHF
            //push all regs, xor si,si, push si
            //0x60, //PUSHA
            0x56, // push si (original value)
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
            // pop si (4 times)
            0x5E, 0x5E, 0x5E, 0x5E,
            // pop si (original value)
            0x5E,
            //0x61, 0x9D, // pop all regs, pop flags
            0xCB // retf
        };
        for (int i = 0; i < sizeof(shellcode); i++) {
            mem_writeb_checked(DS_OFF + shellcode_start + i, shellcode[i]);
        }
        SegSet16(cs, DS);
        reg_eip = shellcode_start + 1;
        fprintf(debuglog, "cs:eip = %04x:%04x\n", SegValue(cs), reg_eip);
    }
}

void apply_weapon_fire(const WeaponFire &fire) {
    /*if (!should_simulate_damage(ship_id, ship_id)) {
        return;
    }*/
    NetworkShipId id = NetworkShipId::from_net(fire.shooter());
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
            //0x9C, //PUSHF
            //push all regs, xor si,si, push si
            //0x60, //PUSHA
            0x56, // push si (original value)
            0xbe, gun_id & 0xff, gun_id >> 8,// mov si <-- gun_id
            0x56, // push si
            0xbe, ship_id & 0xff, ship_id >> 8, // mov si <- ship_id
            0x56, // push si
            // call far 12d7:012E
            0x9A, 0x2E, 0x01, 0xd7, 0x12,
            // pop si, pop si, pop si
            0x5E, 0x5E, 0x5E,
            //0x61, 0x9D, // pop all regs, pop flags
            0xCB // retf
        };
        for (int i = 0; i < sizeof(shellcode); i++) {
            mem_writeb_checked(DS_OFF + shellcode_start + i, shellcode[i]);
        }
        SegSet16(cs, DS);
        reg_eip = shellcode_start + 1;
        fprintf(debuglog, "cs:eip = %04x:%04x\n", SegValue(cs), reg_eip);
    }
}

void apply_spawn(const Spawn &spawn) {
    if (!spawn.has_mission_ship_id() || !spawn.has_situation_id()) {
        fprintf(stderr, "Invalid spawn event!\n");
        return;
    }
    /*
    if (spawn.has_ship_id()) {
        force_ship_spawn_entity_id(NetworkShipId::from_net(spawn.ship_id()));
    }*/
    uint32_t mission_ship_id = spawn.mission_ship_id();
    uint32_t situation_id = spawn.situation_id();
    fprintf(stderr, "\r\napply_spawn(%d, %d)\r\n",
            mission_ship_id, situation_id);
    {
        CPU_Push16((Bit16u)SegValue(cs));
        CPU_Push16((Bit16u)reg_eip);
        Bit8u shellcode[] = {
            0x00, // nul terminate string
            // push flags,
            //0x9C, //PUSHF
            //push all regs, xor si,si, push si
            //0x60, //PUSHA
            0x56, // push si (original value)
            0xbe, situation_id & 0xff, situation_id >> 8, // mov si <- ship_id
            0x56, // push si
            0xbe, mission_ship_id & 0xff, mission_ship_id >> 8,// mov si <-- gun_id
            0x56, // push si
            // call far 12f2:00b6
            0x9A, 0xB6, 0x00, 0xF2, 0x12,
            // pop si, pop si, pop si
            0x5E, 0x5E, 0x5E,
            //0x61, 0x9D, // pop all regs, pop flags
            0xCB // retf
        };
        for (int i = 0; i < sizeof(shellcode); i++) {
            mem_writeb_checked(DS_OFF + shellcode_start + i, shellcode[i]);
        }
        SegSet16(cs, DS);
        reg_eip = shellcode_start + 1;
        fprintf(debuglog, "cs:eip = %04x:%04x\n", SegValue(cs), reg_eip);
    }
}

void apply_despawn(const Despawn &despawn) {
    /*if (!should_simulate_damage(ship_id, ship_id)) {
        return;
    }*/
    if (!despawn.has_ship_id()) {
        return;
    }
    NetworkShipId id = NetworkShipId::from_net(despawn.ship_id());
    uint32_t ship_id = id.to_local();
    fprintf(stderr, "\r\napply_despawn(%d->%d)\r\n",
            id.to_net(), id.to_local());
    {
        CPU_Push16((Bit16u)SegValue(cs));
        CPU_Push16((Bit16u)reg_eip);
        Bit8u shellcode[] = {
            0x00, // nul terminate string
            // push flags,
            //0x9C, //PUSHF
            //push all regs, xor si,si, push si
            //0x60, //PUSHA
            0x56, // push si (original value)
            0xbe, ship_id & 0xff, ship_id >> 8, // mov si <- ship_id
            0x56, // push si
            // call far 12d7:012E
            0x9A, 0xDD, 0x01, 0xad, 0x12,
            // pop si, pop si
            0x5E, 0x5E,
            //0x61, 0x9D, // pop all regs, pop flags
            0xCB // retf
        };
        for (int i = 0; i < sizeof(shellcode); i++) {
            mem_writeb_checked(DS_OFF + shellcode_start + i, shellcode[i]);
        }
        SegSet16(cs, DS);
        reg_eip = shellcode_start + 1;
        fprintf(debuglog, "cs:eip = %04x:%04x\n", SegValue(cs), reg_eip);
    }
}

void run_briefing(int missionId, int seriesId) {
    {
        CPU_Push16((Bit16u)SegValue(cs));
        CPU_Push16((Bit16u)reg_eip + 5);
        Bit8u shellcode[] = {
            0x55, // push bp
            0x8B, 0xEC, // mov sp, bp
            0x56, // push si (original value)
            0xbe, seriesId & 0xff, seriesId >> 8, // mov si <- ship_id
            0x56, // push si
            0xbe, missionId & 0xff, missionId >> 8, // mov si <- ship_id
            0x56, // push si
            // call far stub148:005C (j_outerLoadBriefingAnimation)
            0x9A, 0x5C, 0x00, STUB148 & 0xff, STUB148 >> 8,
            // call far stub151:0025 (j_loadScrambleAnimation)
            0x9A, 0x25, 0x00, STUB151 & 0xff, STUB151 >> 8,
            // pop si, pop si, pop si
            0x5E, 0x5E, 0x5E,
            0x5d, // pop bp
            0xCB // retf
        };
        for (int i = 0; i < sizeof(shellcode); i++) {
            mem_writeb_checked(DS_OFF + DS_mission_loader + i, shellcode[i]);
        }
        SegSet16(cs, DS);
        reg_eip = DS_mission_loader;
    }
}

void run_campaign(int missionId, int seriesId) {
    mem_writeb_checked(DS_OFF + 0xC255, missionId);
    mem_writeb_checked(DS_OFF + 0xC256, seriesId);
    CPU_Push16((Bit16u)SegValue(cs));
    CPU_Push16((Bit16u)reg_eip + 5);
    SegSet16(cs, STUB161);
    reg_eip = 0x0039; // runHangarMission
    //forceBreak = true;
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
    }
    for (int i = 0; i < frame.event_size(); i++) {
        const Event &event = frame.event(i);
        // FIXME: Check that the ship is authoritive
        *pendingState.frame().add_event() = event;
    }
    for (int i = 0; i < frame.event_size(); i++) {
        const Event &ev = frame.event(i);
        queuedEvents.push_back(ev);
    }
}

void apply_frame(const Frame &frame, bool applyOwnLocation=false) {
    for (int i = 0; i < frame.update_size(); i++) {
        const ShipUpdate &su = frame.update(i);
        if (!su.has_ship_id()) {
            continue;
        }
        NetworkShipId ship_id = NetworkShipId::from_net(su.ship_id());
        if (ship_id.to_local() >= WCE_MIN_TEMPORARY_ID) {
            continue; // Do not simulate ephemeral objects.
        }
        if (applyOwnLocation || (client && !client->is_authoritative(ship_id)) || (server && ship_id.to_local() != 0)) {
            apply_ship_update_location(su);
        }
    }
    if (!server) {
        for (int i = 0; i < frame.event_size(); i++) {
            const Event &ev = frame.event(i);
            std::string debug = ev.DebugString();
            fprintf(stderr, "Received event %s\n", debug.c_str());
            queuedEvents.push_back(ev);
        }
    }
}

void apply_starting_frame(const Frame &frame) {
    apply_frame(frame, true);
}

void print_banner() {
    if (client) {
        fprintf(stderr,
            "=========================================================\n"
            "======================== CLIENT =========================\n"
            "=========================================================\n\n");
    } else {
        fprintf(stderr,
            "=========================================================\n"
            "=========--------------- SERVER ----------------=========\n"
            "=========================================================\n\n");
    }
}

void process_network() {
  {
    fprintf(stderr, "entity-types " );
    for (int i = 0; i <= 0x3f; i++) {
	if (i == WCE_MIN_TEMPORARY_ID) {
            fprintf(stderr, "| ");
	}
        fprintf(stderr, "%02x ", mem_readw(DS_OFF + DS_entity_types + i * 2));
    }
    fprintf(stderr, "\n");
  }
  {
    fprintf(stderr, "entity-alloc " );
    for (int i = 0; i <= 0x3f; i++) {
	if (i == WCE_MIN_TEMPORARY_ID) {
            fprintf(stderr, "| ");
	}
        fprintf(stderr, "%04x ", mem_readw(DS_OFF + DS_entity_allocated + i * 2));
    }
    fprintf(stderr, "\n");
  }
    gFrameNum++;
    //fprintf(stderr, "Start process_network for frame %d\n", gFrameNum);
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
        print_banner();
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
            for (std::map<NetworkShipId, Spawn>::iterator it = pendingState.currentlySpawnedShips.begin(); it != pendingState.currentlySpawnedShips.end(); it++) {
                Event *ev = frame->add_event();
                *ev->mutable_spawn() = it->second;
            }
            std::string debug = frame->DebugString();
            fprintf(stderr, "Sending starting state to client %d: %s\n",
                    cl->id.to_net(), debug.c_str());
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

    //fprintf(stderr, "Jumping to trampoline\n");
    CPU_Push16((Bit16u)SegValue(cs));
    CPU_Push16((Bit16u)reg_eip);
    go_to_trampoline();
    // After trampoline, we will return to the start of process_network.
    gIgnoreNextProcessNetwork = true;
}

template <class EventBuilder>
void process_intercepted_event(EventBuilder builder) {
    if (!builder.should_hook()) {
        return;
    }
    builder.debug();
    //void(*build_event)(Event*), Bit16u retfAddr) {
    if (!gIsProcessingTrampoline) {
        if (!queuedEvents.empty()) {
            fprintf(stderr, "queudEvents should be empty!\n");
            assert(false);
        }
        if (builder.should_run_locally()) {
            queuedEvents.push_back(Event());
            builder.build_event(&queuedEvents.back());
            go_to_trampoline();
        } else {
            // if we go in here, dosbox will return and NOT EXECUTE the fire.
            // return -- do not apply damage
            reg_eip = builder.ret_addr(); //ovr143
        }
        
        if (builder.should_sync()) {
            Event *ev = pendingState.frame().add_event();
            builder.build_event(ev);
            std::string debug = ev->DebugString();
            fprintf(stderr, "Added event %s\n", debug.c_str());
        }
    }
}

class FireEventBuilder {
public:
    void build_event(Event *ev) {
        NetworkShipId src = NetworkShipId::from_memory_word(DS_OFF + reg_esp + 4);
        Bit16u gun_id = mem_readw(DS_OFF + reg_esp + 6);
        //Bit32u randomSeed = mem_readd(DS_OFF + DS_RandomSeed);
        WeaponFire *fire = ev->mutable_fire();
        fire->set_shooter(src.to_net());
        fire->set_gun_id(gun_id);
    }

    bool should_hook() {
        return true;
    }

    bool should_sync() {
        NetworkShipId src = NetworkShipId::from_memory_word(DS_OFF + reg_esp + 4);
        if (server) {
            return server->get_client(src.to_local()) == NULL;
        } else if (client) {
            return src == client->shipId;
        }
        return false;
    }

    Bit16u ret_addr() {
        return 0x0d44;
    }

    bool should_run_locally() {
        return isServer;
    }

    void debug() {
        /*
        fprintf(stderr, "\r\ndoDamage%s(%d->%d, %d->%d, %d, <%d, %d, %d>) rng=%x\r\n",
                shouldSim ? "[added-to-pending-frame]" : "[not-sent]",
                NetworkShipId::from_net(src).to_net(), src.to_local(), dst.to_net(), dst.to_local(),
                quantity, vec->x(), vec->y(), vec->z(), randomSeed);
        */
    }
};

class DamageEventBuilder {
public:
    void build_event(Event *ev) {
        NetworkShipId src = NetworkShipId::from_memory_word(DS_OFF + reg_esp + 4);
        NetworkShipId dst = NetworkShipId::from_memory_word(DS_OFF + reg_esp + 6);
        Bit16u quantity = mem_readw(DS_OFF + reg_esp + 8);
        Bit16u vectorAddr = mem_readw(DS_OFF + reg_esp + 10);
        Bit32u randomSeed = mem_readd(DS_OFF + DS_RandomSeed);
        Damage *damage = ev->mutable_damage();
        damage->set_ship_id(dst.to_net());
        damage->set_shooter(src.to_net());
        damage->set_quantity(quantity);
        Vector *vec = damage->mutable_pos();
        populate_vector(vec, vectorAddr);
        damage->set_seed(randomSeed);
    }

    bool should_hook() {
        return true;
    }

    bool should_sync() {
        return isServer;
    }

    bool should_run_locally() {
        return isServer;
    }

    Bit16u ret_addr() {
        return 0x0d44;
    }

    void debug() {
    }
};

class SpawnEventBuilder {
public:
    void build_event(Event *ev) {
        NetworkShipId shipid = find_first_free_ship_entity();
        if (shipid.is_invalid()) {
            fprintf(stderr, "Bad: IS INVALID AFTER SPAWN!!!");
            return;
        }
        Bit16u missionShipId = mem_readw(DS_OFF + reg_esp + 4);
        Bit16u situationId = mem_readw(DS_OFF + reg_esp + 6); // index into navpoint
        Bit32u randomSeed = mem_readd(DS_OFF + DS_RandomSeed);
        Spawn *spawn = ev->mutable_spawn();
        spawn->set_ship_id(shipid.to_net());
        fprintf(stderr, "set spawn ship [%d->%d]\n", shipid.to_net(), shipid.to_local());
        spawn->set_mission_ship_id(missionShipId);
        spawn->set_situation_id(situationId);
        spawn->set_seed(randomSeed);
    }

    bool should_hook() {
        Bit16u missionShipId = mem_readw(DS_OFF + reg_esp + 4);
        Bit16u situationId = mem_readw(DS_OFF + reg_esp + 6); // index into navpoint
        fprintf(stderr, "about to spwan spawn ship (%d,%d)\n", missionShipId, situationId);
        /*if (!gIsProcessingTrampoline) {
          forceBreak = true;
          }*/
        //return false;
        return true;
    }

    bool should_sync() {
        return isServer;
    }

    bool should_run_locally() {
        return isServer;
    }

    Bit16u ret_addr() {
        return 0x1252;
    }

    void debug() {
        fprintf(stderr, "process_intercepted_event %s %d %d %d mem=%d\n",
            __PRETTY_FUNCTION__, gIsProcessingTrampoline,
            should_run_locally(), should_sync(),
            mem_readw(DS_OFF + reg_esp + 4));
    }
};

static bool forceBreakAlternate = false;

class DespawnEventBuilder {
public:
    void build_event(Event *ev) {
        NetworkShipId shipid = NetworkShipId::from_memory_word(DS_OFF + reg_esp + 4);
        Despawn *despawn = ev->mutable_despawn();
        despawn->set_ship_id(shipid.to_net());
    }

    bool should_hook() {
        if (client && (Bit16u)mem_readw(DS_OFF + reg_esp + 4) == 65535) {
            /*if (!forceBreakAlternate) {
	        forceBreak = true;
	    }
            forceBreakAlternate = !forceBreakAlternate;*/
        }
        NetworkShipId shipid = NetworkShipId::from_memory_word(DS_OFF + reg_esp + 4);
        return shipid.to_local() <= WCE_MAX_PERMANENT_ID;
    }
    
    bool should_sync() {
        NetworkShipId shipid = NetworkShipId::from_memory_word(DS_OFF + reg_esp + 4);
        bool isWingmanDeath = server && server->get_client(shipid) != NULL;
        if (isWingmanDeath) {
            fprintf(stderr, "Ignoring wingman death %d\n", shipid.to_net());
        }
        return isServer && !isWingmanDeath;
    }

    bool should_run_locally() {
        // FIXME: on client, we try to ignore despawns,
        // but we observe that when server autopilots, and the client autopilots
        // the destruction animation is continuously playing on all faraway
        // objects, and those objects are not targettable.
        // We need to figure out how to prevent this "destroyed" state from
        // being set.
        return should_sync();
    }

    Bit16u ret_addr() {
        return 0x1ce0;
    }

    void debug() {
    }
};

/*
Entity types:

0 - unallocated
2 - ??? high ids / always exist. maybe nav map point?
3 - nav point icon
4 - space dust
5 - explosion
6 - sparkle (damage)
7 - engine sprite
8 - bolt
9 - asteroid
a - mine
b - missile
c - ship
d - capship
 */

void spawn_ship_hook() {
    // return -- do not apply damage
    reg_eax = 0xffffffff;
    reg_eip = 0x1252; // ovr145 retf
}

void despawn_ship_hook() {
    // return -- do not apply damage
    reg_eip = 0x1ce0; // ovr140 retf
}

void process_spawn_ship() {
    // beginning of doDamage.
    if (manualSpawnShip) {
        if (manualSpawnShip > 0) {
            manualSpawnShip--;
        }
    } else {
        spawn_ship_hook();
    }
}

void process_despawn_ship() {
    // beginning of doDamage.
    NetworkShipId ship = NetworkShipId::from_memory_word(DS_OFF + reg_esp + 4);
    //fprintf(stderr,"despawn %d\n", ship.to_net());

    if (manualDespawnShip) {
        if (manualDespawnShip > 0) {
            manualDespawnShip--;
        }
    } else {
        despawn_ship_hook();
    }
}

void process_trampoline() {
    //fprintf(stderr, "Trampoline: start %d\n", (int)queuedEvents.size());
    gIsProcessingTrampoline = true;
    {
        const Event &ev = gCurrentEvent;
        if (ev.has_fire()) {
            // We just finished applying weapon fire.
            fprintf(stderr, "Trampoline: finished fire\n");
        } else if (ev.has_damage()) {
            // We just finished dealing damage.
            fprintf(stderr, "Trampoline: finished damage\n");
        } else if (ev.has_spawn()) {
            // Finished spawning
            fprintf(stderr, "Trampoline: finished spawn %d\n", reg_eax & 0xffff);
            const Spawn &spawn = ev.spawn();
            if (spawn.has_ship_id()) {
                if (client) {
                    client->insert_spawn_id(spawn.ship_id(), reg_eax & 0xffff);
                }
                NetworkShipId id = NetworkShipId::from_net(spawn.ship_id());
                NetworkShipId returnId = NetworkShipId::from_local(reg_eax & 0xffff);
                if (id != returnId) {
                    fprintf(stderr, "Info: Wanted to spawn %d but spawned %d\n",
                            id.to_local(), returnId.to_local());
                }
                //restore_ship_spawn_entities(id);
            }
            pendingState.add_ship(spawn);
            if (!queuedEvents.empty()) {
                if (isServer) {
                    fprintf(stderr, "Bad: there are extra queued events!\n");
                }
            }
        } else if (ev.has_despawn()) {
            // Finished despawning
            fprintf(stderr, "Trampoline: finished despawn\n");
            const Despawn &despawn = ev.despawn();
            NetworkShipId id = NetworkShipId::from_net(despawn.ship_id());
            pendingState.remove_ship(id);
        } else {
            //fprintf(stderr, "Trampoline: no events finished yet\n");
        }
    }

    while (!queuedEvents.empty()) {
        gCurrentEvent = queuedEvents.front();
        queuedEvents.pop_front();

        const Event &ev = gCurrentEvent;
        
        if (ev.has_fire()) {
            fprintf(stderr, "Trampoline: starting fire\n");
            apply_weapon_fire(ev.fire());
        }
        if (ev.has_damage()) {
            fprintf(stderr, "Trampoline: starting damage\n");
            apply_damage(ev.damage());
        }
        if (ev.has_spawn()) {
            fprintf(stderr, "Trampoline: spawn!!!!!!\n");
            apply_spawn(ev.spawn());
        }
        if (ev.has_despawn()) {
            fprintf(stderr, "Trampoline: despawn!!!!!!!\n");
            apply_despawn(ev.despawn());
        }
        if (reg_eip != DS_tramp_ret_NOP) {
            if (reg_eip == shellcode_start + 1) {
                fprintf(stderr, "Trampoline: Starting next bounce\n");
                // The processor has been sent out on an away mission.
                // we will get back to process_trampoline after the current
                // function has executed.
                return;
            } else {
                std::string debug = ev.DebugString();
                fprintf(stderr, "Unimplemented event %s\n", debug.c_str());
            }
        }
    }
    // We have finished executing all events.
    gCurrentEvent.Clear();

    // Now anything else to execute after processing all events this frame
    //fprintf(stderr, "Finished processing events for frame %d\n", gFrameNum);
    gIsProcessingTrampoline = false;
}

void go_to_trampoline() {
    for (int i = 0; i < sizeof(trampoline_code); i++) {
        mem_writeb_checked(DS_OFF + DS_trampoline + i, trampoline_code[i]);
    }
    SegSet16(cs, DS);
    reg_eip = DS_trampoline;
}

bool isExecutingFunction(Bit16u stubSeg, Bit16u stubOff) {
    Bit8u instType = mem_readb(stubSeg * 0x10 + stubOff);
    if (instType != 0xea) {
        return false;
    }
    Bit16u realOff = mem_readw(stubSeg * 0x10 + stubOff + 1);
    Bit16u realSeg = mem_readw(stubSeg * 0x10 + stubOff + 3);
    if (SegValue(cs) == realSeg && reg_eip == realOff) {
        return true;
    }
    return false;
}

extern void setBreakpoint(Bit16u seg, Bit32u off);

bool skipBarracks = false;

void wc_net_check_cpu_hooks() {
    /*{
        Bit16u stubSeg = STUB145;
        Bit16u stubOff = 0x00b6;
        Bit8u instType = mem_readb(stubSeg * 0x10 + stubOff);
        if (instType == 0xea) {
            Bit16u realOff = mem_readw(stubSeg * 0x10 + stubOff + 1);
            Bit16u realSeg = mem_readw(stubSeg * 0x10 + stubOff + 3);
            static bool didSetBreakpoint = (
                setBreakpoint(realSeg,realOff),
                //setBreakpoint(DS, DS_tramp_lite),
                //setBreakpoint(DS, DS_trampoline),
                setBreakpoint(DS, shellcode_start + 1),
                setBreakpoint(DS, shellcode_start + 2),
                fprintf(stderr, "Setting breakpoints...\n"),
                    true);
        }
        }*/
    // do_damage
    if (isExecutingFunction(STUB143, 0x0084)) {
        process_intercepted_event(DamageEventBuilder());
    }
    // fireGunFromShip
    if (isExecutingFunction(STUB143, 0x012e)) {
        process_intercepted_event(FireEventBuilder());
    }
    // outerSpawnShipEntity
    if (isExecutingFunction(STUB145, 0x00b6)) {
        process_intercepted_event(SpawnEventBuilder());
    }
    // despawn
    if (isExecutingFunction(STUB140, 0x01dd)) {
        process_intercepted_event(DespawnEventBuilder());
    }
    if (isExecutingFunction(STUB140, 0x0101)) {
        // allocate anon entity
        /*
         reg_eax = 12; // force ephemeral objects to a specific slot
         reg_eip = 0x1ce0; // ovr140 retf
        */
    }
    if (skipBarracks && isExecutingFunction(STUB150, 0x00AC)) {
        skipBarracks = false;
        reg_eax = 7;
        reg_eip = 0x1391; // ret
    }
    // Skip orchestra...
    if (SegValue(cs) == SEG001 && reg_eip == 0x04F2) {
        reg_eip += 5;
    }
    if (SegValue(cs) == SEG001 && reg_eip == 0x0512) {
        char *misenv = getenv("MIS");
        char *serenv = getenv("SERIES");
        int miss = atoi(misenv ? misenv : "0");
        int series = atoi(serenv ? serenv : "1");
        if (miss != 0 || series != 0) {
            run_campaign(miss, series);
            skipBarracks = true;
            //forceBreak = true;
        }
    }
    if (SegValue(cs) == DS && reg_eip == DS_tramp_ret_NOP) {
        process_trampoline();
    }
    if (SegValue(cs) == 0x0560 && reg_eip == 0x20e3) {
        // this is the beginning of the WC main loop while in fighting.
        // then we can process network commands here and introduce things
        // before the frame is processed in a predictable place
        if (gIgnoreNextProcessNetwork) {
            gIgnoreNextProcessNetwork = false;
        } else {
            process_network();
        }
    }
}
