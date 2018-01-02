#ifndef WC_NET_H_
#define WC_NET_H_

void wc_net_check_cpu_hooks();

void process_network();
void process_damage();
void process_fire();
void process_spawn_ship();
void process_despawn_ship();

void go_to_trampoline();

class NetConfig {
public:
    const char *host;
    const char *portstr;
    uint16_t port;
    NetConfig();
};
extern NetConfig net_config;

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

class NetworkShipId {
    uint16_t mission_ship_id;
    uint16_t situation_id;
    int local_ship_id; // defaults to one
    static NetworkShipId remap_ship_id_to_net(int ship_id);
    static int remap_ship_id_to_local(NetworkShipId);

    NetworkShipId(uint16_t spawned_mission_ship_id, uint16_t spawned_situation_id)
        : mission_ship_id(spawned_mission_ship_id), situation_id(spawned_situation_id), local_ship_id(-1) {
    }
    static NetworkShipId make_invalid(int local_ship_id) {
        NetworkShipId ret(0xffff, 0xffff);
        ret.local_ship_id = -1;
        return ret;
    }
public:

    static NetworkShipId from_local(int id) {
        return remap_ship_id_to_net(id);
    }
    static NetworkShipId server_wingleader_id() {
        return from_net(1, 0);
    }
    static NetworkShipId client_wingman_id() {
        return from_net(2, 0);
    }
    static NetworkShipId from_net(uint16_t mission_ship_id, uint16_t situation_id) {
        return NetworkShipId(mission_ship_id, situation_id);
    }

    static NetworkShipId from_memory_word(int addr) {
        Bit16u id = -1;
        mem_readw_checked(addr, &id);
        return NetworkShipId::from_local(id);
    }

    bool is_temporary_effect() const {
        return mission_ship_id == 0xffff && situation_id == 0xffff;
    }

    int to_local() const {
        if (local_ship_id != -1 ) {
            return local_ship_id;
        }
        return remap_ship_id_to_local(*this);
    }
    uint16_t to_net_situation_id() const {
        if(is_temporary_effect()) {
            abort();
        }
        return situation_id;
    }
    uint16_t to_net_mission_ship_id() const {
        if(is_temporary_effect()) {
            abort();
        }
        return mission_ship_id;
    }

    bool operator== (const NetworkShipId &other) const {
        if (is_temporary_effect()) {
            return local_ship_id == other.local_ship_id;
        }
        return mission_ship_id == other.mission_ship_id && 
            situation_id == other.situation_id;
    }

    bool operator!= (const NetworkShipId &other) const {
        return !(*this == other);
    }

    bool operator< (const NetworkShipId &other) const {
        uint64_t a = mission_ship_id;
        uint64_t b = other.mission_ship_id;
        a <<= 16;
        b <<= 16;
        a|= situation_id;
        b|= other.situation_id;
        a<<=32;
        b<<=32;
        if (is_temporary_effect()) {
            a = 0;
            a ^= (uint32_t)local_ship_id;
        }
        if (other.is_temporary_effect()) {
            b = 0;
            b ^= (uint32_t)local_ship_id;
        }
        return a < b;
    }
};

enum WcEntityConstants {
    WCE_PLAYER_ID = 0,
    WCE_MIN_PERMANENT_ID = 1,
    WCE_MAX_PERMANENT_ID = 9,
    WCE_MIN_TEMPORARY_ID = 10,
    WCE_MAX_TEMPORARY_ID = 0x3c,
    WCE_CAMERA_ID = 0x3d,
    WCE_TEMP_VECTOR_ID = 0x3f
};

#define STATIC_ASSERT(expr, message) do { int STATIC_ASSERTION(int[-!(expr)]); } while(0)

enum {
    SEG000 = 0x1a2, // ida:000
    SEG001 = 0x560, // ida:3be
    SEG002 = 0x78c, // ida:5ea
    STUB140 = 0x12ad, // ida:110B
    STUB141 = 0x12cc, // ida:112A
    STUB142 = 0x12d4, // ida:1132
    STUB143 = 0x12d7,
    STUB144 = 0x12ed,
    STUB145 = 0x12f2,
    STUB146 = 0x12fe,
    STUB147 = 0x130e,
    STUB148 = 0x1318,
    STUB150 = 0x1327,
    STUB151 = 0x1333,
    STUB161 = 0x1361
};

#endif
