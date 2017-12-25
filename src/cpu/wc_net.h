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
    int id;

    static int remap_ship_id(int ship_id, bool to_local);

    explicit NetworkShipId(int id)
        : id(id) {
        if (id < 0) {
            fprintf(stderr, "Negative ship id found %d\n", id);
            //id = 0x3f;
        }
        if (id >= 0x3d) {
            fprintf(stderr, "Too large ship id found %d\n", id);
            //id = 0x3f;
        }
    }

public:

    static NetworkShipId invalid() {
        return NetworkShipId(-1);
    }
    
    static NetworkShipId from_local(int id) {
        return NetworkShipId(remap_ship_id(id, false));
    }

    static NetworkShipId from_net(int id) {
        return NetworkShipId(id);
    }

    static NetworkShipId from_memory_word(int addr) {
        Bit16u id = -1;
        mem_readw_checked(addr, &id);
        return NetworkShipId::from_local(id);
    }

    bool is_invalid() const {
        return id < 0 || id >= 0x3d;
    }

    int to_local() const {
        return remap_ship_id(id, true);
    }
    int to_net() const {
        return id;
    }

    bool operator== (const NetworkShipId &other) const {
        return id == other.id;
    }

    bool operator!= (const NetworkShipId &other) const {
        return id != other.id;
    }

    bool operator< (const NetworkShipId &other) const {
        return id < other.id;
    }
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
