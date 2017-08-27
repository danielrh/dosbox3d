#ifndef WC_NET_H_
#define WC_NET_H_

void process_network();
void process_damage();
void process_fire();
class NetConfig {
public:
    char *host;
    char *portstr;
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

    static int remap_ship_id(int ship_id);

    explicit NetworkShipId(int id)
        : id(id) {
        if (id < 0) {
            fprintf(stderr, "Negative ship id found %d\n", id);
            id = 0x3f;
        }
        if (id >= 0x3d) {
            fprintf(stderr, "Too large ship id found %d\n", id);
            id = 0x3f;
        }
    }
public:

    static NetworkShipId from_local(int id) {
        return NetworkShipId(remap_ship_id(id));
    }

    static NetworkShipId from_net(int id) {
        return NetworkShipId(id);
    }

    static NetworkShipId from_memory_word(int addr) {
        Bit16u id = -1;
        mem_readw_checked(addr, &id);
        return NetworkShipId(id);
    }

    int to_local() const {
        return remap_ship_id(id);
    }
    int to_net() const {
        return id;
    }

    bool operator== (const NetworkShipId &other) const {
        return id == other.id;
    }
};

#define STATIC_ASSERT(expr, message) do { int STATIC_ASSERTION(int[-!(expr)]); } while(0)

#endif
