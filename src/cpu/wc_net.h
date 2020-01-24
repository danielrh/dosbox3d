#ifndef WC_NET_H_
#define WC_NET_H_
#include "net_config.h"
void wc_net_check_cpu_hooks();

void process_network(bool ignoreClientUpdate=false);
void process_damage();
void process_fire();

void go_to_trampoline();

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

    static NetworkShipId from_top_level_local(int id) {
        return from_local(NetworkShipId::getTopLevelParent(id));
    }

    static int getTopLevelParent(int local_id);
    
    static NetworkShipId from_net(int id) {
        return NetworkShipId(id);
    }

    static NetworkShipId from_memory_word(int addr) {
        Bit16u id = -1;
        mem_readw_checked(addr, &id);
        return NetworkShipId::from_local(id);
    }

    static NetworkShipId parent_from_memory_word(int addr) {
        Bit16u id = -1;
        mem_readw_checked(addr, &id);
        return NetworkShipId::from_local(getTopLevelParent(id));
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
    STUB133 = 0x1266, // ida:10C4
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
    STUB161 = 0x1361, // ida: 11bf
    STUB162 = 0x1366, // ida: 11c4
    STUB163 = 0x1370, // ida: 11ce
    STUB164 = 0x1381, // ida: 11df
};

enum {
    DS = 0x13d3,
    DS_OFF = DS * 0x10,
    Instr_RETF = 0xCB
};
enum DataSegValues {
    DS_SetSpeed = 0xB9F6,
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
    DS_parent_ship = 0xC30E,
    DS_entity_types = 0xBD1A,
    DS_entity_allocated = 0xACC4,
    DS_victoryPoints = 0xC280,
    DS_missionId = 0xC255,
    DS_seriesId = 0xC256,
    DS_hasLoadedSaveGame = 0x300c,
};

#endif
