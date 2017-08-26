void process_network();
void process_damage();
class NetConfig {
public:
    char *host;
    char *portstr;
    uint16_t port;
    NetConfig();
};
extern NetConfig net_config;

