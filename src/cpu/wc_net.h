void process_network();
void process_damage();
class NetConfig {
public:
    char *host;
    char *portstr;
    uint16_t port;
    NetConfig() {
        host = getenv("WCHOST");
        portstr = getenv("WCPORT");
        port = portstr ? (uint16_t)atoi(portstr) : 0;
        if (port < 1024) {
            fprintf(stderr, "You must set the WCPORT and (optionally) WCHOST env variables!\n");
            abort();
        }
    }
};
extern NetConfig net_config;

