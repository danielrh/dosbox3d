class NetConfig {
public:
    const char *host;
    const char *portstr;
    uint16_t port;
    NetConfig();
    void reset_from_env();
    void reset(const char *host, const char* portstr);
    
};
extern NetConfig net_config;

