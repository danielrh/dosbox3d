#ifndef WC_NET_H_
#define WC_NET_H_

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

#define STATIC_ASSERT(expr, message) do { int STATIC_ASSERTION(int[-!(expr)]); } while(0)

#endif
