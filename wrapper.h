#ifdef __linux__
#include <linux/if.h>
#include <linux/if_tun.h>
#else
#include <net/if.h>
#define IFF_TUN 0x0001
#define IFF_TAP 0x0002
#define IFF_NO_PI 0x1000
#define TUNSETIFF _IOW('T', 202, int)
#endif
#include <sys/ioctl.h>
