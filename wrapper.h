#ifdef __linux__
#include <linux/if.h>
#include <linux/if_tun.h>
#else
#include <net/if.h>
#define IFF_TUN 0x0001
#define IFF_NO_PI 0x1000
#endif
#include <sys/ioctl.h>
