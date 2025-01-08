#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/ioctl.h>

#define DEVICE_PATH "/dev/LKM_device"
#define IOCTL_CALL_FUNC _IOR('a', 1, int32_t *)

typedef struct pair {
    uint64_t p1, p2;
} PAIR;

int main() {
    int fd;
    int32_t value = 10;
    int32_t result = 0;

    pid_t pid;

    if (pid=fork()) {
        printf("child pid: %d\n", pid);
        fd = open(DEVICE_PATH, O_RDWR);
        if (fd < 0) {
            perror("Failed to open the device");
            return -1;
        }
        PAIR val;
        val.p1 = pid; val.p2=value;
        if (ioctl(fd, IOCTL_CALL_FUNC, &val) == -1) {
            perror("Failed to call ioctl");
            close(fd);
            return -1;
        }
        printf("Kernel function returned: %d %d\n", fd, value);
        close(fd);
    }
    else {
        for (int i = 0 ; i < 2 ; ++ i) sleep(1);
    }
    return 0;
}
