
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <flibc.h>

static unsigned int fuzz_case = 0;

/*
FUZZ_TCP_SERVER(original_main, 5000, int client_fd, const uint8_t* data, size_t size) {
	int written = write(client_fd, data, size);
}
*/

void print_ascii(const uint8_t *data, size_t size) {
    uint8_t data_copy[size+1];
    for(int i = 0; i < size; ++i) {
        if((data[i] >= 32 && data[i] <= 126) || data[i] == 10) {
            data_copy[i] = data[i];
        } else {
            data_copy[i] = 46; // dot '.'
        }
    }
    data_copy[size] = 0;
    fprintf(stderr, "%s\n", data_copy);
}

const int port = 5000;

static void TestOneNetworkInput(int client_fd, const uint8_t* data, size_t size) {
    // Test: disable nagle algorithm to send data immediately
    int flag = 1; 
    setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, (char *) &flag, sizeof(int));

    fuzz_case++;
    fprintf(stderr, "%06u ===============================\n", fuzz_case);
    fprintf(stderr, "%06u FD: %d\n", fuzz_case, client_fd);
    //fprintf(stderr, "%.*s\n", size, data);
    print_ascii(data, size);

    // Make sure we have at least one newline in the request,
    // so that we get a response from the server.
    uint8_t request[size];
    memcpy(request, data, size);
    request[size-1] = '\n';
    int written = write(client_fd, request, size);

    // This should also work, but hangs the fuzz test for some reason
    //WaitForReaction(client_fd, 10);

    
    struct timeval tv = {0};
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    fd_set fdread;
    FD_ZERO(&fdread);
    FD_SET(client_fd, &fdread);
    fd_set fderr;
    FD_ZERO(&fderr);
    FD_SET(client_fd, &fderr);
    int selectStatus = select(client_fd+1, &fdread, NULL, &fderr, &tv);
    
    while(selectStatus > 0) {
        if(FD_ISSET(client_fd, &fdread)) {
            fprintf(stderr, "%06u FD_ISSET: read\n", fuzz_case);
        }
        if(FD_ISSET(client_fd, &fderr)) {
            fprintf(stderr, "%06u FD_ISSET: error\n", fuzz_case);
            break;
        }

        // Read the response
        uint8_t response[10000];
        ssize_t num_bytes = read(client_fd, response, 10000);
        if(num_bytes <= 0) {
            fprintf(stderr, "%06u READ END\n", fuzz_case);
            break;
        }

        tv.tv_sec = 0;
        tv.tv_usec = 20000;
        FD_ZERO(&fdread);
        FD_SET(client_fd, &fdread);
        FD_ZERO(&fderr);
        FD_SET(client_fd, &fderr);
        selectStatus = select(client_fd+1, &fdread, NULL, &fderr, &tv);
    }

    fprintf(stderr, "%06u =========== END ===============\n", fuzz_case);
}

int (*original_main)(int, char **);

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    original_main = (int (*)(int, char **))dlsym(RTLD_NEXT, "main");
    InitializeSocketFuzzer(SOCK_STREAM, port, argc, argv);
    RunTarget(original_main, argc, argv);
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if(size < 5) return 0;
    int client_fd = ConnectToFuzzedServerSocket();
    if (client_fd < 0) return 0;
    TestOneNetworkInput(client_fd, data, size);
    shutdown(client_fd, SHUT_RDWR);
    close(client_fd);
    return 0;
}