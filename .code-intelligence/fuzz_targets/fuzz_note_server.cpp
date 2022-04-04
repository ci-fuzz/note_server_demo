
#include <unistd.h>
#include <string.h>
#include <flibc.h>

/*
FUZZ_TCP_SERVER(original_main, 5000, int client_fd, const uint8_t* data, size_t size) {
	int written = write(client_fd, data, size);
}
*/

const int port = 5000;

static void TestOneNetworkInput(int client_fd, const uint8_t* data, size_t size) {
    // Make sure we have at least one newline in the request,
    // so that we get a response from the server.
    uint8_t request[size];
    memcpy(request, data, size);
    request[size-1] = '\n';
    int written = write(client_fd, request, size);
    // Wait 1ms
    usleep(1000);
    // Read the response
    uint8_t response[1000];
    read(client_fd, response, 1000);

    // This should also work, but hangs the fuzz test for some reason
    //WaitForReaction(client_fd, 10);
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