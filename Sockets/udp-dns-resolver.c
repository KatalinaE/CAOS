#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

enum {
    REQUEST_QR = 0,
    STANDART_OPCODE = 0,
    NOAUTH_AA = 0,
    FULL_TC = 0,
    RECURSIVE_RD = 1,
    RECURSIVE_AVAILABLE_RA = 1,
    DATA_AD = 1,
    NOCHECK_CD = 0,
    NOERROR_RC = 0,
    INTERNET_CLASS = 1,
    IP4_TYPE = 1,

    BUFSIZE = 4096,
    NAMESIZE = 1024,
    STRIPSIZE = 16,
};

typedef unsigned short bit;
typedef unsigned short Count;
typedef struct {
    bit QR : 1;     // 0 - Ð·Ð°Ð¿Ñ€Ð¾Ñ, 1 - Ð¾Ñ‚Ð²ÐµÑ‚
    bit Opcode : 4; // ÐžÐ¿ÐµÑ€Ð°Ñ†Ð¸Ñ
    bit AA : 1;     // ÐÐ²Ñ‚Ð¾Ñ€Ð¸Ð·Ð¾Ð²Ð°Ð½Ð½Ð¾ÑÑ‚ÑŒ
    bit TC : 1;     // Ð£ÐºÐ¾Ñ€Ð¾Ñ‡ÐµÐ½Ð½Ñ‹Ð¹ Ð»Ð¸
    bit RD : 1;     // Ð ÐµÐºÑƒÑ€ÑÐ¸Ð²Ð½Ñ‹Ð¹ Ð»Ð¸
    bit RA : 1;     // Ð”Ð¾ÑÑ‚ÑƒÐ¿Ð½Ð° Ð»Ð¸ Ñ€ÐµÐºÑƒÑ€ÑÐ¸Ñ
    bit : 1;        // ÐÐµÐ¸ÑÐ¿Ð¾Ð»ÑŒÐ·Ð¾Ð²Ð°Ð½
    bit AD : 1;     // Ð•ÑÑ‚ÑŒ Ð»Ð¸ Ð´Ð°Ð½Ð½Ñ‹Ðµ Ð°Ð²Ñ‚Ð¾Ñ€Ð¸Ð·Ð°Ñ†Ð¸Ð¸
    bit CD : 1;     // Ð•ÑÑ‚ÑŒ Ð»Ð¸ Ð¿Ñ€Ð¾Ð²ÐµÑ€ÐºÐ¸
    bit RCODE : 4;  // ÐžÑˆÐ¸Ð±ÐºÐ¸
} QueryParam;
typedef struct {
    unsigned short
        ID; // Ð¸Ð½Ð´Ð¸Ð²Ð¸Ð´ÑƒÐ°Ð»ÐµÐ½ Ð²Ð½ÑƒÑ‚Ñ€Ð¸ Ð¾Ð´Ð½Ð¾Ð³Ð¾ ÑÐ¾ÐµÐ´Ð¸Ð½ÐµÐ½Ð¸Ñ(Ð½Ð° ÑÐ»ÑƒÑ‡Ð°Ð¹ Ð½ÐµÑÐºÐ»ÑŒÐºÐ¸Ñ… Ð·Ð°Ð¿Ñ€Ð¾ÑÐ¾Ð²)
    QueryParam param; // Ð¿Ð°Ñ€Ð°Ð¼ÐµÑ‚Ñ€Ñ‹
    Count Qestions;   // ÐšÐ¾Ð»Ð¸Ñ‡ÐµÑÑ‚Ð²Ð¾ Ð²Ð¾Ð¿Ñ€Ð¾ÑÐ¾Ð²
    Count Answers;    // ÐšÐ¾Ð»Ð¸Ñ‡ÐµÑÑ‚Ð²Ð¾ Ð¾Ñ‚Ð²ÐµÑ‚Ð¾Ð²
    Count Servers;    // ÐšÐ¾Ð»Ð¸Ñ‡ÐµÑÑ‚Ð²Ð¾ Ð¡ÐµÑ€Ð²ÐµÑ€Ð¾Ð²
    Count Notes; // ÐšÐ¾Ð»Ð¸Ñ‡ÐµÑÑ‚Ð²Ð¾ Ð´Ð¾Ð¿Ð¾Ð»Ð½Ð¸Ñ‚ÐµÐ»ÑŒÐ½Ñ‹Ñ… Ð·Ð°Ð¿Ð¸ÑÐµÐ¹
} QueryHead;
typedef struct {
    // RequestName - Ð¡ÐµÐºÑ†Ð¸Ð¸ (Ð½Ðµ Ð¾Ð±ÑÐ·Ð°Ñ‚ÐµÐ»ÑŒÐ½Ð¾ ÐºÑ€Ð°Ñ‚Ð½Ð¾ 2)
    unsigned short type; // ÐšÐ°ÐºÑƒÑŽ Ð¸Ð½Ñ„Ð¾Ñ€Ð¼Ð°Ñ†Ð¸ÑŽ Ð·Ð°Ð¿Ñ€Ð°ÑˆÐ¸Ð²Ð°ÐµÐ¼
    unsigned short class; // Ð’Ð¸Ð´ Ð¾Ñ‚Ð¿Ñ€Ð°Ð²ÐºÐ¸ Ð·Ð°Ð¿Ñ€Ð¾ÑÐ°
} QueryRequestTail;
typedef struct {
    bit offset : 14; // Ð¡Ð¼ÐµÑ‰ÐµÐ½Ð¸Ðµ Ðº Ð½Ð°Ñ‡Ð°Ð»Ñƒ Ð²Ð¾Ð¿Ñ€Ð¾ÑÐ°, Ð½Ð° ÐºÐ¾Ñ‚Ð¾Ñ€Ñ‹Ð¹ ÑÐ²Ð»ÑÐµÑ‚ÑÑ Ð¾Ñ‚Ð²ÐµÑ‚Ð¾Ð¼
    bit : 2; // ÐŸÐ¾ ÑƒÐ¼Ð¾Ð»Ñ‡Ð°Ð½Ð¸ÑŽ Ñ€Ð°Ð²Ð½Ð¾ 3 (Ð½Ðµ Ð¸ÑÐ¿Ð¾Ð»ÑŒÐ·ÑƒÐµÑ‚ÑÑ)
    unsigned short type;  // ÐšÐ°ÐºÑƒÑŽ Ð¸Ð½Ñ„Ð¾Ñ€Ð¼Ð°Ñ†Ð¸ÑŽ Ð¿Ð¾Ð»ÑƒÑ‡Ð¸Ð»Ð¸
    unsigned short class; // Ð’Ð¸Ð´ Ð¿Ð¾Ð»ÑƒÑ‡ÐµÐ½Ð¸Ñ Ð¾Ñ‚Ð²ÐµÑ‚Ð°
    unsigned short ttl0; // Ð’Ñ€ÐµÐ¼Ñ Ð¶Ð¸Ð·Ð½Ð¸ ÐºÐµÑˆÐ° Ñ ÑÑ‚Ð¸Ð¼Ð¸ Ð´Ð°Ð½Ð½Ñ‹Ð¼Ð¸
    unsigned short ttl1; // Ð’Ñ€ÐµÐ¼Ñ Ð¶Ð¸Ð·Ð½Ð¸ ÐºÐµÑˆÐ° Ñ ÑÑ‚Ð¸Ð¼Ð¸ Ð´Ð°Ð½Ð½Ñ‹Ð¼Ð¸
    Count byte;          // Ð”Ð»Ð¸Ð½Ð½Ð° Ð¾Ñ‚Ð²ÐµÑ‚Ð°
    // Data - Ð”Ð°Ð»ÑŒÑˆÐµ Ð¸Ð´ÑƒÑ‚ Ð´Ð°Ð½Ð½Ñ‹Ðµ Ð·Ð°Ð´Ð°Ð½Ð½Ð¾Ð³Ð¾ ÐºÐ¾Ð»Ð¸Ñ‡ÐµÑÑ‚Ð²Ð° Ð±Ð°Ð¹Ñ‚
} QueryAnswerHead;

// ÐŸÐµÑ‡Ð°Ñ‚Ð°ÐµÑ‚ Domain Ñ€Ð°Ð·Ð±Ð¸Ð²Ð°Ñ Ð½Ð° ÑÐµÐºÑ†Ð¸Ð¸ Ð¿Ð¾ ÑƒÐºÐ°Ð·Ð°Ñ‚ÐµÐ»ÑŽ it
// Ð”Ð¾Ð»Ð¶Ð½Ð¾ Ð³Ð°Ñ€Ð°Ð½Ñ‚Ð¸Ñ€Ð¾Ð²Ð°Ñ‚ÑŒÑÑ, Ñ‡Ñ‚Ð¾ Ð¼ÐµÑÑ‚Ð° Ð´Ð¾ÑÑ‚Ð°Ñ‚Ð¾Ñ‡Ð½Ð¾
char* domainToSections(char* it, const char* url)
{
    for (char* next; next = strchr(url, '.'); url = next + 1, it += *it + 1) {
        *it = next - url;
        memcpy(it + 1, url, *it);
    }
    *it = strchr(url, 0) - url;
    memcpy(it + 1, url, *it + 1);
    it += *it + 2;
    return it;
}

char* netcpy(void* dst_, void* src_, int size)
{
    char* it = dst_;
    const char* src = src_;
    for (int i = 0; i < size; i += 2, it += 2) {
        *it = src[i + 1];
        it[1] = src[i];
    }
    return it;
}

int main()
{
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(53);
    serv_addr.sin_addr.s_addr = inet_addr("8.8.8.8");

    bind(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));

    QueryHead head = {
        0,
        {
            .QR = REQUEST_QR,
            .Opcode = STANDART_OPCODE,
            .AA = NOAUTH_AA,
            .TC = FULL_TC,
            .RD = RECURSIVE_RD,
            .RA = RECURSIVE_AVAILABLE_RA,
            .AD = DATA_AD,
            .CD = NOCHECK_CD,
            .RCODE = NOERROR_RC,
        },
        1,
        0,
        0,
        0,
    };
    QueryRequestTail tail = {
        .type = IP4_TYPE,
        .class = INTERNET_CLASS,
    };

    char domain[NAMESIZE], buf[BUFSIZE], *it;
    for (int ID = 1; it = buf, scanf("%s", domain) == 1; ++ID) {
        head.ID = ID;
        it = netcpy(it, &head, sizeof(head));
        it = domainToSections(it, domain);
        it = netcpy(it, &tail, sizeof(tail));

        int request_size = it - buf;
        sendto(
            sockfd,
            buf,
            request_size,
            MSG_CONFIRM,
            (const struct sockaddr*)&serv_addr,
            sizeof(serv_addr));

        int ip4, responce_size =
                     request_size + sizeof(QueryAnswerHead) + sizeof(ip4);
        recvfrom(sockfd, buf, responce_size, MSG_WAITALL, NULL, NULL);

        QueryAnswerHead ahead;
        netcpy(&ahead, buf + request_size, sizeof(ahead));
        if (ahead.offset != sizeof(head))
            return 1;
        memcpy(&ip4, buf + responce_size - sizeof(ip4), sizeof(ip4));
        char strIp[STRIPSIZE];
        inet_ntop(AF_INET, &ip4, strIp, STRIPSIZE);
        printf("%s\n", strIp);
    }

    close(sockfd);

    return 0;
}
