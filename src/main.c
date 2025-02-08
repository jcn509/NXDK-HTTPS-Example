#define _CRT_RAND_S

#include <stdarg.h>
#include <string.h>

#include <hal/debug.h>
#include <hal/video.h>
#include <nxdk/net.h>

#include <lwip/netdb.h>
#include <lwip/sockets.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>


/* Replace with your server's CA certificate */
static const char ca_cert[] =
"-----BEGIN CERTIFICATE-----\n"
"MIIDQTCCAimgAwIBAgITBmyfz5m/jAo54vB4ikPmljZbyjANBgkqhkiG9w0BAQsF\n"
"ADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6\n"
"b24gUm9vdCBDQSAxMB4XDTE1MDUyNjAwMDAwMFoXDTM4MDExNzAwMDAwMFowOTEL\n"
"MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJv\n"
"b3QgQ0EgMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALJ4gHHKeNXj\n"
"ca9HgFB0fW7Y14h29Jlo91ghYPl0hAEvrAIthtOgQ3pOsqTQNroBvo3bSMgHFzZM\n"
"9O6II8c+6zf1tRn4SWiw3te5djgdYZ6k/oI2peVKVuRF4fn9tBb6dNqcmzU5L/qw\n"
"IFAGbHrQgLKm+a/sRxmPUDgH3KKHOVj4utWp+UhnMJbulHheb4mjUcAwhmahRWa6\n"
"VOujw5H5SNz/0egwLX0tdHA114gk957EWW67c4cX8jJGKLhD+rcdqsq08p8kDi1L\n"
"93FcXmn/6pUCyziKrlA4b9v7LWIbxcceVOF34GfID5yHI9Y/QCB/IIDEgEw+OyQm\n"
"jgSubJrIqg0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMC\n"
"AYYwHQYDVR0OBBYEFIQYzIU07LwMlJQuCFmcx7IQTgoIMA0GCSqGSIb3DQEBCwUA\n"
"A4IBAQCY8jdaQZChGsV2USggNiMOruYou6r4lK5IpDB/G/wkjUu0yKGX9rbxenDI\n"
"U5PMCCjjmCXPI6T53iHTfIUJrU6adTrCC2qJeHZERxhlbI1Bjjt/msv0tadQ1wUs\n"
"N+gDS63pYaACbvXy8MWy7Vu33PqUXHeeE6V/Uq2V8viTO96LXFvKWlJbYK8U90vv\n"
"o/ufQJVtMVT8QtPHRh8jrdkPSHCa2XV4cdFyQzR1bldZwgJcJmApzyMZFo6IQ6XU\n"
"5MsI+yMRQ+hDKXJioaldXgjUkK642M4UwtBV8ob2xJNDd2ZhwLnoQdeXeGADbkpy\n"
"rqXRfboQnoZsG4q5WTP468SQvvG5\n"
"-----END CERTIFICATE-----\n";

// BEGIN: Glue code provided by Thrimbor
int custom_mbedtls_net_send( void *ctx, const unsigned char *buf, size_t len )
{
    int fd = ((mbedtls_net_context *) ctx)->fd;
    return send(fd, buf, len, 0);
}

int custom_mbedtls_net_recv( void *ctx, unsigned char *buf, size_t len )
{
    int fd = ((mbedtls_net_context *) ctx)->fd;
    int r = recv(fd, buf, len, 0);
    if (r == -1) debugPrint("failed, errno: %d\n", errno);
    return r;
}

int custom_mbedtls_net_connect( mbedtls_net_context *ctx, const char *host,
                         const char *port, int proto )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    struct addrinfo hints, *addr_list, *cur;

    /* Do name resolution with IPv4 */
    memset( &hints, 0, sizeof( hints ) );
    hints.ai_family = AF_INET;
    hints.ai_socktype = proto == MBEDTLS_NET_PROTO_UDP ? SOCK_DGRAM : SOCK_STREAM;
    hints.ai_protocol = proto == MBEDTLS_NET_PROTO_UDP ? IPPROTO_UDP : IPPROTO_TCP;

    if( getaddrinfo( host, port, &hints, &addr_list ) != 0 )
        return( MBEDTLS_ERR_NET_UNKNOWN_HOST );

    /* Try the sockaddrs until a connection succeeds */
    ret = MBEDTLS_ERR_NET_UNKNOWN_HOST;
    for( cur = addr_list; cur != NULL; cur = cur->ai_next )
    {
        ctx->fd = (int) socket( cur->ai_family, cur->ai_socktype,
                            cur->ai_protocol );
        if( ctx->fd < 0 )
        {
            ret = MBEDTLS_ERR_NET_SOCKET_FAILED;
            continue;
        }

        if( connect( ctx->fd, cur->ai_addr, cur->ai_addrlen ) == 0 )
        {
            ret = 0;
            break;
        }

        close( ctx->fd );
        ret = MBEDTLS_ERR_NET_CONNECT_FAILED;
    }

    freeaddrinfo( addr_list );

    return( ret );
}

static inline size_t min (size_t a, size_t b)
{
    return (a < b) ? a : b;
}

int mbedtls_hardware_poll (void *data, unsigned char *output, size_t len, size_t *olen) {
    size_t written = 0;
    while (written < len) {
        uint32_t buf;
        rand_s(&buf);
        size_t bytes_to_copy = min(len-written, 4);
        memcpy(output, &buf, bytes_to_copy);
        output += bytes_to_copy;
        written += bytes_to_copy;
    }

    *olen = written;
    return 0;
}
// END: Glue code provided by Thrimbor

void try_https_request(void* arg) {

    mbedtls_net_context server_fd;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    mbedtls_x509_crt cacert;

    const char *host = "httpbin.org";
    const char *path = "/anything";
    const char *port = "443";
    char request[1000];
    char error_buf[100];
    int ret;
    sprintf(request, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, host);

    // Initialize structures
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_x509_crt_init(&cacert);

    // Seed the RNG
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0)) != 0) {
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        debugPrint("Failed to seed RNG: %s\n", error_buf);
        goto exit;
    }

    // Configure SSL defaults
    if ((ret = mbedtls_ssl_config_defaults(&conf,
                    MBEDTLS_SSL_IS_CLIENT,
                    MBEDTLS_SSL_TRANSPORT_STREAM,
                    MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        debugPrint("SSL config defaults failed: %s\n", error_buf);
        goto exit;
    }

    mbedtls_x509_crt_parse(&cacert, (const unsigned char *)ca_cert, sizeof(ca_cert));
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    // Insecure option for testing (disable certificate verification)
    //mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);

    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

    // Connect to server using custom function
    if ((ret = custom_mbedtls_net_connect(&server_fd, host, port, MBEDTLS_NET_PROTO_TCP)) != 0) {
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        debugPrint("Connection failed: %s\n", error_buf);
        goto exit;
    }

    // Setup SSL context
    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        debugPrint("SSL setup failed: %s\n", error_buf);
        goto exit;
    }

    // Set hostname for SNI
    if ((ret = mbedtls_ssl_set_hostname(&ssl, host)) != 0) {
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        debugPrint("Hostname set failed: %s\n", error_buf);
        goto exit;
    }

    // Set custom BIO callbacks
    mbedtls_ssl_set_bio(&ssl, &server_fd, custom_mbedtls_net_send, custom_mbedtls_net_recv, NULL);

    // Perform SSL handshake
    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_strerror(ret, error_buf, sizeof(error_buf));
            debugPrint("Handshake failed: %s\n", error_buf);
            goto exit;
        }
    }

    // Verify server certificate (if verification enabled)
    uint32_t flags = mbedtls_ssl_get_verify_result(&ssl);
    if (flags != 0) {
        debugPrint("Certificate verification failed (Flags: 0x%X)\n", flags);
        goto exit;
    }

    // Send HTTP request
    size_t written = 0;
    size_t request_len = strlen(request);
    while (written < request_len) {
        ret = mbedtls_ssl_write(&ssl, (const unsigned char*)request + written, request_len - written);
        if (ret <= 0) {
            if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
            mbedtls_strerror(ret, error_buf, sizeof(error_buf));
            debugPrint("Write failed: %s\n", error_buf);
            goto exit;
        }
        written += ret;
    }

    // Read response
    unsigned char buf[1024];
    do {
        ret = mbedtls_ssl_read(&ssl, buf, sizeof(buf) - 1);
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
        if (ret <= 0) break;

        buf[ret] = '\0';
        debugPrint("%s", buf);
    } while (1);

    if (ret < 0 && ret != MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        debugPrint("Read failed: %s\n", error_buf);
    }

exit:
    // Cleanup
    mbedtls_ssl_close_notify(&ssl);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_x509_crt_free(&cacert);
}

int main(void) {
    // Note: using widescreen mode here because otherwise the content
    // won't quite fit on the screen when using debugPrint...
    XVideoSetMode(720, 480, 32, REFRESH_DEFAULT);
    int net_init = nxNetInit(NULL);
    if (net_init != 0) {
        debugPrint("Failed to intialise net %i\n", net_init);
        while (1) NtYieldExecution();
    }

    debugPrint("NXDK HTTPS test!\n");
    sys_thread_new("https_client_netconn", try_https_request, NULL, DEFAULT_THREAD_STACKSIZE, DEFAULT_THREAD_PRIO);

    while (1) {
        NtYieldExecution();
    }
    return 0;
}
