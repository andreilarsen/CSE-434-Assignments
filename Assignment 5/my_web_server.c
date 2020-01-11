#include "mongoose.h"

// CAUTION: our web server listens on port number 8000 instead of 80, mainly to avoid
// port number collision with existing server such the Apache web server
static const char *s_http_port = "8000";
static struct mg_serve_http_opts s_http_server_opts;

static void ev_handler(struct mg_connection *nc, int ev, void *p) {

    if (ev == MG_EV_HTTP_REQUEST) {

        struct http_message *phttp_req = (struct http_message *) p;
        printf("%s", phttp_req->message.p);

        // This function handles all HTTP requests and generates responses.
        mg_serve_http(nc, phttp_req, s_http_server_opts);
    }
}

int main(void) {

    struct mg_mgr mgr;
    struct mg_connection *nc;

    mg_mgr_init(&mgr, NULL);
    printf("Starting web server on port %s\n", s_http_port);
    nc = mg_bind(&mgr, s_http_port, ev_handler);
    if (nc == NULL) {
        printf("Failed to create listener\n");
        return 1;
    }

    // Set up HTTP server parameters
    mg_set_protocol_http_websocket(nc);
    s_http_server_opts.document_root = ".";  // Serve current directory
    s_http_server_opts.enable_directory_listing = "yes";

    for (;;) {
        mg_mgr_poll(&mgr, 1000);
    }
    mg_mgr_free(&mgr);

    return 0;
}
