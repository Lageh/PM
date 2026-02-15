from .server import PMHandler, ThreadingHTTPServer, HOST, PORT, init_db


if __name__ == '__main__':
    init_db()
    server = ThreadingHTTPServer((HOST, PORT), PMHandler)
    print(f'Servidor rodando em http://{HOST}:{PORT}')
    server.serve_forever()
