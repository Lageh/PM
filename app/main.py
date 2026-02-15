from .server import PMHandler, ThreadingHTTPServer, HOST, PORT, get_access_url, init_db


if __name__ == '__main__':
    init_db()
    server = ThreadingHTTPServer((HOST, PORT), PMHandler)
    print(f'Servidor rodando em {get_access_url()}')
    server.serve_forever()
