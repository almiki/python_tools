import http.server
import threading


class Server(object):
    def __init__(self):
        self.__server = None
        self.__thread = None
        self.__thread_lock = threading.RLock()

    def start(self, port, webroot):
        print("Start webroot={} port={}".format(webroot, port))

        class MyHandler(http.server.SimpleHTTPRequestHandler):
            def __init__(self, request, client_address, server):
                http.server.SimpleHTTPRequestHandler.__init__(self, request, client_address, server, directory=webroot)

        class HttpServer(http.server.ThreadingHTTPServer):
            def __init__(self, *args, **kwargs):
                http.server.ThreadingHTTPServer.__init__(self, *args, **kwargs)
                self.__lock = threading.RLock()
                self.__cond = threading.Condition(self.__lock)

            def serve_forever(self, *args, **kwargs):
                with self.__lock:
                    self.__serving_forever = True
                    self.__serviced_actions = False

                try:
                    http.server.ThreadingHTTPServer.serve_forever(self, *args, **kwargs)
                finally:
                    with self.__lock:
                        self.__serving_forever = False
                        self.__cond.notify_all()

            def service_actions(self, *args, **kwargs):
                http.server.ThreadingHTTPServer.service_actions(self, *args, **kwargs)

                with self.__lock:
                    self.__serviced_actions = True
                    self.__cond.notify_all()

            def shutdown_safe(self):
                with self.__lock:
                    while self.__serving_forever and not self.__serviced_actions:
                        self.__cond.wait()

                    if not self.__serving_forever:
                        return

                    self.__serving_forever = self.__serviced_actions = False
                    self.shutdown()

        with self.__thread_lock:
            if self.__server is None:
                server = self.__server = HttpServer(("", port),  MyHandler)

                def thread_run():
                    print("thread_run")

                    with self.__thread_lock:
                        if server is not self.__server:
                            return

                        self.__thread = threading.current_thread()

                    self.__server.serve_forever()

                    print("done serving")

                thread = threading.Thread(target=thread_run)
                thread.start()

    def stop(self):
        print("Stopping server...")
        with self.__thread_lock:
            if self.__server is not None:
                self.__server.shutdown_safe()
                self.__server.server_close()
                self.__server = None

                if self.__thread is not None:
                    self.__thread.join()
                    self.__thread = None

        print("Stopped server")


def _get_certbot_nginx_conf():
    import certbot_nginx
    import os
    import inspect

    path = inspect.getfile(certbot_nginx)
    while True:
        d, f = os.path.split(path)
        if os.path.isfile(path):
            path = d
        else:
            break

    return os.path.join(path, "_internal", "tls_configs", "options-ssl-nginx.conf")


# Notes:
#  -n : 'non-interactive', so doesn't prompt for user input/agreement/etc
#  --force-renewal : force renewing even if the cert isn't due yet

# certbot certonly -n --test-cert --webroot -w /home/user/certbot/.webroot -d almiki2.asuscomm.com --config-dir .config --work-dir .work --logs-dir .logs
# certbot renew -n --force-renewal --test-cert --cert-name almiki2.asuscomm.com --config-dir .config --work-dir .work --logs-dir .logs


def main():
    import argparse
    import os
    import shutil
    import hashlib

    p = argparse.ArgumentParser(description='certbot tool')
    p.add_argument('--webroot', '-w', dest="webroot", required=True, help="webroot directory")
    p.add_argument('--storage', '-s', dest="storage", required=True, help="storage directory")
    p.add_argument('--domain', '-d', dest="domain", required=True, help="domain")
    p.add_argument('--port', '-p', dest="port", type=int, required=False, default=8080, help="HTTP server port")
    p.add_argument('--email', '-e', dest="email", required=True, help="Email address for Let's Encrypt")
    p.add_argument('--outputs', '-o', dest="outputs", nargs="*", help="Directories to copy the fullchain.pem and privkey.pem to")
    p.add_argument('--force', dest="force", action=argparse.BooleanOptionalAction, help="Force renewal?")
    p.add_argument('--real', dest="real", action=argparse.BooleanOptionalAction, help="Do it for real?")
    p.add_argument('action', choices=['create','renew','wipe'], help="action")
    args = p.parse_args()

    webroot = os.path.abspath(args.webroot)
    storage = os.path.abspath(args.storage)
    outputs = [os.path.join(o) for o in args.outputs] if args.outputs is not None else []

    for folder in (webroot, storage) + tuple(outputs):
        if not os.path.isdir(folder):
            raise Exception("Missing directory: " + folder)

    if args.action == "wipe":
        for d in [webroot, storage]:
            shutil.rmtree(d)
            os.mkdir(d)
            print("Wiped " + d)
        return

    server = Server()

    try:
        server.start(args.port, webroot)

        if args.action == "create":
            op = "certonly"
            result = os.system("certbot certonly -n {test} {force} -m {email} --agree-tos --webroot -w {webroot} -d {domain} --config-dir {config} --work-dir {work} --logs-dir {logs}"
                               .format(test="--test-cert" if not args.real else "",
                                       force="--force-renewal" if args.force else "",
                                       email=args.email,
                                       webroot=webroot,
                                       domain=args.domain,
                                       config=os.path.join(storage, ".config"),
                                       work=os.path.join(storage, ".work"),
                                       logs=os.path.join(storage, ".logs")))

        elif args.action == "renew":
            op = "renew"
            result = os.system("certbot renew -n {test} {force} --cert-name {domain} --config-dir {config} --work-dir {work} --logs-dir {logs}"
                               .format(test="--test-cert" if not args.real else "",
                                       force="--force-renewal" if args.force else "",
                                       domain=args.domain,
                                       config=os.path.join(storage, ".config"),
                                       work=os.path.join(storage, ".work"),
                                       logs=os.path.join(storage, ".logs")))

        else:
            raise Exception("Unsupported: " + args.action)

        if result != 0:
            raise Exception("{} result {}".format(op, result))

        print("Cmd result: ".format(result))

        cert_file = os.path.join(storage, ".config", "live", args.domain, "fullchain.pem")
        key_file = os.path.join(storage, ".config", "live", args.domain, "privkey.pem")
        nginx_file = _get_certbot_nginx_conf()

        for f in [cert_file, key_file, nginx_file]:
            if not os.path.isfile(f):
                raise Exception("Can't find " + f)

        for o in outputs:
            cf = os.path.join(o, "fullchain.pem")
            kf = os.path.join(o, "privkey.pem")
            nf = os.path.join(o, "options-ssl-nginx.conf")

            for source, dest in [(cert_file, cf), (key_file, kf), (nginx_file, nf)]:
                try:
                    with open(source, 'rb') as f:
                        src_hash = hashlib.file_digest(f, 'sha256').hexdigest()
                except:
                    src_hash = None

                try:
                    with open(dest, 'rb') as f:
                        dest_hash = hashlib.file_digest(f, 'sha256').hexdigest()
                except:
                    dest_hash = None

                if src_hash is None or dest_hash is None or src_hash != dest_hash:
                    shutil.copyfile(source, dest)
                    print("Copied '{}' to '{}'".format(source, dest))
                else:
                    print("Skipping copy of '{}' to '{}'".format(source, dest))

    finally:
        server.stop()



if __name__ == "__main__":
    main()
