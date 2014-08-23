#!/usr/bin/env python

from blog_auth import BlogAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

def main():
    # Instantiate FTP handler class
    handler = FTPHandler
    handler.authorizer = BlogAuthorizer()

    # Define a customized banner (string returned when client connects)
    handler.banner = "FTP for USTC Blog owners. Login username is domain\\username, password is your WordPress password."

    # Specify a masquerade address and the range of ports to use for
    # passive connections.  Decomment in case you're behind a NAT.
    handler.masquerade_address = '202.141.160.99'
    handler.passive_ports = range(60000, 65535)

    address = ('0.0.0.0', 2121)
    server = FTPServer(address, handler)

    # set a limit for connections
    server.max_cons = 256
    server.max_cons_per_ip = 5
    server.max_login_attempts = 10

    # start ftp server
    server.serve_forever()

if __name__ == '__main__':
    main()
