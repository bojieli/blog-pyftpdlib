#!/usr/bin/env python

import errno
import os
import sys
import warnings

from pyftpdlib._compat import PY3, unicode, getcwdu
from pyftpdlib.authorizers import (AuthenticationFailed, AuthorizerError)
import httplib, urllib

__all__ = ['BlogAuthorizer',
           ]

# ===================================================================
# --- base class
# ===================================================================

class BlogAuthorizer(object):
    read_perms = "elr"
    write_perms = "adfmwM"

    def __init__(self):
        pass

        """
        Read permissions:
         - "e" = change directory (CWD command)
         - "l" = list files (LIST, NLST, STAT, MLSD, MLST, SIZE, MDTM commands)
         - "r" = retrieve file from the server (RETR command)

        Write permissions:
         - "a" = append data to an existing file (APPE command)
         - "d" = delete file or directory (DELE, RMD commands)
         - "f" = rename file or directory (RNFR, RNTO commands)
         - "m" = create directory (MKD command)
         - "w" = store a file to the server (STOR, STOU commands)
         - "M" = change file mode (SITE CHMOD command)

        Optional msg_login and msg_quit arguments can be specified to
        provide customized response strings when user log-in and quit.
        """

    def _parse_domain_username(self, username):
        if username == 'anonymous' or username == '':
            raise AuthenticationFailed('Anonymous access not allowed')

        username_splits = username.split('\\')
        if len(username_splits) != 2:
            raise AuthenticationFailed('Please use domain\\username as FTP username to login. The username should have administrator privilege in your WordPress blog.')
        if username_splits[0] == '' or username_splits[1] == '':
            raise AuthenticationFailed('Domain and username must not be empty.')
        # if the client has specified FQDN as the domain part, use the leftmost subdomain only
        domain_splits = username_splits[0].split('.')
        domain = domain_splits[0] 

        return domain, username_splits[1]

    def validate_authentication(self, username, password, handler):
        """Raises AuthenticationFailed if supplied username and
        password don't match the stored credentials, else return
        None.
        """
        domain, user = self._parse_domain_username(username)
        data = urllib.urlencode({'@domain': domain, '@user': user, '@pass': password })
        headers = {"Content-type": "application/x-www-form-urlencoded", "User-Agent": "pyftplib" }
        api_connection = httplib.HTTPConnection('blog.ustc.edu.cn', timeout=3)
        api_connection.request('POST', '/wp_admin_api.php', data, headers)
        response = api_connection.getresponse()
        if response.status != 200:
            raise AuthenticationFailed(str(response.status) + ' ' + response.reason)
        data = response.read()
        if data == '':
            raise AuthenticationFailed('500 Internal Server Error')
        status_code = int(data.split(' ')[0])
        if status_code == 403:
            raise AuthenticationFailed('Login Failed. Please login with correct domain\\username and password combination.')
        if status_code == 401:
            raise AuthenticationFailed('Sorry, you do not have WordPress administrator privileges.');
        elif status_code != 200:
            raise AuthenticationFailed(data)

    def get_home_dir(self, username):
        """Return the user's home directory.
        Since this is called during authentication (PASS),
        AuthenticationFailed can be freely raised by subclasses in case
        the provided username no longer exists.
        """
        basedir = '/srv/blog/base'
        return basedir + '/' + self._parse_domain_username(username)[0]

    def impersonate_user(self, username, password):
        """Impersonate another user (noop).

        It is always called before accessing the filesystem.
        By default it does nothing.  The subclass overriding this
        method is expected to provide a mechanism to change the
        current user.
        """

    def terminate_impersonation(self, username):
        """Terminate impersonation (noop).

        It is always called after having accessed the filesystem.
        By default it does nothing.  The subclass overriding this
        method is expected to provide a mechanism to switch back
        to the original user.
        """

    def has_user(self, username):
        """Whether the username exists in the virtual users table."""
        return True

    def has_perm(self, username, perm, path=None):
        """Whether the user has permission over path (an absolute
        pathname of a file or a directory).

        Expected perm argument is one of the following letters:
        "elradfmwM".
        """
        if path is None:
            return True

        path = os.path.normcase(path)
        try:
            base = self.get_home_dir(username)
            return self._issubpath(path, base)
        except:
            return False

    def get_perms(self, username):
        """Return current user permissions."""
        return self.read_perms + self.write_perms

    def get_msg_login(self, username):
        """Return the user's login message."""
        return 'Welcome to USTC Blog FTP. You are logged in as ' + username

    def get_msg_quit(self, username):
        """Return the user's quitting message."""
        return 'Goodbye. You are logged out as ' + username

    def _issubpath(self, a, b):
        """Return True if a is a sub-path of b or if the paths are equal."""
        p1 = a.rstrip(os.sep).split(os.sep)
        p2 = b.rstrip(os.sep).split(os.sep)
        return p1[:len(p2)] == p2
