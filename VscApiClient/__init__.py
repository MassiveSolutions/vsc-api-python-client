"""
Client for VSC API.
"""

import json
import ipaddr
import dns.resolver
import random
import urllib
import urllib2

from .errors import *

# ----------------------------------------------------------------------
# local definitions

DEFAULT_HOSTNAME = 'api.vsc.com'
DEFAULT_TCP_PORT = 8914
DEFAULT_TIMEOUT = 5
SRV_PREFIX = '_vsc-api-server._tcp.'

class VscApiClient():

    addrs = []
    secure = True
    username = None
    password = None
    timeout = DEFAULT_TIMEOUT

    def __init__(self, username = None, password = None,
                 hostname = None, port = None, secure = True,
                 timeout = None):
        """
        Class constructor.

        :param username: Caller user login name.
        :type username: string
        :param password: Caller user password.
        :type password: string
        :param hostname: VSC API endpoint address.
        :type hostname: string
        :param port: TCP port number to use.
        :type port: integer between 1 and 65535
        :param secure: use HTTPS or not. Default is True.
        :type secure: boolean
        :param timeout: maximum timeout
        :type timeout: integer
        """
        self.secure = secure
        if timeout is not None:
            self.timeout = timeout
        self.setEndPoint(hostname, port)
        self.setAuth(username, password)

    def setEndPoint(self, hostname = None, port = None):
        """
        Set VSC API endpoint address.

        :param hostname: VSC API endpoint address.
        :type hostname: string
        :param port: TCP port number to use.
        :type port: integer between 1 and 65535
        """
        if hostname is None:
            hostname = DEFAULT_HOSTNAME
        try:
            ipaddr.IPAddress(hostname)
            if port is not None:
                self.addrs = [(hostname, port)]
            else:
                self.addrs = [(hostname, DEFAULT_TCP_PORT)]
        except Exception:
            self.addrs = self._resolve(hostname, port)

    def setAuth(self, username, password):
        """
        Set new authentication requisites for the Client.

        :param username: Caller user login name.
        :type username: string
        :param password: Caller user password.
        :type password: string
        """
        self.username = username
        self.password = password

    def dropAuth(self):
        """
        Drop all authentication requisites for the Client.
        """
        self.username = None
        self.password = None

    # -----------------------------------------------------------------
    # VSC API bindings
    # -----------------------------------------------------------------

    # -----------------------------------------------------------------
    # AAA methods

    def aaaAddUser(self, userdata):
        """
        Create a new VSC user
        """
        return self._request('POST')

    def aaaListRoles(self):
        """
        Return a list of UUIDs of all roles.

        :rtype: list of strings
        """
        return self._request('GET', 'aaa/role')

    # -----------------------------------------------------------------
    # Internal methods
    # -----------------------------------------------------------------

    def _request(self, method, path, args = None):
        """
        Do the request to a VSC API Server.

        :param method: HTTP method to use.
        :type method: string
        :param path: resource path
        :type path: string
        :param args: dictionary with extra datum.
        :type args: dict or None
        :rtype: dict
        """
        host, port = random.choice(self.addrs)
        if self.secure:
            url = 'https://{0}:{1}/{2}'.format(host, port, path.strip('/'))
        else:
            url = 'http://{0}:{1}/{2}'.format(host, port, path.strip('/'))
        if args is not None and method in ('GET', 'HEAD', 'DELETE', 'STOP'):
            url += '?' + urllib.urlencode(args)
        request = urllib2.Request(url)
        request.get_method = lambda: method
        request.add_header('User-Agent', 'VscApiPythonClient')
        if self.username is not None and self.password is not None:
            request.add_header('X-VSC-Login', self.username)
            request.add_header('X-VSC-Password', self.password)
        if args is not None and method in ('POST', 'PUT'):
            request.add_header('Content-Type', 'application/json')
            encoded_args = json.dumps(args)
            request.add_header('Content-Length', len(encoded_args))
            request.add_data(encoded_args)
        reply = urllib2.urlopen(request, timeout = self.timeout)
        reply_data = reply.read()
        if reply_data is not None:
            return json.loads(reply_data)

    def _resolve(self, hostname, port):
        """
        Resolve DNS name to VSC API endpoint addresses.

        :param hostname: DNS name to resolve.
        :type hostname: string
        :param port: TCP port number to use.
        :type port: integer between 1 and 65535
        :rtype: list of (host, port) tuples
        """
        if hostname.startswith(SRV_PREFIX):
            srvname = hostname
        else:
            srvname = SRV_PREFIX + hostname
        try:
            return [(item.target.to_text().strip('.'), item.port)
                    for item in dns.resolver.query(srvname, 'srv')]
        except dns.resolver.NXDOMAIN:
            # no SRV record found. We'll try to use plain DNS name
            if port is not None:
                self.addrs = [(hostname, port)]
            else:
                self.addrs = [(hostname, DEFAULT_TCP_PORT)]
