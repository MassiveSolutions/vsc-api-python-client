"""
Client for VSC API.
"""

import base64
import json
import ipaddr
import dns.resolver
import random
import urllib
import urllib2
import uuid

from .errors import *

# ----------------------------------------------------------------------
# local definitions

DEFAULT_HOSTNAME = 'api.vsc.com'
DEFAULT_TCP_PORT = 8914
DEFAULT_TIMEOUT = 5
SRV_PREFIX = '_vsc-api-server._tcp.'


class VscApiClient():
    """
    VSC API Client implementation.
    """

    __addrs = []
    __secure = True
    __username = None
    __password = None
    __user_id = None
    __timeout = DEFAULT_TIMEOUT

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
        self.__secure = secure
        if timeout is not None:
            self.__timeout = timeout
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
                self.__addrs = [(hostname, port)]
            else:
                self.__addrs = [(hostname, DEFAULT_TCP_PORT)]
        except Exception:
            self.__addrs = _resolve(hostname, port)

    def setAuth(self, username, password):
        """
        Set new authentication requisites for the Client.

        :param username: Caller user login name.
        :type username: string
        :param password: Caller user password.
        :type password: string
        """
        if username != self.__username:
            self.__user_id = None
        self.__username = username
        self.__password = password

    def dropAuth(self):
        """
        Drop all authentication requisites for the Client.
        """
        self.__username = None
        self.__password = None
        self.__user_id = None

    # -----------------------------------------------------------------
    # VSC API bindings
    # -----------------------------------------------------------------

    def whoami(self):
        """
        Return current user ID - UUID of the user, identified by
        the username and the password.

        :rtype: string
        """
        reply = self._request('GET', '/whoami')
        return reply['id']

    # -----------------------------------------------------------------
    # AAA methods

    def aaaAddUser(self, data, user_id = None):
        """
        Create a new VSC user.
        On success return UUID of the user created.

        :param data: user data dictionary.
        :type data: dict
        :param user_id: unique ID for the new user.
        :type user_id: string or None
        :rtype: string
        """
        if user_id is None:
            user_id = uuid.uuid4().hex
        url_path = 'aaa/user/{0}'.format(user_id)
        self._request('PUT', url_path, {'create': 1}, data)
        return user_id

    def aaaUpdateUser(self, user_id, data):
        """
        Update the VSC user info.

        :param user_id: unique ID for the user.
        :type user_id: string
        :param data: user data dictionary.
        :type data: dict
        """
        self._request('PUT', 'aaa/user/{0}'.format(user_id), None, data)

    def aaaPasswd(self, password):
        """
        Change the password for the current user.
        After success the Client must be reconfigured with
        setAuth() method to apply the new password for a
        next request.

        :param password: new password for the user.
        :type password: string
        """
        self._request('POST', 'aaa/passwd', None, password)

    def aaaListUsers(self, format = 'ids_only'):
        """
        Return a list of UUIDs of all users.

        :param format: result format. Can be 'ids_only' which is the
            default and 'full'. In former case the method will return
            a plain list of user IDs found; in latter case - the list of
            [user_id, user_data] lists, where each user_id is string and
            user_data is dict.
        :type format: string, one of ('ids_only', 'full').
        :rtype: list of strings
        """
        return self._request('GET', 'aaa/user', {'format': format})

    def aaaGetUserData(self, user_id):
        """
        Return user data dictionary.

        :param user_id: UUID of the user.
        :type user_id: string
        :rtype: dict
        """
        return self._request('GET', 'aaa/user/{0}'.format(user_id))

    def aaaAddRole(self, data, role_id = None):
        """
        Create a new VSC role.
        On success return UUID of the role created.

        :param data: role data dictionary.
        :type data: dict
        :param role_id: unique ID for the new role.
        :type role_id: string or None
        :rtype: string
        """
        if role_id is None:
            role_id = uuid.uuid4().hex
        url_path = 'aaa/role/{0}'.format(role_id)
        self._request('PUT', url_path, {'create': 1}, data)
        return role_id

    def aaaUpdateRole(self, role_id, data):
        """
        Update the VSC role info.

        :param user_id: unique ID for the new user.
        :type user_id: string
        :param data: user data dictionary.
        :type data: dict
        """
        self._request('PUT', 'aaa/role/{0}'.format(role_id), None, data)

    def aaaDelRole(self, role_id):
        """
        Remove the VSC role identified by the UUID.

        :param role_id: UUID of the role.
        :type role_id: string
        """
        self._request('DELETE', 'aaa/role/{0}'.format(role_id))

    def aaaListRoles(self, format = 'ids_only'):
        """
        Return a list of UUIDs of all roles.

        :param format: result format. Can be 'ids_only' which is the
            default and 'full'. In former case the method will return
            a plain list of role IDs found; in latter case - the list of
            [role_id, role_data] lists, where each role_id is string and
            role_data is dict.
        :type format: string, one of ('ids_only', 'full').
        :rtype: list of strings
        """
        return self._request('GET', 'aaa/role', {'format': format})

    def aaaGetRoleData(self, role_id):
        """
        Return role data dictionary.

        :param role_id: UUID of the role.
        :type role_id: string
        :rtype: dict
        """
        return self._request('GET', 'aaa/role/{0}'.format(role_id))

    def aaaAddRoleRoleRelation(self, major_id, minor_id):
        """
        Add a directional relation between the two roles.
        The roles must exist before performing the operation.
        The operation is idempotent.

        :param major_id: UUID of the major role.
        :type major_id: string
        :param minor_id: UUID of the minor role.
        :type minor_id: string
        """
        url_path = 'aaa/role/{0}/minors/{1}'.format(major_id, minor_id)
        self._request('PUT', url_path)

    def aaaDelRoleRoleRelation(self, major_id, minor_id):
        """
        Remove the directional relation between the two roles.
        It's not an error to supply the roles not assigned with
        each other so the operation is idempotent.

        :param major_id: UUID of the major role.
        :type major_id: string
        :param minor_id: UUID of the minor role.
        :type minor_id: string
        """
        url_path = 'aaa/role/{0}/minors/{1}'.format(major_id, minor_id)
        self._request('DELETE', url_path)

    def aaaSetRoleMinors(self, major_id, minor_ids):
        """
        Update list of minor roles assigned to the role.
        If the major role has some minor roles assigned before
        the call and the minor roles does not exist in the
        minor_ids list, this relations between the major role and
        the minor roles will be removed. So, to completely remove
        all role-to-role associations for the major role
        aaaSetRoleMinors(user_id, []) call can be used effectively.

        :param major_id: UUID of the major role
        :type major_id: string
        :param minor_ids: UUIDs of the minor roles.
        :type minor_ids: list of strings
        """
        url_path = 'aaa/role/{0}/minors'.format(major_id)
        self._request('PUT', url_path, None, minor_ids)

    def aaaListRoleMinors(self, major_id):
        """
        Return a list of minor roles for the role.

        :param role_id: UUID of the role.
        :type role_id: string
        :rtype: list of UUIDs (list of strings)
        """
        url_path = 'aaa/role/{0}/minors'.format(major_id)
        return self._request('GET', url_path)

    def aaaListRoleMajors(self, minor_id):
        """
        Return a list of major roles for the role.

        :param role_id: UUID of the role.
        :type role_id: string
        :rtype: list of UUIDs (list of strings)
        """
        url_path = 'aaa/role/{0}/majors'.format(minor_id)
        return self._request('GET', url_path)

    def aaaAddUserRoleRelation(self, user_id, role_id):
        """
        Add a user-to-role relation.
        The user and the role must exist before the operation.
        The operation is idempotent.

        :param user_id: UUID of the user.
        :type user_id: string
        :param role_id: UUID of the role.
        :type role_id: string
        """
        url_path = 'aaa/user/{0}/roles/{1}'.format(user_id, role_id)
        self._request('PUT', url_path)

    def aaaDelUserRoleRelation(self, user_id, role_id):
        """
        Remove the user-to-role relation.
        The operation is idempotent.

        :param user_id: UUID of the user.
        :type user_id: string
        :param role_id: UUID of the role.
        :type role_id: string
        """
        url_path = 'aaa/user/{0}/roles/{1}'.format(user_id, role_id)
        self._request('DELETE', url_path)

    def aaaSetUserRoles(self, user_id, role_ids):
        """
        Update list of roles assigned to the user.
        If the user has some roles assigned before the call
        and the roles does not exist in the role_ids list,
        this relations between the user and the roles will
        be removed. So, to completely remove all user-role
        associations for the user aaaSetUserRoles(user_id, [])
        call can be used effectively.

        :param user_id: UUID of the user
        :type user_id: string
        :param role_ids: UUIDs of the roles.
        :type role_ids: list of strings
        """
        url_path = 'aaa/user/{0}/roles'.format(user_id)
        self._request('PUT', url_path, None, role_ids)

    def aaaListUserRoles(self, user_id):
        """
        Return a list of roles assigned to the user.

        :param user_id: UUID of the user.
        :type user_id: string
        :rtype: list of UUIDs (list of strings)
        """
        url_path = 'aaa/user/{0}/roles'.format(user_id)
        return self._request('GET', url_path)

    def aaaListRoleUsers(self, role_id):
        """
        Return a list of users assigned to the role.

        :param role_id: UUID of the role.
        :type role_id: string
        :rtype: list of UUIDs (list of strings)
        """
        url_path = 'aaa/role/{0}/users'.format(role_id)
        return self._request('GET', url_path)

    def jobAdd(self, data, job_id = None):
        """
        Create a new job and enqueue it.
        Return a UUID for the created job on success.

        :param data: preferences for the job.
        :type data: dictionary
        :param job_id: UUID for the new job. Will be autogenerated
            when not defined explicitly.
        :type job_id: string or None
        :rtype: string
        """
        if job_id is None:
            job_id = uuid.uuid4().hex + uuid.uuid4().hex
        url_path = 'job/{0}'.format(job_id)
        self._request('PUT', url_path, {'create': 1}, data)
        return job_id

    def jobGetData(self, job_id, format = 'basic'):
        """
        Return Job info.
        Format can be 'basic' which is the default and 'full' which
        can be fullfilled only with extra privileges.
        On success return a dictionary with job info.

        :param job_id: UUID of the job.
        :type job_id: string
        :param format: result format.
        :type format: 'basic' or 'full'
        :rtype: dict
        """
        if format not in ('basic', 'full'):
            raise BadArgError('Bad format value')
        url_path = 'job/{0}'.format(job_id)
        return self._request('GET', url_path, {'format': format})

    def jobStop(self, job_id, save = False, saved_description = None,
                save_homefs = False, force = False):
        """
        Immediately stop the job.

        :param job_id: UUID of the job.
        :type job_id: string
        :param save: save the PaaS cluster or not. Default is False;
        :type save: boolean
        :param saved_description: textual description for
            cluster (for save).
        :type saved_description: string
        :param save_homefs: save the cluster's home FS or not.
            Default is False.
        :type save_homefs: boolean
        :param force: force stop stalled job.
        :type force: boolean
        """
        entity = {}
        if saved_description is not None:
            entity['description'] = saved_description
        if save_homefs:
            entity['save_homefs'] = 1
        params = {'save': int(save), 'force': int(force)}
        url = 'job/{0}'.format(job_id)
        self._request('STOP', url, params, entity)

    def jobList(self, format = 'basic', historic = False):
        """
        Return list of user's jobs.
        Format of the list is defined by the 'format' argument
        which can be 'basic' (default), 'full' (extra permissions
        required) and 'ids_only'.
        For the 'basic' and 'full' format a list of dicts will be
        returned. For the 'ids_only' format a list of UUIDs (strings)
        will be returned.
        If 'historic' argument is set to False (which is the default),
        an active jobs will be returned, otherwise will be returned
        a list of stopped jobs.

        :param format: result format type.
        :type format: 'basic', 'full' or 'ids_only'.
        :param historic: which jobs will be returned.
        :type historic: boolean
        :rtype: list
        """
        if format not in ('basic', 'full', 'ids_only'):
            raise BadArgError('Bad format value')
        if not isinstance(historic, bool):
            raise BadArgError('Bad value for "historic"')
        if self.__user_id is not None:
            # user ID already known. requesting directly
            return self.jobListAll(format, historic, self.__user_id)
        # user ID is not known yet. requesting redirection
        params = {'format': format, 'historic': int(historic)}
        return self._request('GET', 'list_jobs', params)

    def jobListAll(self, format = 'basic', historic = False,
                   user_id = None):
        """
        Return list of jobs.
        Format of the list is defined by the 'format' argument
        which can be 'basic' (default), 'full' (extra permissions
        required) and 'ids_only'.
        For the 'basic' and 'full' format a list of dicts will be
        returned. For the 'ids_only' format a list of UUIDs (strings)
        will be returned.
        If 'historic' argument is set to False (which is the default),
        an active jobs will be returned, otherwise will be returned
        a list of stopped jobs.
        If 'user_id' is defined, only jobs owned by the user will
        be returned.

        :param format: result format type.
        :type format: 'basic', 'full' or 'ids_only'.
        :param historic: which jobs will be returned.
        :type historic: boolean
        :param user_id: UUID of the job's owner.
        :type user_id: string or None
        :rtype: list
        """
        if format not in ('basic', 'full', 'ids_only'):
            raise BadArgError('Bad format value')
        if not isinstance(historic, bool):
            raise BadArgError('Bad value for "historic"')
        params = {'format': format, 'historic': int(historic)}
        if user_id is not None:
            params['user'] = user_id
        return self._request('GET', 'job', params)

    def jobForward(self, job_id, tcp_ports):
        """
        Create TCP connection forwardings from the Internet
        to the Access node of the virtual cluster.

        :param job_id: UUID of the job.
        :type job_id: string
        :param tcp_ports: TCP port numbers to forward.
        :type tcp_ports: list of integers between 1 and 65535
        """
        url_path = '/job/{0}/fwd'.format(job_id)
        self._request('PUT', url_path, None, tcp_ports)

    def jobGetForwardMap(self, job_id):
        """
        Return current connection forwarding map for the job.

        :param job_id: UUID of the job.
        :type job_id: string
        :rtype: list of (public_ip, public_port, destination_port)
            where public_ip is string, public_port and
            destination_port are integers.
        """
        url_path = '/job/{0}/fwd'.format(job_id)
        return self._request('GET', url_path)

    def packageGetData(self, package_id):
        """
        Return package info.

        :param package_id: UUID of the package.
        :type package_id: string
        :rtype: dict
        """
        return self._request('GET', 'package/{0}'.format(package_id))

    def packageCreate(self, data, package_id = None):
        """
        Create a new package.
        Return an UUID of the created package on success.

        :param data: package metainfo.
        :type data: dict
        :param package_id: UUID of the package.
        :type package_id: string or None.
        :rtype: string
        """
        if package_id is None:
            package_id = uuid.uuid4().hex
        url_path = 'package/{0}'.format(package_id)
        self._request('PUT', url_path, {'create': 1}, data)
        return package_id

    def packageUpdate(self, package_id, data):
        """
        Update metainfo for the existing package.

        :param package_id: UUID of the package.
        :type package_id: string
        :param data: package metainfo.
        :type data: dict
        """
        self._request('PUT', 'package/{0}'.format(package_id), None, data)

    def packageDel(self, package_id):
        """
        Remove the package.

        :param package_id: UUID of the package.
        :type package_id: string
        """
        self._request('DELETE', 'package/{0}'.format(package_id))

    def packageList(self, format = 'full'):
        """
        List packages owned by the caller.

        :param format: result format. Can be 'full' (which is the default)
            and 'ids_only'. In the former case the method will return list
            of dictionaries (a dictionary with metainfo for each package
            found), and the latter case the method will return a plain
            list of UUID of packages found.
        :type format: string
        :rtype: list of dicts or list of strings
        """
        if format not in ('full', 'ids_only'):
            raise BadArgError('Bad format value')
        if self.__user_id is not None:
            # user ID already known. requesting directly
            return self.packageListAll(format, self.__user_id)
        # user ID is not known yet. requesting redirection
        return self._request('GET', 'list_packages', {'format': format})

    def packageListAll(self, format = 'full', user_id = None):
        """
        List all packages.

        :param format: result format. Can be 'full' (which is the default)
            and 'ids_only'. In the former case the method will return list
            of dictionaries (a dictionary with metainfo for each package
            found), and the latter case the method will return a plain
            list of UUID of packages found.
        :type format: string
        :param user_id: UUID of the package's owner. If defined,
            only packages owned by the user will be searched.
        :type user_id: string or None
        :rtype: list of dicts or list of strings
        """
        if format not in ('full', 'ids_only'):
            raise BadArgError('Bad format value')
        params = {'format': format}
        if user_id is not None:
            params['user'] = user_id
        return self._request('GET', 'package', params)

    def imageGetData(self, image_id):
        """
        Return image info.

        :param image_id: UUID of the image.
        :type image_id: string
        :rtype: dict
        """
        return self._request('GET', 'image/{0}'.format(image_id))

    def imageGenerateUrl(self, image_id):
        """
        Generate temporary URL which can be used to download
        the image archive.

        :param image_id: UUID of the image.
        :type image_id: string or None.
        :rtype: string
        """
        return self._request('GET', 'image/{0}/genurl'.format(image_id))

    def imageCreate(self, data, image_id = None):
        """
        Create a new image.
        Return an UUID of the created image on success.

        :param data: image metainfo.
        :type data: dict
        :param image_id: UUID of the image.
        :type image_id: string or None.
        :rtype: string
        """
        if image_id is None:
            image_id = uuid.uuid4().hex
        url_path = 'image/{0}'.format(image_id)
        self._request('PUT', url_path, {'create': 1}, data)
        return image_id

    def imageUpdate(self, image_id, data):
        """
        Update metainfo for the existing image.

        :param image_id: UUID of the image.
        :type image_id: string
        :param data: image metainfo.
        :type data: dict
        """
        self._request('PUT', 'image/{0}'.format(image_id), None, data)

    def imageDel(self, image_id):
        """
        Remove the image.

        :param image_id: UUID of the image.
        :type image_id: string
        """
        self._request('DELETE', 'image/{0}'.format(image_id))

    def imageList(self, format = 'full'):
        """
        List images owned by the caller.

        :param format: result format. Can be 'full' (which is the default)
            and 'ids_only'. In the former case the method will return list
            of dictionaries (a dictionary with metainfo for each image
            found), and the latter case the method will return a plain
            list of UUID of images found.
        :type format: string
        :rtype: list of dicts or list of strings
        """
        if format not in ('full', 'ids_only'):
            raise BadArgError('Bad format value')
        if self.__user_id is not None:
            # user ID already known. requesting directly
            return self.imageListAll(format, self.__user_id)
        # user ID is not known yet. requesting redirection
        return self._request('GET', 'list_images', {'format': format})

    def imageListAll(self, format = 'full', user_id = None):
        """
        List all images.

        :param format: result format. Can be 'full' (which is the default)
            and 'ids_only'. In the former case the method will return list
            of dictionaries (a dictionary with metainfo for each image
            found), and the latter case the method will return a plain
            list of UUID of images found.
        :type format: string
        :param user_id: UUID of the image's owner. If defined,
            only images owned by the user will be searched.
        :type user_id: string or None
        :rtype: list of dicts or list of strings
        """
        if format not in ('full', 'ids_only'):
            raise BadArgError('Bad format value')
        params = {'format': format}
        if user_id is not None:
            params['user'] = user_id
        return self._request('GET', 'image', params)

    def getImageReceiverBaseURLs(self):
        """
        Return list of base URLs for available VSC Image Receivers.

        :rtype: list of strings
        """
        return self._request('GET', 'image_receiver')

    def jobProfileCreate(self, job_profile_data, is_public = False,
                         job_profile_id = None):
        """
        Create a new job profile.
        On success return UUID of the job profile created.

        :param job_profile_data: data for the job profile.
        :type job_profile_data: dict
        :param is_public: make the job profile public or not.
            Default is False (job profile will not be published).
        :type is_public: boolean
        :param job_profile_id: UUID of job profile to create.
            If not defined, will be generated automatically.
        :type job_profile_id: string or NoneType
        :rtype: string
        """
        if job_profile_id is None:
            job_profile_id = uuid.uuid4().hex
        url = 'job_profile/{0}'.format(job_profile_id)
        params = {'create': 1, 'public': int(is_public)}
        self._request('PUT', url, params, job_profile_data)
        return job_profile_id

    def jobProfileUpdate(self, job_profile_id, job_profile_data,
                         is_public):
        """
        Update an existing job profile.

        :param job_profile_id: UUID of job profile to update.
        :type job_profile_id: string
        :param job_profile_data: new data for the job profile.
        :type job_profile_data: dict
        :param is_public: make the job profile public or not.
        :type is_public: boolean
        """
        url = 'job_profile/{0}'.format(job_profile_id)
        params = {'public': is_public}
        self._request('PUT', url, params, job_profile_data)

    def jobProfileDelete(self, job_profile_id):
        """
        Delete an existing job profile.

        :param job_profile_id: UUID of job profile to delete.
        :type job_profile_id: string
        """
        self._request('DELETE', 'job_profile/' + job_profile_id)

    def jobProfileList(self, format = 'full'):
        """
        List job profiles owned by the current user.

        :param format: result format. Can be 'full' (which is the default)
            and 'ids_only'. In the former case the method will return list
            of (id, dict) pairs for each job profile, and the latter case
            the method will return a plain list of UUID of job profiles found.
        :type format: string
        :rtype: list of (id, dict) pairs or list of strings
        """
        if format not in ('full', 'ids_only'):
            raise BadArgError('Bad format value')
        if self.__user_id is not None:
            # user ID already known. requesting directly
            return self.jobProfileListAll(format, self.__user_id)
        # user ID is not known yet. requesting redirection
        return self._request('GET', 'list_job_profiles',
            {'format': format})

    def jobProfileListPublic(self, format = 'full'):
        """
        List all public job profiles.

        :param format: result format. Can be 'full' (which is the default)
            and 'ids_only'. In the former case the method will return list
            of (id, dict) pairs for each job profile, and the latter case
            the method will return a plain list of UUID of job profiles found.
        :type format: string
        :rtype: list of (id, dict) pairs or list of strings
        """
        if format not in ('full', 'ids_only'):
            raise BadArgError('Bad format value')
        return self._request('GET', 'list_public_job_profiles',
            {'format': format})

    def jobProfileListAll(self, format = 'full', user_id = None):
        """
        List all job profiles. If the user_id is defined,
        the method will list all job profiles owned by the user.

        :param format: result format. Can be 'full' (which is the default)
            and 'ids_only'. In the former case the method will return list
            of (id, dict) pairs for each job profile, and the latter case
            the method will return a plain list of UUID of job profiles found.
        :type format: string
        :param user_id: UUID of the job profile's owner. If defined,
            only job profiles owned by the user will be searched.
        :type user_id: string or None
        :rtype: list of (id, dict) pairs or list of strings
        """
        if format not in ('full', 'ids_only'):
            raise BadArgError('Bad format value')
        params = {'format': format}
        if user_id is not None:
            params['user'] = user_id
        return self._request('GET', 'list_job_profiles', params)

    # -----------------------------------------------------------------
    # Internal methods
    # -----------------------------------------------------------------

    def _request(self, method, path, params = None, data = None):
        """
        Do the request to a VSC API Server.

        :param method: HTTP method to use.
        :type method: string
        :param path: resource path
        :type path: string
        :param params: dictionary with URL "query" parameters.
        :type params: dict or None
        :param data: dictionary with extra datum. Will be passed
            to the server as HTTP message body.
        :type data: dict or None
        :rtype: dict
        """
        host, port = random.choice(self.__addrs)
        if self.__secure:
            url = 'https://{0}:{1}/{2}'.format(host, port, path.strip('/'))
        else:
            url = 'http://{0}:{1}/{2}'.format(host, port, path.strip('/'))
        if params is not None:
            url += '?' + urllib.urlencode(params)
        request = urllib2.Request(url)
        request.get_method = lambda: method
        request.add_header('User-Agent', 'VscApiPythonClient')
        if self.__username is not None and self.__password is not None:
            plain_ident = '{0}:{1}'.format(self.__username, self.__password)
            encoded_ident = base64.b64encode(plain_ident)
            request.add_header('Authorization', 'Basic ' + encoded_ident)
        if data is not None:
            request.add_header('Content-Type', 'application/json')
            body = json.dumps(data)
            request.add_header('Content-Length', len(body))
            request.add_data(body)
        try:
            reply = urllib2.urlopen(request, timeout = self.__timeout)
        except urllib2.HTTPError as exc:
            _decodeErrorResponse(exc)
        user_id = reply.headers.get('X-VSC-User-ID')
        if user_id is not None:
            self.__user_id = user_id
        if reply.getcode() != 204:
            reply_data = reply.read()
            if reply_data is not None:
                return json.loads(reply_data)


def _decodeErrorResponse(http_exception):
    """
    Decode the error HTTP response received from the VSC API Server
    and raise an appropriate exception.
    The goal of the method is to provide the most adequate feedback
    to the user.

    :param http_exception: error response.
    :type http_exception: an instance of urllib2.HTTPError
    """
    # look if we have one of simple error cases
    if http_exception.code == 401:
        raise NotAuthenticatedError
    elif http_exception.code == 500:
        raise InternalServerError
    elif http_exception.code == 501:
        raise NotImplementedError
    elif http_exception.code == 404:
        raise NotFoundError
    # ...or try to find more error details in the message body
    error_classes_map = {403: {'access_denied': NotAuthorizedError,
                               'bad_argument': BadArgError}}
    classes = error_classes_map.get(http_exception.code)
    if classes is None:
        # unrecognized error => nothing to decode => re-raise it as is.
        raise http_exception
    # read and decode the entity
    content_length = int(http_exception.headers.get('Content-Length', '0'))
    content_type = http_exception.headers.get('Content-Type')
    if content_type != 'application/json' or content_length <= 0:
        # nothing to decode => re-raise it as is
        raise http_exception
    encoded_entity = http_exception.read(content_length)
    if len(encoded_entity) != content_length:
        # bad message body length => re-raise it as is
        raise http_exception
    try:
        entity = json.loads(encoded_entity)
        error_class = entity['error_class']
        error_message = entity['error_message']
    except Exception:
        # received entity is not valid => re-raise the origin
        # exception as is
        raise http_exception
    # try to map encoded error class to an exception class
    class_name = classes.get(error_class)
    if class_name is None:
        # no exception class found => re-raise it as is
        raise http_exception
    raise class_name(error_message)


def _resolve(hostname, port):
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
        # TODO: obey SRV-record priorities
        return [(item.target.to_text().strip('.'), item.port)
                for item in dns.resolver.query(srvname, 'srv')]
    except dns.resolver.NXDOMAIN:
        # no SRV record found. We'll try to use plain DNS name
        if port is not None:
            return [(hostname, port)]
        else:
            return [(hostname, DEFAULT_TCP_PORT)]
