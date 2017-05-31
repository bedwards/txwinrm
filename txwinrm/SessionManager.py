##############################################################################
#
# Copyright (C) Zenoss, Inc. 2016, all rights reserved.
#
# This content is made available according to terms specified in
# License.zenoss under the directory where your Zenoss product is installed.
#
##############################################################################

"""txsessionmgr - Python module for a single persistent connection to a device
for multiple clients.

Useful for situations when multiple connections to a device can be handled
with one connection through a single login, e.g. txciscoapic, txwinrm

The global SESSION_MANAGER is instantiated one time and is used to manage
all sessions

Session should be subclassed and implemented to login/logout, send requests,
and handle responses

A Client should always have a key property.  This will be unique to the types
of transactions/requests being made through a single Session

"""

from twisted.internet.defer import inlineCallbacks, returnValue


class Session(object):

    """Session handler for connection to a device.

    Session class is responsible for implementing the login/logout methods.
    """

    def __init__(self):
        # Used to keep track of clients using session.
        self._clients = set()

        # The currently valid token. This can be anything that the client
        # needs to know the connection is alive.
        self._token = None

        # Deferred waiting for login result.
        self._login_d = None

        # Error from last login if applicable.
        self._login_error = None

    @inlineCallbacks
    def deferred_login(self, client):
        """Kick off a deferred login to a device from the first
        client that needs the connection.

        Subsequent clients will use the data returned from the first login.

        :param client: Client initiating a connection
        :type client: ZenPack specific client
        :rtype: Deferred
        :return: Returns ZenPack unique token to be used for a session.
        """
        self._clients.add(client)
        if self._token:
            returnValue(self._token)

        # No one already waiting for a token. Login to get a new one.
        if not self._login_d or self._login_d.called:
            self._login_d = self._deferred_login(client)

            try:
                self._token = yield self._login_d
            except Exception as e:
                self._login_error = e
                raise

        # At least one other client is already waiting for a token, and
        # the login to get it is already in progress. Wait for that
        # login to finish, then return its token.
        else:
            yield self._login_d
            if self._login_error:
                raise self._login_error

        returnValue(self._token)

    @inlineCallbacks
    def deferred_logout(self, client):
        """Calls session._deferred_logout() only if all other clients
        using the same session have also called deferred_logout.
        """
        if len(self._clients) <= 1:
            if self._token:
                try:
                    yield self._deferred_logout(client)
                except Exception:
                    pass

            self._token = None

        self._clients.discard(client)
        returnValue(None)

    @inlineCallbacks
    def _deferred_login(self, client):
        """Performs the ZenPack specific login to a device.

        This will only be called from the first client to fire off the deferred.
        All other clients will use the _token returned from this method.

        :param client: Client initiating a connection
        :type client: ZenPack specific client
        :rtype: Deferred
        :return: Returns a Deferred which is logs into the device.
        """
        returnValue(None)

    @inlineCallbacks
    def _deferred_logout(self, client):
        """Performs the ZenPack specific logout from a device.

        This will only be called by the last client to logout of the session.

        :param client: Client closing connection
        :type client: ZenPack specific client
        :rtype: Deferred
        :return: Returns a Deferred which logs out of the device.
        """
        returnValue(None)


class SessionManager(object):

    """Class to manage open sessions to devices."""

    def __init__(self):
        # Used to keep track of sessions.
        self._sessions = {}

    def get_connection(self, key):
        """Return the session for a given key."""
        if key is None:
            raise Exception('Client key cannot be empty')
        return self._sessions.get(key, None)

    def remove_connection(self, key):
        """End a session by a key.

        This can happen if the token is too old, the server reboots, or if
        the XML API is disabled and enabled.
        """
        session = self.get_connection(key)
        if session:
            self._sessions.pop(key)

    @inlineCallbacks
    def init_connection(self, client, session_class=Session):
        """Initialize connection to device.

        If a session is already started return it
        else kick off deferred to initiate session.
        The client must contain a key for session storage.

        :param client: Client initiating connection
        :type client: ZenPack defined client
        """
        if not hasattr(client, 'key'):
            raise Exception('Client must contain a key field')

        session = self.get_connection(client.key)
        if session:
            if session._token:
                session._clients.add(client)
                returnValue(session._token)

        if session is None:
            session = session_class()
            self._sessions[client.key] = session

        token = yield session.deferred_login(client)
        returnValue(token)

    @inlineCallbacks
    def close_connection(self, client):
        """Kick off a session's logout.

        If there are no more clients using a session, remove it.

        :param client: Client closing connection
        :type client: ZenPack defined class
        """
        session = self.get_connection(client.key)
        if not session:
            returnValue(None)
        yield session.deferred_logout(client)
        if not session._clients:
            # No more clients so we don't need to keep the session.
            self._sessions.pop(client.key)
        returnValue(None)


SESSION_MANAGER = SessionManager()
