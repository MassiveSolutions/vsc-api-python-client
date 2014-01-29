"""
VSC API Client exception definitions.
"""

class Error(Exception):
    """Base class for VSC API Client exceptions."""
    pass

class NotAuthorizedError(Error):
    pass

class InternalServerError(Error):
    pass

class NotFoundError(Error):
    pass

class UnknownError(Error):
    pass

class NoAliveServersError(Error):
    pass
