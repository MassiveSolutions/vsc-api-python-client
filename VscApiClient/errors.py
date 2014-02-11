"""
VSC API Client exception definitions.
"""


class Error(Exception):
    """Base class for VSC API Client exceptions."""
    pass


class NoAliveServersError(Error):
    """
    There is no alive servers to make request.
    """
    pass


class NotAuthorizedError(Error):
    """
    User isn't authorized to perform the action.
    """
    pass


class NotFoundError(Error):
    """
    Object not found.
    """
    pass


class BadArgError(Error):
    """
    Invalid argument.
    """
    pass


class InternalServerError(Error):
    """
    Internal server exception.
    """
    pass


class UnknownError(Error):
    """
    Exception which never shouldn't ocurred.
    """
    pass
