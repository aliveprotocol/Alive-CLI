class AliveMissingDependencyExeption(Exception):
    """
    Required dependency is not installed (i.e. missing NodeJS/npm)
    """
    pass

class AliveBlockchainAPIException(Exception):
    """
    Blockchain API call failure
    """
    pass

class AliveAuthException(Exception):
    """
    Incorrect authentication info (wrong private key etc.)
    """
    pass

class AliveRequestException(Exception):
    """
    Alive indexer (i.e. HAlive) API call failure
    """
    pass

class AliveAuthRequestException(Exception):
    """
    Authentication request failure to external endpoints
    """
    pass

class AliveDBIntegrityException(Exception):
    """
    AliveDB source files checksum error
    """
    pass

class AliveDeprecationException(Exception):
    """
    Deprecated Alive Protocol features
    """
    pass