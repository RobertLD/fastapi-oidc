class TokenSpecificationError(BaseException):
    """
    Exception raised for errors in the token specification.

    This exception is intended to be used when there is an issue with the specification
    of a token, such as missing or invalid claims, incorrect formatting, or other
    specification-related problems.

    Attributes:
        message (str): Optional. A human-readable message describing the error.
    """
    def __init__(self, message: str = "There was an error in the token specification"):
        """
        Initialize a TokenSpecificationError instance.

        Args:
            message (str): A human-readable message describing the error. Defaults to
                           "There was an error in the token specification".
        """
        super().__init__(message)
