from typing import List

from pydantic import BaseModel
from pydantic import Extra


class OIDCConfig(BaseModel):
    client_id: str
    base_authorization_server_uri: str
    issuer: str
    signature_cache_ttl: str


class IDToken(BaseModel):
    """Pydantic model representing an OIDC ID Token.

    ID Tokens are polymorphic and may have many attributes not defined in the spec thus this model accepts
    all addition fields. Only required fields are listed in the attributes section of this docstring or
    enforced by pydantic.

    See the specifications here. https://openid.net/specs/openid-connect-core-1_0.html#IDToken

    Attributes:
        iss (str): Issuer Identifier for the Issuer of the response.
        sub (str): Subject Identifier.
        aud (str): Audience(s) that this ID Token is intended for.
        exp (str): Expiration time on or after which the ID Token MUST NOT be accepted for processing.
        iat (iat): Time at which the JWT was issued.

    """

    iss: str
    sub: str
    aud: str
    exp: int
    iat: int

    class Config:
        extra = Extra.allow


class OktaIDToken(IDToken):
    """
    Pydantic Model for the IDToken returned by Okta's OIDC implementation.

    This class represents the structure of an ID token issued by Okta's OpenID Connect
    (OIDC) implementation. The ID token contains various claims about the authentication
    of an end-user.

    Attributes:
        auth_time (int): The time when the authentication occurred, represented as a Unix timestamp.
        ver (int): The version of the ID token.
        jti (str): The unique identifier for the ID token.
        amr (List[str]): The Authentication Methods Reference, indicating the methods used for authentication.
        idp (str): The identifier for the identity provider.
        nonce (str): A string value used to associate a client session with an ID token to mitigate replay attacks.
        at_hash (str): The hash value of the access token. Used to validate the access token.
        name (str): The full name of the end-user.
        email (str): The email address of the end-user.
        preferred_username (str): The preferred username of the end-user.
    """

    auth_time: int
    ver: int
    jti: str
    amr: List[str]
    idp: str
    nonce: str
    at_hash: str
    name: str
    email: str
    preferred_username: str
