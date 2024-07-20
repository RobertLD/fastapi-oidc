from typing import Dict
import requests
from cachetools import TTLCache, cached


def configure(*_, cache_ttl: int):
    """
    Configure the functions to retrieve OpenID Connect (OIDC) server
    information and cache the responses.

    Args:
        cache_ttl (int): The time-to-live for the cache in seconds.

    Returns:
        functions: A class containing the configured functions for
        interacting with the OIDC server.

    """

    @cached(TTLCache(1, cache_ttl), key=lambda d: d["jwks_uri"])
    def get_authentication_server_public_keys(OIDC_spec: Dict, ssl_verify: bool = True):
        """
        Retrieve the public keys used by the authentication server for signing OIDC ID tokens.

        This function fetches the JSON Web Key Set (JWKS) from the specified URI in the OIDC
        specification and returns the keys as a dictionary. The result is cached based on the
        `jwks_uri` value provided in the OIDC specification.

        Args:
            OIDC_spec (Dict): The OpenID Connect specification containing the `jwks_uri` key.

        Returns:
            Dict: The public keys used by the authentication server.

        """
        keys_uri = OIDC_spec["jwks_uri"]
        r = requests.get(keys_uri, ssl_verify=ssl_verify)
        keys = r.json()
        return keys

    def get_signing_algos(OIDC_spec: Dict):
        """
        Retrieve the supported signing algorithms for ID tokens.

        This function extracts the supported signing algorithms for ID tokens from the OIDC
        specification.

        Args:
            OIDC_spec (Dict): The OpenID Connect specification containing the
                              `id_token_signing_alg_values_supported` key.

        Returns:
            list: A list of supported signing algorithms.

        """
        algos = OIDC_spec["id_token_signing_alg_values_supported"]
        return algos

    @cached(TTLCache(1, cache_ttl))
    def discover_auth_server(*_, base_url: str,  ssl_verify: bool = True) -> Dict:
        """
        Discover the OpenID Connect configuration from the authentication server.

        This function performs OIDC discovery by retrieving the configuration from the
        authentication server's well-known configuration URL. The result is cached to
        minimize network calls.

        Args:
            base_url (str): The base URL of the authentication server.

        Returns:
            Dict: The OpenID Connect configuration.

        Raises:
            requests.exceptions.HTTPError: If the request to the discovery URL fails.

        """
        discovery_url = f"{base_url}/.well-known/openid-configuration"
        r = requests.get(discovery_url, ssl_verify=ssl_verify)
        r.raise_for_status()
        configuration = r.json()
        return configuration

    class functions:
        """
        A class to encapsulate the configured functions for interacting with the OIDC server.

        Attributes:
            auth_server (function): The function to discover the OIDC configuration.
            public_keys (function): The function to retrieve the authentication server's public keys.
            signing_algos (function): The function to retrieve supported signing algorithms.
        """
        auth_server = discover_auth_server
        public_keys = get_authentication_server_public_keys
        signing_algos = get_signing_algos

    return functions
