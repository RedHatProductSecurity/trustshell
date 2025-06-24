#!/usr/bin/env python

import json
import logging
import os
import secrets

import urllib.parse

import jwt
import pkce
import httpx

logger = logging.getLogger("trustshell")
CLIENT_ID = "atlas-frontend"
# this script will spawn an HTTP server to capture the code your browser gets from the SSO server
LOCAL_SERVER_PORT = 8650
REDIRECT_URI = "http://localhost:" + str(LOCAL_SERVER_PORT) + "/index.html"
# other oidc things you generally shouldnt have to touch
SCOPE = "openid"
CODE_CHALLENGE_METHOD = "S256"
RESPONSE_TYPE = "code"
GRANT_TYPE = "authorization_code"

AUTH_ENDPOINT = os.getenv("AUTH_ENDPOINT")
HEADLESS = "DISPLAY" not in os.environ

token_endpoint = f"{AUTH_ENDPOINT}/token"


def gen_things():
    logging.debug("Generating verifier, challenge, state")
    code_verifier, code_challenge = pkce.generate_pkce_pair()
    state = secrets.token_urlsafe(16)
    logger.debug(f"Code Verifier: {code_verifier}")
    logger.debug(f"Code Challenge: {code_challenge}")
    logger.debug(f"state: {state}")
    return code_verifier, code_challenge, state


def build_url(code_challenge, state, auth_server=""):
    params = {
        "response_type": RESPONSE_TYPE,
        "client_id": CLIENT_ID,
        "scope": SCOPE,
        "redirect_uri": REDIRECT_URI,
        "code_challenge": code_challenge,
        "code_challenge_method": CODE_CHALLENGE_METHOD,
        "state": state,
    }
    encoded_params = urllib.parse.urlencode(params)
    authz_endpoint = f"{AUTH_ENDPOINT}/auth"
    if auth_server:
        authz_endpoint = f"{auth_server}/auth"
    url = f"{authz_endpoint}?{encoded_params}"
    return url


def code_to_token(code, code_verifier):
    logger.debug(
        "Exchanging the code for a token via http calls inside of this script."
    )
    data = {
        "grant_type": GRANT_TYPE,
        "client_id": CLIENT_ID,
        "code_verifier": code_verifier,
        "code": code,
        "redirect_uri": REDIRECT_URI,
    }
    c2t = httpx.post(url=token_endpoint, data=data)
    c2t_json = json.loads(c2t.text)
    access_token = c2t_json["access_token"]
    refresh_token = c2t_json["refresh_token"]
    id_token = c2t_json["id_token"]
    logger.debug("Each raw part of the response body:")
    for k, v in c2t_json.items():
        logger.debug(f"{k}:{v}")
    logger.debug("User readable access_token:")
    logger.debug(
        json.dumps(
            jwt.decode(access_token, options={"verify_signature": False}),
            indent=4,
            sort_keys=True,
        )
    )
    logger.debug("User readable refresh_token:")
    logger.debug(
        json.dumps(
            jwt.decode(refresh_token, options={"verify_signature": False}),
            indent=4,
            sort_keys=True,
        )
    )
    logger.debug("User readable id_token:")
    logger.debug(
        json.dumps(
            jwt.decode(id_token, options={"verify_signature": False}),
            indent=4,
            sort_keys=True,
        )
    )
    logger.debug(f"Access Token: {access_token}")
    return access_token, refresh_token, id_token


def get_fresh_token(refresh_token):
    logger.debug(
        "Exchange the refresh token for a new access token via http calls inside of this script."
    )
    data = {
        "grant_type": "refresh_token",
        "client_id": CLIENT_ID,
        "refresh_token": refresh_token,
    }
    r2a = httpx.post(url=token_endpoint, data=data)
    r2a_json = json.loads(r2a.text)
    access_token = r2a_json["access_token"]
    refresh_token = r2a_json["refresh_token"]

    logger.debug("Each raw part of the response body:")
    for k, v in r2a_json.items():
        logger.debug(f"{k}:{v}")
    else:
        logger.debug(f"Access Token: {access_token}")
    return access_token, refresh_token
