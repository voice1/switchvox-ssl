#!/usr/bin/env python
"""
Copyright (c) 2021, VOICE1, LLC.
B. Davis <support@voice1.me>

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

import os
import sys
import argparse
import requests
try:
    import ujson as json
except ImportError:
    import json
from loguru import logger

API_URL = ""

def read_file(filename, **kwargs):
    """Read file and return contents as string"""
    if not filename:
        return

    MODE = kwargs.get('mode', 'r')
    content = ''
    with open(filename, MODE) as reader:
        content = reader.read()
    return content

def set_log_level(level='INFO'):
    """Set log level"""
    if os.getenv('LOGURU_LEVEL'):
        logger.info(f"Log level set using shell variable.")
        return logger
    logger.remove()
    logger.add(sys.stderr, level=level)
    logger.info(f"Log level set to: {level}")
    return logger

def check_progress():
    # TODO: Something to add.
    return

def update_ssl(parameters=None, query_params={}, **kwargs):
    """
    Update the switchvox SSL certificate,
    mode=direct uses switchvox credentials and directly connects to your switchvox
    mode=api uses the api.switchvoxuc.com API.
    """
    mode = kwargs.get('MODE', 'direct')
    auth = (kwargs.get('username'), kwargs.get('password'))
    hostname = kwargs.get('host')
    regcode = kwargs.get('regcode', None)

    if mode.lower() == 'api':
        # This is for internal use only by VOICE1, LLC.
        if not regcode:
            logger.critical(f"You must specifiy the regcode when using API mode.")
            return
        url = API_URL + "/networking/ssl"
        payload = parameters
    else: # Direct to PBX
        logger.info(f"Using mode: '{mode}'")
        url = f"https://{hostname}/json"
        payload = {
            "request":
            {
                "method": "switchvox.network.ssl.update",
                "parameters": parameters,
                "transaction_id": "sslUpdate"
            }
        }
        logger.debug(f"direct request: {payload}")
    try:
        r = requests.post(url, json=payload, params=query_params, auth=auth)
        r.raise_for_status()
        logger.info(f"{r.request.method} {r.url} {r.status_code} {r.reason} - {r.text}")
        return r.json()

    except requests.HTTPError as e:
        logger.critical(f"HTTPError: {e}")
        return None

def load_certificate(key=None, cert=None, ca_bundle=None, **kwargs):
    """
    Loads certificate, if enviormnet variables set to file paths they will be used over provided certificates.
    """


    RSA_PRIVATE_KEY = read_file(os.getenv('RSA_PRIVATE_KEY')) or read_file(key)
    X509_CERTIFICATE = read_file(os.getenv('X509_CERTIFICATE')) or read_file(cert)
    INTERMEIDATE_CA_CERTIFICATE = read_file(os.getenv('INTERMEIDATE_CA_CERTIFICATE')) or read_file(ca_bundle)

    certificate = dict(
        x509_certificate=X509_CERTIFICATE,
        rsa_private_key=RSA_PRIVATE_KEY,
        intermediate_ca_certificate=INTERMEIDATE_CA_CERTIFICATE
    )
    logger.debug(f"certificate: {certificate}")
    if None in certificate.values():
        logger.critical(f"No SSL Certificates found. Try setting your enviroment variable to the SSL cert paths or pass them in as parameters to the script.")
        sys.exit()
    return certificate

def make_params(**kwargs):
    """
    Read in cert, key, and ca_bundle files and format switchvox params
    """
    logger.info(f"Loading certificates")
    key = kwargs.get('key', None)
    cert = kwargs.get('cert', None)
    ca_bundle=kwargs.get('ca_bundle', None)
    ca_certs = kwargs.get('ca_certs', [])

    # If no SSL files provided, use global default.
    certificate = load_certificate(key=key, cert=cert, ca_bundle=ca_bundle)

    params = {
        'x509_certificate': certificate['x509_certificate'],
        'rsa_private_key': certificate['rsa_private_key'],
        'intermediate_ca_certificate': certificate['intermediate_ca_certificate'],
        'ca_certs': ca_certs
    }
    return params

def menu(**kwargs):
    parser = argparse.ArgumentParser()
    parser.add_argument("MODE", choices=['api', 'direct'],
        default='direct',
        help="For 'api' the api.switchvoxuc.com API will be used. 'direct' will connect to the switchvox directly.")

    ssl_group = parser.add_argument_group('SSL Certificates')
    ssl_group.add_argument("--key",
        help="Private key must be of type RSA. file or export RSA_PRIVATE_KEY=")
    ssl_group.add_argument("--cert",
        help="Issued Certificate. file or export X509_CERTIFICATE=")
    ssl_group.add_argument("--ca-bundle",
        help="CA Bundle/ intermediate cert. file or export INTERMEIDATE_CA_CERTIFICATE=")
    ssl_group.add_argument("--ca-certs", help="List of CA certs. (Not usually required)", default=[])

    hosts_group = parser.add_argument_group('Hosts')
    hosts_group.add_argument('--regcode', help="Switchvox 6 char regcode. Required for 'api' mode.")
    hosts_group.add_argument("--host", help="Hostname")
    hosts_group.add_argument("--username", help="username")
    hosts_group.add_argument("--password", help="password")

    log_group = parser.add_argument_group('Logging')
    log_group.add_argument('--log-level', help="Set log level",
        choices=['INFO', 'SUCCESS', 'WARNING', 'ERROR', 'CRITICAL', 'DEBUG', 'TRACE'], default='INFO')
    return parser.parse_args()

if __name__ == '__main__':
    args = menu()
    logger = set_log_level(level=args.log_level)
    if args.key:
        logger.info(f"Using provided ssl certificate files.")
        params = make_params(key=args.key, cert=args.cert, ca_bundle=args.ca_bundle, ca_certs=args.ca_certs)
    else:
        logger.info(f"Using ENV Variables for certificates.")
        params = make_params()
    update_ssl(parameters=params, **vars(args))
