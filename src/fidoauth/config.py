"""
FIDOAuth configuration class. When imported, this module reads defaults from the `configs/defaults.cfg` file embedded in
this wheel, and the path specified by `CONFIG_FILE_PATH`.
"""

import datetime
import logging
import logging.handlers

import importlib
import importlib.resources
import configparser

from pathlib import Path
import sys


CONFIG_FILE_PATH = "/etc/fidoauth/fidoauth.conf"

config = configparser.ConfigParser()

#Read the defaults out of the package...
with importlib.resources.files(__package__).joinpath("config/default.cfg").open() as f:
    config.read_file(f)

#Read the values from the config file
config.read(CONFIG_FILE_PATH)


HTTP_ORIGIN = config["config"]["expected_origin"]
HOST = HTTP_ORIGIN[len('https://'):]
AUTHENTICATION_TIMEOUT = datetime.timedelta(seconds=int(config["config"]["authentication_timeout"]))
LOG_FILE = config["config"]["log_file"]
DEFAULT_URL = config["config"]["default_url"]
MAX_VALID_AUTH_IDS = int(config["config"]["max_auth_ids"])
SERVER_USER = config["config"]["server_user"]

CREDS_FILE = config["config"]["creds_file"]
CHALLENGE_FILE = config["config"]["challenge_file"]
MOD_TKT_CONFIG_FILE = config["config"]["mod_tkt_config"]

SCRIPT_SAVE_CREDS = Path(sys.executable).parent / "save_creds.py"

#If present, parese the mod_tkt config to get the secret and digest type
MOD_TKT_SECRET = None
MOD_TKT_DIGEST_TYPE = None
if Path(MOD_TKT_CONFIG_FILE).is_file():
    with open(MOD_TKT_CONFIG_FILE, "r", encoding="utf8") as f:
        for line in f:
            if "TKTAuthSecret" in line:
                MOD_TKT_SECRET = line.strip().split(" ")[1].strip("\"")
            elif "TKTAuthDigestType" in line:
                MOD_TKT_DIGEST_TYPE = line.strip().split(" ")[1]

def get_logger():
    """
    Returns the logger object pointing to the log file specified in the configuration.
    """
    logger = logging.getLogger(__file__)
    handler = logging.handlers.RotatingFileHandler(LOG_FILE, maxBytes=2000, backupCount=10)
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s (%(filename)s:%(lineno)d)')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    return logger

def get_authenticator():
    """
    Returns an instance of the configured authenticator plugin
    """
    return importlib.import_module(f".plugins.{config['config']['authenticator']}", package="fidoauth").Authenticator()
