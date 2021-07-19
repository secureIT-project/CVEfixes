import sys
import logging
from configparser import ConfigParser
from pathlib import Path

# set sensible defaults for the configurable fields
DATA_PATH = 'Data'
DATABASE_NAME = 'CVEfixes_sample.db'
USER = None
TOKEN = None
SAMPLE_LIMIT = 25
NUM_WORKERS = 4
LOGGING_LEVEL = logging.WARNING

# full path to the .db file
DATABASE = Path(DATA_PATH) / DATABASE_NAME
config_read = False

log_level_map = { 'DEBUG': logging.DEBUG,
                  'INFO': logging.INFO,
                  'WARNING': logging.WARNING,
                  'ERROR': logging.ERROR,
                  'CRITICAL': logging.CRITICAL,
                }

logging.basicConfig(level=LOGGING_LEVEL,
                    format='%(asctime)s %(levelname)-3s: %(message)s',
                    datefmt='%m/%d/%Y %H:%M:%S')
logger = logging.getLogger(__name__)
logger.removeHandler(sys.stderr)


def read_config() -> None:
    """
    Read CVEfixes configuration from .CVEfixies.ini, $HOME/.config/CVEfixes.ini or $HOME/.CVEfixes.ini

    Sets global constants with values found in the ini file.
    """
    global DATA_PATH, DATABASE_NAME, DATABASE, USER, TOKEN, SAMPLE_LIMIT, NUM_WORKERS, config_read

    config = ConfigParser()
    if config.read(['.CVEfixes.ini',
                    Path.home() / '.config' / 'CVEfixes.ini',
                    Path.home() / '.CVEfixes.ini']):
        # try and update settings for each of the values, use
        DATA_PATH = config.get('CVEfixes', 'database_path', fallback=DATA_PATH)
        DATABASE_NAME = config.get('CVEfixes', 'database_name', fallback=DATABASE_NAME)
        USER = config.get('GitHub', 'user', fallback=USER)
        TOKEN = config.get('GitHub', 'token', fallback=TOKEN)
        SAMPLE_LIMIT = config.getint('CVEfixes', 'sample_limit', fallback=SAMPLE_LIMIT)
        NUM_WORKERS = config.getint('CVEfixes', 'num_workers', fallback=NUM_WORKERS)
        Path(DATA_PATH).mkdir(parents=True, exist_ok=True)  # create the directory if not exists.
        DATABASE = Path(DATA_PATH) / DATABASE_NAME
        LOGGING_LEVEL = log_level_map.get(config.get('CVEfixes', 'logging_level', fallback='WARNING'), logging.WARNING)
        config_read = True
    else:
        logger.warning('Cannot find CVEfixes config file in the working or $HOME directory, see INSTALL.md')
        sys.exit()


if not config_read:
    read_config()
    logger.setLevel(LOGGING_LEVEL)
    logging.getLogger("requests").setLevel(LOGGING_LEVEL)
    logging.getLogger("urllib3").setLevel(LOGGING_LEVEL)
    logging.getLogger("urllib3.connection").setLevel(LOGGING_LEVEL)
    logging.getLogger("pathlib").setLevel(LOGGING_LEVEL)
    logging.getLogger("subprocess").setLevel(LOGGING_LEVEL)
    logging.getLogger("h5py._conv").setLevel(LOGGING_LEVEL)
    logging.getLogger("git.cmd").setLevel(LOGGING_LEVEL)
    logging.getLogger("github.Requester").setLevel(LOGGING_LEVEL)


