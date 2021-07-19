import sqlite3
import sys
import configuration as cf
from sqlite3 import Error

conn = None


def create_connection(db_file):
    """
    create a connection to sqlite3 database
    """
    try:
        return sqlite3.connect(db_file, timeout=10)  # connection via sqlite3
    except Error as e:
        cf.logger.critical(e)
        sys.exit(1)


def table_exists(table_name):
    """
    checks whether table exists or not
    :returns boolean yes/no
    """
    query = ("SELECT name FROM sqlite_master WHERE TYPE='table' AND name='" + table_name + "';")
    cursor = conn.cursor()
    cursor.execute(query)
    result = cursor.fetchone()
    if result is not None:
        return True
    else:
        return False


def execute_sql_cmd(query):
    cursor = conn.cursor()
    cursor.execute(query)


def execute_data_cmd(query, data):
    cursor = conn.cursor()
    cursor.execute(query, data)
    conn.commit()


def fetchone_query(table_name, col, value):
    """
    checks whether table exists or not
    :returns boolean yes/no
    """
    query = ("SELECT " + col + " FROM " + table_name + " WHERE repo_url='" + value + "'")
    cursor = conn.cursor()
    cursor.execute(query)
    result = cursor.fetchone()
    return True if result is not None else False


if not conn:
    conn = create_connection(cf.DATABASE)
