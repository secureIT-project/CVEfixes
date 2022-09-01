from __future__ import annotations

import pathlib
import random
import sqlite3
import string
from logging import CRITICAL

import pytest
import pytest_mock

import database


def random_str(n: int) -> str:
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(n))


def create_random_tables_in_db(conn: sqlite3.Connection, num_tables: int) -> list[str]:
    table_names: list[str] = [random_str(16) for _ in range(num_tables)]

    query = ('''
    CREATE TABLE ? (
	    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
   	    value TEXT NOT NULL,
   	    repo_url TEXT
    );''')

    for name in table_names:
        conn.cursor().execute(query.replace('?', name))

    conn.commit()

    return table_names


def test_creating_connection(tmp_dir: str, mocker: pytest_mock.MockerFixture) -> None:
    """
    Test creating a connection to a sqlite3 database
    """
    mocker.patch.object(database, 'conn', None)
    db_connection: sqlite3.Connection = database.create_connection(pathlib.Path(tmp_dir).joinpath("database.db"))

    assert isinstance(db_connection, sqlite3.Connection)


def test_table_exist(conn: sqlite3.Connection) -> None:
    """ Test table_exist for existing and non exiting tables """

    num_tables = 10

    existing_tables: list[str] = create_random_tables_in_db(conn, num_tables=num_tables)
    non_existing_tables: list[str] = [
        random_str(16) for _ in range(num_tables)
    ]

    for table_name in existing_tables:
        assert database.table_exists(table_name) is True

    for table_name in non_existing_tables:
        assert database.table_exists(table_name) is False


def test_fetchone_query(conn: sqlite3.Connection) -> None:
    table: str = create_random_tables_in_db(conn, num_tables=1)[0]
    repo_url: str = "www.repo.url"

    insert_entry_query: str = f"""
    INSERT INTO {table} (id, value, repo_url) 
        VALUES (9, 'fetchone_query', '{repo_url}')"""
    conn.cursor().execute(insert_entry_query)

    assert database.fetchone_query(table, 'repo_url', repo_url) is True
    assert database.fetchone_query(table, 'repo_url', repo_url[::-1]) is False


def test_create_connection_error(caplog: pytest.LogCaptureFixture, mocker: pytest_mock.MockerFixture) -> None:
    error_msg = "Test Error"

    # Raise error on connect to db
    mocked_connection = mocker.patch.object(database.sqlite3, 'connect')
    mocked_connection.side_effect = sqlite3.Error(error_msg)

    # Disable sys.exit
    mocked_sys_exit = mocker.patch.object(database.sys, 'exit')
    mocked_sys_exit.return_value = False

    database.create_connection(":memory:")

    assert caplog.records[-1].levelno == CRITICAL
    assert caplog.records[-1].message == error_msg
