#!/usr/bin/env bash
#
# create a SQLite3 database file of the CVEfixes.

# ------------------------------------------------------------------------------
DATA_PATH=Output/
gzcat $DATA_PATH/CVEfixes.sql.gz | sqlite3 $DATA_PATH/CVEfixes.db

#------------------------------------------------------------------------------