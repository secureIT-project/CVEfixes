import glob
import os
import json
from shutil import copyfile
from datetime import date
from pathlib import Path

import pandas as pd

import configuration as cf
import database as db

output_dir = 'Output'  # path to save all the compressed output files


def make_timestamp(json_path):
    """
    generates timestamp by picking the latest timestamp from the CVE JSON files.
    pars: json_path is the path of the JSON files.
    """
    date_list = []
    for file in json_path.glob('*.json'):
        with open(file, 'r') as jsonfile:
            x = json.load(jsonfile)
            date_list.append(date.fromisoformat(x['CVE_data_timestamp'].split('T')[0]))
    date_timestamp = str(max(date_list))
    return date_timestamp


def create_zip_files():
    timestamp = make_timestamp(Path(cf.DATA_PATH) / "json")
    cwe_xml_gz = Path(output_dir, 'cwe-' + timestamp + '.xml.gz')
    jsonl_gz = Path(output_dir, 'nvd-' + timestamp + '.jsonl.gz')
    db_sql_gz = Path(output_dir, cf.DATABASE_NAME.split('.')[0] + '-' + timestamp + '.sql.gz')

    Path(output_dir).mkdir(parents=True, exist_ok=True)

    # overwrite whatever was saved before for this timestamp with the current data
    if os.system('gzip -c Data/cwec_v4.4.xml > ' + str(cwe_xml_gz)) == 0:
        cf.logger.info('CWE XML file is saved to', cwe_xml_gz)

    if os.system('jq -c "." Data/json/*.json | gzip > ' + str(jsonl_gz)) == 0:
        cf.logger.info('JSON files are zipped to', jsonl_gz)

    if os.system('sqlite3 ' + str(cf.DATABASE) + ' .dump | gzip > ' + str(db_sql_gz)) == 0:
        cf.logger.info('The sql dump of the database file is zipped to', db_sql_gz)


def add_tbd_repos(tbd_repos):
    """
    return the list of dummy entries for some repos, the information will be filled up later.
    """
    tbd_rows = []
    if len(tbd_repos) > 0:
        for repo_url in tbd_repos:
            if '/' in repo_url:
                tbd_rows.append({
                        'repo_url': repo_url,
                        'repo_name': 'visit repo url',
                        'description': 'visit repo url',
                        'date_created': 'visit repo url',
                        'date_last_push': 'visit repo url',
                        'homepage': 'visit repo url',
                        'repo_language': 'visit repo url',
                        'forks_count': 'visit repo url',
                        'stars_count': 'visit repo url',
                        'owner': repo_url.split('/')[-2]
                })
    return tbd_rows


def filter_non_textual(df_file):
    """
    filtering out the non-textual files which have number of added and deleted lines equal 0.
    """
    non_text_files = []
    count_files = 0
    for i in range(len(df_file)):
        if df_file.num_lines_added[i] == '0' and df_file.num_lines_deleted[i] == '0':
            non_text_files.append(df_file.file_change_id[i])
            count_files += 1
    cf.logger.debug('Non-textual files: ', count_files)

    assert len(df_file[df_file.file_change_id.isin(non_text_files)]) == len(non_text_files), \
        'Non-textual files should not be more than len of the items in file table'

    df_file = df_file[~df_file.file_change_id.isin(non_text_files)].reset_index(drop=True)

    return df_file


def prune_tables(datafile):
    """
    filtering out the unlinked data from the tables.
    """
    cf.logger.info('-'*70)
    cf.logger.info('Wait while pruning the data...')
    # copyfile(datafile, str(datafile).split('.')[0] + '_raw.db')

    connf = db.create_connection(datafile)
    df_commit = pd.read_sql('SELECT * FROM commits', con=connf)
    df_cve = pd.read_sql('SELECT * FROM cve', con=connf)
    df_file = pd.read_sql('SELECT * FROM file_change', con=connf)
    df_method = pd.read_sql('SELECT * FROM method_change', con=connf)
    df_fixes = pd.read_sql('SELECT * FROM fixes', con=connf)
    df_cwe_class = pd.read_sql('SELECT * FROM cwe_classification', con=connf)
    df_cwe = pd.read_sql('SELECT * FROM cwe', con=connf)
    df_repo = pd.read_sql('SELECT * FROM repository', con=connf)


    # processing commit, file and method tables for filtering out some invalid records
    df_commit['repo_url'] = df_commit.repo_url.apply(lambda x: x.rsplit('.git')[0])
    df_commit = df_commit.drop_duplicates().reset_index(drop=True)
    df_repo = df_repo.drop_duplicates().reset_index(drop=True)
    invalid_hashes = set(list(df_commit.hash.unique())).difference(set(list(df_fixes.hash.unique())))

    # replace short hash of fix table with long hash from the commits table
    count_replaces = 0
    for full_hash in invalid_hashes:
        url = df_commit[df_commit.hash == full_hash]['repo_url'].values[0]
        fix_url = df_fixes[df_fixes.repo_url == url]
        for short_hash in fix_url.hash:
            if short_hash.strip()[0:4] == full_hash.strip()[0:4]:
                df_fixes.loc[df_fixes.hash == short_hash, 'hash'] = full_hash
                count_replaces += 1
    cf.logger.debug('#Short hashes are replaced by the long hashes: ', count_replaces)

    # filtering some non-textual files
    df_file = filter_non_textual(df_file)
    # filtering some no names methods
    no_name_methods = list(df_method[df_method.name == ''].name.unique())
    df_method = df_method[~df_method.name.isin(no_name_methods)].reset_index(drop=True)


    # filtering out the hashes that are not correctly collected in the commits table
    incorrect_hashes = set(list(df_commit.hash.unique())).difference(set(list(df_fixes.hash.unique())))
    df_commit_filtered = df_commit[~df_commit.hash.isin(incorrect_hashes)].reset_index(drop=True)

    # removing invalid hashes records from file and method tables.
    cf.logger.debug('Removing invalid hashes...')
    df_file_filtered = df_file[df_file.hash.isin(list(df_commit_filtered.hash.unique()))].reset_index(drop=True)
    remove_files_ids = set(list(df_file.file_change_id.unique())).difference(
        set(list(df_file_filtered.file_change_id.unique())))
    df_method_filtered = df_method[~df_method.file_change_id.isin(list(remove_files_ids))].reset_index(drop=True)

    # filtering the dataframes
    cf.logger.debug('Filtering the dataframes...')
    df_fixes_filtered = df_fixes[df_fixes.hash.isin(list(df_commit_filtered.hash.unique()))].reset_index(drop=True)
    df_cve_filtered = df_cve[df_cve.cve_id.isin(list(df_fixes_filtered.cve_id.unique()))].reset_index(drop=True)
    df_cwe_class_filtered = df_cwe_class[df_cwe_class.cve_id.isin(list(df_cve_filtered.cve_id.unique()))].reset_index(drop=True)
    df_cwe_filtered = df_cwe[df_cwe.cwe_id.isin(list(df_cwe_class_filtered.cwe_id.unique()))].reset_index(drop=True)

    # processing repository table before filtering
    cf.logger.debug('Processing repository table before filtering...')
    tbd_repos_list = set(list(df_fixes_filtered.repo_url.unique())).difference(set(list(df_repo.repo_url.unique())))
    tbd_rows = add_tbd_repos(tbd_repos_list)
    df_repo_with_tbd = df_repo.append(tbd_rows, ignore_index=True, sort=False).reset_index(drop=True)
    df_repo_filtered = df_repo_with_tbd[df_repo_with_tbd.repo_url.isin(list(df_fixes_filtered.repo_url.unique()))].reset_index(drop=True)

    cf.logger.debug('Checking validity of assertions ...')
    # list of assertions before saving the cleaned data into the database
    assert df_fixes_filtered.cve_id.nunique() == len(df_cve_filtered.cve_id), \
        'Mismatch between unique cve_ids in the cve table and the fixes table'

    assert df_commit_filtered.hash.nunique() == df_fixes_filtered.hash.nunique(), \
        'Mismatch between unique hashes in commits table and the fixes table'

    assert df_cve_filtered.cve_id.nunique() == df_cwe_class_filtered.cve_id.nunique(), \
        'Mismatch between unique cve_ids in the cve table and the cwe table'

    assert df_cwe_filtered.cwe_id.nunique() == df_cwe_class_filtered.cwe_id.nunique(), \
        'Mismatch between unique cwe_ids in the cwe_classification table and the cwe table'

    assert df_repo_filtered.repo_url.nunique() == df_fixes_filtered.repo_url.nunique(), \
        'Mismatch between unique repo_urls in the fixes table and the repository table'

    assert df_commit_filtered.hash.nunique() >= df_file_filtered.hash.nunique(), \
        'Unique hashes in the fixes table must be equal or more than of file_change table'

    assert df_file_filtered.file_change_id.nunique() >= df_method_filtered.file_change_id.nunique(), \
        'Unique file_change_id in the file_change table must be equal or more than of method_change table'

    # saving the filtered dataframes in tables
    cf.logger.debug('Saving the filtered tables replacing the previous unfiltered to the database...')
    cf.logger.debug('Saving fixes ...')
    df_fixes_filtered.to_sql(name='fixes', con=connf, if_exists='replace', index=False)
    cf.logger.debug('Saving commits ...')
    df_commit_filtered.to_sql(name='commits', con=connf, if_exists='replace', index=False)
    cf.logger.debug('Saving file_change ...')
    df_file_filtered.to_sql(name='file_change', con=connf, if_exists='replace', index=False)
    cf.logger.debug('Saving method_change ...')
    df_method_filtered.to_sql(name='method_change', con=connf, if_exists='replace', index=False)
    cf.logger.debug('Saving cve ...')
    df_cve_filtered.to_sql(name='cve', con=connf, if_exists='replace', index=False)
    cf.logger.debug('Saving cwe ...')
    df_cwe_filtered.to_sql(name='cwe', con=connf, if_exists='replace', index=False)
    cf.logger.debug('Saving cwe_classification...')
    df_cwe_class_filtered.to_sql(name='cwe_classification', con=connf, if_exists='replace', index=False)
    cf.logger.debug('Saving repository ...')
    df_repo_filtered.to_sql(name='repository', con=connf, if_exists='replace', index=False)
    cf.logger.info('Data pruning has been completed successfully')
    cf.logger.info('-' * 70)


def log_commit_urls(repo_url, hashes):
    for hsh in hashes:
        if 'gitlab.' in repo_url:
            cf.logger.debug(f'{repo_url}/-/commit/{hsh}')
        else:
            cf.logger.debug(f'{repo_url}/commit/{hsh}')


# run this file only enabling the below if-else in case you want to prune the table.
# if db.table_exists('method_change'):
#     prune_tables(cf.DATABASE)
# else:
#     cf.logger.warning('Data pruning is not possible because there is not information in method_change table')
#

# # Uncomment the below line to create zipped .gz files of sql dump of the database, NVD jsonl, and cwe xml file.
# create_zip_files()

