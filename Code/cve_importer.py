# Obtaining and processing CVE json **files**
# The code is to download nvdcve zip files from NIST since 2002 to the current year,
# unzip and append all the JSON files together,
# and extracts all the entries from json files of the projects.

import datetime
import json
import os
import re
from io import BytesIO
import pandas as pd
import requests
from pathlib import Path
from zipfile import ZipFile
from pandas import json_normalize

from extract_cwe_record import add_cwe_class,  extract_cwe
import configuration as cf
import database as db

# ---------------------------------------------------------------------------------------------------------------------

urlhead = 'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-'
urltail = '.json.zip'
initYear = 2002
currentYear = datetime.datetime.now().year

# Consider only current year CVE records when sample_limit>0 for the simplified example.
if cf.SAMPLE_LIMIT > 0:
    initYear = currentYear

df = pd.DataFrame()

ordered_cve_columns = ['cve_id', 'published_date', 'last_modified_date', 'description', 'nodes', 'severity',
                       'obtain_all_privilege', 'obtain_user_privilege', 'obtain_other_privilege',
                       'user_interaction_required',
                       'cvss2_vector_string', 'cvss2_access_vector', 'cvss2_access_complexity', 'cvss2_authentication',
                       'cvss2_confidentiality_impact', 'cvss2_integrity_impact', 'cvss2_availability_impact',
                       'cvss2_base_score',
                       'cvss3_vector_string', 'cvss3_attack_vector', 'cvss3_attack_complexity',
                       'cvss3_privileges_required',
                       'cvss3_user_interaction', 'cvss3_scope', 'cvss3_confidentiality_impact',
                       'cvss3_integrity_impact',
                       'cvss3_availability_impact', 'cvss3_base_score', 'cvss3_base_severity',
                       'exploitability_score', 'impact_score', 'ac_insuf_info',
                       'reference_json', 'problemtype_json']

cwe_columns = ['cwe_id', 'cwe_name', 'description', 'extended_description', 'url', 'is_category']

# ---------------------------------------------------------------------------------------------------------------------


def rename_columns(name):
    """
    converts the other cases of string to snake_case, and further processing of column names.
    """
    name = name.split('.', 2)[-1].replace('.', '_')
    name = re.sub(r'(?<!^)(?=[A-Z])', '_', name).lower()
    name = name.replace('cvss_v', 'cvss').replace('_data', '_json').replace('description_json', 'description')
    return name


def preprocess_jsons(df_in):
    """
    Flattening CVE_Items and removing the duplicates
    :param df_in: merged dataframe of all years json files
    """
    cf.logger.info('Flattening CVE items and removing the duplicates...')
    cve_items = json_normalize(df_in['CVE_Items'])
    df_cve = pd.concat([df_in.reset_index(), cve_items], axis=1)

    # Removing all CVE entries which have null values in reference-data at [cve.references.reference_data] column
    df_cve = df_cve[df_cve['cve.references.reference_data'].str.len() != 0]

    # Re-ordering and filtering some redundant and unnecessary columns
    df_cve = df_cve.rename(columns={'cve.CVE_data_meta.ID': 'cve_id'})
    df_cve = df_cve.drop(
        labels=[
            'index',
            'CVE_Items',
            'cve.data_type',
            'cve.data_format',
            'cve.data_version',
            'CVE_data_type',
            'CVE_data_format',
            'CVE_data_version',
            'CVE_data_numberOfCVEs',
            'CVE_data_timestamp',
            'cve.CVE_data_meta.ASSIGNER',
            'configurations.CVE_data_version',
            'impact.baseMetricV2.cvssV2.version',
            'impact.baseMetricV2.exploitabilityScore',
            'impact.baseMetricV2.impactScore',
            'impact.baseMetricV3.cvssV3.version',
        ], axis=1, errors='ignore')

    # renaming the column names
    df_cve.columns = [rename_columns(i) for i in df_cve.columns]

    # Check and add columns if they are not present in the dataframe
    for col in ordered_cve_columns:
        if col not in df_cve.columns:
            df_cve[col] = ""

    # ordering the cve columns
    df_cve = df_cve[ordered_cve_columns]

    return df_cve


def assign_cwes_to_cves(df_cve: pd.DataFrame):
    df_cwes = extract_cwe()
    # fetching CWE associations to CVE records
    cf.logger.info('Adding CWE category to CVE records...')
    df_cwes_class = df_cve[['cve_id', 'problemtype_json']].copy()
    df_cwes_class['cwe_id'] = add_cwe_class(df_cwes_class['problemtype_json'].tolist())  # list of CWE-IDs' portion

    # exploding the multiple CWEs list of a CVE into multiple rows.
    df_cwes_class = df_cwes_class.assign(
        cwe_id=df_cwes_class.cwe_id).explode('cwe_id').reset_index()[['cve_id', 'cwe_id']]
    df_cwes_class = df_cwes_class.drop_duplicates(subset=['cve_id', 'cwe_id']).reset_index(drop=True)
    df_cwes_class['cwe_id'] = df_cwes_class['cwe_id'].str.replace('unknown', 'NVD-CWE-noinfo')

    no_ref_cwes = set(list(df_cwes_class.cwe_id)).difference(set(list(df_cwes.cwe_id)))
    if len(no_ref_cwes) > 0:
        cf.logger.debug('List of CWEs from CVEs that are not associated to cwe table are as follows:')
        cf.logger.debug(no_ref_cwes)

    # Applying the assertion to cve-, cwe- and cwe_classification table.
    assert df_cwes.cwe_id.is_unique, "Primary keys are not unique in cwe records!"
    assert df_cwes_class.set_index(['cve_id', 'cwe_id']).index.is_unique, \
        'Primary keys are not unique in cwe_classification records!'
    assert set(list(df_cwes_class.cwe_id)).issubset(set(list(df_cwes.cwe_id))), \
        'Not all foreign keys for the cwe_classification records are present in the cwe table!'

    df_cwes = df_cwes[cwe_columns].reset_index()  # to maintain the order of the columns
    df_cwes.to_sql(name="cwe", con=db.conn, if_exists='replace', index=False)
    df_cwes_class.to_sql(name='cwe_classification', con=db.conn, if_exists='replace', index=False)
    cf.logger.info('Added cwe and cwe_classification tables')


def import_cves():
    """
    gathering CVE records by processing JSON files.
    """
    cf.logger.info('-' * 70)
    if db.table_exists('cve'):
        cf.logger.warning('The cve table already exists, loading and continuing extraction...')
        # df_cve = pd.read_sql(sql="SELECT * FROM cve", con=db.conn)
    else:
        for year in range(initYear, currentYear + 1):
            extract_target = 'nvdcve-1.1-' + str(year) + '.json'
            zip_file_url = urlhead + str(year) + urltail

            # Check if the directory already has the json file or not ?
            if os.path.isfile(Path(cf.DATA_PATH) / 'json' / extract_target):
                cf.logger.warning(f'Reusing the {year} CVE json file that was downloaded earlier...')
                json_file = Path(cf.DATA_PATH) / 'json' / extract_target
            else:
                # url_to_open = urlopen(zip_file_url, timeout=10)
                r = requests.get(zip_file_url)
                z = ZipFile(BytesIO(r.content))  # BytesIO keeps the file in memory
                json_file = z.extract(extract_target, Path(cf.DATA_PATH) / 'json')

            with open(json_file) as f:
                yearly_data = json.load(f)
                if year == initYear:  # initialize the df_methods by the first year data
                    df_cve = pd.DataFrame(yearly_data)
                else:
                    df_cve = df_cve.append(pd.DataFrame(yearly_data))
                cf.logger.info(f'The CVE json for {year} has been merged')

        df_cve = preprocess_jsons(df_cve)
        df_cve = df_cve.applymap(str)
        assert df_cve.cve_id.is_unique, 'Primary keys are not unique in cve records!'
        df_cve.to_sql(name="cve", con=db.conn, if_exists="replace", index=False)
        cf.logger.info('All CVEs have been merged into the cve table')
        cf.logger.info('-' * 70)

        assign_cwes_to_cves(df_cve=df_cve)
