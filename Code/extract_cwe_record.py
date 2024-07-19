import ast
import json
import time
import fnmatch
import xml.etree.ElementTree as et
import pandas as pd
from pathlib import Path
from io import BytesIO
from urllib.request import urlopen
from zipfile import ZipFile
from pandas import json_normalize
import configuration as cf

# --------------------------------------------------------------------------------------------------------


def extract_cwe():
    """
    obtains the table of CWE categories from NVD.nist.gov site
    :return df_CWE: dataframe of CWE category table
    """

    cwe_doc = sorted(Path(cf.DATA_PATH).glob('cwec_*.xml'))
    if len(cwe_doc) > 0:
        cf.logger.info('Reusing the CWE XML file that is already in the directory')
        xtree = et.parse(cwe_doc[-1])
    else:
        cwe_url = 'https://cwe.mitre.org/data/xml/cwec_latest.xml.zip'
        cwe_zip = ZipFile(BytesIO(urlopen(cwe_url).read()))
        cwe_doc = sorted(fnmatch.filter(cwe_zip.namelist(),'cwec_*.xml'))  # assumes all files at top level
        assert len(cwe_doc) > 0, \
            'Cannot find a CWE XML file in https://cwe.mitre.org/data/xml/cwec_latest.xml.zip'
        cf.logger.info(f'Extracting CWE data from {cwe_doc[-1]}')
        cwe_file = cwe_zip.extract(cwe_doc[-1], cf.DATA_PATH)
        xtree = et.parse(cwe_file)
        time.sleep(2)

    xroot = xtree.getroot()
    cat_flag = 0
    rows = []

    # include only types 0, 1 and 2 (0 is for weaknesses, 1 for Categories, 2 for Views, 3 for External_References)
    for parents in xroot[0:2]:
        for node in parents:
            cwe_id = 'CWE-' + str(node.attrib['ID'])
            cwe_name = node.attrib['Name'] if node.attrib['Name'] is not None else None
            description = node[0].text if node[0].text is not None else None
            extended_des = et.tostring(node[1], encoding="unicode", method='text') if cat_flag != 1 else ''
            url = 'https://cwe.mitre.org/data/definitions/' + str(node.attrib['ID']).strip() + '.html' if int(node.attrib['ID']) > 0 else None
            is_cat = True if cat_flag == 1 else False

            rows.append({
                'cwe_id': cwe_id,
                'cwe_name': cwe_name,
                'description': description,
                'extended_description': extended_des,
                'url': url,
                'is_category': is_cat,
            })
        cat_flag += 1

    # explicitly adding three CWEs that are not in the xml file
    rows.append({
        'cwe_id': 'NVD-CWE-noinfo',
        'cwe_name': 'Insufficient Information',
        'description': 'There is insufficient information about the issue to classify it; details are unkown or unspecified.',
        'extended_description': 'Insufficient Information',
        'url': 'https://nvd.nist.gov/vuln/categories',
        'is_category': False
    })
    rows.append({
        'cwe_id': 'NVD-CWE-Other',
        'cwe_name': 'Other',
        'description': 'NVD is only using a subset of CWE for mapping instead of the entire CWE, and the weakness type is not covered by that subset.',
        'extended_description': 'Insufficient Information',
        'url': 'https://nvd.nist.gov/vuln/categories',
        'is_category': False
    })

    df_cwe = pd.DataFrame.from_dict(rows)
    df_cwe = df_cwe.drop_duplicates(subset=['cwe_id']).reset_index(drop=True)
    return df_cwe


def parse_cwes(str1):
    """
    Converts string to list.
    """
    lst = ast.literal_eval(str1)
    lst = [x.strip() for x in lst]
    return lst


def add_cwe_class(problem_col):
    """
    returns CWEs of the CVE.
    """
    cwe_classes = []
    for p in problem_col:
        des = str(p).replace("'", '"')
        des = json.loads(des)
        for cwes in json_normalize(des)["description"]:  # for every cwe of each cve.
            if len(cwes) != 0:
                cwe_classes.append([cwe_id for cwe_id in json_normalize(cwes)["value"]])
            else:
                cwe_classes.append(["unknown"])

    assert len(problem_col) == len(cwe_classes), \
        "Sizes are not equal - Problem occurred while fetching the cwe classification records!"
    return cwe_classes
