# Instructions to use CVEfixes


## Converting the CVEfixes dataset from the compressed SQL dump

Because of limitations in GitHub storage, we provide a compressed SQL
dump of the _CVEfixes_ vulnerability dataset via Zenodo with DOI:
[10.5281/zenodo.4476563](https://doi.org/10.5281/zenodo.4476563). The
following script can be used to convert this compressed SQL dump into
an SQLite3 database:

```console
$ sh Code/create_CVEfixes_from_dump.sh
```

It is also possible to do this by hand (Windows users can use
`sqlite3.exe` instead of `sqlite3`)

```console
$ gzcat Data/CVEfixes.sql.gz | sqlite3 Data/CVEfixes.db
```

## Exploring the vulnerability data

The overall structure of the database is as shown in [ER diagram]
(Doc/ER_diagram.png). You can use any SQLite tool to view and query the
database. [DB Browser for SQLite](https://sqlitebrowser.org/) is an
open source visual explorer for SQLite databases that is available for
Mac, Windows and Linux.

We provide a [Jupyter Notebook](Examples/query_CVEfixes.ipynb) with
example queries to extract the data at different abstraction levels,
code to generate statistics, as well as the code to replicate all
tables and plots presented in the [paper]
(Doc/Bhandari-Naseer-Moonen_-_CVEfixes.pdf) based on the _CVEfixes_
data. 

Some example queries to extract the part of _CVEfixes_ database are as
follows:

- a query to extract all the method_level vulnerability data of C
  programming language.

```console
SQL_QUERY = "SELECT m.method_change_id, m.name, m.code, m.before_change, f.programming_language
from file_change f, method_change m
WHERE m.file_change_id=f.file_change_id
AND f.programming_language='C';"
```

- another example as a query to extract all the code patches of Java
  programming language that have added/removed only a single statement
  to fix vulnerabilities.

```console
SQL_QUERY = "SELECT cv.cve_id, f.filename, f.num_lines_added, f.num_lines_deleted, f.code_before, f.code_after, cc.cwe_id
FROM file_change f, commits c, fixes fx, cve cv, cwe_classification cc
WHERE f.hash = c.hash
AND c.hash = fx.hash
AND fx.cve_id = cv.cve_id
AND cv.cve_id = cc.cve_id
AND f.num_lines_added<=1
AND f.num_lines_deleted<=1
AND f.programming_language='Java';;"
```



# (Re)Collecting the CVEfixes dataset from scratch


## Setting up the configuration file

Create a `.CVEfixes.ini` configuration file in the project root
(where this INSTALL.md file lives) defines the following variables 
to customize paths in the `[CVEfixes]` section: 

* `database_path`: directory that should contain the CVEfixes 
  database file (and some temporary files during extraction). 

* `sample_limit`: The number of samples to be extracted, 
  sample_limit = 0 is interpreted as unlimited samples, 
  this is discussed in more detail below. 

The repository contains a file `example.CVEfixes.ini`.


## Setting up a GitHub token

We observe that more than 98% repositories of _CVEfixes_ are hosted on
GitHub. The [GitHub API]
(https://docs.github.com/en/github/authenticating-to-github/creating-a-personal-access-token)
allows us to retrieve meta information of public repositories. Without
configuration of a token, this API is rate limited and only allows
gathering the information for approximately 25 repositories. Thus, we
recommend the user to obtain a GitHub token and configure a [GitHub]
section of the `.CVEfixes.ini` configuration file which has two
variables `user` and `token` for your GitHub username and access token
respectively. Change the values of these variables to set up the token.
It is recommended to not disclose the token information to prevent its
misuse.


## Gathering the CVEfixes dataset

The following script recreates the _CVEfixes_ database file from scratch
up for a time-frame from 2002 up to the latest available CVE records. Be
warned that depending on available internet speed and processing power,
the process can take quite some time (with a modern laptop, around 8-10
hours on T1, and up to 3 days on a simple home connection). Note that
running this script will overwrite an existing `CVEfixes.db`  file in
`database_path`, but that it is possible to restore the database from
the SQL dump on Zenodo, as mentioned above. Before running the
extraction, see also the above remark on [setting up a GitHub
token](#setting-up-a-github-token).


```console
$ sh Code/create_CVEfixes_from_scratch.sh
```

## Gathering only a sample of CVEfixes for demonstration purposes

As mentioned, the complete extraction of the _CVEfixes_ dataset could
take up to 3 days depending on the internet connection. To enable simple
demonstrations, the `.CVEfixes.ini` configuration file has a
`sample_limit` variable that is used to define the number of commits for
CVEs to collect. Setting `sample_limit = 0` is interpreted as unlimited,
i.e. collect all available data. When the `sample_limit` is set to a
value different than `0`, only that many commits are collected from CVEs
for the current year. We tested `sample_limit = 25`, which took
approximately 12 minutes to gather. However, this can take much longer
if any of the CVEs corresponds to major projects. Therefore, whenever
`sample_limit` is set to a value different than `0`, we filter out five
major projects to minimize the time to collect a sample. 


