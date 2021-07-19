[![source under MIT licence](https://img.shields.io/badge/source%20license-MIT-green)](LICENSE.txt)
[![data under CC BY 4.0 license](https://img.shields.io/badge/data%20license-CC%20BY%204.0-green)](https://creativecommons.org/licenses/by/4.0/)

# CVEfixes: Automated Collection of Vulnerabilities and Their Fixes from Open-Source Software

_CVEfixes_ is a comprehensive vulnerability dataset that is automatically
collected and curated from Common Vulnerabilities and Exposures
(CVE) records in the public [U.S. National Vulnerability Database (NVD)]
(https://nvd.nist.gov/). The goal is to support data-driven security
research based on source code and source code metrics related to fixes
for CVEs in the NVD by providing detailed information at different
interlinked levels of abstraction, such as the commit-, file-, and
method level, as well as the repository- and CVE level.

At the initial release, the dataset covers all published CVEs up to 9
June 2021. All open-source projects that were reported in CVE records
in the NVD in this time frame and had publicly available git
repositories were fetched and considered for the construction of this
vulnerability dataset. The dataset is organized as a relational
database and covers 5495 vulnerability fixing commits in 1754 open
source projects for a total of 5365 CVEs in 180 different Common
Weakness Enumeration (CWE) types. The dataset includes the source code
before and after fixing of 18249 files, and 50322 functions. Because 
of limitations in GitHub storage, we provide a compressed SQL
dump of the _CVEfixes_ vulnerability dataset via Zenodo with DOI:
[10.5281/zenodo.4476563](https://doi.org/10.5281/zenodo.4476563).

This repository includes the code to replicate the data collection. 
The complete process has been documented in the paper _"CVEfixes: 
Automated Collection of Vulnerabilities and Their Fixes from Open-
Source Software"_, a copy of which you will find in the Doc folder.

  * instructions for using _CVEfixes_ are in the 
    first section of [INSTALL.md](INSTALL.md).
  * requirements for gathering _CVEfixes_ from scratch 
    are in [REQUIREMENTS.md](REQUIREMENTS.md).
  * instructions for gathering _CVEfixes_ from scratch 
    are in the second section of [INSTALL.md](INSTALL.md).


## Citation and Zenodo links

Please site this work by referring to the paper: 
> Guru Bhandari, Amara Naseer, and Leon Moonen. 2021. CVEfixes:
> Automated Collection of Vulnerabilities and Their Fixes from
> Open-Source Software. In Proceedings of the 17th International
> Conference on Predictive Models and Data Analytics in Software
> Engineering (PROMISE '21). ACM, 10 pages.
> <https://doi.org/10.1145/3475960.3475985>

    @inproceedings{bhandari2021:cvefixes,
        title = {{CVEfixes: Automated Collection of Vulnerabilities  and Their Fixes from Open-Source Software}},
        booktitle = {{Proceedings of the 17th International Conference on Predictive Models and Data Analytics in Software Engineering (PROMISE '21)}},
        author = {Bhandari, Guru and Naseer, Amara and Moonen, Leon},
        year = {2021},
        pages = {10},
        publisher = {{ACM}},
        doi = {10.1145/3475960.3475985},
        copyright = {Open Access},
        isbn = {978-1-4503-8680-7},
        language = {en}
    }

The GitHub repository containing the code to automatically collect the
dataset can be found at <https://github.com/secureIT-project/CVEfixes>,
released with DOI:
[10.5281/zenodo.5111494](https://doi.org/10.5281/zenodo.5111494). The 
dataset has been released on Zenodo with DOI:
[10.5281/zenodo.4476563](https://doi.org/10.5281/zenodo.4476563). 


## Acknowledgement

This work has been financially supported by the Research Council of
Norway through the secureIT project (RCN contract \#288787).
