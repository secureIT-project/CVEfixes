# System requirements for gathering CVEfixes from scratch

 - minimum disk space requirement: 5GB
 - Interpreter: Python v3.8 or v3.9 on Inter Mac or Ubuntu 20.04LTS
   (Aug 2022: Python v3.10 cannot resolve the requirements)
 - Database: SQLite v3.x 
 - Python packages: 
   - The main requirements for collection are pandas, numpy, PyGithub, PyDriller, 
     and guesslang. The example jupyter notebook adds seaborn and matplotlib.
   - We provide minimally constrained versions of required packages in
     - [requirements.txt](requirements.txt) and [environment.yml](environment.yml) 
     for use with pip/virtualenv and (mini)conda, respectively.
   - In addition, we provide "frozen" versions that list the actual versions 
     at the time of development as respectively
     [requirements.frozen.txt](requirements.frozen.txt) and [environment.frozen.yml](environment.frozen.yml)
   - _note that other versions of these packages may work but have not been tested_
    
**Note Aug 2022**: replication experiments show that the minimally constrained 
requirements can lead to issues due to incompatible changes to some dependencies. 
We are working on updating the minimal requirements, but until that time recommend
using the frozen versions.  The frozen versions are confirmed to work on (Intel) 
macOS 12.5 and Ubuntu 20.04LTS with python v3.8 and v3.9.