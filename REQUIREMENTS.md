# System requirements for gathering CVEfixes from scratch

 - minimum disk space requirement: 5GB
 - Interpreter: Python3.8 or newer
 - Database: SQLite v3.x 
 - Python packages: 
   - The main requirements for collection are pandas, numpy, PyGithub, PyDriller, 
     and guesslang. The example jupyter notebook adds seaborn and matplotlib.
   - We provide minimally constrained versions or required packages in
     - [requirements.txt](requirements.txt) and [environment.yml](environment.yml) 
     for use with pip/virtualenv and (mini)conda, respectively.
   - In addition, we provide "frozen" versions that list the actual versions 
     at the time of development as respectively
     [requirements.frozen.txt](requirements.frozen.txt) and [environment.frozen.yml](environment.frozen.yml)
   - _note that other versions of these packages may work but have not been tested_
    
