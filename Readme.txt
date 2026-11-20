In order to run the encryption/decryption script (aes-gcm_message_encryption.py) and the attack script (nounce_reuse_attacks.py) these are the requirements:

1. aes-gcm_message_encryption.py :
    Need to have Python installed with Cryptography installed
        pip install cryptography
    To run the encryption/decryption script:
        python3 aes-gcm_message_encryption.py

2. nounce_reuse_attacks.py :
    Need to have SageMaths installed in WSL or a Linux distro and running on a virtual environment with Cryptography installed:
    On WSL/Linux install SageMaths (https://doc.sagemath.org/html/en/installation/index.html):
        curl -L -O "https://github.com/conda-forge/miniforge/releases/latest/download/Miniforge3-$(uname)-$(uname -m).sh"
        bash Miniforge3-$(uname)-$(uname -m).sh
        source ~/.bashrc
        conda create -n sage sage python=3.12
        conda activate sage
        pip install cryptography
    After all is installed to run the attack script:    
        sage nouce_reuse_attacks.py

