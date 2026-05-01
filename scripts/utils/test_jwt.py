import os, sys
from sdk.common.auth import token_validator

token = sys.argv[1]
try:
    print(token_validator.validate(token))
except Exception as e:
    print("ERROR:", e)
