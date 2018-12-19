import requests
from requests.auth import HTTPBasicAuth
import json

class CIStatus():
    API_BASE_URL = "https://api.cloudinsight.alertlogic.com"

    def __init__(self):
        pass
    
    def authenticate(self, auth_token = None, username = None, password = None):
        if auth_token:
            self.auth_token = auth_token
        else:
            self.auth_token = CIStatus._authenticate(username, password)
    
    @staticmethod
    def _authenticate(username, password):

        url = CIStatus.API_BASE_URL + "/aims/v1/authenticate"

        try:
            r = requests.post(url, auth=HTTPBasicAuth(username, password))
        except Exception as e:
            print(e)
            return None

        r = json.loads(r.text)

        return (r["authentication"]["token"])