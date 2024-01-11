import requests

# Token d'administration pour l'API
token_admin = "lt4lddr4dutilpzcoaom8xxdsouw10"

# L'adresse de l'API
api_url = "http://127.0.0.1:8080/messages"

# Faire la requête à l'API
headers = {"XAPITOKEN": token_admin}
response = requests.get(api_url, headers=headers)

if response.status_code == 200:
    # Parsez le JSON de la réponse
    data = response.json()
    # Comptez le nombre de messages
    total_messages = len(data.get('messages', []))
    print(f"Nombre total de messages : {total_messages}")
else:
    print(f"Erreur : {response.status_code}")
