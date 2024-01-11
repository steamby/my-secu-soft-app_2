# My secu soft app [Application Web Simple]

Cette application est un exemple simple de serveur web construit en Python en utilisant le module `http.server` standard et SQLite comme base de données. Elle permet aux utilisateurs de s'inscrire et de se connecter.

## Fonctionnalités

- Inscription des utilisateurs avec des détails comme le nom d'utilisateur, le mot de passe, l'e-mail, l'âge et une bio.
- Connexion des utilisateurs avec vérification du nom d'utilisateur et du mot de passe.

## Configuration et exécution

1. **Prérequis**:
   
   - Python 3.8 ou versions ultérieures.
   - SQLite (généralement inclus avec Python).

2. **Exécution**:

   Pour démarrer le serveur :

   ```bash
   python3 app.py
   ```

   Une fois le serveur en cours d'exécution, ouvrez un navigateur web et accédez à :

   ```
   http://127.0.0.1:8080/register
   ```

   pour vous inscrire. Après l'inscription, vous pouvez vous connecter à :

   ```
   http://127.0.0.1:8080/login
   ```

## Utilisation du FatClient

   Le fatclient est un client lourd qui permettra a celui qui l'obtient d'aquérir le nombre de message échange sur notre sitw web. Il est sous un formet binaire pour empecher que les personnes mal intentionner ne puisse recuperer la clé du token.

1. **Prérequis**:
   Pour transformer un script Python en fichier exécutable, on a utilisé un outil comme PyInstaller.
      
   ```bash
   pip install pyinstaller
   ```

   Créer l'exécutable :
   ```bash
   pyinstaller --onefile fatClient.py
   ```

2. **Exécution**:

   Une fois le processus terminé, on retrouve l'exécutable dans le dossier dist qui est créé dans le répertoire de notre script.

   ```bash
   ./fatclient
   ```

   Obtention du nombre de message de notre site web.


## Sécurité

Veuillez noter que cette application est à des fins de démonstration et d'apprentissage. Elle ne doit pas être utilisée en production car elle manque de fonctionnalités essentielles en matière de sécurité, notamment le hachage des mots de passe et l'utilisation d'HTTPS.





## COMMANDES CURL POUR TESTER LES API

1. 
- user : curl -H "XAPITOKEN: 123321" http://127.0.0.1:8080/messages -w "\n"
- admin : curl -H "XAPITOKEN: 11119" http://127.0.0.1:8080/messages -w "\n"

Donc 123321 correspond à un token d'un user standard et le 11119 correspond à un token d'un admin.

2. 
- user : curl -H "XAPITOKEN: TOKEN" http://127.0.0.1:8080/message/message_id
   - exemple : curl -H "XAPITOKEN: 123321" http://127.0.0.1:8080/message/12

- admin : même chose, mais l'admin (11119) peut indiquer n'importe quoi dans le message_id et cela affichera tous les messages.

3. curl -X POST -H "XAPITOKEN: TOKEN" -d "MESSAGE" http://127.0.0.1:8080/message
- exemple : curl -X POST -H "XAPITOKEN: 123321" -d "Je suis content que mon API fonctionne..." http://127.0.0.1:8080/message