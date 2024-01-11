import http.server
import socketserver
import sqlite3
from urllib.parse import parse_qs
import datetime
import random
import smtplib
import string
from jinja2 import Environment, FileSystemLoader
from urllib.parse import unquote_plus
import cgi
import os
import requests
import uuid
from mimetypes import guess_type
import json


# Définition du port sur lequel le serveur web sera exécuté.
PORT = 8080

# Ajoutons une structure pour stocker le dernier timestamp d'activité pour chaque utilisateur
user_last_activity = {}

# Durée avant expiration de la session (par exemple, 30 minutes)
SESSION_DURATION = datetime.timedelta(seconds=60)

# Crée un environnement Jinja2 à partir du répertoire de templates
template_env = Environment(loader=FileSystemLoader('templates'))

def check_session(username):
    """Vérifie si la session d'un utilisateur est toujours valide."""
    last_activity = user_last_activity.get(username)
    if not last_activity:
        return False  # Pas de dernière activité trouvée, probablement pas connecté
    if datetime.datetime.now() - last_activity > SESSION_DURATION:
        return False  # Session expirée
    return True

def update_session_activity(username):
    """Mise à jour du timestamp d'activité pour un utilisateur."""
    user_last_activity[username] = datetime.datetime.now()

def get_user_role(username):
    try:
        # Connexion à la base de données SQLite
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()

        # Exécutez une requête SQL pour obtenir le rôle de l'utilisateur
        cursor.execute("SELECT role FROM users WHERE username=?", (username,))
        result = cursor.fetchone()  # Récupérez le résultat de la requête

        if result is not None and result[0] == "admin":
            return "admin"  # L'utilisateur est un administrateur
        else:
            return "user"  # L'utilisateur n'est pas un administrateur

    except Exception as e:
        print(f"Erreur lors de la vérification du rôle de l'utilisateur : {e}")
        return False  # En cas d'erreur, considérez que l'utilisateur n'est pas un administrateur

    finally:
        conn.close()

def get_all_users():
    # Créez une connexion à votre base de données SQLite
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # Exécutez une requête SQL pour récupérer tous les utilisateurs
    cursor.execute("SELECT * FROM users")
    user_records = cursor.fetchall()

    # Fermez la connexion à la base de données
    conn.close()

    # Traitez les données pour les convertir en une liste de dictionnaires
    # où chaque dictionnaire représente un utilisateur
    users = []
    for record in user_records:
        user = {
            'username': record[0],
            'password': record[1],
            'email': record[2],
            'age': record[3],
            'bio': record[4],
            'avatar': record[6],
            'token': record[7]
        }
        users.append(user)

    return users

def update_user(username, new_username, new_password, new_email, new_age, new_bio, new_avatar, new_token):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET username=?, password=?, email=?, age=?, bio=?, avatar=?, token=? WHERE username=?", (new_username, new_password, new_email, new_age, new_bio, new_avatar, new_token, username))
    conn.commit()
    conn.close()

def delete_user(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE username=?", (username,))
    conn.commit()
    conn.close()

def save_message(sender, recipient, message, timestamp):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO messages (from_user, to_user, timestamp, message) VALUES (?, ?, ?, ?)", (sender, recipient, timestamp, message))
    conn.commit()
    conn.close()

def get_username_and_role_from_token(token):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    cursor.execute("SELECT username, role FROM users WHERE token=?", (token,))
    user = cursor.fetchone()
    
    conn.close()
    
    if user:
        return {
            'username': user[0],
            'role': user[1]
        }
    else:
        return None

def get_messages_id(username, user_role):
    if user_role == 'admin':
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM messages")
        messages = cursor.fetchall()
        conn.close()
        return [message[0] for message in messages]
    else:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM messages WHERE to_user=?", (username,))
        messages = cursor.fetchall()
        conn.close()
        return [message[0] for message in messages]

def get_message_content(username, user_role, message_id=None):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    if user_role == 'admin':
        cursor.execute("SELECT message FROM messages")
    else:
        if message_id is not None:
            # Si un ID de message est spécifié, renvoyer son contenu s'il appartient à l'utilisateur
            cursor.execute("SELECT message FROM messages WHERE id=? AND to_user=?", (message_id, username))
        else:
            # Si aucun ID de message n'est spécifié, renvoyer les contenus des messages de l'utilisateur
            cursor.execute("SELECT message FROM messages WHERE to_user=?", (username,))

    message_content = cursor.fetchall()
    conn.close()

    return [content[0] for content in message_content]


def save_user_post(username, message_content):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # Insérez le message dans la table userposts
    cursor.execute("INSERT INTO userposts (username, message) VALUES (?, ?)",
                   (username, message_content))

    # Validez les changements dans la base de données
    conn.commit()

    # Fermez la connexion
    conn.close()

def report_message(message_id):
    try:
        # Convertir message_id en entier si nécessaire
        message_id = int(message_id)

        # Increment the report count for the message in the database
        conn = sqlite3.connect('users.db') 
        cursor = conn.cursor()
        # Vérifier d'abord la valeur actuelle de report_count
        cursor.execute("SELECT report_count FROM userposts WHERE id = ?", (message_id,))
        result = cursor.fetchone()
        if result and result[0] is not None:
            new_report_count = result[0] + 1
        else:
            new_report_count = 1  # S'assurer que report_count est initialisé à 1 s'il est NULL
        # Mettre à jour avec la nouvelle valeur de report_count
        cursor.execute("UPDATE userposts SET report_count = ? WHERE id = ?", (new_report_count, message_id))
        conn.commit()
        rows_updated = cursor.rowcount
        print(f"Rows updated: {rows_updated}")
        conn.close()

        if rows_updated == 0:
            # print(f"No post found with id {message_id} to report.")
            return False
        # print(f"Message id {message_id} reported successfully.")
        return True
    except Exception as e:
        # print(f"Error when reporting message id {message_id}: {e}")
        return False

def hide_post(post_id):
    try:
        # Convertir post_id en entier si nécessaire
        post_id = int(post_id)

        # Mettre à jour le champ is_hidden pour le post dans la base de données
        conn = sqlite3.connect('users.db') 
        cursor = conn.cursor()

        # Vérifier d'abord la valeur actuelle de is_hidden
        cursor.execute("SELECT is_hidden FROM userposts WHERE id = ?", (post_id,))
        result = cursor.fetchone()

        if result and result[0] is not None:
            new_is_hidden = 1 - result[0]  # Inverse la valeur actuelle de is_hidden
        else:
            new_is_hidden = 1  # S'assurer que is_hidden est initialisé à 1 s'il est NULL

        # Mettre à jour avec la nouvelle valeur de is_hidden
        cursor.execute("UPDATE userposts SET is_hidden = ? WHERE id = ?", (new_is_hidden, post_id))
        conn.commit()
        conn.close()
        
        # print(f"Post id {post_id} hidden successfully.")
        return True
    except Exception as e:
        # print(f"Error when hiding post id {post_id}: {e}")
        return False

def delete_post(post_id):
    try:
        # Convertir post_id en entier si nécessaire
        post_id = int(post_id)

        # Supprimer le post de la base de données
        conn = sqlite3.connect('users.db') 
        cursor = conn.cursor()

        cursor.execute("DELETE FROM userposts WHERE id = ?", (post_id,))
        
        conn.commit()
        conn.close()
        
        # print(f"Post id {post_id} deleted successfully.")
        return True
    except Exception as e:
        # print(f"Error when deleting post id {post_id}: {e}")
        return False


# Définition de la classe MyHandler qui hérite de SimpleHTTPRequestHandler.
class MyHandler(http.server.SimpleHTTPRequestHandler):

    def create_user(self, username, email, password, age, bio):
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()

        # Vérifier si le nom d'utilisateur existe déjà
        cursor.execute("SELECT * FROM users WHERE username=?", (username,))
        existing_username = cursor.fetchone()

        if existing_username:
            conn.close()
            return "Nom d'utilisateur déjà utilisé."

        # Vérifier si l'adresse e-mail existe déjà
        cursor.execute("SELECT * FROM users WHERE email=?", (email,))
        existing_email = cursor.fetchone()

        if existing_email:
            conn.close()
            return "Adresse mail déjà utilisé."

        # Si le nom d'utilisateur et l'adresse e-mail sont uniques, insérer l'utilisateur dans la base de données
        cursor.execute("INSERT INTO users (username, email, password, age, bio) VALUES (?, ?, ?, ?, ?)",
                    (username, email, password, age, bio))
        conn.commit()
        conn.close()
        return "True"

    def publish_article(self, username, message, image_filename=None):
        # Insérez le nouvel article dans la base de données (table userposts)
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        print("Insertion dans la base de données avec:", username, message, image_filename)  # Ajout de l'instruction print ici
        cursor.execute("INSERT INTO userposts (username, message, image_filename) VALUES (?, ?, ?)", 
               (username, message, image_filename))
        conn.commit()
        conn.close()


    def send_custom_response(self, response, header_type, header_format):
        # Envoyer une réponse HTTP 200 (OK).
        self.send_response(response)
        # Ajouter l'en-tête pour préciser le type de contenu.
        self.send_header(header_type, header_format)
        # Fin de l'en tête
        self.end_headers()

    def get_username_from_cookies(self):
        cookies = self.headers.get('Cookie').split('; ')
        username_cookie = [cursor.split('=') for cursor in cookies if cursor.startswith('username=')]

        if not username_cookie:
            # Gestion de l'erreur si le cookie n'est pas présent
            self.send_response(401)  # Unauthorized
            self.end_headers()
            self.wfile.write(b"Access denied!")
            return None  # Aucun cookie "username" trouvé

        return username_cookie[0][1]


    # Cette méthode est appelée lorsqu'une requête GET est reçue par le serveur.
    def do_GET(self):
        # Si l'utilisateur accède au chemin '/register'.
        if self.path == '/register':
            self.send_custom_response(200, "Content-type", "text/html")

            # Envoyer le formulaire d'inscription au navigateur de l'utilisateur.
            with open('templates/register.html', 'rb') as f:
                self.wfile.write(f.read())

        # Si l'utilisateur accède au chemin '/login'.
        elif self.path == '/login':
            self.send_custom_response(200, "Content-type", "text/html")

            # Envoyer le formulaire de connexion au navigateur de l'utilisateur.
            with open('templates/login.html', 'rb') as f:
                self.wfile.write(f.read())
        
        elif self.path == '/':
            # Connexion à la base de données SQLite
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()

            # Exécute une requête SQL pour récupérer les userposts avec l'avatar de chaque utilisateur
            cursor.execute("""
                SELECT userposts.id, userposts.username, userposts.horodatage, userposts.message,
                    userposts.image_filename, users.avatar 
                FROM userposts 
                INNER JOIN users ON userposts.username = users.username 
                WHERE userposts.is_hidden IS NULL OR userposts.is_hidden = 0
                ORDER BY userposts.horodatage DESC
            """)
            userposts = cursor.fetchall()

            posts_data = []

            for post in userposts:
                # Extrait les données de chaque ligne et les stocke dans un dictionnaire
                post_data = {
                    'id': post[0],  # 'id' est la première colonne sélectionnée
                    'username': post[1],  # 'username' est la deuxième colonne sélectionnée
                    'timestamp': post[2],  # 'horodatage' est la troisième colonne sélectionnée
                    'message': post[3],  # 'message' est la quatrième colonne sélectionnée
                    'image_filename': post[4],  # 'image_filename' est la cinquième colonne sélectionnée
                    'avatar': post[5],  # 'avatar' est la sixième colonne sélectionnée
                }
                posts_data.append(post_data)

            # Fermez la connexion à la base de données
            conn.close()


            # Récupérez le nom d'utilisateur à partir des cookies en utilisant la fonction get_username_from_cookies
            username = self.get_username_from_cookies()
            user_role = get_user_role(username)
        
            # Charge le modèle Jinja2
            print(posts_data)  # Pour déboguer et vérifier la structure de vos données
            template = template_env.get_template('homepage.html')
            # Rend le modèle avec les données des userposts et le nom d'utilisateur
            rendered_template = template.render(userposts=posts_data, utilisateur_connecte=username, user_role=user_role, id=id)

            # Envoie la réponse HTTP avec le modèle rendu
            self.send_custom_response(200, 'Content-type', 'text/html')
            self.wfile.write(rendered_template.encode('utf-8'))

        elif self.path.startswith('/profil/'):
            # Récupère le nom d'utilisateur à partir de l'URL
            username = self.path[len('/profil/'):]

            # Connexion à la base de données SQLite
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()

            # Exécute une requête SQL pour récupérer les informations de l'utilisateur
            cursor.execute("SELECT * FROM users WHERE username=?", (username,))
            user_info = cursor.fetchone()

            # Si l'utilisateur n'existe pas, renvoyez une erreur ou redirigez
            if not user_info:
                self.send_custom_response(200, 'Content-type', 'text/html')
                error_message = "L'utilisateur demandé n'a pas été trouvé."
                self.wfile.write(error_message.encode('utf-8'))
                return
            
            # Si l'utilisateur existe, continuez à récupérer ses posts
            cursor.execute("SELECT * FROM userposts WHERE username=? ORDER BY horodatage DESC", (username,))
            userposts = cursor.fetchall()

            # Ferme la connexion à la base de données
            conn.close()

            # Récupérez le nom d'utilisateur à partir des cookies en utilisant la fonction get_username_from_cookies
            current_user = self.get_username_from_cookies()

            # Si l'utilisateur consulte son propre profil, utilisez le template user_profile.html
            if username == current_user:
                template = template_env.get_template('user_profile.html')
            else:
                template = template_env.get_template('profile.html')

            # Rend le modèle avec les données de l'utilisateur et de ses userposts
            rendered_template = template.render(users=user_info, userposts=userposts)

            # Envoie la réponse HTTP avec le modèle rendu
            self.send_custom_response(200, 'Content-type', 'text/html')
            self.wfile.write(rendered_template.encode('utf-8'))

        elif self.path == '/myprofile':
            if self.get_username_from_cookies():
                username = self.get_username_from_cookies()

                # Ajout de la vérification de session
                if not check_session(username):
                    self.send_custom_response(302, 'Location', '/login')
                    return

                # Mettre à jour le timestamp d'activité pour l'utilisateur
                update_session_activity(username)

                # Connexion à la base de données SQLite
                conn = sqlite3.connect('users.db')
                cursor = conn.cursor()

                # Exécute une requête SQL pour récupérer les informations de l'utilisateur
                cursor.execute("SELECT * FROM users WHERE username=?", (username,))
                user_info = cursor.fetchone()

                # Récupérer les articles de l'utilisateur depuis la table userposts
                cursor.execute("SELECT horodatage, message, image_filename FROM userposts WHERE username=?", (username,))
                user_posts = cursor.fetchall()

                conn.close()

                if user_info:
                    role = user_info[4]  # Récupère le rôle depuis les données
                    self.send_custom_response(200, "Content-type", "text/html")
                    time_left = SESSION_DURATION.total_seconds()

                    # Charge le modèle Jinja2
                    template = template_env.get_template('user_profile.html')

                    # Rend le modèle avec les données de l'utilisateur et de ses userposts
                    rendered_template = template.render(users=user_info, userposts=user_posts)

                    # Envoie la réponse HTTP avec le modèle rendu
                    self.send_custom_response(200, 'Content-type', 'text/html')
                    self.wfile.write(rendered_template.encode('utf-8'))

                else:
                    self.send_response(401)  # Unauthorized
                    self.end_headers()
                    self.wfile.write(b"Access denied!")

                return

            # Si pas de cookie ou cookie non valide, redirigez vers la page de connexion
            self.send_custom_response(302, 'Location', '/login')


        elif self.path.startswith('/files/'):
            self.serve_static_file(self.path[1:])  # remove the leading slash
            if os.path.exists(file_path):
                with open(file_path, 'rb') as f:
                    self.send_response(200)
                    self.send_header('Content-Type', 'image/jpeg')  # assuming all images are JPEGs; adjust if not
                    self.end_headers()
                    self.wfile.write(f.read())
            else:
                self.send_response(404)
                self.end_headers()
    
        elif self.path == '/logout':
            self.send_response(302)  # Redirection vers la page de login
            self.send_header('Location', '/login')
            self.send_header('Set-Cookie', 'username=; expires=Thu, 01 Jan 1970 00:00:00 GMT')  # Supprime le cookie username
            self.end_headers()

        elif self.path == '/config':
            # Assurez-vous que l'utilisateur est connecté
            username = self.get_username_from_cookies()

            if username:
                # Récupérez les informations de l'utilisateur pour les préremplir dans le formulaire
                conn = sqlite3.connect('users.db')
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM users WHERE username=?", (username,))
                user_info = cursor.fetchone()
                conn.close()
                if user_info:
                    template = template_env.get_template('config.html')
                    rendered_template = template.render(username = username, users=user_info)
                    self.send_custom_response(200, 'Content-type', 'text/html')
                    self.wfile.write(rendered_template.encode('utf-8'))
                    return

            # Redirigez l'utilisateur vers la page de connexion s'il n'est pas connecté
            self.send_custom_response(302, 'Location', '/login')


        elif self.path == '/all_config':
            # Vérifiez si l'utilisateur est un administrateur
            username = self.get_username_from_cookies()
            user_role = get_user_role(username)

            if user_role == "admin":
                # Récupérez la liste de tous les utilisateurs depuis la base de données
                user_list = get_all_users()

                # Récupérez les posts reportés depuis la base de données
                conn = sqlite3.connect('users.db')
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM userposts WHERE report_count > 0 ORDER BY report_count DESC")
                reported_posts = cursor.fetchall()
                conn.close()

                # Convertissez les résultats en liste de dictionnaires
                reported_posts_data = [
                    {'id': post[0], 'username': post[1], 'horodatage': post[2], 'message': post[3],
                    'image_filename': post[4], 'report_count': post[5]} 
                    for post in reported_posts
                ]

                # Chargez le modèle HTML pour les administrateurs
                template = template_env.get_template('all_config.html')
                # Passez les posts reportés et la liste des utilisateurs au modèle
                rendered_template = template.render(username=username, user_list=user_list, reported_posts=reported_posts_data)
                self.send_custom_response(200, 'Content-type', 'text/html')
                self.wfile.write(rendered_template.encode('utf-8'))

            else:
                # Redirigez l'utilisateur vers la page de connexion s'il n'est pas un administrateur
                self.send_custom_response(302, 'Location', '/login')

        
        elif self.path == '/inbox':

            if self.get_username_from_cookies():
                username = self.get_username_from_cookies()
                # Récupérez les messages de l'utilisateur actuellement connecté depuis la base de données

                # Connexion à la base de données SQLite
                conn = sqlite3.connect('users.db')
                cursor = conn.cursor()
                # Récupérer les messages reçus
                cursor.execute("SELECT * FROM messages WHERE to_user=?", (username,))
                message_from = cursor.fetchall()
                # Récupérer les messages envoyés
                cursor.execute("SELECT * FROM messages WHERE from_user=?", (username,))
                message_to = cursor.fetchall()
                conn.close()

                # Rend le modèle avec les messages concernés
                template = template_env.get_template('inbox.html')  
                rendered_template = template.render(username = username, messages_from=message_from, messages_to=message_to)

                self.send_custom_response(200, 'Content-type', 'text/html')
                self.wfile.write(rendered_template.encode('utf-8'))

            else:
                self.send_custom_response(302, 'Location', '/login')

        elif self.path == '/messages':
            # Obtenir le token du header de la requête
            token = self.headers.get('XAPITOKEN')

            if token:
                user_info = get_username_and_role_from_token(token)
                if user_info:
                    username = user_info['username']
                    role = user_info['role']

                    # Maintenant, vous pouvez utiliser 'username' et 'role' pour répondre à la requête                   
                    messages_id = get_messages_id(username, role)

                    # Ensuite, renvoyez les messages en réponse (exemple en JSON)
                    response = {'messages': messages_id}
                    json_response = json.dumps(response)      
                    self.send_custom_response(200, 'Content-type', 'application/json')                    
                    self.wfile.write(json_response.encode('utf-8'))
                else:
                    # Le token est invalide, renvoyez une réponse d'erreur
                    self.send_response(401)
                    self.end_headers()
                    self.wfile.write(b'Invalid token')
            else:
                # Le token est manquant, renvoyez une réponse d'erreur
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b'Missing token')

        elif self.path.startswith('/message/'):
            # Extrait l'ID du message de l'URL
            message_id = int(self.path.split('/')[-1])

            # Obtenir le token du header de la requête
            token = self.headers.get('XAPITOKEN')

            if token:
                user_info = get_username_and_role_from_token(token)
                if user_info:
                    username = user_info['username']
                    role = user_info['role']

                    message_content = get_message_content(username, role, message_id)
                      
                    if message_content:
                        # Envoi de la réponse JSON avec le contenu du message
                        response = {'message_content': message_content}
                        json_response = json.dumps(response, ensure_ascii=False, indent=2)
                        self.send_custom_response(200, 'Content-type', 'application/json')
                        self.wfile.write((json_response + '\n').encode('utf-8'))
                    
                    else:
                        # Aucun message trouvé avec l'ID spécifié
                        self.send_response(404)
                        self.end_headers()
                        self.wfile.write(b'Message not found')

                else:
                    # Le token est invalide, renvoyer une réponse d'erreur
                    self.send_response(401)
                    self.end_headers()
                    self.wfile.write(b'Invalid token')
            else:
                # Le token est manquant, renvoyer une réponse d'erreur
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b'Missing token')      

        else:
            super().do_GET()

    # Cette méthode est appelée lorsqu'une requête POST est reçue par le serveur.
    def do_POST(self):

        if self.path == '/password':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            data = parse_qs(post_data)

            # Récupérer l'adresse e-mail saisie dans le formulaire
            email_address = data.get('email', [''])[0]

            # Générer une chaîne aléatoire de 10 caractères
            allowed_characters = string.ascii_letters + string.digits  # Lettres majuscules, lettres minuscules et chiffres
            random_string = ''.join(random.choice(allowed_characters) for _ in range(10))
           
            try:
                # Envoie de l'email
                with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:  # Utilisation de SMTP_SSL pour une connexion directe sécurisée
                    server.login('mailwwittossuppt@gmail.com', 'pcqgppzwuerunhit')  # Votre adresse e-mail et mot de passe
                    message = f"Subject: Nouveau mot de passe\n\nVoici votre nouveau mot de passe: {random_string}"
                    server.sendmail('mailwwittossuppt@gmail.com', email_address, message)

                self.send_custom_response(200, "Content-type", "text/html")
                self.wfile.write(b"E-mail sent successfully!")
                # Mise à jour de la BDD
                conn = sqlite3.connect('users.db')
                cursor = conn.cursor()
                cursor.execute("UPDATE users SET password = ? WHERE email = ?", (random_string, email_address))
                conn.commit()
                conn.close()

            except Exception as e:
                self.send_custom_response(500, "Content-type", "text/html")
                self.wfile.write(b"Error sending e-mail: " + str(e).encode())


        # Si la requête est pour le chemin '/register'.
        elif self.path == '/register':
            # Récupérer la longueur du contenu POST.
            content_length = int(self.headers['Content-Length'])
            # Lire les données POST.
            post_data = self.rfile.read(content_length).decode('utf-8')
            # Analyser les données POST pour les transformer en dictionnaire.
            data = parse_qs(post_data)
            
            username = data['username'][0]
            email = data['email'][0]
            password = data['password'][0]
            age = int(data['age'][0])
            bio = data['bio'][0]

            # Appeler la fonction create_user pour insérer l'utilisateur dans la base de données
            register_return = self.create_user(username, email, password, age, bio)

            if register_return == "True":
                # Envoyer une réponse indiquant que l'utilisateur est enregistré.
                self.send_response(400)
                self.send_header('Content-Type', 'text/plain; charset=utf-8')
                self.end_headers()
                self.wfile.write("L'utilisateur a été enregistré avec succès.".encode('utf-8'))

            else:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(register_return)


        # Si la requête est pour le chemin '/login'.
        elif self.path == '/login':
            # Récupérer la longueur du contenu POST et lire les données.
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            data = parse_qs(post_data)

            # Extraire le nom d'utilisateur et le mot de passe des données POST.
            username = data['username'][0]
            password = data['password'][0]

            # Se connecter à la base de données et récupérer le mot de passe stocké pour cet utilisateur.
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            cursor.execute("SELECT password FROM users WHERE username=?", (username,))
            stored_password = cursor.fetchone()
            conn.close()

            # Vérifier si le mot de passe soumis correspond au mot de passe stocké.
            if stored_password and password == stored_password[0]:
                update_session_activity(username)  # Ajouter une entrée pour l'utilisateur avec le timestamp actuel
                # Redirect to profile page
                expiration = datetime.datetime.now() + datetime.timedelta(minutes=30)  # Expire in 30 minutes
                formatted_expiration = expiration.strftime('%a, %d-%b-%Y %H:%M:%S GMT')
                self.send_response(303)
                self.send_header('Location', '/')
                self.send_header('Set-Cookie', f'username={username}; Expires={formatted_expiration}; Path=/;')
                self.end_headers()
            else:
                self.send_custom_response(401, "Content-type", "text/html")
                self.wfile.write(b"Login failed!")

            return
            
        elif self.path == '/profile':
            form = cgi.FieldStorage(fp=self.rfile, headers=self.headers, environ={'REQUEST_METHOD': 'POST', 'CONTENT_TYPE': self.headers['Content-Type']})

            # Récupérer le texte du message
            new_post = form.getvalue('message')
            username = self.get_username_from_cookies()

            # Traiter l'image
            fileitem = form['image']
            image_url = form.getvalue('image_url')  # Nouveau champ pour l'URL de l'image
            image_filename = None

            if image_url:  # Si une URL d'image est fournie
                response = requests.get(image_url, stream=True)
                if response.status_code == 200:
                    image_filename = os.path.basename(image_url)
                    with open("files/" + image_filename, "wb") as f:
                        for chunk in response.iter_content(1024):
                            f.write(chunk)
            elif hasattr(fileitem, 'filename') and fileitem.filename:
                # strip leading path from file name to avoid directory traversal attacks
                print("Nom du fichier reçu:", fileitem.filename)  # Ajout de l'instruction print ici
                image_filename = os.path.basename(fileitem.filename)
                with open("files/" + image_filename, "wb") as f:
                    f.write(fileitem.file.read())
                # Vous pouvez également stocker le nom du fichier dans la base de données avec le message si nécessaire

            # Insérez le nouvel article dans la base de données (avec le nom du fichier image si nécessaire)
            self.publish_article(username, new_post, image_filename=image_filename)

            # Redirigez l'utilisateur vers sa page de profil après la publication
            self.send_custom_response(302, 'Location', f'/profil/{username}')
            print(f"Redirection vers le profil de {username}")  # Ajout de l'instruction print ici
            return

        elif self.path == '/logout':
            self.send_response(302)  # HTTP Status Code for redirection
            self.send_header('Set-Cookie', 'username=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/;')
            self.send_header('Location', '/login')  # The URL to redirect to
            self.end_headers()

        elif self.path == '/config':
            form = cgi.FieldStorage(fp=self.rfile, headers=self.headers, environ={'REQUEST_METHOD': 'POST', 'CONTENT_TYPE': self.headers['Content-Type']})
            username = self.get_username_from_cookies()

            # Traiter l'avatar
            avatar_item = form['new_avatar']

            if hasattr(avatar_item, 'filename') and avatar_item.filename:
                # strip leading path from file name to avoid directory traversal attacks
                avatar_filename = os.path.basename(avatar_item.filename)
                avatar_path = os.path.join("files", avatar_filename)  # Just save the filename and folder, not the full path
                with open(avatar_path, "wb") as f:
                    f.write(avatar_item.file.read())

                # Mettre à jour l'avatar de l'utilisateur dans la base de données
                conn = sqlite3.connect('users.db')
                cursor = conn.cursor()
                cursor.execute("UPDATE users SET avatar=? WHERE username=?", (avatar_filename, username))
                conn.commit()
                conn.close()

            age = form.getvalue('age')
            bio = form.getvalue('bio')
            email = form.getvalue('email')
            token = form.getvalue('token')
            # avatar = form.getvalue('avatar')

            # Mettez à jour la base de données avec les nouvelles informations
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET age=?, bio=?, email=?, token=? WHERE username=?", (age, bio, email, token, username))
            conn.commit()
            conn.close()

            self.send_custom_response(302, 'Location', f'/profil/{username}')


        elif self.path == '/admin_config':

            # form_data = self.rfile.read(int(self.headers['Content-Length']))
            # print("Form data received:", form_data)


            form = cgi.FieldStorage(fp=self.rfile, headers=self.headers, environ={'REQUEST_METHOD': 'POST', 'CONTENT_TYPE': self.headers['Content-Type']})
            
            # Récupérez la liste de tous les utilisateurs
            user_list = get_all_users()

            for user in user_list:
                username = user['username']
                # Analysez les données du formulaire pour chaque utilisateur
                username_key = f'username_{username}'
                password_key = f'password_{username}'
                email_key = f'email_{username}'
                age_key = f'age_{username}'
                bio_key = f'bio_{username}'
                avatar_key = f'avatar_{username}'
                token_key = f'token_{username}'
                delete_key = f'delete_{username}'

                if username_key in form:
                    # Mettez à jour les données de l'utilisateur dans la base de données
                    new_username = form[username_key].value
                    new_password = form[password_key].value
                    new_email = form[email_key].value
                    new_age = form[age_key].value
                    new_bio = form[bio_key].value
                    new_avatar = form[avatar_key].value
                    new_token = form[token_key].value

                    # Mettez à jour l'utilisateur dans la base de données avec les nouvelles valeurs
                    update_user(username, new_username, new_password, new_email, new_age, new_bio, new_avatar, new_token)

                if delete_key in form and form[delete_key].value == "1":
                    # Supprimez l'utilisateur de la base de données
                    delete_user(username)

            # Redirigez l'utilisateur vers la page de configuration après les modifications
            self.send_custom_response(302, 'Location', '/all_config')

        elif self.path == '/send_message':
            form = cgi.FieldStorage(fp=self.rfile, headers=self.headers, environ={'REQUEST_METHOD': 'POST', 'CONTENT_TYPE': self.headers['Content-Type']})

            # Récupérez les données du formulaire, y compris le message, l'expéditeur et le destinataire
            message = form.getvalue('message')
            sender = self.get_username_from_cookies()
            recipient = form.getvalue('to_user')

            # Obtenez le timestamp actuel
            time = datetime.datetime.now()
            timestamp = time.strftime('%H:%M')

            # Enregistrez le message dans la base de données
            save_message(sender, recipient, message, timestamp)

            # Redirigez l'utilisateur vers la page de conversation appropriée
            self.send_custom_response(302, 'Location', '/inbox')

        # Check the path to determine if this is a report action
        elif self.path == '/report_message':
            # print("Entrée dans le endpoint /report_message")  # Ajout d'un log pour le débogage
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            post_data = json.loads(post_data)
            message_id = post_data.get('message_id')  # Utilisez .get pour éviter KeyError si message_id n'existe pas

            if message_id:
                # print(f"message_id reçu: {message_id}")  # Confirmez que vous avez reçu un message_id
                report_message(message_id)  # Supposons que cette fonction imprime également ses propres logs

                self.send_custom_response(200, 'Content-type', '/all_config')
                # self.wfile.write("Message reported successfully.".encode('utf-8'))
                self.wfile.write(b'Message reported successfully.')
            else:
                print("Aucun message_id reçu ou message_id est vide.")
                # Gérez le cas où message_id est vide ou non reçu
                self.send_custom_response(400, 'Content-type', '/all_config')
                # self.wfile.write("No message_id received.".encode('utf-8'))
                self.wfile.write(b'No message_id received.')


        elif self.path == '/hide_post':
            username = self.get_username_from_cookies()
            user_role = get_user_role(username)

            if user_role == "admin":
                form_data = cgi.FieldStorage(
                    fp=self.rfile, headers=self.headers, environ={'REQUEST_METHOD': 'POST', 'CONTENT_TYPE': self.headers['Content-Type']}
                )

                # Récupérez les noms de tous les boutons "Cacher" et "Supprimer"
                hide_buttons = [key for key in form_data.keys() if key.startswith('hide_button_')]
                delete_buttons = [key for key in form_data.keys() if key.startswith('delete_button_')]

                for hide_button in hide_buttons:
                    post_id = hide_button.replace('hide_button_', '')
                    # print(f"post_id reçu: {post_id}")
                    hide_post(post_id)

                for delete_button in delete_buttons:
                    post_id = delete_button.replace('delete_button_', '')
                    # print(f"post_id reçu pour suppression: {post_id}")
                    delete_post(post_id)

                self.send_custom_response(200, 'Content-type', '/all_config')
                # self.wfile.write("Posts hidden successfully.".encode('utf-8'))
                self.wfile.write(b'Posts hidden successfully')
            else:
                self.send_custom_response(403, 'Content-type', '/all_config')
                # self.wfile.write("You do not have permission to hide posts.".encode('utf-8'))
                self.wfile.write(b'You do not have permission to hide posts.')
                

        elif self.path == '/message':
            # Obtenir le token du header de la requête
            token = self.headers.get('XAPITOKEN')

            if token:
                user_info = get_username_and_role_from_token(token)
                if user_info:
                    username = user_info['username']

                    # Lire le contenu du message depuis le corps de la requête POST
                    content_length = int(self.headers['Content-Length'])
                    message_content = self.rfile.read(content_length).decode('utf-8')

                    # Enregistrez le message dans la base de données
                    save_user_post(username, message_content)

                    # Répondre avec un succès
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b'Message sent successfully')
                else:
                    # Le token est invalide, renvoyer une réponse d'erreur
                    self.send_response(401)
                    self.end_headers()
                    self.wfile.write(b'Invalid token')
            else:
                # Le token est manquant, renvoyer une réponse d'erreur
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b'Missing token')

    
    def serve_static_file(self, path):
        """Serve a static file."""
        try:
            # Open the static file and read its content
            with open(path, 'rb') as f:
                content = f.read()
            self.send_response(200)
            # You might want to add more content types based on the file extensions
            if path.endswith('.jpg') or path.endswith('.jpeg'):
                self.send_header('Content-type', 'image/jpeg')
            elif path.endswith('.css'):
                self.send_header('Content-type', 'text/css')
            elif path.endswith('.js'):
                self.send_header('Content-type', 'application/javascript')
            elif path.endswith('.html'):
                self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(content)
        except FileNotFoundError:
            self.send_error(404, 'File Not Found: %s' % path)

# Créer et démarrer le serveur web.
with socketserver.TCPServer(("", PORT), MyHandler) as httpd:
    print("serving at port", PORT)
    httpd.serve_forever()
