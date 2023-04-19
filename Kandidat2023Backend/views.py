from django.http import JsonResponse
from django.db import connections, connection
import bcrypt
import json
from django.views.decorators.csrf import csrf_exempt
from datetime import datetime, timedelta
import random
import string

def generate_random_string(n):
    return ''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase + string.digits, k=n))

def generate_jwt(user_id):
    exp_time = datetime.utcnow() + timedelta(hours=1)

    payload = {
        'user_id': user_id,
        'exp': exp_time
    }

    token = generate_random_string(10)
    print(token)

    # Write the token to the database
    with connection.cursor() as cursor:
        cursor.execute(
            "INSERT INTO Token (user_id, token, expires_at) VALUES (%s, %s, %s)",
            [user_id, token, exp_time]
        )

    return print(token)


@csrf_exempt ## This is needed to allow POST requests from the frontend, otherwise it will return a 403 error
def create_user(request):
    data = json.loads(request.body.decode('utf-8'))
    email = data.get('email')
    password = data.get('password')
    print(f"Email: {email}, Password: {password}")
    hashed_password, salt = hash_password(password)
    print(f"Hashed password: {hashed_password}, Salt: {salt}")
    response = "Hello World!"
    with connection.cursor() as cursor:
        cursor.execute(
            "INSERT INTO  User(email, password_hash, salt) VALUES (%s, %s, %s)",
            [email, hashed_password, salt]
        )
    return JsonResponse({'message': response})


def see_users(request): ##just a test function to see if the user is added to the database
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM User")
        row = cursor.fetchall()
        print(row)
    return JsonResponse({'message': 'Success'})

def hash_password(password): ##creating salt and password hash
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password.decode('utf-8'), salt.decode('utf-8')

def register_user(email, password): ##registering user, putting them into database
    hashed_password, salt = hash_password(password)
    with connection.cursor() as cursor:
        cursor.execute(
            "INSERT INTO  User(email, password_hash, salt) VALUES (%s, %s, %s)",
            [email, hashed_password, salt]
        )

def authenticate_user(email, password):
    with connection.cursor() as cursor:
        cursor.execute("SELECT password_hash, salt FROM User WHERE email=%s", [email])
        row = cursor.fetchone()
        print(row)
        if not row:
            return None
        hashed_password, salt = row
        if bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):
            cursor.execute("SELECT idUser, email FROM User WHERE email=%s", [email])
            row = cursor.fetchone()
            if not row:
                return None
            id, email = row
            generate_jwt(id)
            return True
        else:
            return None


@csrf_exempt
def send_back_auth(request):
    data = json.loads(request.body.decode('utf-8'))
    email = data.get('email')
    password = data.get('password')
    if(authenticate_user(email, password)):
        with connection.cursor() as cursor:
            cursor.execute("SELECT idUser, email FROM User WHERE email=%s", [email])
            row = cursor.fetchone()
            cursor.execute("SELECT token FROM Token WHERE user_id=%s", [row[0]])
            token = cursor.fetchone()
            somethingToReturn = token[0]
    else:
        somethingToReturn = "User not authenticated"
    return JsonResponse({'message': somethingToReturn})


@csrf_exempt
def fetchJobs(request):
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM Jobs")
        columns = [col[0] for col in cursor.description]
        job_list = [
            dict(zip(columns, row))
            for row in cursor.fetchall()
        ]
    return JsonResponse(job_list, safe=False)