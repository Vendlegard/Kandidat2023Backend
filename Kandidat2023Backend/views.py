from django.http import JsonResponse
from django.http import HttpResponse
from django.db import connections, connection
import json
import bcrypt
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
            "INSERT INTO Token (userID, token, expires_at) VALUES (%s, %s, %s)",
            [user_id, token, exp_time]
        )

    return print(token)


@csrf_exempt ## This is needed to allow POST requests from the frontend, otherwise it will return a 403 error
def create_user(request):
    data = json.loads(request.body.decode('utf-8'))
    email = data.get('email')
    password = data.get('password')
    first_name = data.get('firstName')
    last_name = data.get('lastName')
    university = data.get('university')
    education = data.get('education')
    print(f"Email: {email}, Password: {password}, First name: {first_name}, Last name: {last_name}, University: {university}, Education: {education}")
    hashed_password, salt = hash_password(password)
    print(f"Hashed password: {hashed_password}, Salt: {salt}")
    response = "Hello World!"
    with connection.cursor() as cursor:
        cursor.execute(
            "INSERT INTO  User(firstName, lastName, userEmail, passwordHash, education, university, salt) VALUES (%s, %s, %s, %s, %s, %s, %s)",
            [first_name, last_name, email, hashed_password, education, university, salt]
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

def register_user(email, password): ##registering user, putting them into database #Verkar som  denna inte används, men håll än så länge
    hashed_password, salt = hash_password(password)
    with connection.cursor() as cursor:
        cursor.execute(
            "INSERT INTO  User(userEmail, passwordHash, salt) VALUES (%s, %s, %s)",
            [email, hashed_password, salt]
        )


def authenticate_user(email, password):
    with connection.cursor() as cursor:
        cursor.execute("SELECT passwordHash, salt FROM User WHERE userEmail=%s", [email])
        row = cursor.fetchone()
        print(row)
        if not row:
            return None
        hashed_password, salt = row
        if bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):
            cursor.execute("SELECT userID, userEmail FROM User WHERE userEmail=%s", [email])
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
            cursor.execute("SELECT userID, userEmail, firstName, lastName, university, education FROM User WHERE userEmail=%s", [email])
            row = cursor.fetchone()
            cursor.execute("SELECT token FROM Token WHERE userID=%s", [row[0]])
            token = cursor.fetchone()
            somethingToReturn = token[0]
    else:
        somethingToReturn = "User not authenticated"
    return JsonResponse({'message_token': somethingToReturn, 'message_userInfo': 'Success'}) #jag la till success heter nåt annt på elins


def data_view(request):
    print("testar data_view")

def fetch_jobs(request):

    with connection.cursor() as cursor:
        cursor.execute("SELECT jobName, employerName "
                       "FROM Job LEFT OUTER JOIN Employer "
                       "ON Job.orgNR = Employer.orgNR;")
        rows = cursor.fetchall()
        for row in rows:
            print("första printen \n", row)

    rowslist = list(rows)
    #jsonStr = json.dumps(rowslist) ## den här fuckar upp och ger 126 lång lista, fattar inte varför
    #ser dock likadan ut så är skumt
    # print("andra printen \n", "här är jsonStr: ", jsonStr)
    #print("tredje printen \n", "vad är detta för typ: ", type(jsonStr))


    return JsonResponse({'message': rowslist}, safe=False)

@csrf_exempt
def write_comp_and_int(request):
    data = json.loads(request.body.decode('utf-8'))
    email = data.get('email')
    competencies = data.get('competencies')
    interests = data.get('interests')

    with connection.cursor() as cursor:
        cursor.execute("SELECT userID FROM User WHERE userEmail=%s", [email])
        userToSelect = cursor.fetchone()
        print(userToSelect)
        for interest in interests:
            print("interest we want to add", interest)
            cursor.execute("SELECT interestID FROM Interests WHERE interestName=%s", [interest])
            interestToAddID = cursor.fetchone()
            interestToAddVariable = interestToAddID[0]
            userToSelectVariable  = userToSelect[0]
            print(interestToAddID[0])
            cursor.execute(f"INSERT INTO UserInterests(userID, interestID) VALUES ({userToSelectVariable}, {interestToAddVariable})"
                           )
        for competence in competencies:
            cursor.execute("SELECT compID FROM Competence WHERE compName=%s", [competence])
            compToAddID = cursor.fetchone()
            compToAddVariable = compToAddID[0]
            userToSelectVariable = userToSelect[0]
            cursor.execute(
                f"INSERT INTO UserCompetence(userID, compID) VALUES ({userToSelectVariable}, {compToAddVariable})"
            )






    return JsonResponse({'message': data}, safe=False)