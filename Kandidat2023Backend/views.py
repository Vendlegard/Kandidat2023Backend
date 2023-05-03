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
    exp_time = datetime.utcnow() + timedelta(hours=300)

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
            userDataJson = {
                'userID': row[0],
                'userEmail': row[1],
                'firstName': row[2],
                'lastName': row[3],
                'university': row[4],
                'education': row[5]
            }
            cursor.execute("SELECT token FROM Token WHERE userID=%s", [row[0]])
            token = cursor.fetchone()
            somethingToReturn = token[0]
    else:
        somethingToReturn = "User not authenticated"
    return JsonResponse({'token': somethingToReturn, 'userInfo': userDataJson}) #jag la till success heter nåt annt på elins

@csrf_exempt
def auth_with_token(request):
    data = json.loads(request.body.decode('utf-8'))
    token = data.get('token')
    with connection.cursor() as cursor: ##kollar inte om den är expired men sak samma detta fixar vi.
        cursor.execute("SELECT userID FROM Token WHERE token=%s", [token])
        row = cursor.fetchone()
        if not row:
            return None
        userID = row[0]
        cursor.execute("SELECT userID, userEmail, firstName, lastName, university, education FROM User WHERE userID=%s", [userID])
        row = cursor.fetchone()

        userDataJson = {
            'userID': row[0],
            'userEmail': row[1],
            'firstName': row[2],
            'lastName': row[3],
            'university': row[4],
            'education': row[5]
        }
        return JsonResponse({'userInfo': userDataJson})


def data_view(request):
    print("testar data_view")


@csrf_exempt
def fetch_jobs(request):
    data = json.loads(request.body.decode('utf-8'))
    user_id = data.get('id')
    print(user_id, "we got from fetch_jobs")

    with connection.cursor() as cursor:
        cursor.execute(f"SELECT Job.jobID, Job.jobName, Job.location,Job.jobType, Job.jobDescription ,Employer.employerImage "
                       f"FROM Job CROSS JOIN Employer ON Employer.orgNR=Job.orgNR "
                       f"WHERE jobID NOT IN (SELECT jobID FROM UserLikesJob WHERE userID = {user_id} UNION SELECT jobID FROM UserNotLikeJob WHERE userID = {user_id})")


        columns = [col[0] for col in cursor.description]
        liked_jobs = [
            dict(zip(columns, row))
            for row in cursor.fetchall()
        ]

    return JsonResponse({'jobs': liked_jobs})



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
@csrf_exempt
def get_comp(request):
    data = json.loads(request.body.decode('utf-8'))
    user_id = data.get('id')
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT Competence.compName "
                       f"FROM Competence WHERE compID IN "
                       f"(SELECT compID FROM UserCompetence WHERE userID = {user_id})")
        user_comp = [row[0] for row in cursor.fetchall()]

        print(user_comp)

    return JsonResponse({'comp_list': user_comp})

@csrf_exempt
def get_interest(request):
    data = json.loads(request.body.decode('utf-8'))
    user_id = data.get('id')
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT Interests.interestName "
                       f"FROM Interests WHERE interestID IN "
                       f"(SELECT interestID FROM UserInterests WHERE userID = {user_id})")
        user_interest = [row[0] for row in cursor.fetchall()]

        print(user_interest)

    return JsonResponse({'interest_list': user_interest})


@csrf_exempt
def fetch_all_comp(request):

    with connection.cursor() as cursor:
        cursor.execute("SELECT compName FROM Competence")
        all_comp = [row[0] for row in cursor.fetchall()]

    return JsonResponse({'all_comp': all_comp})

@csrf_exempt
def fetch_all_interests(request):

    with connection.cursor() as cursor:
        cursor.execute("SELECT interestName FROM Interests")
        all_interests = [row[0] for row in cursor.fetchall()]

    return JsonResponse({'all_interests': all_interests})

@csrf_exempt
def liked_job(request):
    data = json.loads(request.body.decode('utf-8'))
    userID = data.get('id')
    likes = data.get('liked')
    response = "job was liked"

    try:
        with connection.cursor() as cursor:
            cursor.execute("INSERT INTO UserLikesJob(userID, jobID) VALUES (%s, %s)", [userID, likes])
    except:
        response = "job was already liked"

    try:
        with connection.cursor() as cursor:
            cursor.execute("DELETE FROM UserNotLikeJob WHERE userID=%s AND jobID=%s", [userID, likes])
            print("deleted from disliked jobs")
    except Exception as e:
        print(e)
        response = "something went wrong"



    return JsonResponse({'message': response}, safe=False)


@csrf_exempt
def disliked_job(request):
    data = json.loads(request.body.decode('utf-8'))
    userID = data.get('id')
    dislikes = data.get('disliked')
    response = "job was liked"

    try:
        with connection.cursor() as cursor:
            cursor.execute("INSERT INTO UserNotLikeJob(userID, jobID) VALUES (%s, %s)", [userID, dislikes])
    except:
        response = "job was already disliked"

    try:
        with connection.cursor() as cursor:
            cursor.execute("DELETE FROM UserLikesJob WHERE userID=%s AND jobID=%s", [userID, dislikes])
            print("deleted from liked jobs")
    except Exception as e:
        print(e)
        response = "something went wrong"

    return JsonResponse({'message': response}, safe=False)

@csrf_exempt
def fetch_liked_jobs(request):

    data = json.loads(request.body.decode('utf-8'))
    user_id = data.get('id')

    liked_jobs = []

    try:
        with connection.cursor() as cursor:

            cursor.execute(f"SELECT Job.jobID, Job.jobName, Job.location,Job.jobType, Job.jobDescription ,Employer.employerImage "
                           "FROM Job CROSS JOIN Employer ON Employer.orgNR=Job.orgNR "
                           "WHERE jobID IN (SELECT jobID FROM UserLikesJob "
                           "WHERE userID = %s)", [user_id])
            columns = [col[0] for col in cursor.description]
            liked_jobs = [
                dict(zip(columns, row))
                for row in cursor.fetchall()
            ]
    except:
        response = "something went wrong fetching the jobs"
        print(response)
    return JsonResponse({'liked_jobs': liked_jobs}, safe=False)


@csrf_exempt
def fetch_disliked_jobs(request):
    data = json.loads(request.body.decode('utf-8'))
    user_id = data.get('id')


    print("fetch disliked jobs")


    try:
        with connection.cursor() as cursor:

            cursor.execute(f"SELECT Job.jobID, Job.jobName, Job.location,Job.jobType, Job.jobDescription ,Employer.employerImage "
                           "FROM Job CROSS JOIN Employer ON Employer.orgNR=Job.orgNR "
                           "WHERE jobID IN (SELECT jobID FROM UserNotLikeJob "
                           "WHERE userID = %s)", [user_id])
            columns = [col[0] for col in cursor.description]
            disliked_jobs = [
                dict(zip(columns, row))
                for row in cursor.fetchall()
            ]
            return JsonResponse({'disliked_jobs': disliked_jobs}, safe=False)
    except:
        response = "something went wrong fetching the jobs"
        return JsonResponse({'message': response}, safe=False)

