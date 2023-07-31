import pyrebase
config={
    "apiKey": "AIzaSyAjiSpbW-qxxSTWWbk_AS10wvj-7O7PzvY",
    "authDomain": "meshhawk-b897d.firebaseapp.com",
    "projectId": "meshhawk-b897d",
    "storageBucket": "meshhawk-b897d.appspot.com",
    "messagingSenderId": "1097191319781",
    "appId": "1:1097191319781:web:a4734e2e02eea9a73b4c0c",
    "measurementId": "G-TQZTZHTR79",
    "databaseURL":""
}

firebase = pyrebase.initialize_app(config)
auth=firebase.auth()

email='sanskardwivedi003@gmail.com'
password='string'

# user=auth.create_user_with_email_and_password(email,password)
# print(user)

usersignin=auth.sign_in_with_email_and_password(email,password)
# print(usersignin)
info=auth.get_account_info(usersignin['idToken'])
print(info['users'][0]['email'])