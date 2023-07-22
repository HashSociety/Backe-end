import networkx as nx
import matplotlib.pyplot as plt
from fastapi import FastAPI, UploadFile, File ,Request, HTTPException, Depends,status
from fastapi.responses import JSONResponse
from tempfile import NamedTemporaryFile
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
import pyshark
from models import *  
import pyrebase
import asyncio
from srcdest import *

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def index(request: Request):
    
    return {"message": "Hello"}
config = {
    "apiKey":"AIzaSyAkuhoVUDIMQwy6QEa-yzqUyFsBEUzPhL8",
    "authDomain":"meshhawk-c168a.firebaseapp.com",
    "projectId":"meshhawk-c168a",
    "storageBucket": "meshhawk-c168a.appspot.com",
    "messagingSenderId": "647266716782",
    "appId": "1:647266716782:web:8671d1a85cda7aedcd2a7f",
    "measurementId": "G-E5BY1Q33NL",
    "databaseURL": ""
}
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")
firebase = pyrebase.initialize_app(config)
auth = firebase.auth()

@app.post("/signup")
def signup(request: SignupRequest):
    try:
        user = auth.create_user_with_email_and_password(request.email, request.password)
        return {"message": "Signup successful", "user": f"{user['email']}"}
    except Exception as e:
        raise HTTPException(status_code=400, detail="Signup failed")

def authenticate_user(username: str, password: str):
    try:
        response=auth.sign_in_with_email_and_password(username,password)

        access_token = response['idToken']
        
        return {"access_token": access_token, "token_type": "bearer"}
    # except client.exceptions.NotAuthorizedException:
    #     raise Exception("Invalid credentials")
    # except client.exceptions.UserNotFoundException:
    #     raise Exception("User not found")
    except Exception as e:
        raise Exception(str(e))


@app.post("/login", response_model=Token,tags=['Auth'])
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    return authenticate_user(form_data.username, form_data.password)

@app.get("/get_userid",tags=['Auth'])
async def get_userid(token : str= Depends(oauth2_scheme)):
    info=auth.get_account_info(token)
    #print(info['users'][0]['email'])
    email=info['users'][0]['email']
    return {"userid": email} 

def extract_addresses(pcapng_file):
    capture = pyshark.FileCapture(pcapng_file)
    ls = []
    for packet in capture:
        source_address = packet.wlan.sa
        destination_address = packet.wlan.da
        receiver_address = packet.wlan.ra
        transmitter_address = packet.wlan.ta
        ls.append([source_address, receiver_address, transmitter_address, destination_address])
    capture.close()
    return ls

async def async_extract_addresses(pcapng_file):
    loop = asyncio.get_event_loop()
    addresses = await loop.run_in_executor(None, extract_addresses, pcapng_file)
    return addresses

@app.post("/upload")
async def upload_pcap(pcapng_file: UploadFile = UploadFile(...)):
    with NamedTemporaryFile(delete=False) as tmp:
        pcapng_file_path = tmp.name
        pcapng_file.seek(0)
        tmp.write(pcapng_file.file.read())

    addresses = await async_extract_addresses(pcapng_file_path)
    graph=create_graph(addresses)

    components=make_components(graph)



    return {"addresses": addresses, "compenents":components}






@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content={"message": exc.detail},
    )

@app.exception_handler(Exception)
async def generic_exception_handler(request, exc):
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"message": "Internal Server Error"},
    )