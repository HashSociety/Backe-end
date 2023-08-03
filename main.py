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
import pandas as pd
import io
from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse
from subprocess import Popen, PIPE
import os

# from secondsec import *
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

@app.post("/upload/pcap")
async def upload_pcap(pcapng_file: UploadFile = UploadFile(...)):
    with NamedTemporaryFile(delete=False) as tmp:
        pcapng_file_path = tmp.name
        pcapng_file.seek(0)
        tmp.write(pcapng_file.file.read())

    addresses = await async_extract_addresses(pcapng_file_path)
    graph=create_graph(addresses)

    components=make_components(graph)
    no_of_disconnected_graphs=count_disconnected_graphs(graph)
    access_point=find_mac_with_highest_degree(graph)




    return {"addresses": addresses, "compenents":components,"no_of_disconnected_graphs":no_of_disconnected_graphs,'access_point':access_point}

def load_first_section_of_csv(content):
    # Find the index of the blank row that separates the two sections of headers
    blank_row_index = content.find(b'\n\n')

    # Separate the content into the first section
    first_section = content[:blank_row_index]

    # Load the first section using pandas
    df = pd.read_csv(io.BytesIO(first_section), skipinitialspace=True)  # Use skipinitialspace to remove whitespace from keys

    return df

def load_second_section_of_csv(content):
    # Find the index of the blank row that separates the two sections of headers
    blank_row_index = content.find(b'\n\n')

    # Separate the content into the second section
    second_section = content[blank_row_index + 2:]  # +2 to skip the blank row

    # Load the second section using pandas
    df = pd.read_csv(io.BytesIO(second_section), skipinitialspace=True)  # Use skipinitialspace to remove whitespace from keys

    return df

@app.post("/upload/csv")
async def upload_and_analyze(file: UploadFile = File(...)):
    try:
        # Check if the uploaded file is a CSV
        if file.filename.endswith(".csv"):
            # Read the CSV file content
            content = await file.read()

            # Load both sections using the custom functions
            first_section_df = load_first_section_of_csv(content)
            second_section_df = load_second_section_of_csv(content)

            # Perform analysis (for demonstration, we'll just return the first few rows)
            first_section_analysis = first_section_df.to_dict(orient="records")
            second_section_analysis = second_section_df.to_dict(orient="records")

            # Convert floating-point values to strings to ensure JSON compliance
            first_section_analysis = [{str(k): str(v).strip() for k, v in row.items()} for row in first_section_analysis]
            second_section_analysis = [{str(k): str(v).strip() for k, v in row.items()} for row in second_section_analysis]

            # Combine the analysis results into a single dictionary
            analysis_result = {
                "first_section": first_section_analysis,
                "second_section": second_section_analysis
            }

            return JSONResponse(content=analysis_result)

        else:
            raise HTTPException(status_code=400, detail="Uploaded file must be a CSV")

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))








from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse, FileResponse
from subprocess import Popen, PIPE
import os



@app.post("/run_script/")
async def run_script(duration: int = Query(..., gt=0)):
    # Validate the duration parameter
    if duration <= 0:
        return JSONResponse(content={"error": "Duration must be greater than 0."}, status_code=400)

    # Function to execute the script
    def execute_script():
        script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "finalscan.sh")
        process = Popen(["bash", script_path, str(duration)], stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()
        return_code = process.returncode
        return stdout, stderr, return_code  # Return bytes instead of decoded strings

    # Execute the script and return the output
    stdout, stderr, return_code = execute_script()
    print("Script")

    if return_code == 0:
        # Assuming your CSV and PCAP files are generated in the 'output' folder
        csv_file = os.path.join("output", "capture.pcapng-01.csv")
        pcap_file = os.path.join("output", "capture.pcapng")
        print(1)

        # Check if the files exist
        if os.path.isfile(csv_file) and os.path.isfile(pcap_file):
            # Return the CSV and PCAP files as downloadable responses
            print(2)
            return {
                "status": "success",
                "stdout": stdout,  # Returning bytes
                "stderr": stderr,  # Returning bytes
                "csv_file": FileResponse(csv_file, media_type="text/csv", filename="capture.csv"),
                "pcap_file": FileResponse(pcap_file, media_type="application/vnd.tcpdump.pcap", filename="capture.pcap"),
            }
        else:
            return {"status": "success", "stdout": stdout, "stderr": stderr, "error": "Files not found."}
    else:
        return {"status": "failed", "stdout": stdout, "stderr": stderr, "return_code": return_code}


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