import networkx as nx
import matplotlib.pyplot as plt
from fastapi import FastAPI, UploadFile, File ,Request, HTTPException, Depends,status
from fastapi.responses import JSONResponse , FileResponse
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
import subprocess
from fastapi import FastAPI, Query, BackgroundTasks
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

# def is_multicast_mac(mac_address):
#     # Check if the MAC address is in the multicast range (01:00:5e:XX:XX or 33:33:XX:XX)
#     return mac_address.startswith("01:00:5e") or mac_address.startswith("33:33:")
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
    try:
        info=auth.get_account_info(token)
        #print(info['users'][0]['email'])
        email=info['users'][0]['email']
        return {"userid": email} 
    except Exception as e:
        raise HTTPException(status_code=400,detail=str(e))
def is_multicast_mac(mac_address):
    # Check if the MAC address is in the multicast range (01:00:5e:XX:XX or 33:33:XX:XX)
    return mac_address.startswith("01:00:5e") or mac_address.startswith("33:33:") or mac_address.startswith("00:")
def extract_addresses(pcapng_file):
    capture = pyshark.FileCapture(pcapng_file)
    ls = list()
    ls_qos=list()
    qos_set = set()
    idx = 0
    seen_sublists = set()

    for packet in capture:
        idx+=1
        if 'wlan' in packet:
            wlan_layer = packet.wlan
            
            wlan_type = wlan_layer.fc_type
            if hasattr(wlan_layer, 'sa') and hasattr(wlan_layer, 'da') and hasattr(wlan_layer, 'ta') and hasattr(wlan_layer, 'ra') :       
                source_address = packet.wlan.sa
                destination_address = packet.wlan.da
                receiver_address = packet.wlan.ra
                transmitter_address = packet.wlan.ta
                if source_address == "ff:ff:ff:ff:ff:ff" or destination_address == "ff:ff:ff:ff:ff:ff" or \
                                    receiver_address == "ff:ff:ff:ff:ff:ff" or transmitter_address == "ff:ff:ff:ff:ff:ff" or \
                                    is_multicast_mac(source_address) or is_multicast_mac(destination_address) or \
                                    is_multicast_mac(receiver_address) or is_multicast_mac(transmitter_address):
                                        continue
                if wlan_type == "2":
                    source_address_qos= packet.wlan.sa
                    destination_address_qos = packet.wlan.da
                    # receiver_address_qos = packet.wlan.ra
                    # transmitter_address_qos = packet.wlan.ta
                    sublist_tuple = tuple([source_address_qos,destination_address_qos])
                    if sublist_tuple not in seen_sublists:
                        seen_sublists.add(sublist_tuple)
                        ls_qos.append([source_address_qos,destination_address_qos])
                     
                        bss_id = wlan_layer.bssid
                        bssids.append(bss_id)
                # ls.append([source_address, receiver_address, transmitter_address, destination_address])
                
    capture.close()
    return (ls_qos)
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

    components=make_components(graph,addresses)
    no_of_disconnected_graphs=count_disconnected_graphs(graph)
    # access_point=find_mac_with_highest_degree(graph)
    return {"addresses": addresses, "compenents":components,"no_of_disconnected_graphs":no_of_disconnected_graphs}

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










# @app.post("/run_script/")
# async def run_script(duration: int = Query(..., gt=0)):
    # Validate the duration parameter
    if duration <= 0:
        return JSONResponse(content={"error": "Duration must be greater than 0."}, status_code=400)

    # Function to execute the script
    def execute_script():
        script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "finalscan.sh")
        process = Popen(["bash", script_path, str(duration)], stdout=PIPE, stderr=PIPE)
        return_code = process.wait()  # Wait for the process to complete
        return return_code

    # Execute the script and return a minimal response
    return_code = execute_script()

    if return_code == 0:
        return {"status": "success"}
    else:
        return {"status": "failed", "return_code": return_code}
# This modification uses asyncio.create_subprocess_exec() to create an asynchronous subprocess. The await process.communicate() function is used to read the output from the subprocess asynchronously. This way, the API won't hang while waiting for the subprocess to complete.



def execute_script(duration: int):
    script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fullfinal/first.sh")
    try:
        subprocess.Popen(["gnome-terminal", "--", "bash", "-c", f"{script_path} {duration}",'bash'])
    except subprocess.CalledProcessError:
        raise HTTPException(status_code=500, detail="Error executing the script")

@app.post("/run_script/")
async def run_script(background_tasks: BackgroundTasks, duration: int):
    # Validate the duration parameter
    if duration <= 0:
        raise HTTPException(status_code=400, detail="Duration must be greater than 0.")

    # Execute the script in the background
    background_tasks.add_task(execute_script, duration)

    return {"status": "Script execution initiated."}

@app.get("/get_file_csv")
async def get_csv_file():
    # Validate the duration parameter
    # Assuming your CSV and PCAP files are generated in the 'output' folder
    csv_file = os.path.join("fullfinal/output", "capture.csv")
  
    print(1)

        # Check if the files exist
    if os.path.isfile(csv_file) :
            # Return the CSV and PCAP files as downloadable responses
            print(2)
            return FileResponse(csv_file, media_type="text/csv", filename="capture.csv")
                
            
    else:
        return {"status": "success",  "error": "Files not found."}
    
@app.get("/get_file_pcap")
async def get_pcap_file():
    # Validate the duration parameter
    # Assuming your CSV and PCAP files are generated in the 'output' folder
    
    pcap_file = os.path.join("fullfinal/output", "capture")
    print(1)

        # Check if the files exist
    if os.path.isfile(pcap_file):
            # Return the CSV and PCAP files as downloadable responses
            print(2)
            return FileResponse(pcap_file, media_type="application/vnd.tcpdump.pcap", filename="capture.pcapng")
                
            
    else:
        return {"status": "success",  "error": "Files not found."}

def execute_attack(bssid:str,channel: int):
    script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fullfinal/second.sh")
    print(script_path)
    print(type(script_path))
    try:
        subprocess.Popen(["gnome-terminal", "--", "bash", "-c", f"cd fullfinal/ && {script_path} {bssid} {channel}"])
    except subprocess.CalledProcessError:
        raise HTTPException(status_code=500, detail="Error executing the script")

@app.post("/attack")
async def get_attack(background_tasks: BackgroundTasks,bssid:str,channel:int):
    if bssid == None and channel== None:
        raise HTTPException(status_code=400, detail="Value can't be None")
    # Execute the script in the background
    background_tasks.add_task(execute_attack, bssid , channel )

    return {"status": "Script execution initiated."}


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