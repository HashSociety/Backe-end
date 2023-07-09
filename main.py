import os
import networkx as nx
import matplotlib.pyplot as plt
from fastapi import FastAPI, UploadFile, File ,Request , HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from tempfile import NamedTemporaryFile
from scapy.all import *
from scapy.all import Dot11
from models import *  
import pyrebase


app = FastAPI()

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
    except client.exceptions.NotAuthorizedException:
        raise Exception("Invalid credentials")
    except client.exceptions.UserNotFoundException:
        raise Exception("User not found")
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

@app.post("/generate_graph")
def generate_graph(pcapng_file: UploadFile = File(...)):
    def check_mesh_network(pcapng_file):
        packets = rdpcap(pcapng_file)
        mac = []
        for packet in packets:
            if packet.haslayer(Dot11):
                if packet.addr3 == 'ec:a2:a0:69:b1:f9' or packet.addr3 == 'ea:65:32:28:67:0a':
                    pass
                else:
                    rrc_mac = packet.addr2  # receiver
                    src_mac = packet.addr3  # source
                    dst_mac = packet.addr1  # dest
                    mac.append([src_mac, rrc_mac, dst_mac])
        return mac

    def create_mac_graph(mac_addresses):
        graph = nx.Graph()
        for src_mac, rrc_mac, dst_mac in mac_addresses:
            graph.add_edge(src_mac, rrc_mac, color='red')  # Assign color to the edge
            graph.add_edge(rrc_mac, dst_mac, color='blue')  # Assign color to the edge
        return graph

    # Save the uploaded file temporarily
    with NamedTemporaryFile(delete=False) as tmp:
        pcapng_file_path = tmp.name
        pcapng_file.seek(0)
        tmp.write(pcapng_file.file.read())

    mac_addresses_list = check_mesh_network(pcapng_file_path)
    graph = create_mac_graph(mac_addresses_list)

    # Draw the graph with edge colors and prevent layer overlap
    edge_colors = nx.get_edge_attributes(graph, 'color').values()
    pos = nx.spring_layout(graph)
    nx.draw(graph, pos, with_labels=True, edge_color=list(edge_colors))
    
    # Save the graph as an image
    graph_image_path = "graph.png"
    plt.savefig(graph_image_path)

    # Remove the temporary pcapng file
    os.remove(pcapng_file_path)

    return {"message": "Graph generated successfully!", "graph_image_path": graph_image_path}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)





@app.get("/")
async def index(request: Request):
    
    return {"message": "Hello"}

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