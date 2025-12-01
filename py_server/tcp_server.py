import socket
import string
import sys
from main import LLMProxy

HOST = "0.0.0.0" 
PORT = 5000
BUFFER_SIZE = 16384

def get_llm_response(yt_video_titles1: string) -> string:
    client = LLMProxy()

    # It might be faster if somehow not regenerating the session every time, office hours
    response1 = client.generate(
        model = '4o-mini',
        system = 'I will give you a comma separated list of youtube titles. You will need to return a comma sepated list where the values for are 0 or 1, 1 for educational content, 0 for non-educational content. The values must respect the same order the titles were given in. Do not put brackets at the begining and end of the list.',
        query = yt_video_titles1,
        temperature=0.0,
        lastk=0,
        session_id='sesion1',
        rag_usage = False,
    )

    return response1['result']


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
    server_socket.bind((HOST, PORT))
    server_socket.listen()
    conn, addr = server_socket.accept()

    print(f"Server listening on {HOST}:{PORT}", file=sys.stderr)

    while True:
        print("Running", file=sys.stderr)
        
        print(f"Connected by {addr}", file=sys.stderr)
        
        buffer = ''
        while True:
            chunk = conn.recv(BUFFER_SIZE)
            
            if not chunk:  # Connection closed
                print("Client closed connection", file=sys.stderr)
                exit()
                
            buffer += chunk.decode('utf-8')
            
            
            if buffer[-5:] == "0\r\n\r\n":  # Complete message received
                break
            
        if not buffer:
            continue

        
        html_page = buffer[6:-5] # This is the html page we can parse using beautiful soup

        new_html_page = html_page # After filtering

        response = "270b\r\n" + new_html_page + "0\r\n\r\n"

        # print("Data sent back to the proxy", response, file=sys.stderr)
        
        # Ensure response is bytes
        if isinstance(response, str):
            response = response.encode()
        conn.sendall(response)

