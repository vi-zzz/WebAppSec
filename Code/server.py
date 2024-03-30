import sys , re , ssl , socket , threading
import parser as p                      #from parser.py
import magic
from datetime import datetime
import os
import pytz
import traceback
import mimetypes


# Returns the current UTC time in a specific string format.
def current_time():
    current_utc = datetime.utcnow()
    return current_utc.strftime('%a, %d %b %Y %H:%M:%S GMT')
# Reads and returns the entire content of a given file.
def loadFileText(file_path):
    with open(file_path, 'r') as file:
        file_contents = file.read()
    return file_contents

def fetchContentType(file_name):
    mime_type, _ = mimetypes.guess_type(file_name)
    return mime_type if mime_type else 'application/octet-stream'
# Returns the current local time in a specific string format for logging.
def log_time():
    return datetime.now().strftime("%Y/%m/%d %H-%M-%S")

def log(req_ip, valid_req):
    time = log_time()
    log_entry = f"Time: {time} | IP: {req_ip.strip()} | Valid: {valid_req}\n"
    file = open("logfile.txt", "a")
    file.write(log_entry)
    file.close()

# Constructs and returns a 411 Length Required HTTP response.
def resp_411(httpv):
    body_elements = ["<!DOCTYPE html>","<html>","<head>","<title>Error 411 </title>","</head>","<body>","<h1>Error 411 - Length Required</h1>","<p>Request should have content length</p>","<p>Check for correct parameter.</p>","</body>","</html>"]
    body = "\n".join(body_elements)
    
    resp = f"{httpv} 411 Length Required \r\n"
    resp += "Content-Type: text/html\r\n"
    resp += f"Content-Length: {len(body)}\r\n\r\n"
    resp += f"{body}\r\n"

    return resp

# Constructs and returns a 400 Bad Request HTTP response.
def resp_400(httpv):
    body_elements = ["<!DOCTYPE html>","<html>","<head>","<title>Error 400 - Bad Request</title>","</head>","<body>","<h1>Error 400 - Bad Request</h1>","<p>Either invalid parameters or malformed request</p>","<p>Check Parameters</p>","</body>","</html>"]
    body = "\n".join(body_elements)
    
    resp = f"{httpv} 400 Bad Request \r\n"
    resp += "Content-Type: text/html\r\n"
    resp += f"Content-Length: {len(body)}\r\n\r\n"
    resp += f"{body}\r\n"

    return resp

# Constructs and returns a 501 Not Implemented HTTP response.
def resp_501(httpv):
    body_elements = ["<!DOCTYPE html>", "<html>","<head>","<title>Error 501 - Not Implemented</title>","</head>","<body>","<h1>Error 501 - Not Implemented</h1>","<p>Request method not supported</p>","<p>These are supported: <code>GET, POST, PUT, DELETE,HEAD</code>.</p>","</body>","</html>"]
    body = "\n".join(body_elements)
    
    resp = f"{httpv} 501 Not Implemented \r\n"
    resp += "Content-Type: text/html\r\n"
    resp += f"Content-Length: {len(body)}\r\n\r\n"
    resp += f"{body}\r\n"

    return resp
# Constructs and returns a 505 HTTP Version Not Supported response.

def resp_505(httpv):
    body_elements = ["<!DOCTYPE html>","<html>","<head>","<title>Error 505 </title>","</head>","<body>","<h1>Error 505 - HTTP Version Not Supported</h1>","<p>This server does not support this http version</p>","<p>It supports either HTTP 1.0 or 1.1.</p>","</body>","</html>"]
    body = "\n".join(body_elements)
    
    resp = f"{httpv} 505 HTTP Version Not Supported  \r\n"
    resp += "Content-Type: text/html\r\n"
    resp += f"Content-Length: {len(body)}\r\n\r\n"
    resp += f"{body}\r\n"

    return resp

# Constructs and returns a 500 Internal Server Error response.

def resp_500(httpv):
    body_elements = ["<!DOCTYPE html>","<html>","<head>","<title>Error 500</title>","</head>","<body>","<h1>Error 500: Internal Server Error</h1>","<p>Error occured on server while processing this request</p>","</body>","</html>"]
    body = "\n".join(body_elements)
    
    resp = f"{httpv} 500 Internal Server Error  \r\n"
    resp += "Content-Type: text/html\r\n"
    resp += f"Content-Length: {len(body)}\r\n\r\n"
    resp += f"{body}\r\n"

    return resp

# Handles GET requests, returning the appropriate HTTP response.

def get(resourceIdentifier, httpv):
    path = directory_root + resourceIdentifier

    try:
        # Establish the body_content and content_type by analyzing the resourceIdentifier.
        if resourceIdentifier == "/":
            body_content = loadFileText(directory_root + "/index.html")
            content_type = fetchContentType(directory_root + "/index.html")
        elif ".php" in resourceIdentifier:
            body_content, content_type = handle_php_request(resourceIdentifier)
        else:
            body_content = loadFileText(path)
            content_type = fetchContentType(path)

        # Construct and return the HTTP response
        resp = construct_http_response(httpv, "200 OK", content_type, body_content)
        return resp
    except PermissionError:
        # 403 Forbidden response
        body_elements = ["<!DOCTYPE html>", "<html>", "<head>","<title>Error 403: Forbidden</title>", "</head>", "<body>","<h1>Error 403: Forbidden</h1>","<p>The server understands your request but refuses to authorize it.</p>","<p>Please make sure you have the permissions to access this resource.</p>","</body>", "</html>"]
        body_content = "\n".join(body_elements)
        resp = construct_http_response(httpv, "403 Forbidden", "text/html", body_content)
        return resp

    except FileNotFoundError:
        # 404 notfound
        body_elements = ["<!DOCTYPE html>", "<html>", "<head>","<title>Error 404: Not Found</title>", "</head>", "<body>","<h1>Error 404: Not Found</h1>","<p>The server cannot find the requested resource.</p>","</body>", "</html>"]
        body_content = "\n".join(body_elements)
        resp = construct_http_response(httpv, "404 Not Found", "text/html", body_content)
        return resp



def construct_http_response(http_version, status, content_type, body):
    resp = f"{http_version} {status}\r\n"
    resp += f"Content-Type: {content_type}\r\n"
    resp += f"Content-Length: {len(body)}\r\n\r\n"
    resp += body + "\r\n"
    return resp


def handle_php_request(resourceIdentifier):
    # file path extraction
    path, query = resourceIdentifier.split('?', 1)
    path = directory_root + path
    club_name, country_name = [param.split('=')[1] for param in query.split('&')]

    command = f"php-cgi {path} club_name={club_name} country_name={country_name}"
    print(command)
    body_php = os.popen(command).read().replace("\n", "\r\n")
    body_resp = "".join(body_php.split("\r\n\r\n")[1:])

    # HTML body construction
    body_elements = ["<!DOCTYPE html>", "<html>", "<head>","<title>Hello!</title>", "</head>", "<body>",body_resp,"</body>", "</html>"]
    return "\n".join(body_elements), "text/html"



def post(resourceIdentifier , body , httpv):
     
    try:
        if ".php" in resourceIdentifier:
            script_filename = directory_root+resourceIdentifier
            body_php = body.strip()
            content_length = len(body)
            command = (
    f"export REDIRECT_STATUS=true; "
    f"export GATEWAY_INTERFACE=\"CGI/1.1\"; "
    f"export SCRIPT_FILENAME=\"{script_filename}\"; "
    f"export REQUEST_METHOD=\"POST\"; "
    f"export SERVER_PROTOCOL=\"HTTP/1.1\"; "
    f"export REMOTE_HOST=\"127.0.0.1\"; "
    f"export CONTENT_LENGTH=\"{content_length}\"; "
    f"export BODY=\"{body_php}\"; "
    f"export CONTENT_TYPE=\"application/x-www-form-urlencoded\"; "
    f"exec echo \"$BODY\" | php-cgi")


            body_resp = "".join(os.popen(command).read().split("\n\n")[1:])

            body = ["<!DOCTYPE html>\n","<html>\n","<head>\n","<title> Howdy! </title>\n","</head>\n","<body>\n",body_resp,"</body>\n","</html>\n"]
            body_content = "".join(body)

            cons_response = httpv + " 200 OK  \r\n"
            cons_response += "Content-Location: " + resourceIdentifier + " \r\n"
            cons_response += "Content-Length: " + str(len(body_content)) + "\r\n"
            cons_response += "Content-Type: text/html\r\n\r\n"
            cons_response += body_content + "\r\n" 



        else:
            path = directory_root + resourceIdentifier
            f = open(path, 'a')
            f.write(body)
            f.close()


            body_elements = ["<!DOCTYPE html>\n","<html>\n","<head>\n","<title>Some content Posted </title>\n","</head>\n","<body>\n","<h1>200 OK </h1>\n",f"<p>{resourceIdentifier} has been updated </p>\n","</body>\n","</html>\n"]
            body = ''.join(body_elements)



            cons_response = httpv + " 200 OK  \r\n"
            cons_response += "Content-Location: " + resourceIdentifier + " \r\n\r\n"
            cons_response += "Content-Length: " + str(len(body)) + "\r\n\r\n"
            cons_response += body + "\r\n"          

        return cons_response 

 
    except PermissionError:
        # craft error response for 403 Forbidden
        body_elements = ["<!DOCTYPE html>", "<html>", "<head>","<title>Error 403: Forbidden</title>", "</head>", "<body>","<h1>Error 403: Forbidden</h1>","<p>The server understands your request but refuses to authorize it.</p>","<p>Please make sure you have the permissions to access this resource.</p>","</body>", "</html>"]
        body_content = "\n".join(body_elements)
        cons_response = construct_http_response(httpv, "403 Forbidden", "text/html", body_content)
        return cons_response

    except FileNotFoundError:
        # craft error response for 404 Not Found
        body_elements = ["<!DOCTYPE html>", "<html>", "<head>","<title>Error 404: Not Found</title>", "</head>", "<body>","<h1>Error 404: Not Found</h1>","<p>The server cannot find the requested resource.</p>","</body>", "</html>"]
        body_content = "\n".join(body_elements)
        cons_response = construct_http_response(httpv, "404 Not Found", "text/html", body_content)
        return cons_response


#------------------------------------PUT--------------------------------
def put(resourceIdentifier, body, httpv):
    try:
        # Writing to the file
        path = directory_root + resourceIdentifier
        with open(path, 'w') as f:
            f.write(body)

        # Constructing the HTML response body
        body_elements = ["<!DOCTYPE html>\n","<html>\n","<head>\n","<title>File Created</title>\n","</head>\n","<body>\n","<h1>201 Created: The file has been created!</h1>\n",f"<p>{resourceIdentifier} has been created!</p>\n","</body>\n","</html>\n"
        ]
        body_content = "".join(body_elements)

        # Constructing the HTTP response
        resp_elements = [
            f"{httpv} 201 Created\r\n",
            f"Content-Location: {resourceIdentifier}\r\n",
            f"Content-Length: {str(len(body_content))}\r\n\r\n",
            body_content,
            "\r\n"
        ]
        resp = "".join(resp_elements)

        return resp


    except PermissionError:
        # craft error response for 403 Forbidden
        body_elements = ["<!DOCTYPE html>", "<html>", "<head>","<title>Error 403: Forbidden</title>", "</head>", "<body>","<h1>Error 403: Forbidden</h1>","<p>The server understands your request but refuses to authorize it.</p>","<p>Please make sure you have the permissions to access this resource.</p>","</body>", "</html>"]
        body_content = "\n".join(body_elements)
        resp = construct_http_response(httpv, "403 Forbidden", "text/html", body_content)
        return resp

    except FileNotFoundError:
        # craft error response for 404 Not Found
        body_elements = ["<!DOCTYPE html>", "<html>", "<head>","<title>Error 404: Not Found</title>", "</head>", "<body>","<h1>Error 404: Not Found</h1>","<p>The server cannot find the requested resource.</p>","</body>", "</html>"]
        body_content = "\n".join(body_elements)
        resp = construct_http_response(httpv, "404 Not Found", "text/html", body_content)
        return resp
#------------------------------------DELETE--------------------------------

def delete(resourceIdentifier , httpv):
    try:
        if resourceIdentifier == "/":
            resourceIdentifier = "index.html"
        path = directory_root + resourceIdentifier
        os.remove(path)

        body_elements = ["<!DOCTYPE html>\n","<html>\n","<head>\n","<title>File Deleted </title>\n","</head>\n","<body>\n","<h1>200 OK: File Deleted </h1>\n","<p>" + resourceIdentifier + " has beed deleted </p>\n","</body>\n","</html>\n"]
        
        body = ''.join(body_elements)

        resp = httpv + " 200 OK  \r\n"
        resp+= "Date: " + current_time() + "\r\n\r\n"
        resp += body + "\r\n"          

        return resp 
    
    except PermissionError:
        # craft error response for 403 Forbidden
        body_elements = ["<!DOCTYPE html>", "<html>", "<head>","<title>Error 403: Forbidden</title>", "</head>", "<body>","<h1>Error 403: Forbidden</h1>","<p>The server understands your request but refuses to authorize it.</p>","<p>Please make sure you have the permissions to access this resource.</p>","</body>", "</html>"]
        body_content = "\n".join(body_elements)
        resp = construct_http_response(httpv, "403 Forbidden", "text/html", body_content)
        return resp

    except FileNotFoundError:
        # craft error response for 404 Not Found
        body_elements = ["<!DOCTYPE html>", "<html>", "<head>","<title>Error 404: Not Found</title>", "</head>", "<body>","<h1>Error 404: Not Found</h1>","<p>The server cannot find the requested resource.</p>","</body>", "</html>"]
        body_content = "\n".join(body_elements)
        resp = construct_http_response(httpv, "404 Not Found", "text/html", body_content)
        return resp


#------------------------------------HEAD--------------------------------
def head(resourceIdentifier , httpv):
    path = directory_root + resourceIdentifier

    try:
        if resourceIdentifier == "/":
            # index file
            body = loadFileText(directory_root+"/index.html")
            resp = httpv+ " 200 OK  \r\n"
            resp += "Content-Type: " + fetchContentType(directory_root+"/index.html") + " \r\n"
            resp += "Content-Length: " + str(len(body)) + "\r\n\r\n"


        elif ".php" in resourceIdentifier:

            path = directory_root + resourceIdentifier.split("?")[0] 
            query_params = dict(param.split('=') for param in resourceIdentifier.split('?')[1].split('&'))
            club_name = query_params.get('club_name', '')
            country_name = query_params.get('country_name', '')


            command = "php-cgi " + path + " club_name=" + club_name + " country_name=" + country_name
            print(command)
            body_php= os.popen(command).read().replace("\n" , "\r\n")
            body_resp = "".join(body_php.split("\r\n\r\n")[1:])


            body = ["<!DOCTYPE html>\n","<html>\n","<head>\n","<title> owdy! </title>\n""</head>\n","<body>\n",body_resp + "<br><br>\n","</body>\n","</html>\n"]
            


            resp = httpv+ " 200 OK  \r\n"
            resp += "Content-Length: " + str(len(body)) + "\r\n"
            resp += "Content-Type: text/html\r\n\r\n" #no body


        
        else:
            body = loadFileText(path)
            resp = httpv+ " 200 OK  \r\n"
            resp += "Content-Type: " + fetchContentType(path) + " \r\n"
            resp += "Content-Length: " + str(len(body)) + "\r\n\r\n"


        return resp 

    except PermissionError:
        # craft error response for 403 Forbidden
        body_elements = ["<!DOCTYPE html>", "<html>", "<head>","<title>Error 403: Forbidden</title>", "</head>", "<body>","<h1>Error 403: Forbidden</h1>","<p>The server understands your request but refuses to authorize it.</p>","<p>Please make sure you have the permissions to access this resource.</p>","</body>", "</html>"]
        body_content = "\n".join(body_elements)
        resp = construct_http_response(httpv, "403 Forbidden", "text/html", body_content)
        return resp

    except FileNotFoundError:
        # craft error response for 404 Not Found
        body_elements = ["<!DOCTYPE html>", "<html>", "<head>","<title>Error 404: Not Found</title>", "</head>", "<body>","<h1>Error 404: Not Found</h1>","<p>The server cannot find the requested resource.</p>","</body>", "</html>"]
        body_content = "\n".join(body_elements)
        resp = construct_http_response(httpv, "404 Not Found", "text/html", body_content)
        return resp



#------------------------------------RESPONSE--------------------------------
def HTTP_response(req, parser_resp):
    httpv = "HTTP/1.1"  # Default value
    try:
        # Split, extract the first line
        reqlist = req.split('\r\n')
        method, resourceIdentifier, httpv = reqlist[0].strip().split(' ')
        print(method, resourceIdentifier, httpv)

        # body EXTRACTION
        body_index = reqlist.index('') + 1
        body = '\n'.join(reqlist[body_index:])

        # Map methods to their handlers
        method_handlers = {
            "GET": lambda: get(resourceIdentifier, httpv),
            "POST": lambda: post(resourceIdentifier, body, httpv),
            "PUT": lambda: put(resourceIdentifier, body, httpv),
            "DELETE": lambda: delete(resourceIdentifier, httpv),
            "HEAD": lambda: head(resourceIdentifier, httpv)
        }

        # Handle based on parser response
        if parser_resp == "200 OK":
            # Call the handler for the method
            handler = method_handlers.get(method, lambda: resp_501(httpv))
            return handler()

        # Handle other parser responses
        error_response_handlers = {
            "411": lambda: resp_411(httpv),
            "400": lambda: resp_400(httpv),
            "501": lambda: resp_501(httpv),
            "505": lambda: resp_505(httpv)
        }

        return error_response_handlers.get(parser_resp.split(' ')[0], lambda: resp_500(httpv))()

    except Exception as e:
        traceback.print_exc()
        return resp_500(httpv)

  
def HTTP():

    # Define socket host and port
    SERVER_HOST = ip
    SERVER_PORT = int(port)

    # Create socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((SERVER_HOST, SERVER_PORT))
    server_socket.listen(1)

    while True:    
        # Wait for client connections
        client_connection, client_address = server_socket.accept()

        # Get the client request
        request = client_connection.recv(1024).decode()
        print(request , end="\n\n")
        
        # Parse request
        parser_response = p.parse(request)
        print("Parser response: " , parser_response)

        # Send HTTP response
        response = HTTP_response(request,parser_response)
        print("\n----------------------------------")
        print(response)
        print("----------------------------------\n")
        if ("200" in response.split("\n")[0].strip()) or ("201" in response.split("\n")[0].strip()):
            log(client_address[0],request.split("\n")[0].strip()) # log(ip,req)
        client_connection.sendall(response.encode())
        client_connection.close()

    # Close socket
    server_socket.close()

#------------------------------------HTTPS--------------------------------
def HTTPS_handler(conn,addr):
    #   set up HTTPS connection
    context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    context.verify_mode = ssl.CERT_NONE
    context.load_cert_chain(certfile = crt_file , keyfile = priv_key_file , password = None)
    s_conn = context.wrap_socket(conn , server_side = True)

    request = s_conn.recv(1024).decode("utf-8")
    parser_response = p.parse(request)
    print("Parser response: " , parser_response)
    resp = HTTP_response(request,parser_response)
    
    print("\n-----------------------------------")
    print(resp)
    print("-----------------------------------\n")
    status_code = resp.split("\n")[0].strip().split(" ")[1]
    if status_code in ["200", "201"]:
    	log(addr[0], request.split("\n")[0].strip())  # log(ip, req)

    s_conn.send(resp.encode())
    s_conn.close()


def HTTPS():
    srv = socket.socket(socket.AF_INET , socket.SOCK_STREAM)
    srv.bind( (ip , int(port)) )
    srv.listen(5)  
    print("")
    while True:
        connection , addr = srv.accept()
        t = threading.Thread(target = HTTPS_handler , args = (connection,addr))
        t.start()



#------------------------------------MAIN--------------------------------
# Global variable declarations
global ip, port, directory_root, crt_file, priv_key_file

try:
    print("\n----------------------------------\n")
    ip = sys.argv[1]
    port = sys.argv[2]
    directory_root = "./directory_root"

    print(f"Server IP:    {ip}")
    print(f"Port Num:     {port}")
    print("\n----------------------------------\n")

    arg_count = len(sys.argv)
    
    if arg_count == 3:
        HTTP()
    elif arg_count == 5:
        crt_file = sys.argv[3]
        priv_key_file = sys.argv[4]
        HTTPS()
    else:
        print("Invalid command, follow the following format:")
        print("HTTP server:     python3 server.py <IP> <PORT>")
        print("HTTPS server:    python3 server.py <IP> <PORT> <certificate> <Key >\n")

except KeyboardInterrupt:
    print("\nYOU CLOSED ME!\nCOME AGAIN!\n")

except Exception as e:
    traceback.print_exc()
    print("\n Server failed to start. \nInternal Server Error.\n")

