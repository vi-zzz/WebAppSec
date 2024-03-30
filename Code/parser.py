import sys
import re
import math

# check if a string is float (number with decimal point)
def is_float(input_text):
    return True if input_text.replace('.', '', 1).isdigit() else False

#	returning the request headers in a seperate list
def req_header(req):
    return list(line for line in req if line != '' and line is not None)


#	check request headers after the Request Line
def check_headers(headers, method):
    # Check ": " in headers
    if not all(": " in header for header in headers):
        return "400 BAD REQUEST ERROR: The request header syntax was invalid."

    # Organize the request headers into a dictionary
    request_headers = {header.split(": ")[0].lower(): header.split(": ")[1].lower() for header in headers}

    # Check specific headers based on the HTTP method
    if method == "GET" and "host" not in request_headers:
        return "400 BAD REQUEST ERROR: The request header 'Host' was not found."

    if method == "POST" and not all(header in request_headers for header in ["host", "content-type", "content-length"]):
        return "400 BAD REQUEST ERROR: Some required headers were not found."

    return None

#		GET
def check_get(full_req):
    # Adding the request headers in a separate list
    req_headers = req_header(full_req)

    # Req line in a separate variable
    req_line = req_headers[0].split(' ')

    # Check URI format
    if not req_line[1].startswith('/'):
        return "400 BAD REQUEST ERROR: The URI format is invalid."

    # Check HTTP version
    http_version = req_line[2].split("\r")[0].split("/")
    if not (http_version[0] in {"HTTP", "HTTPS"}):
        return "400 BAD REQUEST ERROR: Incorrect HTTP version syntax."
    elif not (is_float(http_version[1]) and 1.0 <= float(http_version[1]) <= 1.1):
        return "505 BAD REQUEST ERROR: Incorrect HTTP version number."

    # Check format of request headers
    error_message = check_headers(req_headers[1:], "GET")
    if error_message:
        return error_message

    return "200 OK"

def check_post(full_req):
    # Adding the request headers in a separate list
    req_headers = req_header(full_req)

    # Req line in a separate variable
    req_line = req_headers[0].split(' ')

    # Check URI format
    if not req_line[1].startswith('/'):
        return "400 BAD REQUEST ERROR: The URI format is invalid."

    # Check HTTP version
    http_version = req_line[2].split("\r")[0].split("/")
    if http_version[0] not in {"HTTP", "HTTPS"}:
        return "400 BAD REQUEST ERROR: Incorrect HTTP version syntax."
    elif not (is_float(http_version[1]) and 1.0 <= float(http_version[1]) <= 1.1):
        return "505 BAD REQUEST ERROR: Incorrect HTTP version number."

    # Check for required headers in the case of "POST"
    if "host" not in [header.split(": ")[0].lower() for header in req_headers[1:]]:
        return "400 BAD REQUEST ERROR: The request header 'Host' was not found."

    required_headers = {"host", "content-type", "content-length"}
    if not required_headers.issubset(set(header.split(": ")[0].lower() for header in req_headers[1:])):
        return "400 BAD REQUEST ERROR: Some required headers were not found."

    return "200 OK"

def check_head(full_req):
    # Adding the request headers in a separate list
    req_headers = req_header(full_req)

    # Req line in a separate variable
    req_line = req_headers[0].split(' ')

    # Check URI format
    if not req_line[1].startswith('/'):
        return "400 BAD REQUEST ERROR: The URI format is invalid."

    # Check HTTP version
    http_version = req_line[2].split("\r")[0].split("/")
    if not (http_version[0] in {"HTTP", "HTTPS"}):
        return "400 BAD REQUEST ERROR: Incorrect HTTP version syntax."
    elif not (is_float(http_version[1]) and 1.0 <= float(http_version[1]) <= 1.1):
        return "505 BAD REQUEST ERROR: Incorrect HTTP version number."

    # Check format of request headers
    error_message = check_headers(req_headers[1:], "HEAD")
    if error_message:
        return error_message

    return "200 OK"

def check_put(full_req):
    # Adding the request headers in a separate list
    req_headers = req_header(full_req)

    # Req line in a separate variable
    req_line = req_headers[0].split(' ')

    # Check URI format
    if not req_line[1].startswith('/'):
        return "400 BAD REQUEST ERROR: The URI format is invalid."

    # Check HTTP version
    http_version = req_line[2].split("\r")[0].split("/")
    if http_version[0] not in {"HTTP", "HTTPS"}:
        return "400 BAD REQUEST ERROR: Incorrect HTTP version syntax."
    elif not (is_float(http_version[1]) and 1.0 <= float(http_version[1]) <= 1.1):
        return "505 BAD REQUEST ERROR: Incorrect HTTP version number."

    # Check for required headers in the case of "PUT"
    required_headers = {"host", "content-length"}  # Adjust the required headers as needed
    if not required_headers.issubset(set(header.split(": ")[0].lower() for header in req_headers[1:])):
        return "400 BAD REQUEST ERROR: Some required headers were not found."

    return "200 OK"


def parse_request(req, req_data):
    handlers = {
        "GET": check_get,
        "POST": check_post,
        "PUT": check_put,
        "DELETE": check_get,
        "HEAD": check_head,
    }

    handler = handlers.get(req)
    if handler:
        return handler(req_data)
    else:
        return "ERROR: Wrong Request Header"
 
#------------------------------------MAIN--------------------------------

#   filedata is the request content
def parse(filedata):
    methods_list = ["GET", "POST", "PUT", "DELETE", "HEAD"]

    lines = filedata.split("\r\n")

    # Print entire request
    print("\n-------------------------------------------")
    for line in lines:
        print(line)
    print("-------------------------------------------\n")

    # Extract request method from the first line
    request_method = lines[0].split(' ')[0]

    # Parse the request (Method Specific)
    if request_method not in methods_list:
        return f"501 BAD REQUEST ERROR: The Request method {request_method} is not in the list of defined methods\nThis parser supports the following request methods: {', '.join(methods_list)}"

    # Find empty line index
    empty_line_index = lines.index('')

    # Check for carriage return at the end of the request
    if empty_line_index == 0:
        return "400 BAD REQUEST ERROR: Did not find the carriage return at the end of the request"

    # Get and print the body of the request
    body = [line for line in lines[empty_line_index + 1:] if line != '']
    # [print(line) for line in body]

    # Call parse_request function
    response_code = parse_request(request_method, lines)

    return response_code
