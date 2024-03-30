# How to run 

We'll go through the commands to run my Server file.

## Running the Server

Refer Code/requirements.txt for the modules needed to run this.

In the 'Code' directory, run:

```bash
# For HTTPS
sudo python3 server.py localhost 443 demo.crt demo.key
# For HTTP
sudo python3 server.py localhost 80 
```
## Ansible

This will run the server automatically on localhost port 443. 
The service name is mywebserver.

On the client, the files will be saved in the /home/ubuntu/final_code directory. 

I have also included the source code in the Ansible folder to make the source path convenient. 

In the 'Ansible' directory, run:  
```bash
sudo ansible-playbook playbook.yml
```
## Docker

This will run on localhost:443

Nginx acts as a proxy server and a load balancer. 

In the 'Docker' directory, run:
```bash
sudo docker-compose up
```

## Selenium
It is required to have Google Chrome to run this script.

In the 'Code/selenium' directory run:
```bash
python3 exploit.py
```

