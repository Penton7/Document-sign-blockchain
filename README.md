## Table of contents
* [General info](#general-info)
* [Technologies](#technologies)
* [Setup](#setup)
* [Configuration And Start](#configuration-and-start)

## General info
Project using python 3
## Technologies


## Setup


Install virtualenv:
```
$ sudo pip3 install virtualenv
```

In cloned directory create new virtual environment:
```
$ mkdir .venv && cd .venv
$ virtualenv --no-site-packages <venv_name>
```
Now activate created virtual environment:
```
$ source .venv/<venv_name>/bin/activate
```
Install all necessary dependencies via PyPI:
```
(<venv_name>)$ pip3 install -r requirements.txt
```

## Configuration And Start

Since local environment isn't configured by default, new configuration file should be created:

```
(<venv_name>)$ cp creds.example/ ./
```
Add there DB connection and other configurations as in example below:

```python
portus_auth = 'login:pass'
zoom_auth = 'Bearer key'
jira_auth = ('JIRA login', 'password')
gitlab_auth = 'api key'
owncloud_auth = 'login:pass'
mattermost_auth = 'Bearer api'

postgres_host = 'postgres'
postgres_port = '5432'
postgres_user = 'postgres'
postgres_password = 'password'
postgres_db = 'manages'

###Nextcloud creds
user = 'login'
password = 'password'
###Nextcloud creds

white_list = ['admin@technorely.com', 'accountant@technorely.com', 'career@ithouse.life',
  'customer@technorely.com', 'dmitriy@technorely.com', 'george@technorely.com',
  'marketing@technorely.com', 'media@technorely.com', 'projects@technorely.com',
  'kirill.g@technorely.com']

# JWT Token #
SECRET_KEY = 'super-secret'

# Registration secret
secret_key = 'test-key'

#SMTP credentials
smtp_host = 'smtp.mailgun.org'
smtp_port = 587
email_user = 'accounts@technorely.com'
email_password = 'password'

#dev creds
email_send_admins = ['ontarget1212@gmail.com', 'sergey.tarasov@technorely.com']
email_send_create = ['andrey.volkov@technorely.com']

# PRODUCTIONS CREDS
#email_send_admins = ['admin@technorely.com', 'sergey.tarasov@technorely.com', 'andrey.volkov@technorely.com']
#email_send_create = ['employee@technorely.com']
```

Run migrations and fill database with necessary data:


> (<venv_name>)$ ___python3 run.py db upgrade___


Now start local server:


> (<venv_name>)$  ___python3 run.py runserver___

Run local server in DEBUG mode:


> (<venv_name>)$  ___export FLASK_DEBUG=True___
>
> (<venv_name>)$  ___python3 run.py runserver___
> 
>OR
>> (<venv_name>)$  ___python3 run.py rundebug___
# Document-sign-blockchain
