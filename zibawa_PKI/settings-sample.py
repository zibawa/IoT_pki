"""
Django settings for zibawa_PKI project.

Generated by 'django-admin startproject' using Django 1.11.3.

For more information on this file, see
https://docs.djangoproject.com/en/1.11/topics/settings/
https://docs.zibawa.com

For the full list of settings and their values, see
https://docs.djangoproject.com/en/1.11/ref/settings/
"""

import os

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/1.11/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = '*w&etzb9h63+)b4^s$($!-i(!=_$k1dgseggesfe?/ffdsgfgdde!'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True


#you will need to add your domain here!
ALLOWED_HOSTS = ['localhost','127.0.0.1','.zibawa.com','.myserver.com']


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'IoT_pki',
    'rest_framework',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'zibawa_PKI.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'zibawa_PKI.wsgi.application'


# Database
# https://docs.djangoproject.com/en/1.11/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
    }
}


# Password validation
# https://docs.djangoproject.com/en/1.11/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/1.11/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_L10N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/1.11/howto/static-files/

STATIC_URL = '/static/'



EMAIL_HOST = 'smtp.mymail.com'
EMAIL_PORT = 587
EMAIL_HOST_USER = 'me@mymail.com'
EMAIL_HOST_PASSWORD = 'mypass'
EMAIL_USE_TLS = True
DEFAULT_FROM_EMAIL='me@mymail.com'


#used to create and renew X509 certificates.  The certificate and key used at below location will be used to sign
#all certificates generated by PKI
PKI={'host':'secret.myserver.com','port':443,
     'user':'admin',
     'password':'secret',
     'use_ssl':True,#should always be True except for testing
     'verify_certs':False,#verify identity of server should be True except for testing
     'path_to_ca_cert':'/path/to/ca.pem',
     'path_to_ca_key':'/path/to/ca.key',
     'path_to_certstore':'/home/myCA/certs/',#requires trailing slash, place to keep CA certs
     'path_to_keystore':'/home/myCA/private/',#requires trailing slash. place to keep ca keys should be permission 400
     
     }

CERT_DEFAULTS={'country_name':"ES",#obligatory must be 2 letter country code 
               'state_or_province_name':"Barcelona",
               'valid_days':365,#validity of certificates generated must be integer not string
               'min_days_remaining_for_renewal':400
               
               }


#used as part of PKI
REST_FRAMEWORK = {
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAdminUser',
    ],
    'PAGE_SIZE': 10
}





#recommended, add logging handlers below are reasonable defaults for testing

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '%(levelname)s %(asctime)s %(message)s'
        },
        'simple': {
            'format': '%(levelname)s %(message)s'
        },
    },
    'handlers': {
        'console': {
        'level':'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'verbose'
        },
        'file': {
            'level': 'ERROR',
            'class': 'logging.handlers.TimedRotatingFileHandler',
            'filename': '/var/log/zibawa/pki.log',
            'formatter': 'verbose',
            'when': 'midnight',
            'backupCount': 5,
        },
    },
    'loggers': {
        'django': {
            'handlers': ['console','file'],
            'level': os.getenv('DJANGO_LOG_LEVEL', 'DEBUG'),
        },
        'IoT_pki': {
            'handlers': ['console','file'],
            'level': 'DEBUG'
        },
    },
}




