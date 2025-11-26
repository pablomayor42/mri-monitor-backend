import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY', 'dev-secret-key')
DEBUG = False
ALLOWED_HOSTS = ['*']

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'mri_monitor.core',
    'mri_monitor.soap_server',
    'mri_monitor.api',
    'corsheaders',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'corsheaders.middleware.CorsMiddleware',
]

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],  # Puedes añadir aquí rutas adicionales si tienes templates propios
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


ROOT_URLCONF = 'mri_monitor.urls'
WSGI_APPLICATION = 'mri_monitor.wsgi.application'
ASGI_APPLICATION = 'mri_monitor.asgi.application'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
LANGUAGE_CODE = 'es-es'
TIME_ZONE = 'Europe/Madrid'
USE_I18N = True
USE_TZ = True
STATIC_URL = '/static/'

# Logging simple: consola + fichero para depuración SOAP
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '[{asctime}] {levelname} {name}: {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
        'soap_file': {
            'class': 'logging.FileHandler',
            'filename': str(BASE_DIR / 'mri_monitor' / 'soap_server' / 'soap.log'),
            'formatter': 'verbose',
            'encoding': 'utf-8',
        },
    },
    'loggers': {
        # logger para el módulo SOAP
        'mri_monitor.soap_server': {
            'handlers': ['console', 'soap_file'],
            'level': 'DEBUG',
            'propagate': False,
        },
        # por si quieres ver info de Django también
        'django': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': True,
        },
    }
}


SUPPORTED_MEMBER = os.environ.get('SUPPORTED_MEMBER', '4DMRI')
SUPPORTED_PASSWORD = os.environ.get('SUPPORTED_PASSWORD', 'Pass')
CORS_ALLOW_ALL_ORIGINS = False
CORS_ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    # añade otros orígenes que uses
]
CORS_ALLOW_CREDENTIALS = True

# (opcional) permitir encabezados comunes
CORS_ALLOW_HEADERS = [
    'accept',
    'accept-encoding',
    'authorization',
    'content-type',
    'dnt',
    'origin',
    'user-agent',
    'x-csrftoken',
    'x-requested-with',
]

# Configuración SMTP para envío real de correos (password reset, notificaciones, etc.)
# Leer desde variables de entorno para no hardcodear credenciales.
EMAIL_BACKEND = os.environ.get('DJANGO_EMAIL_BACKEND', 'django.core.mail.backends.smtp.EmailBackend')
EMAIL_HOST = os.environ.get('DJANGO_EMAIL_HOST', 'smtp.ionos.es')
EMAIL_PORT = int(os.environ.get('DJANGO_EMAIL_PORT', 587))
EMAIL_HOST_USER = os.environ.get('DJANGO_EMAIL_HOST_USER', 'comercial4d@4dmedica.ai')
EMAIL_HOST_PASSWORD = os.environ.get('DJANGO_EMAIL_HOST_PASSWORD', '4DMedica123')
# Seguridad: TLS ó SSL (usar solo uno)
EMAIL_USE_TLS = True
#os.environ.get('DJANGO_EMAIL_USE_TLS', 'True').lower() in ('1', 'true', 'yes')
EMAIL_USE_SSL = False
#os.environ.get('DJANGO_EMAIL_USE_SSL', 'False').lower() in ('1', 'true', 'yes')
# Dirección FROM por defecto
DEFAULT_FROM_EMAIL = os.environ.get('DJANGO_DEFAULT_FROM_EMAIL', 'comercial4d@4dmedica.ai')

# Opcional: tiempo de reintento / logging (puedes ajustar)
EMAIL_TIMEOUT = int(os.environ.get('DJANGO_EMAIL_TIMEOUT', 10))

FRONTEND_BASE = 'http://localhost:5173'