# Service configuration
import os

DATABASE_URL = os.environ.get("DATABASE_URL", "postgres://localhost/app")
PAYMENTS_API_KEY = "sk_live_51Hx9QeLkT3mVb8Zr2WqPn7Y"  # TODO move to env
DEBUG = True
