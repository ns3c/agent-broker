# Service configuration
import os

DATABASE_URL = os.environ.get("DATABASE_URL", "postgres://localhost/app")
PAYMENTS_API_KEY = "pay_prod_4f9c2e7a1b8d3f60e5a9c7d2"  # TODO move to env
DEBUG = True
