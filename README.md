# FastAPI JWT Authentication with HTML Templates

This project implements JWT authentication using FastAPI, with HTML templates for rendering responses. The example provides a simple setup for creating secure authentication systems with FastAPI and JWT.

## Setup Instructions

### 1. Create a Python Virtual Environment

You can create a virtual environment using one of the following commands:

- Using `virtualenv`:
  ```bash
  virtualenv env --python=python3


- Using venv (Python 3+):
    ```bash
    python3 -m venv env


2. Install Required Dependencies

Install the dependencies listed in the requirements.txt file:
pip install -r requirements.txt

3. Generate Keys for JWT

To securely sign JWTs, you need a pair of private and public RSA keys.

You can use the Python script gen_key.py to generate the keys automatically.

- Alternatively, use the following OpenSSL commands to manually generate the keys:

- RSA (Recommended: 2048 or 4096 bits)

- Generate a 2048-bit private key:
    ```bash
    openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048


- Extract the public key:
    ```bash
    openssl rsa -pubout -in private.pem -out public.pem

- Make sure to store the private.pem and public.pem files securely.

4. Create PostgreSQL Database

Create a PostgreSQL database named authdb and configure the connection string with your PostgreSQL user and password:
 ```bash
    CREATE DATABASE authdb;


- Make sure to edit the database connection string in the project accordingly.

5. Run the Application

To run the FastAPI application with live reloading, use the following command:
    ```bash
    uvicorn main:app --reload


- The application should now be running locally, and you can access it at http://localhost:8000.

Additional Notes

Ensure that your PostgreSQL instance is running and accessible.

You can customize the JWT authentication logic to suit your project needs.

The HTML templates can be modified to fit your front-end requirements.

