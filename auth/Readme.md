# Authentication Service

This service handles user authentication for the Future Flow application. It provides mechanisms for users to sign up, log in, and manage their sessions securely.

## Features

* **Local Authentication:** Users can sign up and log in using their email and password.
* **Google Authentication:** Seamless integration with Google for easy sign-up and login using existing Google accounts.
* **Session Management:** Securely manages user sessions using JSON Web Tokens (JWTs).
* **Password Hashing:** Passwords are securely stored using industry-standard hashing algorithms.
* **Input Validation:** Ensures data integrity and security by validating user input.

## Technologies Used

* **Node.js:** The runtime environment for the service.
* **Express.js:** A fast, unopinionated, minimalist web framework for Node.js.
* **Mongoose:** An ODM (Object Data Modeling) library for MongoDB.

* **MongoDB:** A NoSQL document database used to store user data.
* **bcrypt:** A library for hashing passwords.
* **jsonwebtoken:** A library for generating and verifying JSON Web Tokens.
* **Passport.js:** Authentication middleware for Node.js, used for Google OAuth.

## Setup and Installation

1. **Clone the repository:**

    ```bash
    git clone <repository_url>
    cd auth
    ```

2. **Install dependencies:**

    ```bash
    npm install
    ```

3. **Configure environment variables:**
    Create a `.env` file in the root directory of the service and add the following variables:

    ```env
    MONGO_URI=<your_mongodb_connection_string>
    JWT_SECRET=<your_jwt_secret>
    GOOGLE_CLIENT_ID=<your_google_client_id>
    GOOGLE_CLIENT_SECRET=<your_google_client_secret>
    GOOGLE_CALLBACK_URL=<your_google_callback_url>
