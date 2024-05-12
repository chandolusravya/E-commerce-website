# E-commerce Website

This project aims to create a scalable backend system with secure authentication for an E-commerce website. It incorporates OAuth for authentication, Redis caching for improved performance, and load balancing for scalability.


## Features

- **OAuth Integration:** Allows users to sign in using their Google accounts securely.
  
- **Redis Caching:** Utilizes Redis as a caching mechanism to improve performance by storing frequently accessed data in memory.

- **Load Balancing with Nginx:** Distributes incoming traffic across multiple servers to optimize resource utilization and enhance reliability.
  
- **Integration with StripeStripe:** is integrated into the system for processing payments securely. It provides a reliable and easy-to-use platform for handling transactions.

## Additional Points

- **Redis Caching:**
  - Improves application performance by caching frequently accessed data in memory.
  - Reduces the load on the primary database server by serving cached data directly from memory.
  - Enhances scalability and responsiveness by minimizing database queries.
  
- **Load Balancing with Nginx:**
  - Distributes incoming traffic evenly across multiple servers to prevent overload and improve response times.
  - Increases fault tolerance by redirecting traffic away from unhealthy servers.
  - Supports horizontal scaling by adding or removing servers dynamically based on demand.

- **OAuth Integration:**
  - Simplifies user authentication by allowing users to sign in with their existing Google accounts.
  - Enhances security by delegating authentication to Google's trusted identity provider.
  - Provides a seamless and familiar sign-in experience for users with Google credentials.



## Development Environment Setup

To set up the development environment, follow these steps:

1. **Create a directory:**

    ```bash
    mkdir projectname
    ```

2. **Navigate to the created directory:**

    ```bash
    cd projectname
    ```

3. **Setup a virtual environment:**

    ```bash
    python3 -m venv .venv
    ```

4. **Activate the virtual environment:**

    ```bash
    source .venv/bin/activate
    ```

5. **Install Flask:**

    ```bash
    pip install flask
    ```

    or

    ```bash
    pip3 install flask
    ```

6. **Install Honcho (for load balancing):**

    ```bash
    pip3 install honcho
    ```

7. **Install Redis (for caching):**

    ```bash
    brew install redis  # For macOS
    ```

    or

    ```bash
    sudo apt-get install redis-server  # For Ubuntu
    ```

## OAuth Setup

1. **Create OAuth Client ID:**
   
    Register your application with the OAuth provider (e.g., Google) and obtain the client ID and client secret.

2. **Configure OAuth:**

    Update the `client_secret.json` file with the OAuth client ID and secret.

## Usage

To run the application, use the following command:

```bash
honcho start
