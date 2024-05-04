import mysql.connector

# Connect to the MySQL server
#replace the password
conn = mysql.connector.connect(
    host="localhost",
    user="root",
    password="your-password",
    database="ecommerce"
)

# Create a cursor object
cursor = conn.cursor()

# Define the SQL commands
sql_commands = [
    """
    CREATE TABLE User (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(150) UNIQUE NOT NULL,
        password VARCHAR(150),
        first_name VARCHAR(150)
    )
    """,
    """
    CREATE TABLE Category (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(100) NOT NULL
    )
    """,
    
    
    """
    CREATE TABLE Products (
        id INT AUTO_INCREMENT PRIMARY KEY,
        image_url VARCHAR(100),
        price VARCHAR(100),
        name VARCHAR(100) NOT NULL,
        description TEXT NOT NULL,
        category_id INT,
        FOREIGN KEY (category_id) REFERENCES Category(id)
    )
    """,
    """
    CREATE TABLE Kart (
        user_id INT,
        product_id INT,
        PRIMARY KEY (user_id, product_id),
        FOREIGN KEY (user_id) REFERENCES User(id),
        FOREIGN KEY (product_id) REFERENCES Products(id)
    )
    """,
    """ 
    INSERT INTO Category (name) VALUES ('Electronics')
    """,
    """
    INSERT INTO Category (name) VALUES ('Clothing')
    """,
    """
        INSERT INTO Category (name) VALUES ('Books')
    """
]

# Execute each SQL command
for command in sql_commands:
    cursor.execute(command)

# Commit changes and close connection
conn.commit()
conn.close()

print("Tables created successfully!")