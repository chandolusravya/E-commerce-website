import mysql.connector

# Connect to the MySQL server
conn = mysql.connector.connect(
    host="localhost",
    user="root",
    password="password",
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
    """,
    """
    ALTER TABLE User ADD COLUMN address VARCHAR(150), 
    ADD COLUMN city VARCHAR(150), 
    ADD COLUMN state VARCHAR(150), 
    ADD COLUMN pincode VARCHAR(150), 
    ADD COLUMN country VARCHAR(150), 
    ADD COLUMN home VARCHAR(150)
    """,
    """
    ALTER TABLE Products MODIFY COLUMN price INTEGER
    """,
    """ 
    CREATE TABLE Orders (     
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,     
    FOREIGN KEY (user_id) REFERENCES User(id) )
    """
]

# Execute each SQL command
for command in sql_commands:
    cursor.execute(command)

# Define the SQL command to insert data into the Products table
sql_command = """
    INSERT INTO Products (image_url, price, name, description, category_id)
    VALUES (%s, %s, %s, %s, %s)
"""

# Define the values to insert into the Products table
values = [
    ('images/iphone.jpeg', '1200', 'Iphone 15 pro', 'Apple iPhone 15 Pro, 256GB, Black Titanium - Unlocked. 6.1inch Super Retina XDR display. ProMotion technology. Always-On display. Titanium with textured matte glass back. Action button', 1),
    ('images/samsung.jpeg', '1300', 'Samsung Galaxy S23', 'Galaxy S23 Ultra 5G SM-S918B/DS Dual SIM 256GB ROM 8GB RAM GSM Factory Unlocked Global Model (Mobile Cell Phone) (Phantom Green)', 1),
    ('images/shirt.jpeg', '100', 'T-shirt', 'Puma T-Shirt', 2),
    ('images/jacket.jpeg', '50', 'Jacket', 'Adidas Jacket', 2),
    ('images/book1.jpeg', '17', 'Harry Potter', 'Harry Potter Book', 3),
    ('images/dress.jpeg', '17', 'Kids Dress', 'Kid dress', 2)
]

# Execute the SQL command with the values
for value in values:
    cursor.execute(sql_command, value)

# Commit changes and close connection
conn.commit()
conn.close()

print("Tables created successfully and data inserted!")
