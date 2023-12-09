import csv
import random
from faker import Faker

# Initialize Faker to generate fake data
fake = Faker()

# Specify the number of users you want to generate
num_users = random.randint(50000, 99000)

# Create a list to store user data
user_data = []

# Generate data for each user
for _ in range(num_users):
    first_name = fake.first_name()
    last_name = fake.last_name()
    age = random.randint(18, 65)
    street_address = fake.street_address()
    zip_code = fake.zipcode()
    account_number = ''.join([str(random.randint(0, 9)) for _ in range(12)])

    user_data.append([first_name, last_name, age, street_address, zip_code, account_number])

# Write the data to a CSV file
csv_filename = 'fake_user_data.csv'
with open(csv_filename, 'w', newline='') as csv_file:
    csv_writer = csv.writer(csv_file)
    # Write header row
    csv_writer.writerow(['First Name', 'Last Name', 'Age', 'Street Address', 'Zip Code', 'Account Number'])
    # Write user data
    csv_writer.writerows(user_data)

print(f"Generated {num_users} fake user records in '{csv_filename}'")
