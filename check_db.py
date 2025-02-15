from app import app, db, User

with app.app_context():  # Add this to fix the error
    users = User.query.all()
    for user in users:
        print(f"ID: {user.id}, Email: {user.email}")

    if not users:
        print("No users found in the database.")
