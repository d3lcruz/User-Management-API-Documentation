def user_serial(user) -> dict:
    return {
        "id": str(user["_id"]),
        "username": user["username"],
        "email": user["email"],
        "fullname": user.get("fullname"),
        "disabled": user.get("disabled")
    }

def users_serial(users) -> list:
    return [user_serial(user) for user in users]