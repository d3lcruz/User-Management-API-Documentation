# User-Management-API-Documentation
Overview

The User Management API is a robust and secure solution designed to handle user registration, authentication, profile management, and account deletion. Built using FastAPI and MongoDB, this API provides the necessary endpoints to manage user-related operations effectively.
Features

    User Registration: Create new user accounts.
    User Authentication: Authenticate users using JWT tokens.
    Profile Management: Retrieve and update user profiles.
    Password Reset: Initiate and confirm password resets.
    Account Deletion: Permanently delete user accounts.
    Security: Ensure secure operations with JWT authentication and role-based access control.

Endpoints

    User Registration
        Endpoint: /users/register
        Method: POST
        Description: Allows users to register by providing basic information such as username, email, and password.

    User Authentication
        Endpoint: /users/login
        Method: POST
        Description: Enables users to authenticate by providing their credentials (email and password).

    User Profile Retrieval
        Endpoint: /users/profile
        Method: GET
        Description: Retrieves the profile information of the authenticated user.

    User Profile Update
        Endpoint: /users/profile
        Method: PUT
        Description: Allows the authenticated user to update their profile information.

    User Password Reset
        Endpoint: /users/reset-password
        Method: POST
        Description: Initiates the process of resetting the user's password.

    User Password Reset Confirmation
        Endpoint: /users/reset-password/{token}
        Method: POST
        Description: Confirms the password reset with a new password using the token received via email.

    User Deletion
        Endpoint: /users/delete
        Method: DELETE
        Description: Permanently deletes the user account and associated data.

Authentication and Authorization

    JWT (JSON Web Tokens): Authentication is performed using JWTs, which are issued upon successful login and included in subsequent requests for authorization.
    Role-Based Access Control: Different levels of access are granted based on user roles (e.g., admin, regular user).

Error Handling

The API follows standard HTTP status codes and provides informative error messages in case of failures or invalid requests. Common error scenarios are documented along with suggested actions for resolution.
