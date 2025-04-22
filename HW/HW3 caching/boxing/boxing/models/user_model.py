import hashlib
import logging
import os
import secrets
from typing import Optional, Tuple

from flask_login import UserMixin
from sqlalchemy.exc import SQLAlchemyError

from boxing.db import db
from boxing.utils.logger import configure_logger


logger = logging.getLogger(__name__)
configure_logger(logger)


class Users(db.Model, UserMixin):
    """User model for authentication and session management.

    This model represents a user in the authentication system. It inherits from
    Flask-Login's UserMixin to provide required methods for the login system.

    Attributes:
        id (int): Primary key for the user.
        username (str): Unique username for the user.
        salt (str): Random salt used in password hashing.
        password (str): Hashed password.

    """
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    salt = db.Column(db.String(32), nullable=False)  # 16-byte salt in hex
    password = db.Column(db.String(64), nullable=False)  # SHA-256 hash in hex

    @staticmethod
    def _hash_password(password: str, salt: str) -> str:
        """
        Hashes a password with the given salt using SHA-256.

        Args:
            password (str): The plain text password.
            salt (str): The salt as a hex string.

        Returns:
            str: The hashed password as a hex string.
        """
        # Convert the salt from hex to bytes
        salt_bytes = bytes.fromhex(salt)
        
        # Hash the password with the salt
        hash_obj = hashlib.sha256()
        hash_obj.update(salt_bytes)
        hash_obj.update(password.encode('utf-8'))
        
        # Return the hash as a hex string
        return hash_obj.hexdigest()

    @classmethod
    def create_user(cls, username: str, password: str) -> None:
        """
        Creates a new user with a hashed password.

        Args:
            username (str): The username for the new user.
            password (str): The password for the new user.

        Raises:
            ValueError: If the username already exists or inputs are invalid.
            Exception: If there's a database error.
        """
        logger.info(f"Creating user: {username}")
        
        # Input validation
        if not username or not isinstance(username, str):
            logger.error("Invalid username provided")
            raise ValueError("Username must be a non-empty string")
        
        if not password or not isinstance(password, str) or len(password) < 8:
            logger.error("Invalid password provided")
            raise ValueError("Password must be a string of at least 8 characters")
        
        # Check if username already exists
        existing_user = cls.query.filter_by(username=username).first()
        if existing_user:
            logger.error(f"Username already exists: {username}")
            raise ValueError(f"Username '{username}' already exists")
        
        try:
            # Generate a random 16-byte salt and convert to hex
            salt = secrets.token_hex(16)
            
            # Hash the password with the salt
            hashed_password = cls._hash_password(password, salt)
            
            # Create the new user
            new_user = cls(
                username=username,
                salt=salt,
                password=hashed_password
            )
            
            # Add to database and commit
            db.session.add(new_user)
            db.session.commit()
            
            logger.info(f"User created successfully: {username}")
            
        except SQLAlchemyError as e:
            logger.error(f"Database error while creating user: {e}")
            db.session.rollback()
            raise Exception(f"Database error: {e}")

    @classmethod
    def check_password(cls, username: str, password: str) -> bool:
        """
        Verifies a username and password combination.

        Args:
            username (str): The username to check.
            password (str): The password to verify.

        Returns:
            bool: True if username and password match, False otherwise.

        Raises:
            ValueError: If the username or password is invalid.
        """
        logger.info(f"Checking password for user: {username}")
        
        if not username or not password:
            logger.error("Empty username or password provided")
            raise ValueError("Username and password must not be empty")
        
        # Find the user
        user = cls.query.filter_by(username=username).first()
        if not user:
            logger.warning(f"Login attempt with non-existent username: {username}")
            return False
        
        # Hash the provided password with the user's salt
        hashed_password = cls._hash_password(password, user.salt)
        
        # Compare the hashed password with the stored one
        result = hashed_password == user.password
        
        if result:
            logger.info(f"Password check successful for user: {username}")
        else:
            logger.warning(f"Invalid password for user: {username}")
        
        return result

    @classmethod
    def update_password(cls, username: str, new_password: str) -> None:
        """
        Updates a user's password.

        Args:
            username (str): The username of the user.
            new_password (str): The new password to set.

        Raises:
            ValueError: If the user doesn't exist or the new password is invalid.
            Exception: If there's a database error.
        """
        logger.info(f"Updating password for user: {username}")
        
        if not new_password or not isinstance(new_password, str) or len(new_password) < 8:
            logger.error("Invalid new password provided")
            raise ValueError("New password must be a string of at least 8 characters")
        
        # Find the user
        user = cls.query.filter_by(username=username).first()
        if not user:
            logger.error(f"User not found: {username}")
            raise ValueError(f"User '{username}' does not exist")
        
        try:
            # Generate a new salt for better security
            new_salt = secrets.token_hex(16)
            
            # Hash the new password with the new salt
            new_hashed_password = cls._hash_password(new_password, new_salt)
            
            # Update the user's password and salt
            user.salt = new_salt
            user.password = new_hashed_password
            
            # Commit the changes
            db.session.commit()
            
            logger.info(f"Password updated successfully for user: {username}")
            
        except SQLAlchemyError as e:
            logger.error(f"Database error while updating password: {e}")
            db.session.rollback()
            raise Exception(f"Database error: {e}")

    # Flask-Login required methods
    def get_id(self):
        """Required by Flask-Login, returns the user ID as a string."""
        return self.username

    @classmethod
    def delete_user(cls, username: str) -> None:
        """
        Delete a user from the database.

        Args:
            username (str): The username of the user to delete.

        Raises:
            ValueError: If the user does not exist.
        """
        if not user:
            logger.info("User %s not found", username)
        logger.info("User %s deleted successfully", username)

    @classmethod
    def get_id_by_username(cls, username: str) -> int:
        """
        Retrieve the ID of a user by username.

        Args:
            username (str): The username of the user.

        Returns:
            int: The ID of the user.

        Raises:
            ValueError: If the user does not exist.
        """
        if not user:
            raise ValueError(f"User {username} not found")
        pass