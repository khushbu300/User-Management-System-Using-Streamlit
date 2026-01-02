import streamlit as st
import mysql.connector
import re


def connect_db():
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="1111",
        database="ethans_project",
        auth_plugin="mysql_native_password"
    )
    return conn, conn.cursor()



def valid_username(username):
    return len(username) >= 5


def valid_password(password):
    if len(password) < 8:
        return False
    return (
        re.search("[A-Z]", password) and
        re.search("[a-z]", password) and
        re.search("[0-9]", password) and
        re.search("[^A-Za-z0-9]", password)
    )


def signup():
    st.subheader("Signup")

    username = st.text_input("Username")
    password = st.text_input("Password",  type = "password")
    confirm = st.text_input("Confirm Password", type="password")

    if st.button("Signup"):
        if not valid_username(username):
            st.warning("Username must be at least 5 characters long")
            return

        if not valid_password(password):
            st.warning("Password must be strong (Upper, Lower, Digit, Special, 8+ chars)")
            return
        
        if password != confirm:
            st.warning("Passwords do not match")
            return

        conn, cursor = connect_db()
        cursor.execute("SELECT username FROM users WHERE username = %s", (username,))
        if cursor.fetchone():
            st.error("Username already exists")
        else:
            cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)",(username, password))
            conn.commit()
            st.success("Signup successful")

        cursor.close()
        conn.close()


def login():
    st.subheader("Login")

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        conn, cursor = connect_db()
        cursor.execute("SELECT password FROM users WHERE BINARY username = %s",(username,))
        result = cursor.fetchone()

        if result is None:
            st.error("Username does not exist")
        elif password != result[0]:
            st.error("Incorrect password")
        else:
            st.session_state["user"] = username
            st.success("Login successful")
            welcome()

        cursor.close()
        conn.close()


def update_username():
    new_username = st.text_input("New Username")

    if st.button("Update Username"):
        if not valid_username(new_username):
            st.warning("Username must be at least 5 characters long")
            return

        conn, cursor = connect_db()
        cursor.execute("SELECT username FROM users WHERE username=%s", (new_username,))
        if cursor.fetchone():
            st.error("Username already exists")
        else:
            cursor.execute(
                "UPDATE users SET username=%s WHERE username=%s",(new_username, st.session_state["user"]))
            conn.commit()
            st.session_state["user"] = new_username
            st.success("Username updated")

        cursor.close()
        conn.close()



def update_password():
    new_password = st.text_input("New Password", type="password")
    confirm = st.text_input("Confirm Password", type="password")

    if st.button("Update Password"):
        if not valid_password(new_password):
            st.warning("Weak password")
            return
        if new_password != confirm:
            st.warning("Passwords do not match")
            return

        conn, cursor = connect_db()
        cursor.execute("UPDATE users SET password=%s WHERE username=%s",(new_password, st.session_state["user"]))
        conn.commit()
        st.success("Password updated")

        cursor.close()
        conn.close()



def delete_account():
    if st.button("Delete My Account"):
        conn, cursor = connect_db()
        cursor.execute("DELETE FROM users WHERE username=%s",(st.session_state["user"],))
        conn.commit()
        cursor.close()
        conn.close()

        st.session_state.clear()
        st.success("Account deleted")



def welcome():
    st.subheader(f"Welcome {st.session_state['user']}")

    choice = st.radio(label ="Choose an option",options =["Select", "Update Username", "Update Password", "Delete Account", "Logout"])

    if choice == "Update Username":
        update_username()
    elif choice == "Update Password":
        update_password()
    elif choice == "Delete Account":
        delete_account()
    elif choice == "Logout":
        st.session_state.clear()
        st.success("Logged out")



st.title("User Management System")

if "user" not in st.session_state:
    menu = st.radio(label = "Menu",options =  ["Signup", "Login"],)
    if menu == "Signup":
        signup()
    else:
        login()
else:
    welcome()