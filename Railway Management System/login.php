<?php
// start session
session_start();
 
// define variables
$username = $password = '';
$username_err = $password_err = '';
 
// check if form was submitted
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
 
    // validate username
    if (empty(trim($_POST['uname']))) {
        $username_err = 'Please enter your username.';
    } else {
        $username = trim($_POST['uname']);
    }
 
    // validate password
    if (empty(trim($_POST['upswd']))) {
        $password_err = 'Please enter your password.';
    } else {
        $password = trim($_POST['upswd']);
    }
 
    // if there are no errors, attempt to login
    if (empty($username_err) && empty($password_err)) {
 
        // include database connection file
        require_once 'config.php';
 
        // prepare sql statement
        $sql = "SELECT username, password FROM users WHERE username = ?";
 
        if ($stmt = mysqli_prepare($conn, $sql)) {
 
            // bind variables to the prepared statement as parameters
            mysqli_stmt_bind_param($stmt, 's', $param_username);
 
            // set parameters
            $param_username = $username;
 
            // execute sql statement
            if (mysqli_stmt_execute($stmt)) {
 
                // store result
                mysqli_stmt_store_result($stmt);
 
                // if username exists, verify password
                if (mysqli_stmt_num_rows($stmt) == 1) {
 
                    // bind result variables
                    mysqli_stmt_bind_result($stmt, $id, $username, $hashed_password);
                    if (mysqli_stmt_fetch($stmt)) {
                        if (password_verify($password, $hashed_password)) {
 
                            // password is correct, start new session
                            session_start();
 
                            // store data in session variables
                            $_SESSION['loggedin'] = true;
                            $_SESSION['id'] = $id;
                            $_SESSION['username'] = $username;
 
                            // redirect to welcome page
                            header('location: welcome.php');
                        } else {
                            // display error message if password is incorrect
                            $password_err = 'The password you entered is incorrect.';
                        }
                    }
                } else {
                    // display error message if username doesn't exist
                    $username_err = 'No account found with that username.';
                }
            } else {
                echo 'Oops! Something went wrong. Please try again later.';
            }
 
            // close statement
            mysqli_stmt_close($stmt);
        }
 
        // close connection
        mysqli_close($conn);
    }
}
?>