<?php
session_start();

// Initialize variables for handling errors and form state
$activeForm = "login"; // Default form is login
$loginEmailError = $loginPasswordError = "";
$signupEmailError = $signupPasswordError = $confirmPasswordError = "";
$registrationSuccess = false; // Flag for registration success

// MySQL connection (adjust with your details)
$servername = "localhost";
$username = "root";
$password = "";
$dbname = "user_database"; // Your DB name

// Establish a database connection
$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    // Handle login form submission
    if (isset($_POST["action"]) && $_POST["action"] === "login") {
        $email = trim($_POST["email"]);
        $password = trim($_POST["password"]);

        if (empty($email)) {
            $loginEmailError = "Email is required.";
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $loginEmailError = "Invalid email format.";
        }

        if (empty($password)) {
            $loginPasswordError = "Password is required.";
        }

        if (empty($loginEmailError) && empty($loginPasswordError)) {
            // Validate user credentials without password hashing
            $stmt = $conn->prepare("SELECT password FROM users WHERE email = ?");
            $stmt->bind_param("s", $email);
            $stmt->execute();
            $stmt->store_result();

            if ($stmt->num_rows > 0) {
                $stmt->bind_result($storedPassword);
                $stmt->fetch();

                // Direct password comparison (no hashing)
                if ($password === $storedPassword) {
                    $_SESSION['user'] = $email;  // Store user session
                    header("Location: home.html");  // Redirect to homepage after successful login
                    exit();
                } else {
                    $loginPasswordError = "Incorrect password.";
                }
            } else {
                $loginEmailError = "No account found with this email.";
            }
            $stmt->close();
        }
        $activeForm = "login";
    }

    // Handle signup form submission
    if (isset($_POST["action"]) && $_POST["action"] === "signup") {
        $email = trim($_POST["signupEmail"]);
        $password = trim($_POST["signupPassword"]);
        $confirmPassword = trim($_POST["confirmPassword"]);

        if (empty($email)) {
            $signupEmailError = "Email is required.";
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $signupEmailError = "Invalid email format.";
        }

        if (empty($password)) {
            $signupPasswordError = "Password is required.";
        } elseif (strlen($password) < 6) {
            $signupPasswordError = "Password must be at least 6 characters.";
        }

        if ($password !== $confirmPassword) {
            $confirmPasswordError = "Passwords do not match.";
        }

        // If there are no errors, insert into the database
        if (empty($signupEmailError) && empty($signupPasswordError) && empty($confirmPasswordError)) {
            // Check if email already exists
            $stmt = $conn->prepare("SELECT email FROM users WHERE email = ?");
            $stmt->bind_param("s", $email);
            $stmt->execute();
            $stmt->store_result();

            if ($stmt->num_rows > 0) {
                $signupEmailError = "Email already exists.";
            } else {
                // Insert new user into database with plain text password
                $stmt = $conn->prepare("INSERT INTO users (email, password) VALUES (?, ?)");
                $stmt->bind_param("ss", $email, $password);

                if ($stmt->execute()) {
                    $registrationSuccess = true;  // Registration successful
                    header("Location: home.html");  // Redirect to login page after successful signup
                    exit();  // Ensure no further processing happens
                } else {
                    $signupEmailError = "Error creating account. Please try again.";
                }
                $stmt->close();
            }
        }
        $activeForm = "signup";
    }
}

// Close the database connection
$conn->close();
?>