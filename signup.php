<?php
// signup.php

$servername = "localhost";
$username = "root";
$password = "";
$dbname = "event_reminder_db";

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Collect and sanitize form data
    $first_name = $conn->real_escape_string(trim($_POST['first_name']));
    $last_name = $conn->real_escape_string(trim($_POST['last_name']));
    $email = $conn->real_escape_string(trim($_POST['email']));
    $password = $_POST['password'];

    // Validate the input (basic example)
    if (empty($first_name) || empty($last_name) || empty($email) || empty($password)) {
        die("All fields are required.");
    }

    // Hash the password before storing it
    $hashed_password = password_hash($password, PASSWORD_DEFAULT);

    // Prepare and bind
    $stmt = $conn->prepare("INSERT INTO users (first_name, last_name, email, password) VALUES (?, ?, ?, ?)");
    $stmt->bind_param("ssss", $first_name, $last_name, $email, $hashed_password);

    // Execute the statement
    if ($stmt->execute()) {
        echo "Signup successful for $first_name $last_name!";
    } else {
        echo "Error: " . $stmt->error;
    }

    // Close the statement and connection
    $stmt->close();
} else {
    // Handle GET request or other request types
    die("Invalid request method.");
}

$conn->close();
?>
