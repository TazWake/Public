<?php
include_once "./db.inc";
$lname = $_POST["name"];
$conn = new mysqli($host, $user, $pass, $mydatabase);
if ($conn->connect_error) {
  die("Connection failed: " . $conn->connect_error);
}
$sql = "SELECT username,password FROM users WHERE username = '".$lname."'";


echo "<html>";
echo "<head>";
echo "	<title>PASSWORD LOOKUP for ". $lname . " </title>";
echo "</head>";

echo "<body><h1>Results</h1><table border=1>";
echo "<tr><td>Username</td><td>Password</td></tr>";

$result = $conn->query($sql);
if ($result->num_rows > 0) {
    while($pwd = $result->fetch_assoc()){
        echo "<tr><td>" . $pwd["username"] . "</td><td>" . $pwd["password"] . "</td></tr>";
    }
} else {
    echo "<tr><td>" . $lname . "</td><td> NOT FOUND </td></tr>";
}
echo "</table><hr>";

echo "<h2>Thank you for using this service</h2>";
echo '<a href="/index.php">Return Home</a>';

echo "</body";
?>
