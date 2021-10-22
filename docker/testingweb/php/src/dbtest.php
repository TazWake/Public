<?php
include_once "./db.inc";


$conn = new mysqli($host, $user, $pass);
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
} else {
    echo "Connected to MySQL server successfully!";
}
/*
echo "<h1>Registered Users</h1><hr />";

echo "<table border=1>";
echo "<tr><td>Username</td><td>Password</td></tr>";
foreach ($users as $user) {
    echo "<tr>";
    echo "<td>" . $user->username . "</td><td>" . $user->password . "</td>";
    echo "</tr>";
}
echo "</table>";
*/
?>
