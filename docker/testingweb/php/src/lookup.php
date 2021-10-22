<?php
include_once "./db.inc";
$conn = new mysqli($host, $user, $pass, $mydatabase);
$lname = $_POST["name"];

$sql = 'SELECT password FROM users WHERE username = $lname';

if ($result = $conn->query($sql)) {
    while ($data = $result->fetch_object()) {
        $upass[] = $data;
    }
}

echo "<html>";
echo "<head>";
echo "	<title>PASSWORD LOOKUP</title>";
echo "</head>";

echo "<body><h1>Results</h1><table>";
echo "<tr><td>Username</td><td>Password</td></tr>";
foreach ($upass as $pwd) {
    echo "<tr><td>". $lname . "</td><td>" . $pwd . "</td></tr>";
}
echo "</table></body";
?>
