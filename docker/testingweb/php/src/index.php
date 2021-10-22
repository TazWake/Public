<?php

include_once ("./db.inc");
?>

<html>
<head>
	<title>This site is being redeveloped</title>
</head>
<h1>Account Lookup Service</h1>
<h2>OmniCorp Limited - authorised access only</h2>
<hr>
<p>This service has been provided by IT Support to allow users to look up their passwords. Following recent issues is it being redeveloped and has limited functionality.</p>
<p>Thank you for your patience</p>

<h2>Password Lookup form</h2>

<form action="lookup.php" method="post">
<p>Username: <input type="text" name="name" /></p>
<input type="submit">
</form>


</html>
