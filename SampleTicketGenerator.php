<?php
// The following script is a part of 'TicketAuth' MediaWiki's extension.
// The script generates a sample ticket in a web link for authentication

$target = 'http://mywiki.com/w/index.php/Main_Page';
$secretCode = 'f36cb77394acdf45cbf725eddd53059e';
$user = 'Simon';
$password = md5( 'town' );
$name = 'Simon Sayler';
$email = 'simon@example.org';
$time = time();

$sign = md5(
	$user .
	( isset($password) ? $password : '' ) .
	( isset($name) ? $name : '' ) .
	( isset($email) ? $email : '' ) .
	$time .
	$secretCode
);

$link = $target .
	'?user=' . urlencode( $user ) .
	( isset($password) ? '&password=' . $password : '' ) .
	( isset($name) ? '&name=' . urlencode( $name ) : '' ) .
	( isset($email) ? '&email=' . urlencode( $email ) : '' ) .
	'&time=' . $time .
	'&sign=' . $sign;

echo '<!DOCTYPE html>
<html>
	<head>
		<meta http-equiv="content-type" content="text/html; charset=utf-8">
		<title>Sample Ticket Generator</title>
	</head>
	<body>
		<p>
			<br /><br />
			<a href="',$link,'">',$link,'</a>
			<br /><br />
		</p>
	</body>
</html>';