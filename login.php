<?php
require 'variable.php';
require 'facebook-php-sdk/src/facebook.php';
require 'get-facebook-graph/getpage.php';


$facebook = new Facebook(array(
    'appId' => '150815285092613',
    'secret' => 'cfe12caf76b6d0e7d4ff65f63e7758c4',
));


// Get User ID
$user = $facebook->getUser();

if ($user) {
    try {
        // Proceed knowing you have a logged in user who's authenticated.
        $user_profile = $facebook->api('/me');
    } catch (FacebookApiException $e) {
        error_log($e);
        $user = null;
    }
}

if($user) {

    $url = "index.php";
    echo "<script type='text/javascript'>";
    echo "window.location.href='$url'";
    echo "</script>";

}else {
    $params = array(
        'scope' => 'user_about_me,email,user_likes,manage_pages,publish_stream,read_insights,read_stream',
        'redirect_uri' => 'http://fb.odo.com.tw/FbFansAnalysis/index.php'
    );

    $loginUrl = $facebook->getLoginUrl($params);
}

?>

<html>

<head>

    <!--<meta http-equiv="pragma" content="no-cache"/>
    <meta http-equiv="cache-control" content="no-cache"/>
    <meta http-equiv="expires" content="0"/>-->
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
    <title>FbFansAnalysis</title>

    <style type="text/css">
        #login-button {
            display: block;
            margin: auto ;
            width:70%;
        }
        .img {
            display: block;
            margin: auto ;
            width:35%;
        }

    </style>




</head>

<body>
<div id="main-frame">
    <div id="fb-root"></div>

    <div id="login-button">
        <a href="<?php echo $loginUrl; ?>" class="img">
            <img src="pic/facebook-login-buttons.png" border="0"/>
        </a>
    </div>

</div>
</body>
</html>
