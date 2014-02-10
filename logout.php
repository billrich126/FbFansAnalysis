<?php
/**
 * Created by JetBrains PhpStorm.
 * User: cyril928
 * Date: 2013/1/22
 * Time: 下午 10:38
 * To change this template use File | Settings | File Templates.
 */
require 'variable.php';
require 'facebook-php-sdk/src/facebook.php';

$facebook = new Facebook(array(
    'appId' => '150815285092613',
    'secret' => 'cfe12caf76b6d0e7d4ff65f63e7758c4',
));

/*  after logout from facebook server, manually set cookie expired
    and destroy the session to clear the login info of user*/
setcookie('fbs_'.$facebook->getAppId(), '', time()-100, '/', '');
//session_destroy();
$facebook->destroySession();

//header('Location:login.php');
$url = "login.php";
echo "<script type='text/javascript'>";
echo "window.location.href='$url'";
echo "</script>";
?>