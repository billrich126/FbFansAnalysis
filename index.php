<?php

define("INDEX_FILE_ABSOLUTE_PATH", dirname(__FILE__));

require_once (INDEX_FILE_ABSOLUTE_PATH . "/variable.php");
require_once (INDEX_FILE_ABSOLUTE_PATH . "/facebook-php-sdk/src/facebook.php");
require_once (INDEX_FILE_ABSOLUTE_PATH . "/get-facebook-graph/getpage.php");
require_once (INDEX_FILE_ABSOLUTE_PATH . "/ExcelWriter.php");
require_once (INDEX_FILE_ABSOLUTE_PATH . "/Excel-Classes/PHPExcel.php");
require_once (INDEX_FILE_ABSOLUTE_PATH . "/Excel-Classes/PHPExcel/Writer/Excel2007.php");
require_once (INDEX_FILE_ABSOLUTE_PATH . "/Excel-Classes/PHPExcel/Writer/Excel5.php");


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

if ($user) {
    $params = array( 'next' => 'http://fb.odo.com.tw/FbFansAnalysis/logout.php' );
    $logoutUrl = $facebook->getLogoutUrl($params);
} else {
    //header('Location:login.php');
    $url = "login.php";
    echo "<script type='text/javascript'>";
    echo "window.location.href='$url'";
    echo "</script>";
}

?>

<html xmlns="http://www.w3.org/1999/html">
<head>

    <!--<meta http-equiv="pragma" content="no-cache"/>
    <meta http-equiv="cache-control" content="no-cache"/>
    <meta http-equiv="expires" content="0"/>-->
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8"/>
    <title>FbFansAnalysis</title>

    <!-- this index.php's css-->
    <link rel="stylesheet" type="text/css" href="css/main.css" />
    <!---->

    <link rel="stylesheet" type="text/css" href="Timer-jQuery/anytime.css"/>
    <link rel="stylesheet" type="text/css"
          href="jquery-ui-1.10.0.custom/development-bundle/themes/ui-lightness/jquery-ui.css">
    <!--clock ui-->
    <script src="jQuery/jquery-1.9.0.js"></script>
    <!-- if jQuery 1.9+ -->
    <script src="Timer-jQuery/jquery-migrate-1.0.0.js"></script>
    <script src="Timer-jQuery/anytime.js"></script>
    <script src="Timer-jQuery/anytimetz.js"></script>
    <script src="Timer-jQuery/timer.js"></script>

    <style type="text/css">
        #rangeTimeFrom, #rangeTimeTo {
            background-image: url("pic/calendar.png");
            background-position: right center;
            background-repeat: no-repeat;
        }
    </style>
    <!--clock ui-->

    <!--jQuery menu ui-->
    <style>
        .ui-menu {
            width: 260px;
        }
    </style>

    <script src="jquery-ui-1.10.0.custom/js/jquery-ui-1.10.0.custom.js"></script>
    <!--jQuery menu ui-->

    <!--
    <script>

        window.fbAsyncInit = function () {

            // init the FB JS SDK
            FB.init({
                appId:'<?php echo $facebook->getAppID() ?>', // App ID from the App Dashboard
                channelUrl:'http://www.tainantravel.site88.net/FbFansAnalysis/channel.html', // Channel File for x-domain communication
                status:true, // check the login status upon init?
                cookie:true, // set sessions cookies to allow your server to access the session?
                xfbml:true  // parse XFBML tags on this page?
            });

            // Additional initialization code such as adding Event Listeners goes here


            FB.Event.subscribe('auth.logout', function (response) {
                window.location.reload();
            });

        };

        // Load the SDK's source Asynchronously
        // Note that the debug version is being actively developed and might
        // contain some type checks that are overly strict.
        // Please report such bugs using the bugs tool.
        (function (d, debug) {
            var js, id = 'facebook-jssdk', ref = d.getElementsByTagName('script')[0];
            if (d.getElementById(id)) {
                return;
            }
            js = d.createElement('script');
            js.id = id;
            js.async = true;
            js.src = "//connect.facebook.net/zh_TW/all" + (debug ? "/debug" : "") + ".js";
            ref.parentNode.insertBefore(js, ref);
        }(document, false));

        function logout() {
            FB.logout(function (response) {
                console.log('User is now logged out');
            });
        }

    </script>
-->
</head>

        <!--<body <?php if (isset($_GET["pageId"])): ?> onload='initTime("#rangeTimeTo")';<?php endif?>>-->
<body>
<div id="container">
    <div id="fb-root"></div>

    <div id="top">
        <div id="page-info">
            <?php
            if (isset($_GET["pageId"])) {
                ?>
                <div id="page-pic">
                    <img src="http://graph.facebook.com/<?php echo $_GET["pageId"];?>/picture?type=large"
                     alt="page picture">
                </div>
                <div id="page-txt">
                    <?php
                    $info = getPageInfo($facebook, $_GET["pageId"]);
                    if (isset($info['name'])){
                        $groupName = $info['name'];
                        echo  "<p>" . $info['name'] . "</p>";
                    }
                    if (isset($info['about']))
                        echo  "<p>" . $info['about'] . "</p>";
                    if (isset($info['category']))
                        echo  "<p>" . $info['category'] . "</p>";
                    ?>
                </div>
                <?php
            }
            ?>
        </div>
        <div id="top-right">
        <div id="logout-button">
            <a href="<?php echo $logoutUrl;?>" class="img">
                <img src="pic/facebook-logout-buttons.jpg" border="0"/>
            </a>
        </div>
        <div id="excel-report" style="visibility:hidden">
            <p>Download!</p>
                <span id="report1">
                    <a href="excel-report/fansAnalysis.xlsx">Excel 2007 report</a>
                </span>

                <span id="report2">
                    <a href="excel-report/fansAnalysis.xls">Excel 2003 report</a>
                </span>
        </div>
        </div>
    </div> <!--top-->

    <div id="leftnav">
        <!--avoid the server to call getUserPage when user doesn't login
     , because even we redirect to the login.php by javascript, the following
     code is still executed.-->
        <?php
        if ($user) {
            $pageName_array = getuserPage($facebook);
            if (count($pageName_array) == 0) {
                echo "You don't have any page!";
            } else {
                echo "<ul id=\"menu\">";
                echo "<li><a>Your Fan Pages!</a></li>";
                foreach ($pageName_array as $page) {
                    echo "<li><a href=\"index.php?pageId=" . $page['id'] . "\">" . $page['name'] . "</a></li>";
                }
                echo "</ul>";
            }
        }
        ?>

        <!--avoid the server to print this script when user doesn't login
        , because even we redirect to the login.php by javascript, the following
        code is still executed.-->
        <?php if ($user) { ?>
        <script>
            $("#menu").menu();
        </script>
        <?php } ?>
    </div><!--<div id="leftnav">-->


    <div id="rightnav">
        <div id="time-choose">
            <?php
            if (isset($_GET["pageId"])):
                ?>
                <form name="configForm" action="index.php" method="GET">
                    <p>From: <input type="text" id="rangeTimeFrom" name="fromTime" size="20"/></p>
                    <p>To: <input type="text" id="rangeTimeTo" name="toTime" size="20"/></p>
                    <input type="hidden" name="pageId" value="<?php echo $_GET["pageId"]?>">
                    <p>
                    <input type="button" id="rangeTimeToday" value="today"/>
                    <!--<input type="button" id="rangeTimeClear" value="clear"/>-->
                    </p>
                    <p>評論權重:<input type="text" id="weight1" name="commentWeight"
                                value="<?php if (isset($_GET["commentWeight"])) echo $_GET["commentWeight"]; else echo "3";?>"
                                size="3"/></p>
                <!--<p>分享權重:<input type="text" id="weight2" name="shareWeight"
                                value="<?php if (isset($_GET["shareWeight"])) echo $_GET["shareWeight"]; else echo "3";?>"
                                size="3"/></p>-->
                    <p>按讚權重:<input type="text" id="weight3" name="likeWeight"
                                value="<?php if (isset($_GET["likeWeight"])) echo $_GET["likeWeight"]; else echo "2";?>"
                                size="3"/></p>
                    <p>評論按讚權重:<input type="text" id="weight4" name="commentLikeWeight"
                                  value="<?php if (isset($_GET["commentLikeWeight"])) echo $_GET["commentLikeWeight"]; else echo "1";?>" size="3"/></p>
                    <input type="button" value="Run!" onClick="checkForm();">
                </form>
                <script type="text/javascript">
                    function checkForm() {
                        var pass = true;
                        if (configForm.commentWeight.value == "") {
                            alert("未輸入評論權重");
                            pass = false;
                        }
                    /*  if (configForm.shareWeight.value == "") {
                            alert("未輸入分享權重");
                            pass = false;
                        }*/
                        if (configForm.likeWeight.value == "") {
                            alert("未輸入按讚權重");
                            pass = false;
                        }
                        if (configForm.commentLikeWeight.value == "") {
                            alert("未輸入評論按讚權重");
                            pass = false;
                        }
                        if (pass)
                            configForm.submit();
                    }
                </script>
                <script>
                    timer("#rangeTimeFrom", "#rangeTimeTo", "#rangeTimeToday", "#rangeTimeClear");
                        <?php if (isset($_GET["fromTime"]) && isset($_GET["toTime"])): ?>
                    initUserTime("#rangeTimeFrom", "#rangeTimeTo",<?php echo "\"" . $_GET["fromTime"] . "\"";?>,<?php echo "\"" . $_GET["toTime"] . "\"";?>);
                        <?php else: ?>
                    initDefaultTime("#rangeTimeTo");
                        <?php endif;?>
                </script>
                <?php
            endif;
            ?>
        </div>
    </div><!--<div id="rightnav">-->
    <div id="content">
        <?php
        if (isset($_GET["fromTime"]) && isset($_GET["toTime"])) {
            $fromTimeStamp = strtotime($_GET["fromTime"] . ":00+08:00");
            $toTimeStamp = strtotime($_GET["toTime"] . ":59+08:00");
            //echo "</br>" .$fromTimeStamp . "</br>" . $toTimeStamp;
            $postLikeWeight = $_GET["likeWeight"];
            $postCommentWeight = $_GET["commentWeight"];
            $commentLikeWeight = $_GET["commentLikeWeight"];
            $haveResult = fansLikeStatistics($facebook, $_GET["pageId"], $fromTimeStamp, $toTimeStamp);
            if (!$haveResult)
                echo "<p>There are no any posts between time you select!</p>";
            else {
                if (count($fansOrderArray) == 0) {
                    echo "<p>There are no any users who like or comment the posts in this page!</p>";
                } else {
                    //var_dump($fansOrderArray);
                    uasort($fansOrderArray, 'rankCompare');
                    echo "<table>";
                    $i = 0;
                    foreach ($fansOrderArray as $fansID => $fansInfo) {
                        if ($i % 5 == 0) echo "<tr>";
                        echo "<td><img src=\"http://graph.facebook.com/" . $fansID . "/picture?width=75&height=75\" alt=\"page picture\"><p>" . $fansInfo['name'] . "</p><p>" . $fansInfo['score'] . "</p></td>";
                        if ($i % 5 == 4) echo "</tr>";
                        $i++;
                    }
                    echo "</table>";
                    // writer the statistic to excel file.
                    $excelWriter = new ExcelWriter($groupName, $_GET["fromTime"], $_GET["toTime"], $fansOrderArray);
                    $excelWriter -> writeToFile();
                    echo "<script type='text/javascript'>";
                    echo "document.getElementById('excel-report').style.visibility = 'visible';";
                    echo "</script>";
                }
            }
        }
        else{
            echo "<p>please select the time and run for the result.</p>";
        }
        ?>

    </div><!--<div id="content">-->
    <div id="footer"></div><!--<div id="footer">-->
</div>
</body>
</html>

<?php
function rankCompare($a, $b){
    if($a['score'] == $b['score'])
        return 0;
    else{
        return ($a['score'] > $b['score']) ? -1 : 1;
    }
}
?>
