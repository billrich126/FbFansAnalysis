<?php
/**
 * Created by Cyril Lee.
 * Date: 2013/3/16
 * Time: 下午 8:53
 */
define("GETPAGE_FILE_ABSOLUTE_PATH", dirname(__FILE__));
require_once (GETPAGE_FILE_ABSOLUTE_PATH."/../variable.php");

function getUserPage($facebook){
    global $graphUrl;
    $limit = 5000;
    $offset = 0;
    $fields = "id,name";
    $user_pages_array = array();

    $apiQuery = "/me/accounts?limit=".$limit."&offset=".$offset."&fields=".$fields;
    try {
        $data = $facebook->api($apiQuery, 'GET');
        $user_pages_array = array_merge($user_pages_array, $data['data']);
        while(array_key_exists("paging", $data) && array_key_exists("next", $data['paging'])){
            $nextUrl = substr($data['paging']['next'], strlen($graphUrl));
            $data = $facebook->api($nextUrl, 'GET');
            $user_pages_array = array_merge($user_pages_array, $data['data']);
        }
        return $user_pages_array;
    } catch (FacebookApiException $e) {
        // If the user is logged out, you can have a
        // user ID even though the access token is invalid.
        // In this case, we'll get an exception, so we'll
        // just ask the user to login again here.
        $params = array(
            'scope' => 'user_about_me,email,user_likes,manage_pages,publish_stream,read_insights',
            'redirect_uri' => 'http://fb.odo.com.tw/FbFansAnalysis/index.php'
        );

        $loginUrl = $facebook->getLoginUrl($params);
        echo 'Please <a href="' . $loginUrl . '">login.</a>';
        //error_log($e->getType());
        //error_log($e->getMessage());
        error_log("getUserPage".$e);
    }

}

function getPageInfo($facebook, $id){
    $fields = "name,about,category";
    try {

        $page_info = $facebook->api("/".$id."?fields=".$fields, 'GET');
        $info = array();
        if(isset($page_info['name']))
            $info['name'] = $page_info['name'];
        if(isset($page_info['about']))
            $info['about'] = $page_info['about'];
        if(isset($page_info['category']))
            $info['category'] = $page_info['category'];
        return $info;

    } catch (FacebookApiException $e) {
        // If the user is logged out, you can have a
        // user ID even though the access token is invalid.
        // In this case, we'll get an exception, so we'll
        // just ask the user to login again here.
        $params = array(
            'scope' => 'user_about_me,email,user_likes,manage_pages,publish_stream,read_insights',
            'redirect_uri' => 'http://fb.odo.com.tw/FbFansAnalysis/index.php'
        );

        $loginUrl = $facebook->getLoginUrl($params);
        echo 'Please <a href="' . $loginUrl . '">login.</a>';
        //error_log($e->getType());
        //error_log($e->getMessage());
        error_log("getPageInfo".$e);
    }

}

function getPageAccessToken($facebook,$id){
    try {
        $pageAccessToken = 0;
        $user_pages = $facebook->api('/me/accounts', 'GET');
        //echo count($user_pages);

        foreach($user_pages['data'] as $page){
            //echo "<p>".$page['id']."   ".$page['access_token']."</p>";
            if($page['id']==$id){
                $pageAccessToken = $page['access_token'];
            }
        }
        $oldAccessToken = $facebook->getAccessToken();

        $getRefreshAccessTokenQuery = "/oauth/access_token?grant_type=fb_exchange_token&client_id=150815285092613&client_secret=cfe12caf76b6d0e7d4ff65f63e7758c4&fb_exchange_token=".$oldAccessToken;

        $refreshToken = $facebook->api($getRefreshAccessTokenQuery, 'GET');

        var_dump($refreshToken);

        return $pageAccessToken;

    } catch (FacebookApiException $e) {
        // If the user is logged out, you can have a
        // user ID even though the access token is invalid.
        // In this case, we'll get an exception, so we'll
        // just ask the user to login again here.
        $login_url = $facebook->getLoginUrl();
        echo 'Please <a href="' . $login_url . '">login.</a>';
        echo $e->getType();
        echo $e->getMessage();
    }
}

function calculatePostLikes($facebook, $post_array){
    global $graphUrl;
    global $fansOrderArray;
    global $postLikeWeight;
    global $postCommentWeight;
    global $CommentLikeWeight;
    global $limit;
    $post_like_array = array();
    try{
        foreach($post_array as $post){
            if (count($post['likes']['data']) != 0) {
                $data = $post['likes'];
                $post_like_array = array_merge($post_like_array, $data['data']);
                while ((count($data['data']) >= $limit) &&($data['paging']['next'] != null)) {
                    $nextUrl = substr($data['paging']['next'], strlen($graphUrl));
                    $data = $facebook->api($nextUrl, 'GET');
                    $post_like_array = array_merge($post_like_array, $data['data']);
                    error_log("Debug Message:calculatePostLikes:while");
                }
            }
        }
        foreach ($post_like_array as $like) {
            if (array_key_exists($like['id'], $fansOrderArray)) {
                $fansOrderArray[$like['id']]['score'] += $postLikeWeight;
            } else {
                $fansOrderArray[$like['id']] = array(
                    "name" => $like['name'],
                    "score" => $postLikeWeight
                );
            }
        }
    } catch (FacebookApiException $e) {
        $params = array(
            'scope' => 'user_about_me,email,user_likes,manage_pages,publish_stream,read_insights',
            'redirect_uri' => 'http://fb.odo.com.tw/FbFansAnalysis/index.php'
        );

        $loginUrl = $facebook->getLoginUrl($params);
        echo 'Please <a href="' . $loginUrl . '">login.</a>';
        //error_log($e->getType());
        //error_log($e->getMessage());
        error_log("calculatePostLikes".$e);
    }
}

function calculatePostAuthor($facebook, $post_array){
    global $graphUrl;
    global $fansOrderArray;
    global $postLikeWeight;
    global $postCommentWeight;
    global $CommentLikeWeight;
    global $limit;
    $comment_array = array();
    try{
        foreach($post_array as $post){
            if (count($post['comments']['data']) != 0) {
                $data = $post['comments'];
                $comment_array = array_merge($comment_array, $data['data']);
                while ((count($data['data']) >= $limit) &&($data['paging']['next'] != null)) {
                    $nextUrl = substr($data['paging']['next'], strlen($graphUrl));
                    $data = $facebook->api($nextUrl, 'GET');
                    $comment_array = array_merge($comment_array, $data['data']);
                    error_log("Debug Message:calculatePostAuthor:while");
                }
            }
        }
        foreach ($comment_array as $comment) {
            if (array_key_exists($comment['from']['id'], $fansOrderArray)) {
                $fansOrderArray[$comment['from']['id']]['score'] += $postCommentWeight;
            } else {
                $fansOrderArray[$comment['from']['id']] = array(
                    "name" => $comment['from']['name'],
                    "score" => $postCommentWeight
                );
            }
        }
        //var_dump($comment_array);
        calculateCommentLikes($facebook, $comment_array);
    } catch (FacebookApiException $e) {
        $params = array(
            'scope' => 'user_about_me,email,user_likes,manage_pages,publish_stream,read_insights',
            'redirect_uri' => 'http://fb.odo.com.tw/FbFansAnalysis/index.php'
        );

        $loginUrl = $facebook->getLoginUrl($params);
        echo 'Please <a href="' . $loginUrl . '">login.</a>';
        //error_log($e->getType());
        //error_log($e->getMessage());
        error_log("calculatePostAuthor".$e);
    }
}

function calculateCommentLikes($facebook, $comment_array){
    global $graphUrl;
    global $fansOrderArray;
    global $postLikeWeight;
    global $postCommentWeight;
    global $commentLikeWeight;
    global $limit;
    $comment_like_array = array();
    try{
        foreach($comment_array as $comment){
            if (count($comment['likes']['data']) != 0) {
                $data = $comment['likes'];
                $comment_like_array = array_merge($comment_like_array, $data['data']);
                while ((count($data['data']) >= $limit) &&($data['paging']['next'] != null)) {
                    $nextUrl = substr($data['paging']['next'], strlen($graphUrl));
                    $data = $facebook->api($nextUrl, 'GET');
                    $comment_like_array = array_merge($comment_like_array, $data['data']);
                    error_log("Debug Message:calculateCommentLikes:while");
                }
            }
        }
        //var_dump($comment_like_array);
        foreach ($comment_like_array as $like) {
            if (array_key_exists($like['id'], $fansOrderArray)) {
                $fansOrderArray[$like['id']]['score'] += $commentLikeWeight;
            } else {
                $fansOrderArray[$like['id']] = array(
                    "name" => $like['name'],
                    "score" => $commentLikeWeight
                );
            }
        }
    } catch (FacebookApiException $e) {
        $params = array(
            'scope' => 'user_about_me,email,user_likes,manage_pages,publish_stream,read_insights',
            'redirect_uri' => 'http://fb.odo.com.tw/FbFansAnalysis/index.php'
        );

        $loginUrl = $facebook->getLoginUrl($params);
        echo 'Please <a href="' . $loginUrl . '">login.</a>';
        //error_log($e->getType());
        //error_log($e->getMessage());
        error_log("calculateCommentLikes".$e);
    }
}

function fansLikeStatistics($facebook, $pageID, $fromTimeStamp, $toTimeStamp){
    global $graphUrl;
    global $limit;
    $offset = 0;
    //$fields = "id,name";
    $post_array = array();
    //$pageAccessToken = getPageAccessToken($facebook, $pageID);
    try {

        $apiQuery = "/".$pageID."/feed?limit=".$limit."&offset=".$offset."&since=".$fromTimeStamp."&until=".$toTimeStamp."&fields=likes.limit(".$limit.").fields(id,name),comments.limit(".$limit.").fields(from.limit(".$limit.").fields(id,name),likes.limit(".$limit.").fields(id,name))";
        //echo "<p>".$apiQuery."</p>";
        $data = $facebook->api($apiQuery, 'GET');
        $post_array = $data['data'];
        if(count($post_array) != 0){
            calculatePostLikes($facebook, $post_array);
            calculatePostAuthor($facebook, $post_array);
        }
        else{
            return 0;
        }
        while((count($data['data']) >= $limit) && ($data['paging']['next'] != null)){
            $offset += $limit;
            /*$apiQuery = "/".$pageID."?fields=feed.limit(".$limit.").offset(".$offset.").fields(likes.limit(".$limit.").fields(id,name),comments.limit(".$limit.").fields(from.limit(".$limit."),likes.limit(".$limit.").fields(id,name))).since(".$fromTimeStamp.").until(".$toTimeStamp.")";*/
            $apiQuery = "/".$pageID."/feed?limit=".$limit."&offset=".$offset."&since=".$fromTimeStamp."&until=".$toTimeStamp."&fields=likes.limit(".$limit.").fields(id,name),comments.limit(".$limit.").fields(from.limit(".$limit."),likes.limit(".$limit.").fields(id,name))";
            $data = $facebook->api($apiQuery, 'GET');
            $post_array = $data['data'];
            //var_dump($post_array);
            if(count($post_array) != 0){
                calculatePostLikes($facebook, $post_array);
                calculatePostAuthor($facebook, $post_array);
            }
            error_log("Debug Message:fansLikeStatistics:while");
        }
        return 1;

    } catch (FacebookApiException $e) {
        // If the user is logged out, you can have a
        // user ID even though the access token is invalid.
        // In this case, we'll get an exception, so we'll
        // just ask the user to login again here.
        $params = array(
            'scope' => 'user_about_me,email,user_likes,manage_pages,publish_stream,read_insights',
            'redirect_uri' => 'http://fb.odo.com.tw/FbFansAnalysis/index.php'
        );

        $loginUrl = $facebook->getLoginUrl($params);
        echo 'Please <a href="' . $loginUrl . '">login.</a>';
        //error_log($e->getType());
        //error_log($e->getMessage());
        error_log("fansLikeStatistics".$e);
    }
}

?>