<?php
/**
 * Plugin Name: tripointhosting-security
 * Description: This plugin adds multiple security enhancements for
 *              websites hosted at tripointhosting.com
 *
 * Author:      Byron DeLaMatre
 * License:     GNU General Public License v3 or later
 * License URI: http://www.gnu.org/licenses/gpl-3.0.html
 */

// Basic security, prevents file from being loaded directly.
defined('ABSPATH') or die('&nbsp;');

/**
 * Adjust IP Address
**/

function tripoint_get_ip_address(){

    // Grab the real IP address
    if ( isset($_SERVER['HTTP_X_REAL_IP'])
            && empty($_SERVER['HTTP_X_REAL_IP']) === false ) {
        $ip_address = $_SERVER['HTTP_X_REAL_IP'];
    } elseif( isset($_SERVER['HTTP_X_FORWARDED_FOR'])
                     && empty($_SERVER['HTTP_X_FORWARDED_FOR']) === false ) {
        $ip_address = $_SERVER['HTTP_X_FORWARDED_FOR'];
    }else {
        $ip_address = $_SERVER['REMOTE_ADDR'];
    }

    // If multiple IP addresses, extract the first one
    $ip_addresses = explode(',', $ip_address);

    if( is_array($ip_addresses) ){
        $ip_address = $ip_addresses[0];
    }

    return $ip_address;

}

// Set PHP globals
$_SERVER['REMOTE_ADDR'] = tripoint_get_ip_address();

/**
 * Add authentication logging
**/

if (defined('TRIPOINT_LOG_DIR') == false){
    define('TRIPOINT_LOG_DIR', ABSPATH . '../logs');
}

if (defined('TRIPOINT_LOG_PATH') == false){
    define('TRIPOINT_LOG_PATH', TRIPOINT_LOG_DIR . '/authentication_log');
}


// https://codex.wordpress.org/Plugin_API/Action_Reference/wp_login
add_action('wp_login', 'tripoint_login_succeeded', 10, 2);

// https://codex.wordpress.org/Plugin_API/Action_Reference/wp_login_failed
add_action('wp_login_failed', 'tripoint_login_failed', 10, 2);

// Example query to lookup session from table
// SELECT user_id, meta_value FROM wp_usermeta JOIN wp_users ON wp_usermeta.user_id = wp_users.`ID` WHERE meta_key='session_tokens' AND wp_users.user_login = 'username';

function tripoint_login_succeeded( string $username, WP_User $user ){

    // verify directory
    if(is_dir(TRIPOINT_LOG_DIR) === false){
        // note: we won't attempt to create the path
        //       in case the site is moved to
        //       non-compatible hosting
        return;
    }

    // get ip address
    $ip_address = tripoint_get_ip_address();

    // sanitize username
    $username = sanitize_user($username);

    // message
    $log_message = addslashes("WordPress successful login for {$username} from {$ip_address}");

    // line
    // format: application ip_address status username message
    $log_text = "\"wordpress\" \"{$ip_address}\" \"success\" \"{$username }\" \"{$log_message}\"" . PHP_EOL;

    file_put_contents(TRIPOINT_LOG_PATH, $log_text, FILE_APPEND);

}

function tripoint_login_failed( string $username , WP_Error $error ){

    // verify directory
    if(is_dir(TRIPOINT_LOG_DIR) === false){
        // note: we won't attempt to create the path
        //       in case the site is moved to
        //       non-compatible hosting
        return;
    }

    // get ip address
    $ip_address = tripoint_get_ip_address();

    // sanitize username
    $username = sanitize_user($username);

    // message
    $log_message = addslashes("WordPress failed login for {$username} from {$ip_address}");

    // line
    // format: application ip_address status username message
    $log_text = "\"wordpress\" \"{$ip_address}\" \"fail\" \"{$username }\" \"{$log_message}\"" . PHP_EOL;

    file_put_contents(TRIPOINT_LOG_PATH, $log_text, FILE_APPEND);

}

