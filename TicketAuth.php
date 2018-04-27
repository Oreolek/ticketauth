<?php
/**
 * Ticket Authentication 1.13
 * https://www.mediawiki.org/wiki/Extension:Ticket_Authentication
 * This MediaWiki extension creates accounts and authenticates users using simple ticket validation mechanism.
 * Ticket is a special web link which is issued by trusted external site and then validated by this MediaWiki extension.
 * Copyright (c) Iaroslav Vassiliev <codedriller@gmail.com>, 2014-2017, GNU GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html)
 */


/*
// Fill up and add the following global variables to LocalSettings.php MediaWiki's file:

// Secret key, arbitrary string.
$wgTktAuth_SecretKey = 'f36cb77394acdf45cbf725eddd53059e';
// Ticket expiration time (in minutes)
$wgTktAuth_TicketExpiryMinutes = 10;
// Allow user to change password (true/false). If password hash was not provided in ticket's body,
// a user will not be able to log into MediaWiki directly from a login page unless this option
// is set to true and unless the user will reset the password manually
$wgTktAuth_AllowPasswordChange = true;
// Path to this file, relative to MediaWiki installation
require_once("$IP/extensions/TicketAuth/TicketAuth.php");
 */

/*
Ticket format:
http://mywiki.com/w/index.php/Main_Page
?user=Simon
&password=7198cda575b51b68a0dc83f5d66c2aee
&name=Simon+Sayler
&email=simon%40example.org
&time=1389005243
&sign=4522098027f3af0e4e19340c84224ed6 
 */


$wgExtensionCredits['other'][] = array (
  'name' => 'Ticket Authentication',
  'author' => 'Iaroslav Vassiliev <codedriller@gmail.com>',
  'description' => 'Authenticates users using simple web ticket validation mechanism',
  'url' => 'https://www.mediawiki.org/wiki/Extension:Ticket_Authentication',
  'version' => 1.13,
  'path' => __FILE__
);

$wgHooks['UserLoadFromSession'][] = 'efTktAuth_OnUserLoadFromSession';
$wgHooks['PrefsPasswordAudit'][] = 'efTktAuth_OnPrefsPasswordAudit';
$wgHooks['SpecialPasswordResetOnSubmit'][] = 'efTktAuth_OnSpecialPasswordResetOnSubmit';
$wgHooks['UserLoginMailPassword'][] = 'efTktAuth_OnUserLoginMailPassword';

function efTktAuth_OnUserLoadFromSession ( $user, &$result )
  // $user: user object being loaded
  // &$result: set this to a boolean value to abort the normal authentication process
{
  global $wgRequest, $wgUser, $wgContLang, $wgOut;

  $username = $wgRequest->getVal( 'user' );
  if ( $username == null || $username == '' )
    return false;

  $signature = $wgRequest->getVal( 'sign', '' );
  $timestamp = $wgRequest->getInt( 'time', 0 );
  if ( $signature == '' || $timestamp == 0 )
    return false;

  $realName = $wgRequest->getVal( 'name', '' );
  $email = $wgRequest->getVal( 'email', '' );
  $password = $wgRequest->getVal( 'password', '' );

  // check if user is not already logged in
  if ($wgUser->isLoggedIn())
    return false;

  if ( !isset( $GLOBALS['wgTktAuth_SecretKey'] ) )
    $error = 'TicketAuth: wgTktAuth_SecretKey required global variable is not set.';
  if ( !isset( $GLOBALS['wgTktAuth_TicketExpiryMinutes'] ) )
    $error = 'TicketAuth: wgTktAuth_TicketExpiryMinutes required global variable is not set.';
  if ( isset( $error ) ) {
    wfDebug( $error . "\n" );
    die( $error );
  }

  if ( $email != '' && !Sanitizer::validateEmail( $email ) ) {
    $error = 'TicketAuth: Invalid e-mail address was provided.';
    wfDebug( $error . "\n" );
    die( $error );
  }

  if ( $timestamp + ((int) $GLOBALS['wgTktAuth_TicketExpiryMinutes']) * 60 < time() ) {
    $error = 'TicketAuth: Provided ticket has expired. ';
    wfDebug( $error . "\n" );
    die( $error . 'Please, refresh the web page that has generated this link and retry.' );
  }

  if ( $password != '' && !preg_match( '/^[0-9a-f]{32}$/i', $password ) ) {
    $error = 'TicketAuth: Invalid password MD5 hash was provided.';
    wfDebug( $error . "\n" );
    die( $error );
  }
  if ( $password != '' && isset( $wgPasswordSalt ) ) {
    $error = 'TicketAuth: Transferring password hash is incompatible with ' .
      '$wgPasswordSalt setting.';
    wfDebug( $error . "\n" );
    die( $error );
  }

  $validSignature = md5(
    $username .
    ( $password == null ? '' : $password ) .
    ( $realName == null ? '' : $realName ) .
    ( $email == null ? '' : $email ) .
    $timestamp .
    $GLOBALS['wgTktAuth_SecretKey']
  );
  if ( $signature != $validSignature ) {
    $error = 'TicketAuth: Ticket signature is invalid.';
    wfDebug( $error . "\n" );
    die( $error );
  }

  $username = User::getCanonicalName( $username, 'creatable' );
  if ( $username === false ) {
    $error = 'TicketAuth: Provided username is not valid for MediaWiki.';
    wfDebug( $error . "\n" );
    die( $error );
  }

  $user = User::newFromName( $username );
  if ( !$user->getID() ) {
    wfDebug( "TicketAuth: Creating new user account.\n" );
    $userInfo = array();
    if ( $realName != '' ) {
      $userInfo['real_name'] = $realName;
    }
    if ( $email != '' ) {
      $userInfo['email'] = $email;
      $userInfo['email_authenticated'] = wfTimestampNow();
    }
    if ( $password != '' ) {
      $userInfo['password'] = $password;    // incompatible with $wgPasswordSalt
    }
    $user = User::createNew( $username, $userInfo );
    if ( !$user ) {
      $error = 'TicketAuth: Could not create user.';
      wfDebug( $error . "\n" );
      die( $error );
    }
    $user->setOption( 'TicketAuth', true );
    $user->saveSettings();
    if ( session_id() == '' ) {
      wfSetupSession();
    }
    $user->setCookies();
    $wgUser = $user;
    $wgOut->getContext()->setUser( $user );
    wfRunHooks( 'AddNewAccount', array( $user, false ) );
    $user->addNewUserLogEntry( 'autocreate', 'TicketAuth' );
  } else {
    wfDebug( "TicketAuth: Logging user in.\n" );
    if ( !isset( $GLOBALS['wgTktAuth_AllowLoginAll'] ) || $GLOBALS['wgTktAuth_AllowLoginAll'] === false ) {
      if ( !$user->getBoolOption( 'TicketAuth' ) ) {
        $error = 'TicketAuth: User\'s account with this login name already exists and ' .
          'it was not created by TicketAuth. Can\'t authenticate.';
        wfDebug( $error . "\n" );
        die( $error );
      }
    }
    if ( $realName != '' ) {
      $user->setRealName( $realName );
    }
    if ( $email != '' ) {
      $user->setEmail( $email );
      $user->mEmailAuthenticated = wfTimestampNow();
    }
    if ( $password != '' ) {
      $user->mPassword = $password;    // incompatible with $wgPasswordSalt
    }
    $user->saveSettings();
    if ( session_id() == '' ) {
      wfSetupSession();
    }
    $user->setCookies();
    $wgUser = $user;
    $wgOut->getContext()->setUser( $user );
  }

  $result = true;
  return true;
}

function efTktAuth_OnPrefsPasswordAudit ( $user, $newPass, $error )
  // $user: User (object) changing his password
  // $newPass: new password
  // $error: error (string) 'badretype', 'wrongpassword', 'error' or 'success'
{
  if ( !isset( $GLOBALS['wgTktAuth_AllowPasswordChange'] ) ) {
    $error = 'TicketAuth: wgTktAuth_AllowPasswordChange required global variable is not set.';
    wfDebug( $error . "\n" );
    die( $error );
  }

  if ( $GLOBALS['wgTktAuth_AllowPasswordChange'] === true )
    return true;

  if ( !$user->getBoolOption( 'TicketAuth' ) )
    return true;

  throw new PasswordError(
    ( function_exists( 'wfMsg' )
    ? wfMsg( 'resetpass_forbidden' )
    : wfMessage( 'resetpass_forbidden' )->text() 
  ) . ' <Extension:Ticket Authentication>' 
);

  return false;
}

function efTktAuth_OnSpecialPasswordResetOnSubmit ( $users, $data, &$error )
  // Hook available from version 1.18.0
  // $users: array of User objects
  // $data: array of data submitted by the user
  // &$error: string, error code (message name) used to describe to error (out parameter).
  //     The hook needs to return false when setting this, otherwise it will have no effect.
{
  if ( !isset( $GLOBALS['wgTktAuth_AllowPasswordChange'] ) ) {
    $error = 'TicketAuth: wgTktAuth_AllowPasswordChange required global variable is not set.';
    wfDebug( $error . "\n" );
    die( $error );
  }

  if ( $GLOBALS['wgTktAuth_AllowPasswordChange'] === true )
    return true;

  foreach ( $users as $user ) {
    if ( $user->getBoolOption( 'TicketAuth' ) ) {
      $error =
        ( function_exists( 'wfMsg' )
        ? wfMsg( 'resetpass_forbidden' )
        : wfMessage( 'resetpass_forbidden' )->text() 
      ) . ' <Extension:Ticket Authentication>';
      return false;
    }
  }

  return true;
}

function efTktAuth_OnUserLoginMailPassword ( $username, &$error )
  // Hook removed in version 1.18.0
  // $name: the username to email the password of
  // &$error: out-param - the error message to return
{
  if ( !isset( $GLOBALS['wgTktAuth_AllowPasswordChange'] ) ) {
    $error = 'TicketAuth: wgTktAuth_AllowPasswordChange required global variable is not set.';
    wfDebug( $error . "\n" );
    die( $error );
  }

  if ( $GLOBALS['wgTktAuth_AllowPasswordChange'] === true )
    return true;

  $user = User::newFromName( $username );
  if ( !$user->getBoolOption( 'TicketAuth' ) )
    return true;

  $error =
    ( function_exists( 'wfMsg' )
    ? wfMsg( 'resetpass_forbidden' )
    : wfMessage( 'resetpass_forbidden' )->text() 
  ) . ' <Extension:Ticket Authentication>';

  return false;
}
