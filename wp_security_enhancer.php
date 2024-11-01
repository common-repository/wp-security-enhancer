<?php
/*
Plugin Name: WP Security Enhancer
Plugin URI: http://www.radio4seo.de
Description: Enhances the wordpress security
Version: 1.0
Author: Jens Altmann
Author URI: http://gefruckelt.de
License: GPLv3
*/

class WPSecurityEnhancer
{
  function WPSecurityEnhancer()
  {
    register_activation_hook(__FILE__, array($this, 'install'));
    register_deactivation_hook(__FILE__, array($this, 'uninstall'));
    $this->addActions();
  }
  
  function install()
  {
    $files = $this->scanFiles();
    update_option('WPSecurityEnhancer-filelist', $files);
    
    wp_schedule_event(time(), 'hourly', 'hook_WPSecurityEnhancer');
  }
  
  function uninstall()
  {
    //wp_clear_scheduler_hook('hook_WPSecurityEnhancer');
  }
  
  function addActions()
  {
    add_filter('authenticate', array($this, 'checkLogin'), 9999, 3);
    add_action('wp_login', array($this, 'loginSuccess'));
    add_action('wp_login_failed', array($this, 'loginFailed'));
    
    add_action('hook_WPSecurityEnhancer', array($this, 'scan'));
  }
  
  function checkLogin($user, $loginUser, $loginPass)
  {
    if (!username_exists($loginUser))
      return $user;
      
    $userData = get_user_by('login', $loginUser);
    
    $loginCount = get_user_meta($userData->ID, 'login_count', true);
    $lastLoginTime = get_user_meta($userData->ID, 'last_login_time', true);
    
    if ($loginCount >= 5 && $lastLoginTime + (60*10) > time())
    {
      return null;
    }
    
    return $user;
  }
  
  function loginSuccess($loginUser)
  {
    $userData = get_user_by('login', $loginUser);
    
    $loginCount = get_user_meta($userData->ID, 'login_count', true);
    $lastLoginTime = get_user_meta($userData->ID, 'last_login_time', true);
    
    if ($loginCount >= 5 && $lastLoginTime + (60*10) > time())
    {
      return;
    }
    
    update_user_meta($userData->ID, 'login_count', 0);
    update_user_meta($userData->ID, 'last_login_time', time());
  }
  
  function loginFailed($loginUser)
  {
    if (!username_exists($loginUser))
      return;
      
    $userData = get_user_by('login', $loginUser); 
    $loginCount = get_user_meta($userData->ID, 'login_count', true);
    if ($loginCount === false)
      $loginCount = 0;
      
    update_user_meta($userData->ID, 'login_count', $loginCount+1);
    update_user_meta($userData->ID, 'last_login_time', time());    
  }
  
  function compareFileArrays($files, $old_files)
  {
    if ($old_files !== false)
    {
      $newFiles = array();
      $changedFiles = array();
      $deleteFiles = array();
      
      foreach ($files as $hash => $value)
      {
        if (!isset($old_files[$hash]))
        {
          $newFiles[] = $value['uri'];
          continue;
        }
        else
        {
          if ($old_files[$hash]['hash'] != $value['hash'])
            $changedFiles[] = $value['uri'];
        }
      }
      
      foreach ($old_files as $hash => $value)
      {
        if (!isset($files[$hash]))
        {
          $deleteFiles[] = $value['uri'];
        }
        
      }
      
      if (count($newFiles) > 0
          || count($changedFiles) > 0
          || count($deleteFiles) > 0)
      {
        $message = '';
        $message .= '<h1>Es wurden Datei im Dateisystem ge&auml;ndert</h1>';
        
        if (count($newFiles) > 0)
        {
          $message .= '<h1>Neue Dateien</h1>';
          $message .= '<table>';
          $message .= '<tr><td>Dateiname</td></tr>';
          foreach ($newFiles as $file)
          {
            $message .= '<tr><td>'.$file.'</td></tr>';
          }
          $message .= '</table>';
        }
        
        if (count($changedFiles) > 0)
        {
          $message .= '<h1>Ge&auml;nderte Dateien</h1>';
          $message .= '<table>';
          $message .= '<tr><td>Dateiname</td></tr>';
          foreach ($changedFiles as $file)
          {
            $message .= '<tr><td>'.$file.'</td></tr>';
          }
          $message .= '</table>';
        }
        
        if (count($deleteFiles) > 0)
        {
          $message .= '<h1>Gel&ouml;schte Dateien</h1>';
          $message .= '<table>';
          $message .= '<tr><td>Dateiname</td></tr>';
          foreach ($deleteFiles as $file)
          {
            $message .= '<tr><td>'.$file.'</td></tr>';
          }
          $message .= '</table>';
        }
        
        $to = get_option('admin_email');
        $subject = 'WP-Security-Enhancer Alert';
        
        $header = 'From: '.$to."\r\n";
        $header .= 'To: '.$to."\r\n";
        
        mail($to, $subject, $message, $header);
      }
    }
  }
  
  function scan()
  {
    $files = $this->scanFiles();
    $old_files = get_option('WPSecurityEnhancer-filelist');
    $this->compareFileArrays($files, $old_files);
    update_option('WPSecurityEnhancer-filelist', $files);
  }
  
  function scanFiles($path = ABSPATH)
  {
    $files = array();
  
    $dh = opendir($path);
    
    while (($fileName = readdir($dh)) !== false)
    {
      if ($fileName == '.' || $fileName == '..')
        continue;
        
      $uri = $path.'/'.$fileName;

      if (is_dir($uri))
      {
        $filesSubFolder = $this->scanFiles($uri);
        $files = array_merge($filesSubFolder, $files);
      } 
      else      
      {
        $fileNameHash = md5($uri);
        $fileHash = md5_file($uri);
        $fileTime = filemtime($uri);
        
        $files[$fileNameHash] = array('hash' => $fileHash, 'time' => $fileTime, 'uri' => $uri);
      }
    }
    closedir($dh);
    
    return $files;
  }
  
}

$WPSecurityEnhancer = new WPSecurityEnhancer();
?>