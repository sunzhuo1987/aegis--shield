<?php
$update_var=false;
if ($_POST['send_general']==$admin[35]){
	$SETTING->set_value('language', $_POST['language']);
	$SETTING->set_value('public', $_POST['public']);
	$SETTING->set_value('contrab_permission', $_POST['contrab_permission']);
	if ($USER->check_email($_POST['email'])){
		$SETTING->set_value('email', $_POST['email']);
	}
	$SETTING->set_value('url', $_POST['url']);
	$file_path='includes/path_settings.php';
	if (is_writable($file_path)){
		$content_path="<?php\ndefine('PATH_ABS', '".$_POST['path']."');\ndefine('N_LOG', '".$_POST['log_saved']."');\n?>";
		$handle=fopen($file_path, "w");
		fwrite($handle, $content_path);
		fclose($handle);		
	}
	$update_var=true;
}
elseif ($_POST['send_db']==$admin[35]){
	$file_connection='includes/connection_settings.php';
	if (is_writable($file_connection)){
		$content_connection="<?php\n".'$_type_of_db_server="'.$_POST['database'].'";'."\n".'$_host="'.$_POST['dbhost'].'";'."\n".'$_user="'.$_POST['user'].'";'."\n".'$_password="'.$_POST['password'].'";'."\n".'$_db_name="'.$_POST['dbname'].'";'."\n".'$_ulogd_table="'.$_POST['ulogd_table'].'";'."\n".'?>';
		$handle=fopen($file_connection, "w");
		fwrite($handle, $content_connection);
		fclose($handle);
	}
	$update_var=true;
}
elseif ($_POST['send_session']==$admin[35]){
	$file_session='includes/session_settings.php';
	if (is_writable($file_session)){
		$content_session="<?php\n".'$_session_time = '.$_POST['stl'].";\n".'$_session_gc_time = '.$_POST['gc'].";\n?>";
		$handle=fopen($file_session, "w");
		fwrite($handle, $content_session);
		fclose($handle);
	}
	$update_var=true;
}
elseif ($_POST['send_smtp']==$admin[35]){
	$SETTING->set_value('send_mail_type', $_POST['send_mail_type']);
	$SETTING->set_value('mail_server', $_POST['mail_server']);
	$SETTING->set_value('mail_auth', $_POST['mail_auth']);
	$SETTING->set_value('mail_username', $_POST['mail_username']);
	$SETTING->set_value('mail_password', $_POST['mail_password']);	
	$update_var=true;
}

?>

<h4><?php echo $admin[7]; ?></h4>
<?php if ($update_var) { echo '<div class="submit_form">'.$admin[59].'</div>'; }?>

<?php
if ($SETTING->is_modifiable('includes/path_settings.php')){
	$path_check='';
}
else{
	$path_check='disabled="disabled"';
}
?>
<form method="post" action="">
<table id="general_settings" class="default_table">
  <tr class="center"><td colspan="2"><h5><?php echo $admin[29]; ?></h5><br /></td></tr>
  <tr>
    <td><?php echo $admin[30]; ?> *</td>
    <td><?php echo $SETTING->create_select('public', array(array('key'=>'1', 'name'=>$admin[33]), array('key'=>'0', 'name'=>$admin[34])),true, $SETTING->get_value('public')); ?></td>
  </tr>
  <tr>
    <td><?php echo $admin[31]; ?> *</td>
    <td><?php echo $LANGUAGE->languagesList($SETTING->get_value('language')); ?></td>
  </tr>
  <tr>
    <td><?php echo $admin[88]; ?> *</td>
    <td><input type="text" name="url" value="<?php echo $SETTING->get_value('url'); ?>" /></td>
  </tr>
  <tr>
    <td><?php echo $admin[89]; ?> *</td>
    <td><input type="text" name="email" value="<?php echo $SETTING->get_value('email'); ?>" /></td>
  </tr>
  <tr>
    <td><?php echo $admin[32]; ?> *</td>
    <td><input type="text" name="path" <?php echo $path_check; ?> value="<?php if ($_POST['send_general']==$admin[35] && $path_check==''){ echo $_POST['path']; } else{ echo PATH_ABS; } ?>" /></td>
  </tr>
  <tr>
    <td><?php echo $admin[145]; ?> *</td>
    <td><input type="text" name="contrab_permission" value="<?php echo $SETTING->get_value('contrab_permission'); ?>" /></td>
  </tr>
  <tr>
    <td><?php echo $admin[163]; ?> *</td>
    <td><input type="text" name="log_saved" value="<?php if ($_POST['send_general']==$admin[35] && $path_check==''){ echo $_POST['log_saved']; } else{ echo N_LOG; } ?>" /></td>
  </tr>
  <tr>
    <td>&nbsp;</td>
    <td><input type="submit" name="send_general" value="<?php echo $admin[35]; ?>" /></td>
  </tr>
</table>
</form>

<br /><br />

<?php
if ($SETTING->is_modifiable('includes/connection_settings.php')){
	$connection_check='';
}
else{
	$connection_check='disabled="disabled"';
}
?>
<form method="post" action="">
<table id="db_settings" class="default_table">
  <tr class="center"><td colspan="2"><h5><?php echo $admin[36]; ?></h5><br /></td></tr>
  <tr>
    <td><?php echo $admin[58]; ?> *</td>
    <td><?php if ($_POST['send_db']==$admin[35] && $connection_check==''){ echo $SETTING->database_select($_POST['database'], $SETTING->is_modifiable('includes/connection_settings.php')); } else{ echo $SETTING->database_select($_type_of_db_server, $SETTING->is_modifiable('includes/connection_settings.php')); } ?></td>
  </tr>
  <tr>
    <td><?php echo $admin[37]; ?> *</td>
    <td><input type="text" name="dbhost" <?php echo $connection_check; ?> value="<?php if ($_POST['send_db']==$admin[35] && $connection_check==''){ echo $_POST['dbhost']; } else{ echo $_host; } ?>" /></td>
  </tr>
  <tr>
    <td><?php echo $admin[38]; ?> *</td>
    <td><input type="text" name="dbname" <?php echo $connection_check; ?> value="<?php if ($_POST['send_db']==$admin[35] && $connection_check==''){ echo $_POST['dbname']; } else{ echo $_db_name; } ?>" /></td>
  </tr>
  <tr>
    <td><?php echo $admin[21]; ?> *</td>
    <td><input type="text" name="user" <?php echo $connection_check; ?> value="<?php if ($_POST['send_db']==$admin[35] && $connection_check==''){ echo $_POST['user']; } else{ echo $_user; } ?>" /></td>
  </tr>
  <tr>
    <td><?php echo $admin[22]; ?> *</td>
    <td><input type="text" name="password" <?php echo $connection_check; ?> value="<?php if ($_POST['send_db']==$admin[35] && $connection_check==''){ echo $_POST['password']; } else{ echo $_password; } ?>" /></td>
  </tr>
  <tr>
    <td><?php echo $admin[161]; ?></td>
    <td><input type="text" name="ulogd_table" value="<?php if ($_POST['send_db']==$admin[35] && $connection_check==''){ echo $_POST['ulogd_table']; } else{ echo $_ulogd_table; } ?>" /></td>
  </tr>
  <tr>
    <td>&nbsp;</td>
    <td><input type="submit" name="send_db" <?php echo $connection_check; ?> value="<?php echo $admin[35]; ?>" /></td>
  </tr>
</table>
</form>

<br /><br />

<?php
if ($SETTING->is_modifiable('includes/session_settings.php')){
	$session_check='';
}
else{
	$session_check='disabled="disabled"';
}
?>
<form method="post" action="">
<table id="session_settings" class="default_table">
  <tr class="center"><td colspan="2"><h5><?php echo $admin[57]; ?></h5><br /></td></tr>
  <tr>
    <td><?php echo $admin[27]; ?> *</td>
    <td><input type="text" name="gc" <?php echo $session_check; ?> value="<?php if ($_POST['send_session']==$admin[35] && $session_check==''){ echo $_POST['gc']; } else{ echo $_session_gc_time; } ?>" /></td>
  </tr>
  <tr>
    <td><?php echo $admin[28]; ?> *</td>
    <td><input type="text" name="stl" <?php echo $session_check; ?> value="<?php if ($_POST['send_session']==$admin[35] && $session_check==''){ echo $_POST['stl']; } else{ echo $_session_time; } ?>" /></td>
  </tr>
  <tr>
    <td>&nbsp;</td>
    <td><input type="submit" name="send_session" value="<?php echo $admin[35]; ?>" /></td>
  </tr>
</table>
</form>

<br /><br />

<form method="post" action="">
<table id="mail_settings" class="default_table">
  <tr class="center"><td colspan="2"><h5><?php echo $admin[126]; ?></h5><br /></td></tr>
  <tr>
    <td><?php echo $admin[127]; ?> *</td>
    <td><?php echo $SETTING->create_select('send_mail_type', array(array('key'=>LOCAL_STMP, 'name'=>$admin[128]), array('key'=>EXTERNAL_STMP, 'name'=>$admin[129])),true, $SETTING->get_value('send_mail_type')); ?></td>
  </tr>
  <tr>
    <td><?php echo $admin[131]; ?></td>
    <td><input type="text" name="mail_server" value="<?php echo $SETTING->get_value('mail_server'); ?>" /></td>
  </tr>
  <tr>
    <td><?php echo $admin[130]; ?></td>
    <td><?php echo $SETTING->create_select('mail_auth', array(array('key'=>SMTP_AUTH_YES, 'name'=>$admin[33]), array('key'=>SMTP_AUTH_NO, 'name'=>$admin[34])),true, $SETTING->get_value('mail_auth')); ?></td>
  </tr>
  <tr>
    <td><?php echo $admin[21]; ?></td>
    <td><input type="text" name="mail_username" value="<?php echo $SETTING->get_value('mail_username'); ?>" /></td>
  </tr>
  <tr>
    <td><?php echo $admin[22]; ?></td>
    <td><input type="text" name="mail_password" value="<?php echo $SETTING->get_value('mail_password'); ?>" /></td>
  </tr>
  <tr>
    <td>&nbsp;</td>
    <td><input type="submit" name="send_smtp" value="<?php echo $admin[35]; ?>" /></td>
  </tr>
</table>
</form>