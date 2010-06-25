<?php
require_once('includes/config.php');

list($_status, $_user_active) = $SESSION->auth_get_status();

//Load dictionary
//$default_language=$SETTING->get_value('language');
//$language_file='lang/'.$default_language.'/dictionary.php';
$language_file='lang/en/dictionary.php';
if (file_exists($language_file)){
	require_once($language_file);
}
else{
	exit('NO Dictionary!');
}

if($_status == AUTH_NOT_LOGGED && $_POST['send']=='Login'){
	$uname = $_POST['username'];
	$passw = $_POST['passwd'];
	if($uname == "" || $passw == ""){
		$_status = AUTH_FAILED;
	}else{
		list($_status, $_user_active) = $SESSION->login($uname, $passw);
	}
}


/*登录成功后的跳转，中间会显示一个Loading...*/

switch($_status){
	case AUTH_LOGGED:
		switch($_user_active['privilege']){
			case USER:
				$page_redirect='user.php';
			break;
			case ADMIN:
				$page_redirect='admin.php';
			break;
		}
		header("Refresh: 1;URL=$page_redirect");
		echo $PAGE->getHeader('index',$admin[56]);
		echo '<div class="center">Loading...</div>';
		echo $PAGE->getFooter();
		exit();
	break;
}
?>
<?	/*登录页面*/
	echo $PAGE->getHeader('login',$admin[81]);
	$link_logo='index.php';
?>
<form method="post" action="">
  <table id="login">
	<tr><td colspan="2" class="center"><?php echo $UTILITY->get_logo($link_logo); ?></td></tr>
<?php

	//如果登录错误，在这儿显示
	if ($_status==AUTH_FAILED){
		echo '<tr><td colspan="2"><span id="login_failed">'.$admin[90].'</span></td></tr>';
	}	
	?>
    <tr>
      <td><?php echo $admin[21]; ?></td><td><input type="text" name="username" /></td>
    </tr>
    <tr>
      <td><?php echo $admin[22]; ?></td><td><input type="password" name="passwd" /></td>
    </tr>
<?php /*提交表单按钮*/?>
    <tr>
      <td>&nbsp;</td><td><input type="submit" name="send" value="<?php echo 'Login'; ?>" /></td>
    </tr>
	<?php /*找回密码选项*/ ?>
    <tr>
      <td colspan="2"><br /><a href="lost_password.php"><?php echo $admin['83']; ?></a></td>
    </tr>
  </table>
</form>
<?php
echo $PAGE->get_credits();
echo $PAGE->getFooter();
?>