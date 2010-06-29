<?php
require_once('includes/config.php');

list($_status, $_user_active) = $SESSION->auth_get_status();

//Load dictionary
$language_file='lang/ch/dictionary.php';
if (file_exists($language_file)){
	require_once($language_file);
}
else{
	exit('NO Dictionary!');
}

if($_status == AUTH_NOT_LOGGED && $_POST['send']==$admin[202]){
	$uname = $_POST['username'];
	$passw = $_POST['passwd'];
	if($uname == "" || $passw == ""){
		$_status = AUTH_FAILED;
	}else{
		list($_status, $_user_active) = $SESSION->login($uname, $passw);
	}
}


/*��¼�ɹ������ת���м����ʾһ��Loading...*/

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
		echo $PAGE->getHeader('index',$admin[221]);
		echo '<div class="center">'.$admin[220].'</div>';
		echo $PAGE->getFooter();
		exit();
	break;
}
?>
<?	/*��¼ҳ��*/
	echo $PAGE->getHeader('login',$admin[202]);
	$link_logo='index.php';
?>
<form method="post" action="">
  <table id="login">
	<tr><td colspan="2" class="center"><?php echo $UTILITY->get_logo($link_logo); ?></td></tr>
<?php

	//�����¼�����������ʾ
	if ($_status==AUTH_FAILED){
		echo '<tr><td colspan="2"><span id="login_failed">'.' **'.$admin[203].'</span></td></tr>';
	}	
	?>
	<tr></tr>
    <tr>
      <td><?php echo $admin[21]; ?></td><td><input type="text" name="username" /></td>
    </tr>
    <tr>
      <td><?php echo $admin[22]; ?></td><td><input type="password" name="passwd" /></td>
    </tr>
    <tr>
      <td>&nbsp;</td><td><input type="submit" name="send" value="<?php echo $admin[202]; ?>" /></td>
    </tr>
  </table>
</form>
<?php
echo $PAGE->get_credits();
echo $PAGE->getFooter();
?>