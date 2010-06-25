<h4><?php echo 'User management'; ?></h4>

<?php
switch($_GET['type']){
	case 'configure':
	
		if ($_POST['send']=='YES'){
			$user_array=array('id'=>$_GET['id'], 'privilege'=>$_POST['privilege'], 'phone'=>$_POST['phone'], 'fax'=>$_POST['fax'], 'mobile_phone'=>$_POST['mobile_phone'], 'email'=>$_POST['email'], 'language'=>$_POST['language'], 'city'=>$_POST['city'], 'nation'=>$_POST['nation'], 'place'=>$_POST['place'], 'zip_code'=>$_POST['zip_code'], 'address'=>$_POST['address'], 'group_id'=>$_POST['group_id'], 'account'=>$_POST['account']);
			echo '<div class="submit_form">'.$USER->set_user($user_array).'</div>';
		}
		else{
?>

<h5><?php echo 'Manage the user'; ?></h5>
<?php
$user_selected=$USER->get_user($_GET['id']);
?>
<form method="post" action="">
<table id="change_user" class="default_table">
  <tr>
    <td><?php echo $admin[11]; ?> * </td>
    <td><input type="text" name="name" value="<?php echo htmlspecialchars($user_selected['name']); ?>" disabled="disabled" /></td>
  </tr>
  <tr>
    <td><?php echo $admin[12]; ?> * </td>
    <td><input type="text" name="surname" value="<?php echo htmlspecialchars($user_selected['surname']); ?>" disabled="disabled" /></td>
  </tr>
  <tr>
    <td><?php echo $admin[21]; ?> * </td>
    <td><input type="text" name="username" value="<?php echo htmlspecialchars($user_selected['username']); ?>" disabled="disabled" /></td>
  </tr>
  <tr>
    <td><?php echo $admin[23]; ?> * </td>
    <td><input type="text" name="email" value="<?php echo htmlspecialchars($user_selected['email']); ?>" /></td>
  </tr>
  <tr>
    <td><?php echo $admin[25]; ?> * </td>
    <td><?php echo $USER->privilege_list($user_selected['privilege']); ?></td>
  </tr>
  <tr>
    <td>&nbsp;</td>
    <td><input type="submit" name="send" value="<?php echo "YES"; ?>" /></td>
  </tr>
</table>
</form>

<?php
		}
	break;
	case 'delete':
		if ($_POST['send']=="YES"){
			echo '<div class="submit_form">'.$USER->del_user($_GET['id']).'</div>';
		}
		elseif($_POST['send']=="NO"){
			echo '<div class="submit_form">'.'Not deleted'.'</div>';
		}
		else{
?>

<h5><?php echo $admin[68]; ?></h5>
<form method="post" action="">
<table id="delete_user" class="default_table">
<tr class="center"><td><input type="submit" name="send" value="<?php echo $admin[33]; ?>" /></td><td><input type="submit" name="send" value="<?php echo $admin[34]; ?>" /></td>
</tr></table>
</form>

<?php
		}
	break;
	case 'change_password':
		if ($_POST['send']==$admin[35]){
			echo '<div class="submit_form">'.$USER->change_password($_GET['id'], $_POST['password']).'</div>';
		}
		else{
?>

<h5><?php echo $admin[65]; ?></h5>
<form method="post" action="">
<table id="change_password" class="default_table">
<tr class="center"><td><input type="text" name="password" value="" /></td></tr>
<tr class="center"><td><input type="submit" name="send" value="<?php echo $admin[35]; ?>" /></td>
</tr></table>
</form>

<?php
		}
	break;
	case 'view':
?>

<?php
$user_selected=$USER->get_user($_GET['id']);
?>
<h5><?php echo $admin[66]; ?></h5>
<table id="view_user" class="default_table">
  <tr>
    <td><?php echo $admin[11]; ?></td>
    <td><?php echo htmlspecialchars($user_selected['name']); ?></td>
  </tr>
  <tr>
    <td><?php echo $admin[12]; ?></td>
    <td><?php echo htmlspecialchars($user_selected['surname']); ?></td>
  </tr>
  <tr>
    <td><?php echo $admin[21]; ?></td>
    <td><?php echo htmlspecialchars($user_selected['username']); ?></td>
  </tr>
  <tr>
    <td><?php echo $admin[23]; ?></td>
    <td><?php echo htmlspecialchars($user_selected['email']); ?></td>
  </tr>
  <tr>
    <td><?php echo $admin[25]; ?></td>
    <td><?php echo $USER->get_privilege_name($user_selected['privilege']); ?></td>
  </tr>
</table>

<?php
	break;
	case 'log':
?>

<h5><?php echo $admin[67]; ?></h5>
<?php echo '<table id="manage_log" class="default_table">'.$USER->get_log_list($_GET['id']).'</table>'; ?>

<?php
	break;
	case 'add_user':
?>
<?php
	require_once('interfaces/admin/add_user.php'); 
?>
<?php
	break;
	default:
?>
<table id="manage_user" class="default_table">
  <tr>
    <th><?php echo $admin[21]; ?></th>
    <th><?php echo $admin[23]; ?></th>
    <th><?php echo $admin[25]; ?></th>
	<th><?php echo $admin[60]; ?></th>
  </tr>
<?php
	$users_id=$USER->get_users_id();
	foreach($users_id as $value){
		$user_selected=$USER->get_user($value['id']);
		//$group_selected=$GROUP->get_group($user_selected['group_id']);
		echo '</td><td>'.htmlspecialchars($user_selected['username'])
		.'</td><td>'.htmlspecialchars($user_selected['email'])
		.'</td><td>'.$USER->get_privilege_name($user_selected['privilege'])
		.'</td><td>'.$USER->option_list($user_selected['id'])
		.'</td></tr>';
	}
?>
<tr><td>
<a href="admin.php?action=manage_user&type=add_user"><img src="images/add.png", alt="Add User", title="Add User" /></a>
</td></tr>
</table>

<?php
}
?>