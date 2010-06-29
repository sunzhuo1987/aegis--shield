<h4><?php echo $admin[251]; ?></h4>

<?php
switch($_GET['type']){
	case 'configure':
	
		if ($_POST['send']==$admin[327]){
			$user_array=array('id'=>$_GET['id'], 'privilege'=>$_POST['privilege'], 'phone'=>$_POST['phone'], 'fax'=>$_POST['fax'], 'mobile_phone'=>$_POST['mobile_phone'], 'email'=>$_POST['email'], 'language'=>$_POST['language'], 'city'=>$_POST['city'], 'nation'=>$_POST['nation'], 'place'=>$_POST['place'], 'zip_code'=>$_POST['zip_code'], 'address'=>$_POST['address'], 'group_id'=>$_POST['group_id'], 'account'=>$_POST['account']);
			echo '<div class="submit_form">'.$USER->set_user($user_array).'</div>';
		}
		else{
?>

<h5><?php echo $admin[251]; ?></h5>
<?php
$user_selected=$USER->get_user($_GET['id']);
?>
<form method="post" action="">
<table id="change_user" class="default_table">
  <tr>
    <td><?php echo $admin[320]; ?> * </td>
    <td><input type="text" name="name" value="<?php echo htmlspecialchars($user_selected['name']); ?>" disabled="disabled" /></td>
  </tr>
  <tr>
    <td><?php echo $admin[321]; ?> * </td>
    <td><input type="text" name="surname" value="<?php echo htmlspecialchars($user_selected['surname']); ?>" disabled="disabled" /></td>
  </tr>
  <tr>
    <td><?php echo $admin[322]; ?> * </td>
    <td><input type="text" name="username" value="<?php echo htmlspecialchars($user_selected['username']); ?>" disabled="disabled" /></td>
  </tr>
  <tr>
    <td><?php echo $admin[323]; ?> * </td>
    <td><input type="text" name="email" value="<?php echo htmlspecialchars($user_selected['email']); ?>" /></td>
  </tr>
  <tr>
    <td><?php echo $admin[324]; ?> * </td>
    <td><?php echo $USER->privilege_list($user_selected['privilege']); ?></td>
  </tr>
  <tr>
    <td>&nbsp;</td>
    <td><input type="submit" name="send" value="<?php echo $admin[327]; ?>" /></td>
  </tr>
</table>
</form>

<?php
		}
	break;
	case 'delete':
		if ($_POST['send']==$admin[341]){
			echo '<div class="submit_form">'.$USER->del_user($_GET['id']).'</div>';
		}
		elseif($_POST['send']==$admin[342]){
			echo '<div class="submit_form">'.$admin[343].'</div>';
		}
		else{
?>

<h5><?php echo $admin[340]; ?></h5>
<form method="post" action="">
<table id="delete_user" class="default_table">
<tr class="center"><td><input type="submit" name="send" value="<?php echo $admin[341]; ?>" /></td><td><input type="submit" name="send" value="<?php echo $admin[342]; ?>" /></td>
</tr></table>
</form>

<?php
		}
	break;
	case 'change_password':
		if ($_POST['send']==$admin[351]){
			echo '<div class="submit_form">'.$USER->change_password($_GET['id'], $_POST['password']).'</div>';
		}
		else{
?>

<h5><?php echo $admin[350]; ?></h5>
<form method="post" action="">
<table id="change_password" class="default_table">
<tr class="center"><td><input type="text" name="password" value="" /></td></tr>
<tr class="center"><td><input type="submit" name="send" value="<?php echo $admin[351]; ?>" /></td>
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
<h5><?php echo $admin[360]; ?></h5>
<table id="view_user" class="default_table">
  <tr>
    <td><?php echo $admin[361]; ?></td>
    <td><?php echo htmlspecialchars($user_selected['name']); ?></td>
  </tr>
  <tr>
    <td><?php echo $admin[362]; ?></td>
    <td><?php echo htmlspecialchars($user_selected['surname']); ?></td>
  </tr>
  <tr>
    <td><?php echo $admin[363]; ?></td>
    <td><?php echo htmlspecialchars($user_selected['username']); ?></td>
  </tr>
  <tr>
    <td><?php echo $admin[364]; ?></td>
    <td><?php echo htmlspecialchars($user_selected['email']); ?></td>
  </tr>
  <tr>
    <td><?php echo $admin[365]; ?></td>
    <td><?php echo $USER->get_privilege_name($user_selected['privilege']); ?></td>
  </tr>
</table>

<?php
	break;
	case 'log':
?>

<h5><?php echo $admin[309]; ?></h5>
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
    <th><?php echo $admin[300]; ?></th>
    <th><?php echo $admin[301]; ?></th>
    <th><?php echo $admin[302]; ?></th>
	<th><?php echo $admin[303]; ?></th>
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