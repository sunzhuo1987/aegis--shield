<?php
		if ($_POST['send']==$admin[35]){
		$user_array=array('id'=>$_user_active['id'], 'privilege'=>$_user_active['privilege'], 'phone'=>$_POST['phone'], 'fax'=>$_POST['fax'], 'mobile_phone'=>$_POST['mobile_phone'], 'email'=>$_POST['email'], 'language'=>$_POST['language'], 'city'=>$_POST['city'], 'nation'=>$_POST['nation'], 'place'=>$_POST['place'], 'zip_code'=>$_POST['zip_code'], 'address'=>$_POST['address'], 'group_id'=>$_user_active['group_id'], 'account'=>$_user_active['account']);
		echo '<div class="submit_form">'.$USER->set_user($user_array).'</div>';
		}
		else{
?>
<h5><?php echo $admin[120]; ?></h5>
<form method="post" action="">
<table id="change_user" class="default_table">
  <tr>
    <td><?php echo $admin[11]; ?> * </td>
    <td><input type="text" name="name" value="<?php echo htmlspecialchars($_user_active['name']); ?>" disabled="disabled" /></td>
  </tr>
  <tr>
    <td><?php echo $admin[12]; ?> * </td>
    <td><input type="text" name="surname" value="<?php echo htmlspecialchars($_user_active['surname']); ?>" disabled="disabled" /></td>
  </tr>
  <tr>
    <td><?php echo $admin[13]; ?></td>
    <td><input type="text" name="nation" value="<?php echo htmlspecialchars($_user_active['nation']); ?>" /></td>
  </tr>
  <tr>
    <td><?php echo $admin[14]; ?></td>
    <td><input type="text" name="city" value="<?php echo htmlspecialchars($_user_active['city']); ?>" /></td>
  </tr>
  <tr>
    <td><?php echo $admin[15]; ?></td>
    <td><input type="text" name="place" value="<?php echo htmlspecialchars($_user_active['place']); ?>" /></td>
  </tr>
  <tr>
    <td><?php echo $admin[16]; ?></td>
    <td><input type="text" name="zip_code" value="<?php echo htmlspecialchars($_user_active['zip_code']); ?>" /></td>
  </tr>
  <tr>
    <td><?php echo $admin[17]; ?></td>
    <td><input type="text" name="address" value="<?php echo htmlspecialchars($_user_active['address']); ?>" /></td>
  </tr>
  <tr>
    <td><?php echo $admin[18]; ?></td>
    <td><input type="text" name="phone" value="<?php echo htmlspecialchars($_user_active['phone']); ?>" /></td>
  </tr>
  <tr>
    <td><?php echo $admin[19]; ?></td>
    <td><input type="text" name="fax" value="<?php echo htmlspecialchars($_user_active['fax']); ?>" /></td>
  </tr>
  <tr>
    <td><?php echo $admin[20]; ?></td>
    <td><input type="text" name="mobile_phone" value="<?php echo htmlspecialchars($_user_active['mobile_phone']); ?>" /></td>
  </tr>
  <tr>
    <td><?php echo $admin[23]; ?> * </td>
    <td><input type="text" name="email" value="<?php echo htmlspecialchars($_user_active['email']); ?>" /></td>
  </tr>
  <tr>
    <td><?php echo $admin[24]; ?> * </td>
    <td><?php echo $LANGUAGE->languagesList($_user_active['language']); ?></td>
  </tr>
  <tr>
    <td><?php echo $admin[55]; ?> * </td>
    <td>
	<?php
	$group_selected=$GROUP->get_group($_user_active['group_id']);
	echo '<input type="text" name="group" value="'.$group_selected['name'].'" disabled="disabled" />';
	?>
	</td>
  </tr>
  <tr>
    <td><?php echo $admin[25]; ?> * </td>
    <td><?php echo '<input type="text" name="privilege" value="'.$USER->get_privilege_name($_user_active['privilege']).'" disabled="disabled" />'; ?></td>
  </tr>
  <tr>
    <td>&nbsp;</td>
    <td><input type="submit" name="send" value="<?php echo $admin[35]; ?>" /></td>
  </tr>
</table>
</form>
<?php
		}
?>