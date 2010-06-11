<?php
if ($_POST['send']=="Add user"){
		$user_array=array('username'=>$_POST['username'], 'passwd'=>$_POST['passwd'], 'privilege'=>$_POST['privilege'], 'name'=>$_POST['name'], 'surname'=>$_POST['surname'],  'email'=>$_POST['email'], );
		
		echo '<div class="submit_form">'.$USER->add_user($user_array).'</div>';
}
else{
?>

<h4><?php echo "Add user"; ?></h4>
<form method="post" action="">
<table id="add_user" class="default_table">
  <tr>
    <td><?php echo $admin[11]; ?> * </td>
    <td><input type="text" name="name" /></td>
  </tr>
  <tr>
    <td><?php echo $admin[12]; ?> * </td>
    <td><input type="text" name="surname" /></td>
  </tr>
  <tr>
    <td><?php echo $admin[21]; ?> * </td>
    <td><input type="text" name="username" /></td>
  </tr>
  <tr>
    <td><?php echo $admin[22]; ?> * </td>
    <td><input type="text" name="passwd" /></td>
  </tr>
  <tr>
    <td><?php echo $admin[23]; ?> * </td>
    <td><input type="text" name="email" /></td>
  </tr>

  <tr>
    <td><?php echo "Type"; ?> * </td>
    <td><?php echo $USER->privilege_list(); ?></td>
  </tr>
  <tr>
    <td>&nbsp;</td>
    <td><input type="submit" name="send" value="<?php echo "Add user"; ?>" /></td>
  </tr>
</table>
</form>
<br />
<div class="center">* <?php echo 'Mandatory field'; ?><br />
** <?php echo 'The user is mandatory and must have at least 5 characters'; ?></div>
<?php 
}
?>